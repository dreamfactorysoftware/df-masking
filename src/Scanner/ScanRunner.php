<?php

namespace DreamFactory\Core\Masking\Scanner;

use DreamFactory\Core\Masking\Classifier\Engine;
use DreamFactory\Core\Masking\Classifier\Evidence;
use DreamFactory\Core\Masking\Classifier\Ruleset;
use DreamFactory\Core\Masking\Classifier\TableMeta;
use DreamFactory\Core\Masking\Support\Activity;
use DreamFactory\Core\Masking\Support\Catalog;
use DreamFactory\Core\Masking\Support\PolicyVersion;
use DreamFactory\Core\Masking\Support\RulePattern;
use DreamFactory\Core\Masking\Support\ScanHistory;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * Synchronous scan of the covered SQL services (used by `php artisan df:masking scan` and by the
 * detached process ScanLauncher starts).
 *
 * Per service: read the schema through DreamFactory (pass 1, so progress has a total), then per
 * table: sample (head + tail windows), classify with the built-in rule pack, apply admin/baseline
 * rules, write dm_column (sticky admin decisions, add-only automatic changes), forget the sample.
 * Cost-bearing warehouses (Snowflake, Databricks, Trino, Dremio) are classified from column names
 * only unless sampling was explicitly requested ($sample = true). A service that cannot be read is
 * reported and skipped; the others are still scanned.
 *
 * Sampled values live only in memory, one table at a time. Nothing logged, stored or reported
 * here contains a value: evidence is counts and shapes, examples are masked renderings, errors
 * are SQLSTATEs.
 */
final class ScanRunner
{
    public const PENDING_KEY = 'df-masking:scan:pending';
    private const MAX_NAME = 255;

    /** @var list<int> ids of the services this run read successfully (dm_scan.read_services) */
    private array $readIds = [];

    /**
     * @param ?string   $service  one service name, or null for every covered service
     * @param ?int      $scanId   dm_scan row to report into (ScanLauncher creates it); null = create one
     * @param ?callable $progress fn(int $percent, int $columnsDone, int $columnsTotal, string $what): void
     * @param bool      $sample   explicitly sample cost-bearing warehouses too (regular SQL databases
     *                            are always sampled)
     * @return array{scan_id:int, status:string, error:?string, errors:list<string>, services:int, services_failed:list<string>,
     *               failed:list<array{service_id:int,service:string,label:string,reason:string}>, tables:int,
     *               columns:int, masked:int, review:int, clear:int, changed:int, deleted:int, name_only:list<string>,
     *               partial_tables:int, unreadable_columns:int, failed_tables:int, duration_ms:int, mode_switched:bool}
     */
    public function run(?string $service = null, ?int $scanId = null, ?callable $progress = null, bool $sample = false): array
    {
        $t0 = hrtime(true);
        @set_time_limit(0);
        $this->readIds = [];
        $summary = ['scan_id' => 0, 'status' => ScanState::DONE, 'error' => null, 'errors' => [], 'services' => 0, 'services_failed' => [], 'failed' => [],
            'tables' => 0, 'columns' => 0, 'masked' => 0, 'review' => 0, 'clear' => 0, 'changed' => 0, 'deleted' => 0, 'name_only' => [],
            'partial_tables' => 0, 'unreadable_columns' => 0, 'failed_tables' => 0, 'duration_ms' => 0, 'mode_switched' => false];

        if ($scanId !== null) {
            $row = ScanState::find($scanId);
            if ($row === null) {
                throw new \InvalidArgumentException("Scan $scanId does not exist.");
            }
            if (($service === null || $service === '') && $row->service_id !== null) {
                $service = (string) DB::table('service')->where('id', (int) $row->service_id)->value('name') ?: null;
            }
            $state = new ScanState($scanId);
        } else {
            $serviceId = null;
            if ($service !== null && $service !== '') {
                $serviceId = Services::covered($service)[0]['id'];
            }
            $state = ScanState::create($serviceId, Activity::CONSOLE);
        }
        $state->claim((int) getmypid());
        $summary['scan_id'] = $state->id;

        try {
            $targets = Services::covered($service !== '' ? $service : null);
            $done = 0;
            $total = 0;
            $tick = static fn () => $state->beat(0, 0); // heartbeat while schemas load (progress stays 0)
            $loaded = $this->loadSchemas($targets, $summary, $total, $tick);
            $state->total($total);
            $report = function (string $what) use (&$done, &$total, $state, $progress): void {
                $state->beat($done, $total);
                if ($progress !== null) {
                    $progress(ScanState::percent($done, $total), $done, $total, $what);
                }
            };
            $rules = Rules::load();
            $writer = new ColumnWriter(new Examples());
            $engine = Ruleset::engine(gmdate('Y-m-d'));
            // Services whose schema loaded but whose scan has not completed (reported if the scan stops).
            $pendingTargets = array_map(static fn ($svc) => $svc['info'], $loaded);
            foreach ($loaded as $svc) {
                $this->scanOne($svc, $engine, $rules, $writer, $sample, $summary, $done, $report);
                $pendingTargets = array_values(array_filter($pendingTargets, static fn ($t) => $t['id'] !== $svc['info']['id']));
            }
            $pendingTargets = [];
            $seen = array_column($targets, 'name');
            // Background requests that came due meanwhile (ScanLauncher::startThrottled), bounded.
            for ($round = 0; $round < 20; $round++) {
                $extras = $this->pending($seen);
                if ($extras === []) {
                    break;
                }
                foreach ($extras as $extra) {
                    $seen[] = $extra['name'];
                    $extraTotal = 0;
                    foreach ($this->loadSchemas([$extra], $summary, $extraTotal, $tick) as $svc) {
                        $total += $extraTotal;
                        $state->total($total);
                        $this->scanOne($svc, $engine, $rules, $writer, $sample, $summary, $done, $report);
                    }
                }
            }
            $summary['duration_ms'] = intdiv(hrtime(true) - $t0, 1000000);
            $failed = $summary['services_failed'];
            // Admins read activity in the UI, which names services by label (as Compliance does).
            $failedLabels = self::labels($summary['failed']);
            // The service the scan was started for names it, unless the run took on requests for
            // other services as well: then it was a scan of several, like a full one.
            $target = count($seen) > 1 ? null : $service;
            if ($summary['services'] === 0 && $failed !== []) {
                $summary['status'] = ScanState::FAILED;
                $summary['error'] = 'Could not read ' . self::listNames($failed) . '.';
                $summary['errors'] = self::errorList($summary);
                $state->fail($summary['error'], $summary['failed']);
                Activity::log('scan', 'Scan failed: could not read ' . self::listNames($failedLabels), $target, ['scan_id' => $state->id], Activity::SYSTEM);
                Log::warning('df-masking: scan ' . $state->id . ' failed: could not read ' . implode(', ', $failed));
                return $summary;
            }
            $summary['error'] = $failed === [] ? null : 'Could not scan ' . self::listNames($failed) . '.';
            $summary['errors'] = self::errorList($summary);
            $state->finish($done, $total, $summary['error'], $summary['failed'], $this->readIds);
            $text = sprintf('Scan finished: %d %s in %d %s', $summary['columns'], $summary['columns'] === 1 ? 'column' : 'columns',
                $summary['services'], $summary['services'] === 1 ? 'database' : 'databases');
            if ($failed !== []) {
                $text .= ' (could not scan ' . self::listNames($failedLabels) . ')';
            }
            if ($summary['unreadable_columns'] > 0) {
                $text .= sprintf('; values of %d %s could not be read', $summary['unreadable_columns'], $summary['unreadable_columns'] === 1 ? 'column' : 'columns');
            }
            Activity::log('scan', $text, $target, [
                'scan_id' => $state->id, 'masked' => $summary['masked'], 'review' => $summary['review'], 'clear' => $summary['clear'],
                'changed' => $summary['changed'], 'duration_ms' => $summary['duration_ms'],
            ], Activity::SYSTEM);
            if ($summary['services'] > 0 && $summary['columns'] > 0) {
                $summary['mode_switched'] = Settings::afterScanCompleted();
            }
            Log::info(sprintf('df-masking: scan %d finished: %d columns in %d services (%d masked, %d review, %d clear, %d changed) in %d ms',
                $state->id, $summary['columns'], $summary['services'], $summary['masked'], $summary['review'], $summary['clear'],
                $summary['changed'], $summary['duration_ms']));
            $this->rescanForNewValueRules($rules);
        } catch (\Throwable $e) {
            $summary['status'] = ScanState::FAILED;
            $summary['error'] = 'The scan stopped: ' . self::safeMessage($e);
            $summary['errors'] = [$summary['error']];
            $summary['duration_ms'] = intdiv(hrtime(true) - $t0, 1000000);
            foreach ($pendingTargets ?? [] as $t) {
                $summary['failed'][] = ['service_id' => $t['id'], 'service' => $t['name'], 'label' => self::labelOf($t), 'reason' => ScanHistory::reason($e)];
            }
            try {
                $state->fail($summary['error'], $summary['failed']);
                Activity::log('scan', 'Scan failed: ' . self::safeMessage($e), $service, ['scan_id' => $state->id], Activity::SYSTEM);
            } catch (\Throwable $ignored) {
            }
            Log::error('df-masking: scan ' . $state->id . ' failed: ' . get_class($e) . ': ' . self::safeMessage($e));
        }
        return $summary;
    }

    /**
     * Re-applies name rules to stored columns without sampling (after a rule was added).
     * Add-only: never clears or weakens a column, never touches admin decisions.
     *
     * @return int number of columns that changed
     */
    public function reevaluateRules(): int
    {
        $rules = Rules::load();
        if ($rules->isEmpty()) {
            return 0;
        }
        $examples = new Examples();
        $changed = 0;
        DB::table(Tables::COLUMN)->where('source', '!=', 'admin')
            ->select(['id', 'column_name', 'verdict', 'class', 'score', 'evidence', 'examples'])
            ->chunkById(500, function ($rows) use ($rules, $examples, &$changed): void {
                foreach ($rows as $row) {
                    $hit = $rules->matchName((string) $row->column_name);
                    if ($hit === null || Rules::rank('masked', $hit['class']) <= Rules::rank((string) $row->verdict, $row->class)) {
                        continue;
                    }
                    $evidence = json_decode((string) $row->evidence, true);
                    if (!is_array($evidence)) {
                        $evidence = ['total' => (int) $row->score, 'threshold_mask' => 70, 'threshold_review' => 40, 'lines' => [], 'shapes' => []];
                    }
                    $evidence['lines'][] = Evidence::line(Rules::RULE_SCORE, Evidence::KIND_CONTEXT, Rules::describe($hit));
                    $evidence['total'] = max((int) ($evidence['total'] ?? 0), Rules::RULE_SCORE);
                    $previous = json_decode((string) $row->examples, true);
                    DB::table(Tables::COLUMN)->where('id', $row->id)->update([
                        'verdict' => 'masked',
                        'class' => $hit['class'],
                        'tier' => Catalog::tierOf($hit['class']),
                        'score' => max((int) $row->score, Rules::RULE_SCORE),
                        'source' => str_starts_with($hit['source'], 'baseline:') ? 'baseline' : 'rule',
                        'evidence' => ColumnWriter::json($evidence),
                        'examples' => ColumnWriter::json($examples->reuse($hit['class'], is_array($previous) ? $previous : [])),
                        'updated_at' => now(),
                    ]);
                    $changed++;
                }
            });
        if ($changed > 0) {
            PolicyVersion::bump();
        }
        return $changed;
    }

    /**
     * Which columns a candidate rule would match (POST system/data_masking/rule/test).
     * Name rules: stored columns, instantly. Value rules: live sample (small head windows) of the
     * covered services within $budgetMs; partial = true when the budget ran out or a warehouse
     * was skipped (warehouses are never sampled for a test). Values never leave this method.
     *
     * @return array{matches:list<array{id:string}>, partial:bool}
     * @throws \InvalidArgumentException when the pattern is invalid
     */
    public function testRule(string $match, string $pattern, ?int $budgetMs = null): array
    {
        if (($error = RulePattern::validate($pattern)) !== null) {
            throw new \InvalidArgumentException($error);
        }
        $compiled = RulePattern::compile($pattern);
        $names = DB::table('service')->pluck('name', 'id')->all();
        $matches = [];
        if ($match === 'name') {
            DB::table(Tables::COLUMN)->select(['id', 'service_id', 'table_name', 'column_name'])
                ->chunkById(1000, function ($rows) use ($compiled, $names, &$matches): void {
                    foreach ($rows as $row) {
                        if (isset($names[$row->service_id]) && RulePattern::matches($compiled, (string) $row->column_name)) {
                            $matches[] = ['id' => $names[$row->service_id] . '.' . $row->table_name . '.' . $row->column_name];
                        }
                    }
                });
            return ['matches' => $matches, 'partial' => false];
        }
        if ($match !== 'value') {
            throw new \InvalidArgumentException("Rules match 'name' or 'value'.");
        }
        $budgetMs ??= (int) config('df-masking.rules.test_budget_ms', 3000);
        $deadline = hrtime(true) + max(250, $budgetMs) * 1000000;
        $partial = false;
        foreach (Services::covered() as $info) {
            try {
                $svc = app('df.service')->getService($info['name']);
                if (Services::isMissingSqliteFile($svc)) {
                    continue;
                }
                $reader = new SchemaReader($svc);
                $driver = $reader->driver();
                if (Services::isCostBearing($driver, $info['type'])) {
                    $partial = true;
                    continue;
                }
                $sampler = new Sampler($svc->getConnection(), $driver, 32, 1000, 2000);
                foreach ($svc->getTableNames() as $ts) {
                    if (hrtime(true) > $deadline) {
                        return ['matches' => $matches, 'partial' => true];
                    }
                    $full = $svc->getTableSchema($ts->name);
                    if (!is_object($full)) {
                        continue;
                    }
                    $d = SchemaReader::describe($full, $driver);
                    $s = $sampler->sample($d['meta'], $d['plan']);
                    foreach ($d['plan']['columns'] as $c) {
                        if (!$c['sampled']) {
                            continue;
                        }
                        $values = self::values($s['rows'], $c['name']);
                        if (Rules::valueRuleMatches(Rules::countMatches($compiled, $values), count($values))) {
                            $matches[] = ['id' => $info['name'] . '.' . $d['meta']->dfName . '.' . $c['name']];
                        }
                    }
                    unset($s);
                }
            } catch (\Throwable $e) {
                $partial = true;
            }
            self::release($info['name']);
            if (hrtime(true) > $deadline) {
                return ['matches' => $matches, 'partial' => true];
            }
        }
        return ['matches' => $matches, 'partial' => $partial];
    }

    // ------------------------------------------------------------------ internals

    /**
     * Pass 1: schemas of the target services through DreamFactory.
     *
     * @return list<array{info:array, service:object, driver:string, tables:array<string,array>, failed_tables:list<string>}>
     */
    private function loadSchemas(array $targets, array &$summary, int &$total, ?callable $tick = null): array
    {
        $out = [];
        foreach ($targets as $info) {
            // Background requests made before this read are satisfied by it (success or failure;
            // a failure is reported through dm_scan.failed_services, not retried in a loop).
            ScanLauncher::forgetRequest($info['name'], ScanLauncher::clock());
            try {
                $svc = app('df.service')->getService($info['name']);
                if (Services::isMissingSqliteFile($svc)) {
                    // Nothing to classify, and connecting would create the database file.
                    $out[] = ['info' => $info, 'service' => $svc, 'driver' => 'sqlite', 'tables' => [], 'failed_tables' => []];
                    continue;
                }
                $reader = new SchemaReader($svc);
                $driver = $reader->driver();
                $tables = [];
                $failed = [];
                foreach ($reader->tableNames() as $ts) {
                    $name = (string) $ts->name;
                    if ($tick !== null) {
                        $tick();
                    }
                    try {
                        $full = $reader->tableSchema($name);
                        if ($full === null) {
                            continue;
                        }
                        $d = SchemaReader::describe($full, $driver);
                        if (mb_strlen($d['meta']->dfName) > self::MAX_NAME) {
                            continue;
                        }
                        $tables[$d['meta']->dfName] = $d;
                        $total += count($d['meta']->columns);
                    } catch (\Throwable $e) {
                        $failed[] = $name;
                        Log::warning(sprintf("df-masking: could not read table '%s' of service '%s' (%s)", $name, $info['name'], Sampler::sqlState($e)));
                    }
                }
                $out[] = ['info' => $info, 'service' => $svc, 'driver' => $driver, 'tables' => $tables, 'failed_tables' => $failed];
                $summary['failed_tables'] += count($failed);
                self::release($info['name']);
            } catch (\Throwable $e) {
                self::release($info['name']);
                self::serviceFailed($summary, $info, $e);
                Log::warning(sprintf("df-masking: could not read service '%s' (%s)", $info['name'], Sampler::sqlState($e)));
            }
        }
        return $out;
    }

    /**
     * Pass 2 for one service; a failure stops this service only (reported with its reason), never
     * the scan of the others.
     */
    private function scanOne(array $svc, Engine $engine, Rules $rules, ColumnWriter $writer, bool $sample, array &$summary, int &$done, callable $report): void
    {
        try {
            $this->scanService($svc, $engine, $rules, $writer, $sample, $summary, $done, $report);
            $summary['services']++;
            $this->readIds[] = (int) $svc['info']['id'];
        } catch (\Throwable $e) {
            self::release($svc['info']['name']);
            self::serviceFailed($summary, $svc['info'], $e);
            Log::warning(sprintf("df-masking: scan of service '%s' stopped (%s)", $svc['info']['name'], Sampler::sqlState($e)));
        }
        PolicyVersion::bump();
    }

    private static function serviceFailed(array &$summary, array $info, \Throwable $e): void
    {
        $summary['services_failed'][] = $info['name'];
        $summary['failed'][] = ['service_id' => $info['id'], 'service' => $info['name'], 'label' => self::labelOf($info),
            'reason' => ScanHistory::reason($e)];
    }

    /** A service's label, or its name when it has none. */
    private static function labelOf(array $info): string
    {
        $label = trim((string) ($info['label'] ?? ''));

        return $label !== '' ? $label : (string) $info['name'];
    }

    /**
     * Labels (name when unlabelled) of failed services, for activity texts.
     *
     * @param list<array{service:string,label?:string}> $failed
     * @return list<string>
     */
    private static function labels(array $failed): array
    {
        return array_map(static fn (array $f) => self::labelOf(['name' => $f['service'], 'label' => $f['label'] ?? '']), $failed);
    }

    /** Pass 2 for one service. */
    private function scanService(array $svc, Engine $engine, Rules $rules, ColumnWriter $writer, bool $sample, array &$summary, int &$done, callable $report): void
    {
        $info = $svc['info'];
        $driver = $svc['driver'];
        $nameOnly = !$sample && Services::isCostBearing($driver, $info['type']);
        if ($nameOnly) {
            $summary['name_only'][] = $info['name'];
        }
        $tables = $svc['tables'];
        ksort($tables, SORT_STRING);
        $metas = array_map(static fn ($d) => $d['meta'], array_values($tables));
        $contexts = $engine->tableContexts($metas);
        // No tables: no sampler (opening the connection could create an absent SQLite file).
        $sampler = ($nameOnly || $tables === []) ? null : new Sampler(
            $svc['service']->getConnection(),
            $driver,
            Sampler::PER_WINDOW,
            (int) config('df-masking.scan.table_budget_ms', 20000),
            (int) config('df-masking.scan.statement_timeout_ms', 10000),
        );
        $pack = Ruleset::pack();
        $version = Ruleset::version();
        $mode = $nameOnly ? Engine::MODE_NAME_ONLY : Engine::MODE_HYBRID;
        foreach ($tables as $dfName => $d) {
            /** @var TableMeta $meta */
            $meta = $d['meta'];
            $s = $sampler?->sample($meta, $d['plan']);
            if ($s !== null && $s['partial']) {
                $summary['partial_tables']++;
            }
            if ($s !== null && $s['error'] !== null) {
                Log::warning(sprintf("df-masking: could not sample '%s.%s' (%s); columns marked to review", $info['name'], $dfName, $s['error']));
            } elseif ($s !== null && ($s['failed_columns'] ?? []) !== []) {
                Log::warning(sprintf("df-masking: could not read %d column(s) of '%s.%s' (%s); marked to review", count($s['failed_columns']),
                    $info['name'], $dfName, implode(', ', array_unique(array_values($s['failed_columns'])))));
            }
            $verdicts = $engine->classifyTable($meta, $contexts[$dfName], $s, $mode);
            $unreadable = $s === null ? [] : (array) ($s['failed_columns'] ?? []);
            $columns = [];
            $dfTypes = array_column($d['plan']['columns'], 'df_type', 'name');
            foreach ($meta->columns as $i => $c) {
                if (mb_strlen($c->name) > self::MAX_NAME || !isset($verdicts[$c->name])) {
                    continue;
                }
                $result = Evidence::fromEngine($verdicts[$c->name], $nameOnly, $pack);
                $result['detected_class'] = $result['class'];
                $result['detected_score'] = $result['score'];
                $readError = !$c->sampleable || $s === null ? null : ($unreadable[$c->name] ?? $s['error']);
                $values = ($s === null || !$c->sampleable || $readError !== null) ? null : self::values($s['rows'], $c->name);
                $result = $rules->apply($c->name, $values, $result);
                if ($readError !== null) {
                    $result = self::unreadable($result, $readError);
                    $summary['unreadable_columns']++;
                }
                $columns[$c->name] = [
                    'db_type' => $c->dbType,
                    'ordinal' => $i + 1,
                    'fingerprint' => hash('sha256', json_encode([$dfName, $c->name, $c->dbType, $c->dfType, $c->size, $c->isPrimaryKey, $c->isForeignKey, $c->refTable])),
                    'result' => $result,
                    'raw' => $values[0] ?? null,
                    'df_type' => $dfTypes[$c->name] ?? null,
                    'name_only' => $nameOnly || $values === null,
                ];
            }
            unset($s, $values);
            // Computed fields (SELECT db_function) inherit from the columns they read (fix-enforcement).
            $columns = \DreamFactory\Core\Masking\Enforcement\DerivedFields::applyToScan($columns, $d['plan']['columns']);
            $stats = $writer->write((int) $info['id'], $dfName, $columns, $version);
            $summary['tables']++;
            $summary['columns'] += count($columns);
            foreach (['masked', 'review', 'clear', 'changed', 'deleted'] as $k) {
                $summary[$k] += $stats[$k];
            }
            $done += count($meta->columns);
            $report($info['name'] . '.' . $dfName);
        }
        // Tables that no longer exist (keep rows of tables that merely failed to load this time).
        $summary['deleted'] += ColumnWriter::deleteTablesExcept((int) $info['id'], array_merge(array_keys($tables), $svc['failed_tables']));
        self::release($info['name']);
    }

    /**
     * Closes the service's database connection (it reconnects lazily if used again), so a scan
     * of many services never holds more than one customer database connection open at a time.
     */
    private static function release(string $serviceName): void
    {
        try {
            $db = app('db');
            if (method_exists($db, 'getConnections') && array_key_exists('service.' . $serviceName, $db->getConnections())) {
                $db->disconnect('service.' . $serviceName);
            }
        } catch (\Throwable $e) {
            // nothing to release
        }
    }

    /**
     * Non-null cleaned values of one column, in row (key) order.
     *
     * @return list<string>
     */
    private static function values(array $rows, string $column): array
    {
        $out = [];
        foreach ($rows as $r) {
            $v = Engine::cleanValue($r[$column] ?? null);
            if ($v !== null) {
                $out[] = $v;
            }
        }
        return $out;
    }

    /**
     * Services queued while this scan was running (ScanLauncher::startThrottled), not already
     * covered by it.
     *
     * @return list<array{id:int, name:string, label:string, type:string}>
     */
    private function pending(array $scanned): array
    {
        try {
            $legacy = Cache::pull(self::PENDING_KEY, []); // queued by an older version of the launcher
        } catch (\Throwable $e) {
            $legacy = [];
        }
        $names = array_merge(is_array($legacy) ? $legacy : [], ScanLauncher::dueRequests());
        $out = [];
        foreach (array_unique($names) as $name) {
            if (in_array($name, $scanned, true)) {
                ScanLauncher::forgetRequest((string) $name, ScanLauncher::clock());
                continue;
            }
            try {
                $out[] = Services::covered((string) $name)[0];
            } catch (\Throwable $e) {
                // deleted or deactivated meanwhile
            }
        }
        return $out;
    }

    /**
     * A value rule added while this scan ran is not in the rules it loaded at its start, and the
     * scan takes requests for the services it already read as satisfied (pending()). So once it
     * has finished, the services it read are requested again: the next scan starts at once and
     * applies the rule. Checked after finish(): a rule added later finds no scan running and
     * starts its own (RuleHandler).
     */
    private function rescanForNewValueRules(Rules $used): void
    {
        try {
            if ($this->readIds === [] || array_diff(Rules::load()->valueRuleIds(), $used->valueRuleIds()) === []) {
                return;
            }
            foreach (Services::covered() as $info) {
                if (in_array($info['id'], $this->readIds, true)) {
                    ScanLauncher::startThrottled($info['name'], Activity::SYSTEM, 0);
                }
            }
        } catch (\Throwable $e) {
            Log::debug('df-masking: no follow-up scan for new value rules: ' . get_class($e));
        }
    }

    /** @return list<string> human-readable problems of a finished scan (no values) */
    private static function errorList(array $summary): array
    {
        $out = [];
        foreach ($summary['services_failed'] as $name) {
            $out[] = "Could not read service '$name' (see storage/logs for the SQLSTATE).";
        }
        foreach ($summary['name_only'] as $name) {
            $out[] = "'$name' bills per query: classified from column names only. Run with --sample to sample its values.";
        }
        if ($summary['partial_tables'] > 0) {
            $out[] = sprintf('%d large or slow tables were partly sampled (time budget).', $summary['partial_tables']);
        }
        if ($summary['unreadable_columns'] > 0) {
            $out[] = sprintf('Values of %d %s could not be read; they are marked to review.', $summary['unreadable_columns'],
                $summary['unreadable_columns'] === 1 ? 'column' : 'columns');
        }
        if ($summary['failed_tables'] > 0) {
            $out[] = sprintf('%d %s could not be read; their earlier classification was kept.', $summary['failed_tables'],
                $summary['failed_tables'] === 1 ? 'table' : 'tables');
        }
        return $out;
    }

    /**
     * A column whose values could not be read is never served as "not sensitive" on the strength
     * of its name alone: at least review (masked until an admin decides or a scan reads it), with
     * an evidence line saying why. Flagged name-only, so the next scan that reads values replaces
     * the verdict even when it is weaker.
     */
    public static function unreadable(array $result, string $sqlState): array
    {
        $result['evidence']['lines'][] = Evidence::line(0, Evidence::KIND_CONTEXT, sprintf(
            'Values could not be read (%s); masked until a scan reads them or an admin decides', $sqlState
        ));
        $result['evidence']['name_only'] = true;
        if ($result['verdict'] === 'clear') {
            $result['verdict'] = 'review';
            $result['score'] = max((int) $result['score'], 40);
            $result['evidence']['total'] = max((int) ($result['evidence']['total'] ?? 0), 40);
        }
        return $result;
    }

    private static function listNames(array $names): string
    {
        return implode(', ', array_slice($names, 0, 5)) . (count($names) > 5 ? sprintf(' and %d more', count($names) - 5) : '');
    }

    /** Exception message with quoted literals removed (driver messages can echo data). */
    public static function safeMessage(\Throwable $e): string
    {
        if ($e instanceof \InvalidArgumentException) {
            return mb_substr($e->getMessage(), 0, 300); // our own message (service names, ids), never data
        }
        $m = $e instanceof \PDOException || $e instanceof \Illuminate\Database\QueryException
            ? Sampler::sqlState($e)
            : $e->getMessage();
        $m = preg_replace(["/'[^']*'/", '/"[^"]*"/', '/\([^()]*\)=\([^()]*\)/'], ["'\u{2022}\u{2022}\u{2022}'", "\"\u{2022}\u{2022}\u{2022}\"", "(\u{2022}\u{2022}\u{2022})"], $m) ?? '';
        return mb_substr(trim($m) === '' ? (new \ReflectionClass($e))->getShortName() : $m, 0, 300);
    }
}

<?php

namespace DreamFactory\Core\Masking\Resources\Handlers;

use DreamFactory\Core\Exceptions\BadRequestException;
use DreamFactory\Core\Exceptions\NotFoundException;
use DreamFactory\Core\Masking\Baselines\BaselineRegistry;
use DreamFactory\Core\Masking\Support\Activity;
use DreamFactory\Core\Masking\Support\Caller;
use DreamFactory\Core\Masking\Support\Catalog;
use DreamFactory\Core\Masking\Support\Coverage;
use DreamFactory\Core\Masking\Support\PolicyVersion;
use DreamFactory\Core\Masking\Support\RulePattern;
use DreamFactory\Core\Masking\Support\Tables;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * system/data_masking/rule: custom detection rules.
 *
 * - `name` rules match column names (not table names) and re-evaluate stored columns at once
 *   (ScanRunner::reevaluateRules), without sampling.
 * - `value` rules match sampled values, so adding one requests a scan of every active covered
 *   service (scan_started in the answer; a never-scanned instance in mode Off waits for its
 *   first scan). A column a value rule hit carries the evidence line "Custom value rule
 *   <pattern>: N of M values match" (baseline rules: "Baseline value rule <pattern> (<id>): ..."),
 *   which is what `matches` counts.
 * Rules only ever add masking; deleting a rule never unmasks a column.
 *
 * A rule a Compliance baseline added carries its definition's `title` in the list ("Medical
 * record, patient and chart numbers"), so the admin app can name it instead of showing its regex.
 * Rule activity keeps the pattern as target and the match in meta (ActivityHandler returns it).
 */
final class RuleHandler
{
    public const SCAN_RUNNER = 'DreamFactory\\Core\\Masking\\Scanner\\ScanRunner';
    public const SCAN_LAUNCHER = 'DreamFactory\\Core\\Masking\\Scanner\\ScanLauncher';

    /**
     * Requests a background scan of one service after a value rule was added:
     * fn(string $service, string $actor): ?int (the started or running scan id, null when none
     * started). Null = Scanner\ScanLauncher::startThrottled($service, $actor, 0). Tests replace it.
     *
     * @internal
     */
    public static ?\Closure $scanRequester = null;

    /**
     * Evidence lines the scanner writes for rule hits (Scanner\Rules::describe and apply):
     * "Custom rule P", "Custom value rule P: N of M values match", "Baseline rule P (id)",
     * "Baseline value rule P (id): N of M values match"; prefixed "Also matches: " when a
     * stricter class masked the column.
     */
    public const EVIDENCE_CUSTOM_VALUE = 'Custom value rule ';
    public const EVIDENCE_BASELINE_VALUE = 'Baseline value rule ';
    public const EVIDENCE_ALSO = 'Also matches: ';

    private const ROWS_PER_TABLE = 25;

    public function list(): array
    {
        $rules = DB::table(Tables::RULE)->orderBy('id')->get(['id', 'match', 'pattern', 'class', 'source']);
        $columns = null;
        $out = [];
        foreach ($rules as $r) {
            $columns ??= self::storedColumns();
            $wire = self::wire($r, self::countMatches((string)$r->match, (string)$r->pattern, (string)$r->source, $columns));
            if (null !== ($title = self::baselineTitle($r))) {
                $wire['title'] = $title;
            }
            $out[] = $wire;
        }

        return ['resource' => $out];
    }

    /**
     * The title of the baseline rule a row came from: same baseline (source "baseline:<id>"), match
     * and pattern. Null for admin rules, and for a baseline rule its definition no longer has.
     */
    private static function baselineTitle(object $r): ?string
    {
        $source = (string)($r->source ?? '');
        if (!str_starts_with($source, 'baseline:')) {
            return null;
        }
        $definition = BaselineRegistry::get(substr($source, strlen('baseline:')));
        foreach ((array)($definition['apply']['rules'] ?? []) as $rule) {
            if (($rule['match'] ?? null) === (string)$r->match && ($rule['pattern'] ?? null) === (string)$r->pattern) {
                return is_string($rule['title'] ?? null) && $rule['title'] !== '' ? $rule['title'] : null;
            }
        }

        return null;
    }

    /** @throws BadRequestException|\DreamFactory\Core\Exceptions\ForbiddenException */
    public function create(array $payload): array
    {
        Guard::denyAi('Blocked an attempt to change detection rules');
        [$match, $pattern] = self::validated($payload);
        $class = $payload['class'] ?? null;
        if (!is_string($class) || !Catalog::has($class)) {
            throw new BadRequestException('Choose a class for the rule.');
        }
        $exists = DB::table(Tables::RULE)
            ->where('match', $match)->where('pattern', $pattern)->where('class', $class)
            ->exists();
        if ($exists) {
            throw new BadRequestException('This rule already exists.');
        }

        $label = mb_substr(Caller::current()->label(), 0, 255);
        $id = DB::table(Tables::RULE)->insertGetId([
            'match' => $match,
            'pattern' => $pattern,
            'class' => $class,
            'source' => 'admin',
            'created_by' => $label,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        PolicyVersion::bump();

        Activity::log(
            'rule',
            'Added a ' . self::kindLabel($match) . ' rule for ' . Catalog::label($class),
            mb_substr($pattern, 0, 255),
            ['rule_id' => (int)$id, 'match' => $match, 'class' => $class]
        );

        $scanStarted = false;
        if ($match === 'name') {
            self::reevaluate();
        } else {
            $scanStarted = self::rescan((int)$id, $label);
        }

        $row = DB::table(Tables::RULE)->where('id', $id)->first(['id', 'match', 'pattern', 'class', 'source']);

        return self::wire($row, self::countMatches($match, $pattern, 'admin', self::storedColumns()))
            + ['scan_started' => $scanStarted];
    }

    /** @throws NotFoundException|\DreamFactory\Core\Exceptions\ForbiddenException */
    public function delete(string $id): array
    {
        Guard::denyAi('Blocked an attempt to change detection rules');
        if (filter_var($id, FILTER_VALIDATE_INT) === false) {
            throw new NotFoundException("Rule '$id' not found.");
        }
        $row = DB::table(Tables::RULE)->where('id', (int)$id)->first(['id', 'pattern', 'match', 'class']);
        if (!$row) {
            throw new NotFoundException("Rule '$id' not found.");
        }
        DB::table(Tables::RULE)->where('id', (int)$id)->delete();
        PolicyVersion::bump();
        // Says what was deleted, as the add does: "Deleted a value rule for National ID".
        $match = (string)$row->match;
        Activity::log(
            'rule',
            'Deleted a ' . self::kindLabel($match) . ' rule for ' . Catalog::label((string)$row->class),
            mb_substr((string)$row->pattern, 0, 255),
            ['rule_id' => (int)$id, 'match' => $match, 'class' => (string)$row->class]
        );

        return ['id' => (int)$id];
    }

    /** "column name" / "value", as activity names a rule. */
    private static function kindLabel(string $match): string
    {
        return $match === 'name' ? 'column name' : 'value';
    }

    /**
     * POST rule/test {match, pattern}: which columns would match. Value rules sample live with
     * the df-masking.rules.test_budget_ms budget (default 3 s) and return partial:true when the
     * budget ran out or a service could not be sampled. Sampled values stay in memory.
     *
     * @throws BadRequestException
     */
    public function test(array $payload): array
    {
        [$match, $pattern] = self::validated($payload);
        if (class_exists(self::SCAN_RUNNER) && method_exists(self::SCAN_RUNNER, 'testRule')) {
            try {
                $result = (array)app(self::SCAN_RUNNER)->testRule(
                    $match,
                    $pattern,
                    max(250, (int)config('df-masking.rules.test_budget_ms', 3000))
                );

                return [
                    'matches' => array_values(array_map(fn ($m) => ['id' => (string)($m['id'] ?? '')], (array)($result['matches'] ?? []))),
                    'partial' => (bool)($result['partial'] ?? false),
                ];
            } catch (\InvalidArgumentException $e) {
                throw new BadRequestException($e->getMessage());
            }
        }
        if ($match === 'name') {
            $compiled = RulePattern::compile($pattern);
            $ids = [];
            foreach (self::storedColumns() as $c) {
                if (RulePattern::matches($compiled, $c['column'])) {
                    $ids[] = ['id' => $c['id']];
                }
            }

            return ['matches' => $ids, 'partial' => false];
        }

        return self::testValues($pattern);
    }

    public function builtin(): array
    {
        $ruleset = 'dreamfactory.core';
        $version = '';
        $file = dirname(__DIR__, 3) . '/resources/rules/pack.json';
        if (is_file($file)) {
            $pack = json_decode((string)file_get_contents($file), true);
            if (is_array($pack)) {
                $ruleset = (string)($pack['pack'] ?? $ruleset);
                $version = (string)($pack['version'] ?? '');
            }
        }

        return ['ruleset' => $ruleset, 'version' => $version, 'classes' => Catalog::builtinDetectors()];
    }

    // ------------------------------------------------------------------------------------------

    /**
     * @return array{0:string,1:string} [match, pattern]
     * @throws BadRequestException
     */
    private static function validated(array $payload): array
    {
        $match = $payload['match'] ?? null;
        if (!in_array($match, ['name', 'value'], true)) {
            throw new BadRequestException("Invalid match. Use 'name' or 'value'.");
        }
        $pattern = $payload['pattern'] ?? null;
        if (is_string($pattern)) {
            $pattern = trim($pattern);
        }
        if (null !== ($error = RulePattern::validate($pattern))) {
            throw new BadRequestException($error);
        }

        return [$match, $pattern];
    }

    private static function wire(object $r, int $matches): array
    {
        return [
            'id' => (int)$r->id,
            'match' => (string)$r->match,
            'pattern' => (string)$r->pattern,
            'class' => (string)$r->class,
            'source' => (string)($r->source ?? 'admin'),
            'matches' => $matches,
        ];
    }

    /**
     * @param list<array{id:string,service_id:int,table:string,column:string,db_type:string,evidence:?string}> $columns
     */
    private static function countMatches(string $match, string $pattern, string $source, array $columns): int
    {
        $n = 0;
        if ($match === 'name') {
            $compiled = RulePattern::compile($pattern);
            foreach ($columns as $c) {
                if (RulePattern::matches($compiled, $c['column'])) {
                    $n++;
                }
            }

            return $n;
        }
        $needle = str_starts_with($source, 'baseline:')
            ? self::EVIDENCE_BASELINE_VALUE . $pattern . ' (' . substr($source, 9) . ')'
            : self::EVIDENCE_CUSTOM_VALUE . $pattern;
        foreach ($columns as $c) {
            if ($c['evidence'] === null || !str_contains($c['evidence'], 'value rule')) {
                continue;
            }
            $evidence = json_decode($c['evidence'], true);
            foreach ((array)($evidence['lines'] ?? []) as $line) {
                if (is_array($line) && is_string($line['text'] ?? null) && self::isValueRuleLine($line['text'], $needle)) {
                    $n++;
                    break;
                }
            }
        }

        return $n;
    }

    /**
     * The scanner writes "<needle>: N of M values match", or "Also matches: <needle>: ..." when a
     * stricter class won; both are columns the rule matched. The count suffix is checked exactly,
     * so the rule `a` never counts the hits of the rule `a: b`.
     */
    private static function isValueRuleLine(string $text, string $needle): bool
    {
        if (str_starts_with($text, self::EVIDENCE_ALSO)) {
            $text = substr($text, strlen(self::EVIDENCE_ALSO));
        }
        if ($text === $needle) {
            return true;
        }

        return str_starts_with($text, $needle . ': ')
            && preg_match('/^\d+ of \d+ values match$/D', substr($text, strlen($needle) + 2)) === 1;
    }

    /**
     * @return list<array{id:string,service_id:int,table:string,column:string,db_type:string,evidence:?string}>
     */
    private static function storedColumns(): array
    {
        $names = [];
        foreach (Coverage::covered() as $s) {
            $names[$s['id']] = $s['name'];
        }
        if ($names === []) {
            return [];
        }
        $out = [];
        $rows = DB::table(Tables::COLUMN)
            ->whereIn('service_id', array_keys($names))
            ->orderBy('service_id')->orderBy('table_name')->orderBy('ordinal')->orderBy('id')
            ->get(['service_id', 'table_name', 'column_name', 'db_type', 'evidence']);
        foreach ($rows as $row) {
            $sid = (int)$row->service_id;
            $out[] = [
                'id' => ColumnId::format($names[$sid], (string)$row->table_name, (string)$row->column_name),
                'service_id' => $sid,
                'table' => (string)$row->table_name,
                'column' => (string)$row->column_name,
                'db_type' => strtolower((string)$row->db_type),
                'evidence' => $row->evidence === null ? null : (string)$row->evidence,
            ];
        }

        return $out;
    }

    private static function reevaluate(): void
    {
        if (!class_exists(self::SCAN_RUNNER)) {
            return;
        }
        try {
            app(self::SCAN_RUNNER)->reevaluateRules();
        } catch (\Throwable $e) {
            Log::warning('df-masking: re-evaluating name rules failed: ' . $e->getMessage());
        }
    }

    /**
     * Requests a scan of every active covered service, so a new value rule applies without
     * anyone pressing Scan: now, or at the end of a running scan (ScanLauncher::startThrottled,
     * no throttle). Nothing starts before scanning is wanted at all (never scanned, mode Off):
     * the first scan applies the rule. Never fails the rule: a service whose request fails is
     * logged (no values) and skipped.
     *
     * @return bool true when a scan started or will run at the end of the running one
     */
    private static function rescan(int $ruleId, string $actor): bool
    {
        $request = self::$scanRequester;
        if ($request === null) {
            if (!class_exists(self::SCAN_LAUNCHER)) {
                return false;
            }
            $request = static fn (string $service, string $by) => call_user_func([self::SCAN_LAUNCHER, 'startThrottled'], $service, $by, 0);
        }
        $scanId = null;
        foreach (Coverage::covered(true) as $s) {
            try {
                $id = $request($s['name'], $actor);
            } catch (\Throwable $e) {
                Log::warning("df-masking: could not request a scan of '{$s['name']}' to apply a value rule (" . get_class($e) . ')');
                continue;
            }
            if ($scanId === null && is_numeric($id)) {
                $scanId = (int)$id;
            }
        }
        if ($scanId === null) {
            return false;
        }
        Activity::log('scan', 'Scan started to apply a value rule', null, ['rule_id' => $ruleId, 'scan_id' => $scanId]);

        return true;
    }

    /**
     * Live value test: samples up to ROWS_PER_TABLE rows of the text-like columns of every
     * scanned table, round-robin across tables, until the budget runs out. Snowflake services
     * are never sampled here (it bills the customer), which also makes the result partial.
     * Values are trimmed first, as in scans (CHAR(n) values come space-padded).
     */
    private static function testValues(string $pattern): array
    {
        $budgetMs = max(250, (int)config('df-masking.rules.test_budget_ms', 3000));
        $deadline = microtime(true) + $budgetMs / 1000;
        $compiled = RulePattern::compile($pattern);
        $partial = false;

        $byTable = [];
        foreach (self::storedColumns() as $c) {
            if (str_contains($c['column'], '.') || !self::isTextual($c['db_type'])) {
                continue;
            }
            $byTable[$c['service_id'] . "\0" . $c['table']][] = $c;
        }

        $services = [];
        foreach (Coverage::covered(true) as $s) {
            $services[$s['id']] = $s;
        }

        $matches = [];
        foreach ($byTable as $columns) {
            if (microtime(true) >= $deadline) {
                $partial = true;
                break;
            }
            $sid = $columns[0]['service_id'];
            $service = $services[$sid] ?? null;
            if ($service === null) {
                continue; // inactive service
            }
            if (stripos($service['type'], 'snowflake') !== false) {
                $partial = true;
                continue;
            }
            try {
                $connection = \DreamFactory\Core\Facades\ServiceManager::getService($service['name'])->getConnection();
                $rows = $connection->table($columns[0]['table'])
                    ->select(array_map(fn ($c) => $c['column'], $columns))
                    ->limit(self::ROWS_PER_TABLE)
                    ->get();
            } catch (\Throwable $e) {
                $partial = true;
                continue;
            }
            foreach ($columns as $c) {
                foreach ($rows as $row) {
                    $value = $row->{$c['column']} ?? null;
                    $value = is_string($value) ? trim($value) : '';
                    if ($value !== '' && RulePattern::matches($compiled, $value)) {
                        $matches[$c['id']] = ['id' => $c['id']];
                        break;
                    }
                }
            }
            unset($rows);
        }

        return ['matches' => array_values($matches), 'partial' => $partial];
    }

    private static function isTextual(string $dbType): bool
    {
        if ($dbType === '') {
            return true;
        }

        return (bool)preg_match('/char|text|string|clob|json|uuid|citext|inet|xml|enum|set/i', $dbType);
    }
}

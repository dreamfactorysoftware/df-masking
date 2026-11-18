<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Scanner;

use DreamFactory\Core\Exceptions\ForbiddenException;
use DreamFactory\Core\Masking\Classifier\Ruleset;
use DreamFactory\Core\Masking\Resources\Handlers\RuleHandler;
use DreamFactory\Core\Masking\Scanner\ScanLauncher;
use DreamFactory\Core\Masking\Scanner\ScanRunner;
use DreamFactory\Core\Masking\Scanner\ScanState;
use DreamFactory\Core\Masking\Support\Activity;
use DreamFactory\Core\Masking\Support\Caller;
use DreamFactory\Core\Masking\Support\Coverage;
use DreamFactory\Core\Masking\Support\PolicyVersion;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use DreamFactory\Core\Masking\Tests\Unit\Classifier\Support\SyntheticData;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Facade;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;

/**
 * End-to-end scan of a SQLite-backed df-sqldb service: DreamFactory schema objects -> sampler ->
 * engine -> rules -> dm_column, with dm_scan progress, activity, the first-scan mode switch and a
 * stored-value check over every df-masking table.
 */
final class ScanRunnerTest extends TestCase
{
    private array $data;

    protected function setUp(): void
    {
        Harness::boot();
        $this->data = SyntheticData::build();
        $this->addService('crm');
    }

    private function addService(string $name, string $type = 'sqlite'): int
    {
        $ddl = [];
        foreach ($this->data['tables'] as $t) {
            $defs = [];
            foreach ($t['columns'] as [$n, $db, , , $pk, $fk, $ref]) {
                $decl = match (true) {
                    str_starts_with($db, 'character varying') => str_replace('character varying', 'varchar', $db),
                    str_starts_with($db, 'timestamp') => 'timestamp',
                    $db === 'inet' => 'varchar(45)',
                    default => $db,
                };
                $defs[] = sprintf('"%s" %s%s', $n, $decl, $fk ? sprintf(' REFERENCES "%s"(id)', $ref) : '');
            }
            if ($t['pk'] !== []) {
                $defs[] = 'PRIMARY KEY (' . implode(',', array_map(fn ($k) => '"' . $k . '"', $t['pk'])) . ')';
            }
            $ddl[] = sprintf('CREATE TABLE "%s" (%s)', $t['name'], implode(', ', $defs));
        }
        $id = Harness::addService($name, Harness::sqlite($ddl, $this->data['rows']), $type);
        Coverage::forget();
        PolicyVersion::bump();
        return $id;
    }

    private function col(string $table, string $column, string $service = 'crm'): ?object
    {
        $sid = DB::table('service')->where('name', $service)->value('id');
        return DB::table(Tables::COLUMN)->where('service_id', $sid)->where('table_name', $table)->where('column_name', $column)->first();
    }

    public function testFullScan(): void
    {
        $progress = [];
        $summary = (new ScanRunner())->run(null, null, function (int $pct) use (&$progress) {
            $progress[] = $pct;
        });
        $this->assertSame('done', $summary['status'], (string) $summary['error']);
        $this->assertSame(1, $summary['services']);
        $this->assertSame(4, $summary['tables']);
        $this->assertSame(24, $summary['columns']);
        $this->assertSame(24, DB::table(Tables::COLUMN)->count());
        $this->assertSame([], $summary['errors']);
        $this->assertNotEmpty($progress);
        $sorted = $progress;
        sort($sorted);
        $this->assertSame($sorted, $progress, 'progress never goes backwards');
        $this->assertLessThanOrEqual(99, max($progress), '100 is only reported once the scan is done');

        $want = ['customers.email' => 'email', 'customers.ssn' => 'national_id', 'customers.first_name' => 'person_name',
            'customers.birth_date' => 'date_of_birth', 'customers.phone' => 'phone', 'customers.notes' => 'free_text_pii',
            'payments.pan' => 'card_number', 'payments.card_exp' => 'card_expiry', 'audit_log.ip' => 'ip_address'];
        foreach ($want as $key => $class) {
            [$t, $c] = explode('.', $key);
            $row = $this->col($t, $c);
            $this->assertSame(['masked', $class], [$row->verdict, $row->class], $key);
            $this->assertNotNull($row->examples, $key);
            $this->assertNotNull($row->scanned_at);
            $this->assertSame(Ruleset::version(), $row->ruleset_version);
            $this->assertSame(64, strlen($row->fingerprint));
        }
        foreach (['customers.id', 'customers.created_at', 'products.name', 'products.email', 'payments.customer_id'] as $key) {
            [$t, $c] = explode('.', $key);
            $this->assertSame('clear', $this->col($t, $c)->verdict, $key);
        }
        $this->assertSame([1, 2, 3], DB::table(Tables::COLUMN)->where('table_name', 'customers')->orderBy('ordinal')->limit(3)->pluck('ordinal')->map(fn ($v) => (int) $v)->all());

        $scan = DB::table(Tables::SCAN)->where('id', $summary['scan_id'])->first();
        $this->assertSame(['done', 100, 24], [$scan->status, (int) $scan->progress, (int) $scan->columns_done]);
        $this->assertSame('Command line', $scan->triggered_by);

        $activity = DB::table(Tables::ACTIVITY)->orderBy('id')->get();
        $texts = $activity->pluck('text')->all();
        $this->assertContains('Scan finished: 24 columns in 1 database', $texts);
        $this->assertContains('Masking set to Preview after the first scan', $texts);
        $this->assertTrue($summary['mode_switched']);
        Settings::flush();
        $this->assertSame('preview', Settings::mode());

        // Second scan: nothing changes, no second mode switch.
        $again = (new ScanRunner())->run();
        $this->assertSame(0, $again['changed']);
        $this->assertFalse($again['mode_switched']);
    }

    public function testNoSampledValueIsEverStored(): void
    {
        (new ScanRunner())->run();
        $dump = '';
        foreach ([Tables::COLUMN, Tables::SCAN, Tables::ACTIVITY, Tables::SETTING] as $table) {
            $dump .= json_encode(DB::table($table)->get()->all(), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        }
        $checked = 0;
        foreach ($this->data['rows'] as $rows) {
            foreach ($rows as $row) {
                foreach ($row as $v) {
                    $v = trim((string) $v);
                    if (strlen($v) >= 6 && preg_match('/[\d@\s]/', $v)) {
                        $checked++;
                        $this->assertStringNotContainsString($v, $dump);
                        $this->assertStringNotContainsString(substr(json_encode($v, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), 1, -1), $dump);
                    }
                }
            }
        }
        $this->assertGreaterThan(2000, $checked);
    }

    public function testAdminDecisionsSurviveRescans(): void
    {
        (new ScanRunner())->run();
        DB::table(Tables::COLUMN)->where('table_name', 'customers')->where('column_name', 'notes')
            ->update(['verdict' => 'clear', 'class' => null, 'tier' => null, 'source' => 'admin', 'decided_by' => 'Alex Admin']);
        (new ScanRunner())->run('crm');
        $row = $this->col('customers', 'notes');
        $this->assertSame(['clear', 'admin', 'free_text_pii'], [$row->verdict, $row->source, $row->detected_class]);
    }

    public function testRulesApplyAtScanAndOnReevaluation(): void
    {
        (new ScanRunner())->run();
        $this->assertSame('clear', $this->col('customers', 'status')->verdict);
        DB::table(Tables::RULE)->insert(['match' => 'name', 'pattern' => '^status$', 'class' => 'special_category', 'source' => 'admin', 'created_at' => now(), 'updated_at' => now()]);
        $changed = (new ScanRunner())->reevaluateRules();
        $this->assertSame(1, $changed);
        $row = $this->col('customers', 'status');
        $this->assertSame(['masked', 'special_category', 'rule'], [$row->verdict, $row->class, $row->source]);
        $this->assertSame(0, (new ScanRunner())->reevaluateRules(), 'idempotent');

        DB::table(Tables::RULE)->insert(['match' => 'value', 'pattern' => '^SKU-\d{5}$', 'class' => 'tax_id', 'source' => 'baseline:pci_dss', 'created_at' => now(), 'updated_at' => now()]);
        (new ScanRunner())->run();
        $sku = $this->col('products', 'sku');
        $this->assertSame(['masked', 'tax_id', 'baseline'], [$sku->verdict, $sku->class, $sku->source]);
        $this->assertStringContainsString('Baseline value rule ^SKU-\\\\d{5}$ (pci_dss)', $sku->evidence);
        // the rule still applies on the next scan (the name rule too)
        $this->assertSame('special_category', $this->col('customers', 'status')->class);
    }

    /** Before anyone scanned (mode Off), adding a value rule starts nothing: the first scan applies it. */
    public function testAValueRuleAddedBeforeTheFirstScanStartsNothing(): void
    {
        $rule = (new RuleHandler())->create(['match' => 'value', 'pattern' => '^SKU-\d{5}$', 'class' => 'tax_id']);
        $this->assertFalse($rule['scan_started']);
        $this->assertSame(0, DB::table(Tables::SCAN)->count());
        $this->assertSame([], ScanLauncher::dueRequests());
        $this->assertSame(0, DB::table(Tables::ACTIVITY)->where('kind', 'scan')->count());

        (new ScanRunner())->run();
        $this->assertSame('tax_id', $this->col('products', 'sku')->class, 'the first scan applies it');
    }

    /** After a scan, a value rule scans every active covered service again, so it applies without pressing Scan. */
    public function testAValueRuleStartsAScan(): void
    {
        (new ScanRunner())->run();
        $this->assertNotSame('tax_id', $this->col('products', 'sku')->class);
        $name = (new RuleHandler())->create(['match' => 'name', 'pattern' => '^status$', 'class' => 'special_category']);
        $this->assertFalse($name['scan_started'], 'name rules apply at once, without a scan');
        $this->assertSame(1, $name['matches']);
        $this->assertSame(1, DB::table(Tables::SCAN)->count());

        $rule = (new RuleHandler())->create(['match' => 'value', 'pattern' => '^SKU-\d{5}$', 'class' => 'tax_id']);
        $this->assertTrue($rule['scan_started']);
        // No background processes in this harness: the scan ran in-process, so the answer counts it.
        $this->assertSame(1, $rule['matches']);
        $this->assertSame(2, DB::table(Tables::SCAN)->count());
        $sku = $this->col('products', 'sku');
        $this->assertSame(['masked', 'tax_id', 'rule'], [$sku->verdict, $sku->class, $sku->source]);
        $activity = DB::table(Tables::ACTIVITY)->where('text', 'Scan started to apply a value rule')->first();
        $this->assertSame('scan', $activity->kind);
        $scan = DB::table(Tables::SCAN)->orderByDesc('id')->first();
        $this->assertSame(['rule_id' => $rule['id'], 'scan_id' => (int)$scan->id], json_decode($activity->meta, true));
        $this->assertSame($activity->actor, $scan->triggered_by, 'started on behalf of the admin who added the rule');
        $this->assertSame([], ScanLauncher::dueRequests());
    }

    /**
     * A value rule added while a scan runs: the request waits for that scan, which loaded its
     * rules before the rule existed, so a follow-up scan of what it read starts as it finishes.
     * Inactive and non-database services are never requested.
     */
    public function testAValueRuleAddedDuringAScanIsAppliedByAFollowUpScan(): void
    {
        (new ScanRunner())->run();
        $hr = Harness::addService('hr', Harness::sqlite(['CREATE TABLE badges (id integer primary key, code varchar(12))'],
            ['badges' => array_map(static fn ($i) => ['id' => $i, 'code' => sprintf('SKU-%05d', $i)], range(1, 20))]));
        Harness::addService('archive', Harness::sqlite(['CREATE TABLE t (id integer primary key)']), 'sqlite', false);
        DB::table('service')->insert(['name' => 'files', 'label' => 'Files', 'type' => 'local_file', 'is_active' => true]);
        Coverage::forget();
        PolicyVersion::bump();

        $running = ScanState::create(null, 'Alex Admin');
        $rule = null;
        $due = null;
        $summary = (new ScanRunner())->run(null, $running->id, function () use (&$rule, &$due): void {
            if ($rule === null) {
                $rule = (new RuleHandler())->create(['match' => 'value', 'pattern' => '^SKU-\d{5}$', 'class' => 'tax_id']);
                $due = ScanLauncher::dueRequests();
            }
        });
        $this->assertSame('done', $summary['status']);
        $this->assertTrue($rule['scan_started'], 'queued behind the running scan');
        $this->assertSame(['crm', 'hr'], $due, 'every active covered service, nothing else');

        // The first scan, the running one, and the follow-up: in-process here, one per service (a
        // spawned follow-up takes the other services at its end).
        $this->assertSame(4, DB::table(Tables::SCAN)->count());
        $this->assertSame([Activity::SYSTEM, Activity::SYSTEM], DB::table(Tables::SCAN)->where('id', '>', $running->id)->pluck('triggered_by')->all());
        $this->assertSame('tax_id', $this->col('products', 'sku')->class);
        $this->assertSame('tax_id', DB::table(Tables::COLUMN)->where('service_id', $hr)->where('column_name', 'code')->value('class'));
        $this->assertSame([], ScanLauncher::dueRequests());
        $this->assertSame(1, DB::table(Tables::ACTIVITY)->where('text', 'Scan started to apply a value rule')->count());
    }

    /**
     * A scan started for one service that took on requests for others (a value rule asks for every
     * covered service) covered several: its activity names no single service, like a full scan.
     */
    public function testAScanThatTookOnOtherServicesNamesNoSingleTarget(): void
    {
        (new ScanRunner())->run();
        $this->addService('hr');
        $crm = (int)DB::table('service')->where('name', 'crm')->value('id');
        $running = ScanState::create($crm, 'Alex Admin');
        $asked = false;
        (new ScanRunner())->run('crm', $running->id, function () use (&$asked): void {
            if (!$asked) {
                $asked = true;
                ScanLauncher::startThrottled('hr', 'Alex Admin', 0);
            }
        });
        $finished = static fn () => DB::table(Tables::ACTIVITY)->where('kind', 'scan')->where('text', 'like', 'Scan finished:%')
            ->orderByDesc('id')->first();
        $this->assertStringContainsString('in 2 databases', $finished()->text);
        $this->assertNull($finished()->target);

        (new ScanRunner())->run('hr');
        $this->assertStringContainsString('in 1 database', $finished()->text);
        $this->assertSame('hr', $finished()->target, 'a scan of one service still names it');
    }

    /** A value rule's `matches` counts the columns whose evidence names it, also when a stricter class won. */
    public function testValueRuleMatchesCountTheColumnsTheRuleHit(): void
    {
        $rule = static fn (string $match, string $pattern, string $class) => ['match' => $match, 'pattern' => $pattern, 'class' => $class,
            'source' => 'admin', 'created_at' => now(), 'updated_at' => now()];
        DB::table(Tables::RULE)->insert([$rule('name', '^sku$', 'tax_id'), $rule('value', '^SKU-', 'postal_code'),
            $rule('value', 'qqq', 'email'), $rule('value', 'qqq: b', 'email')]);
        (new ScanRunner())->run();
        $this->assertSame('tax_id', $this->col('products', 'sku')->class, 'the stricter name rule won');
        $lines = implode("\n", array_column(json_decode($this->col('products', 'sku')->evidence, true)['lines'], 'text'));
        $this->assertMatchesRegularExpression('/^Also matches: Custom value rule \^SKU-: \d+ of \d+ values match$/m', $lines);
        // Rule `qqq` must not count the hits of rule `qqq: b`.
        DB::table(Tables::COLUMN)->where('column_name', 'status')->update(['evidence' => json_encode(['lines' => [
            ['points' => 70, 'kind' => 'values', 'text' => 'Custom value rule qqq: b: 3 of 4 values match'],
        ]])]);

        $matches = array_column((new RuleHandler())->list()['resource'], 'matches', 'pattern');
        $this->assertSame(['^sku$' => 1, '^SKU-' => 1, 'qqq' => 0, 'qqq: b' => 1], $matches);
    }

    /** RuleHandler's live value test for builds without the scanner trims values too (CHAR(n) padding). */
    public function testTheFallbackValueTestTrimsValues(): void
    {
        $rows = array_map(static fn ($i) => ['id' => $i, 'code' => sprintf('SKU-%05d   ', $i)], range(1, 5));
        Harness::addService('hr', Harness::sqlite(['CREATE TABLE badges (id integer primary key, code char(12))'], ['badges' => $rows]));
        Coverage::forget();
        PolicyVersion::bump();
        (new ScanRunner())->run('hr');

        $fallback = new \ReflectionMethod(RuleHandler::class, 'testValues');
        $this->assertSame(['matches' => [['id' => 'hr.badges.code']], 'partial' => false], $fallback->invoke(null, '^SKU-\d{5}$'));
    }

    /** A scan request that fails never fails the rule: it is saved, the next scan applies it. */
    public function testAScanRequestThatFailsDoesNotFailTheRule(): void
    {
        (new ScanRunner())->run();
        $this->addService('hr');
        $asked = [];
        RuleHandler::$scanRequester = function (string $service) use (&$asked): ?int {
            $asked[] = $service;
            throw new \RuntimeException("could not reach $service with SKU-00001");
        };
        $log = new class extends AbstractLogger {
            public array $lines = [];

            public function log($level, \Stringable|string $message, array $context = []): void
            {
                $this->lines[] = [$level, (string)$message];
            }
        };
        app()->instance('log', $log);
        Facade::clearResolvedInstance('log');
        try {
            $rule = (new RuleHandler())->create(['match' => 'value', 'pattern' => '^SKU-\d{5}$', 'class' => 'tax_id']);
        } finally {
            RuleHandler::$scanRequester = null;
        }
        $this->assertFalse($rule['scan_started']);
        $this->assertSame(['crm', 'hr'], $asked, 'one failing service does not stop the others');
        $this->assertSame(1, DB::table(Tables::RULE)->count());
        $this->assertSame(0, DB::table(Tables::ACTIVITY)->where('text', 'Scan started to apply a value rule')->count());
        $warnings = array_values(array_filter($log->lines, static fn ($l) => $l[0] === 'warning'));
        $this->assertSame([
            ['warning', "df-masking: could not request a scan of 'crm' to apply a value rule (RuntimeException)"],
            ['warning', "df-masking: could not request a scan of 'hr' to apply a value rule (RuntimeException)"],
        ], $warnings, 'no message text, so no values');
    }

    /** AI sessions never change rules, so they never start a scan either. */
    public function testAiSessionsCannotAddRules(): void
    {
        (new ScanRunner())->run();
        app()->instance('df.agent', (object)['name' => 'Ops']);
        Caller::forget();
        try {
            (new RuleHandler())->create(['match' => 'value', 'pattern' => '^SKU-\d{5}$', 'class' => 'tax_id']);
            $this->fail('an AI session added a rule');
        } catch (ForbiddenException $e) {
            $this->assertSame(0, DB::table(Tables::RULE)->count());
            $this->assertSame(1, DB::table(Tables::SCAN)->count());
        }
    }

    public function testTestRule(): void
    {
        (new ScanRunner())->run();
        $name = (new ScanRunner())->testRule('name', '(^|_)email$');
        $this->assertEqualsCanonicalizing(['crm.customers.email', 'crm.products.email'], array_column($name['matches'], 'id'));
        $this->assertFalse($name['partial']);
        $value = (new ScanRunner())->testRule('value', '^SKU-\d{5}$', 5000);
        $this->assertSame(['crm.products.sku'], array_column($value['matches'], 'id'));
        $this->expectException(\InvalidArgumentException::class);
        (new ScanRunner())->testRule('name', '(unclosed');
    }

    public function testWarehousesAreClassifiedFromNamesUnlessSamplingIsRequested(): void
    {
        $this->addService('dw', 'snowflake');
        $summary = (new ScanRunner())->run('dw');
        $this->assertSame(['dw'], $summary['name_only']);
        $ev = json_decode($this->col('customers', 'email', 'dw')->evidence, true);
        $this->assertTrue($ev['name_only']);
        $this->assertSame(15, $ev['threshold_review']);
        $this->assertNotEmpty($summary['errors']);
        // Explicitly requested: sampled (this fake warehouse's SQL dialect fails, so names still decide).
        $sampled = (new ScanRunner())->run('dw', null, null, true);
        $this->assertSame([], $sampled['name_only']);
    }

    public function testAFailingServiceDoesNotStopTheOthers(): void
    {
        $this->addService('broken');
        Harness::$services['broken']->failSchema = true;
        $summary = (new ScanRunner())->run();
        $this->assertSame('done', $summary['status']);
        $this->assertSame(['broken'], $summary['services_failed']);
        $this->assertSame(1, $summary['services']);
        $this->assertStringContainsString('broken', (string) $summary['error']);
        // Activity names the service by its label, as Compliance does.
        $this->assertStringContainsString('could not scan Broken)', (string) DB::table(Tables::ACTIVITY)->where('kind', 'scan')->value('text'));
        // Only a broken service: the scan fails and the mode is not switched.
        DB::table(Tables::SETTING)->delete();
        Settings::flush();
        $only = (new ScanRunner())->run('broken');
        $this->assertSame('failed', $only['status']);
        $this->assertFalse($only['mode_switched']);
    }

    public function testUnknownServiceIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        ScanLauncher::start('nope', 'Alex Admin');
    }

    public function testRunWithAScanIdReportsIntoThatRow(): void
    {
        $id = (int) DB::table(Tables::SCAN)->insertGetId(['service_id' => DB::table('service')->where('name', 'crm')->value('id'), 'status' => 'running',
            'progress' => 0, 'columns_total' => 0, 'columns_done' => 0, 'started_at' => now(), 'triggered_by' => 'Alex Admin', 'created_at' => now(), 'updated_at' => now()]);
        $summary = (new ScanRunner())->run(null, $id);
        $this->assertSame($id, $summary['scan_id']);
        $row = DB::table(Tables::SCAN)->where('id', $id)->first();
        $this->assertSame(['done', getmypid()], [$row->status, (int) $row->pid]);
        $this->assertSame(1, DB::table(Tables::SCAN)->count());
    }
}

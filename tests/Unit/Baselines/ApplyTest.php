<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Baselines;

use DreamFactory\Core\Exceptions\BadRequestException;
use DreamFactory\Core\Exceptions\ConflictResourceException;
use DreamFactory\Core\Exceptions\ServiceUnavailableException;
use DreamFactory\Core\Exceptions\NotFoundException;
use DreamFactory\Core\Masking\Baselines\BaselineService;
use DreamFactory\Core\Masking\Baselines\Report;
use DreamFactory\Core\Masking\Baselines\State;
use DreamFactory\Core\Masking\Support\Activity;
use DreamFactory\Core\Masking\Support\ScanHistory;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use DreamFactory\Core\Masking\Tests\TestCase;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Apply, changes, adoption and the evidence report against real tables (the package's
 * in-memory SQLite harness with every df-masking migration, foreign keys enforced).
 */
final class ApplyTest extends TestCase
{
    /** Must never appear in any output: stands in for a sampled data value. */
    private const SENTINEL = 'SENTINEL-4111-1111-1111-1111';

    /** @var list<string> actors the stubbed scan starter was called with */
    private array $scansStarted = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->bootHarness();
        if (class_exists(ScanHistory::class)) {
            ScanHistory::forget();
        }
        $this->scansStarted = [];
        BaselineService::$scanStarter = function (string $actor): void {
            $this->scansStarted[] = $actor;
        };
        // DreamFactory's service manager, as far as Support\Coverage asks it: SQL types are covered
        // (df-sqldb config), mongodb is a database Data Masking cannot scan.
        $this->app->instance('df.service', new class {
            public function getService(string $name): object
            {
                throw new \RuntimeException('no service instances in this harness');
            }

            public function getServiceType(string $type): ?object
            {
                return new class ($type) {
                    public function __construct(private string $type)
                    {
                    }

                    public function getGroup(): string
                    {
                        return in_array($this->type, ['pgsql', 'mysql', 'sqlite', 'mongodb'], true) ? 'Database' : 'Other';
                    }

                    public function getConfigHandler(): string
                    {
                        return $this->type === 'mongodb' ? \stdClass::class : 'DreamFactory\\Core\\SqlDb\\Models\\PgSqlDbConfig';
                    }
                };
            }
        });
        \DreamFactory\Core\Masking\Support\Coverage::forget();
        // DreamFactory tables the baseline checks read, beyond the harness stubs.
        Schema::table('service', function (Blueprint $t) {
            $t->timestamp('created_date')->nullable();
        });
        Schema::table('user', function (Blueprint $t) {
            $t->timestamp('last_login_date')->nullable();
            $t->timestamp('created_date')->nullable();
        });
        Schema::create('user_config', function (Blueprint $t) {
            $t->unsignedInteger('service_id')->primary();
            $t->boolean('allow_open_registration')->default(false);
        });
        Schema::create('cors_config', function (Blueprint $t) {
            $t->increments('id');
            $t->string('path');
            $t->string('origin');
            $t->boolean('enabled')->default(true);
        });
        Schema::create('service_event_map', function (Blueprint $t) {
            $t->increments('id');
            $t->unsignedInteger('service_id');
            $t->string('event');
        });
        $this->seedLooseInstance();
    }

    protected function tearDown(): void
    {
        BaselineService::$scanStarter = null;
        parent::tearDown();
    }

    private function seedLooseInstance(): void
    {
        $now = now();
        DB::table('service')->insert([
            ['id' => 1, 'name' => 'crm', 'label' => 'CRM', 'type' => 'pgsql', 'is_active' => true, 'created_date' => $now],
        ]);
        DB::table('user')->insert([
            ['id' => 1, 'first_name' => 'Alex', 'last_name' => 'Admin', 'email' => 'admin@example.test', 'is_sys_admin' => true],
            ['id' => 2, 'first_name' => 'Priya', 'last_name' => 'Shah', 'email' => 'priya@example.test', 'is_sys_admin' => true],
            ['id' => 3, 'first_name' => 'Lee', 'last_name' => 'Chen', 'email' => 'lee@example.test', 'is_sys_admin' => true],
        ]);
        DB::table('role')->insert([['id' => 10, 'name' => 'support'], ['id' => 11, 'name' => 'billing']]);

        Settings::set(Settings::AI, 'same_as_admins');
        Settings::set(Settings::ADMINS_MODE, 'all');
        DB::table(Tables::ADMIN_GRANT)->insert([
            ['admin_id' => 2, 'expires_at' => null, 'created_at' => $now, 'updated_at' => $now],
            ['admin_id' => 3, 'expires_at' => $now->copy()->addHour(), 'created_at' => $now, 'updated_at' => $now],
        ]);
        DB::table(Tables::ROLE_ACCESS)->insert([
            ['role_id' => 10, 'enabled' => true, 'scope' => 'all', 'updated_at' => $now],
            ['role_id' => 11, 'enabled' => false, 'scope' => 'all', 'updated_at' => $now],
        ]);
        DB::table(Tables::MASK_FORMAT)->insert(['class' => 'date_of_birth', 'format' => 'token', 'updated_at' => $now]);
        DB::table(Tables::RULE)->insert([
            'match' => 'name', 'pattern' => '^legacy_ssn$', 'class' => 'national_id', 'source' => 'admin',
            'created_at' => $now, 'updated_at' => $now,
        ]);
        DB::table(Tables::COLUMN)->insert([
            $this->column('patients', 'ssn', 'clear', null, 'admin', 'national_id'),
            $this->column('patients', 'dob', 'masked', 'date_of_birth', 'detected', 'date_of_birth'),
            $this->column('patients', 'notes', 'review', 'free_text_pii', 'detected', 'free_text_pii'),
            $this->column('patients', 'id', 'clear', null, 'detected', null),
        ]);
        DB::table(Tables::ACTIVITY)->insert([
            'created_at' => $now, 'actor' => 'Alex Admin', 'kind' => 'decision',
            'text' => 'Marked not sensitive', 'target' => 'crm.patients.ssn',
        ]);
        // The instance has been scanned once (the columns above came from that scan).
        DB::table(Tables::SCAN)->insert([
            'service_id' => null, 'status' => 'done', 'progress' => 100, 'columns_total' => 5, 'columns_done' => 5,
            'started_at' => $now, 'finished_at' => $now,
            'triggered_by' => 'Alex Admin', 'created_at' => $now, 'updated_at' => $now,
        ]);
        Settings::set(Settings::FIRST_SCAN_AT, $now->toIso8601ZuluString());
    }

    /** Back to a never-scanned instance: no scan history, no stored columns. */
    private function forgetScans(): void
    {
        DB::table(Tables::SCAN)->delete();
        DB::table(Tables::COLUMN)->delete();
        Settings::forget(Settings::FIRST_SCAN_AT);
        Settings::forget(Settings::MODE);
    }

    private function column(string $table, string $column, string $verdict, ?string $class, string $source, ?string $detected): array
    {
        $now = now();

        return [
            'service_id' => 1, 'table_name' => $table, 'column_name' => $column, 'db_type' => 'text',
            'verdict' => $verdict, 'class' => $class, 'tier' => null, 'score' => 80, 'source' => $source,
            'detected_class' => $detected, 'detected_score' => 80,
            'evidence' => json_encode(['total' => 80, 'lines' => [['points' => 80, 'kind' => 'value', 'text' => self::SENTINEL]]]),
            'examples' => json_encode([['format' => 'redact', 'value' => self::SENTINEL]]),
            'scanned_at' => $now, 'created_at' => $now, 'updated_at' => $now,
        ];
    }

    public function testDetailListsExactlyWhatApplyChanges(): void
    {
        $detail = BaselineService::detail('hipaa');
        $this->assertFalse($detail['adopted']);
        $this->assertSame(
            ['mode', 'ai', 'admins_mode', 'grant:2', 'role:10', 'format:date_of_birth', 'rule:0', 'rule:1'],
            array_column($detail['changes'], 'id')
        );

        $result = BaselineService::apply('hipaa');

        $this->assertSame($detail['changes'], $result['applied'], 'Apply changed exactly what changes listed');
        $this->assertSame([], $result['changes'], 'nothing left to change');
        $this->assertTrue($result['adopted']);
        $this->assertNotNull($result['adopted_at']);
        $this->assertNotNull($result['applied_at']);

        Settings::flush();
        $this->assertSame('preview', Settings::mode());
        $this->assertSame('masked', Settings::ai());
        $this->assertSame('selected', Settings::adminsMode());

        $grants = DB::table(Tables::ADMIN_GRANT)->orderBy('admin_id')->get()->keyBy('admin_id');
        $this->assertCount(2, $grants, 'grants are capped, never removed');
        $capped = strtotime($grants[2]->expires_at . ' UTC') - time();
        $this->assertGreaterThan(8 * 3600 - 120, $capped);
        $this->assertLessThanOrEqual(8 * 3600 + 5, $capped);
        $this->assertLessThan(3700, strtotime($grants[3]->expires_at . ' UTC') - time(), 'shorter grant untouched');

        $this->assertSame('except_restricted', DB::table(Tables::ROLE_ACCESS)->where('role_id', 10)->value('scope'));
        $this->assertSame('all', DB::table(Tables::ROLE_ACCESS)->where('role_id', 11)->value('scope'), 'disabled role untouched');
        $this->assertSame('year', DB::table(Tables::MASK_FORMAT)->where('class', 'date_of_birth')->value('format'));

        $rules = DB::table(Tables::RULE)->orderBy('id')->get();
        $this->assertCount(3, $rules);
        $this->assertSame('admin', $rules[0]->source, 'admin rule kept');
        $this->assertSame('baseline:hipaa', $rules[1]->source);
        $this->assertSame('baseline:hipaa', $rules[2]->source);

        // Admin decisions and masking are never touched.
        $this->assertSame('admin', DB::table(Tables::COLUMN)->where('column_name', 'ssn')->value('source'));
        $this->assertSame('clear', DB::table(Tables::COLUMN)->where('column_name', 'ssn')->value('verdict'));
        $this->assertSame('review', DB::table(Tables::COLUMN)->where('column_name', 'notes')->value('verdict'));

        $row = DB::table(Tables::BASELINE)->where('baseline_id', 'hipaa')->first();
        $this->assertNotNull($row);
        $status = json_decode($row->last_status, true);
        $this->assertSame(array_column($detail['changes'], 'id'), $status['changes']);
        $this->assertSame($result['score'], $status['score']);

        $activity = DB::table(Tables::ACTIVITY)->whereIn('kind', ['baseline', 'mode'])->orderBy('id')->get();
        $this->assertSame(['baseline', 'mode'], $activity->pluck('kind')->all());
        $this->assertSame('Applied the HIPAA baseline (8 changes)', $activity[0]->text);
        $this->assertSame('hipaa', $activity[0]->target);
        $this->assertSame('Masking set to Preview by the HIPAA baseline', $activity[1]->text);
    }

    public function testApplyIsIdempotentAndKeepsAdoption(): void
    {
        $first = BaselineService::apply('hipaa');
        $adoptedAt = $first['adopted_at'];
        $rules = DB::table(Tables::RULE)->count();

        $again = BaselineService::apply('hipaa');
        $this->assertSame([], $again['applied']);
        $this->assertSame($adoptedAt, $again['adopted_at']);
        $this->assertSame($rules, DB::table(Tables::RULE)->count());
        $this->assertSame(
            'Applied the HIPAA baseline (nothing to change)',
            DB::table(Tables::ACTIVITY)->where('kind', 'baseline')->orderBy('id', 'desc')->value('text')
        );
    }

    public function testModeOn(): void
    {
        $this->assertSame('mode', BaselineService::detail('hipaa', true)['changes'][0]['id']);
        BaselineService::apply('hipaa', 'on');
        Settings::flush();
        $this->assertSame('on', Settings::mode());

        $mode = BaselineService::detail('hipaa');
        $control = array_column($mode['controls'], null, 'id')['masking.mode'];
        $this->assertSame('pass', $control['status']);
    }

    public function testSecondBaselineAddsOnlyWhatItOwns(): void
    {
        BaselineService::apply('hipaa');
        $pci = BaselineService::detail('pci_dss');
        // Formats, grants, roles, AI and admins are already strict enough; only PCI's rules remain.
        $this->assertSame(['rule:0', 'rule:1', 'rule:2', 'rule:3'], array_column($pci['changes'], 'id'));
        $applied = BaselineService::apply('pci_dss');
        $this->assertSame($pci['changes'], $applied['applied']);
        $this->assertSame(7, DB::table(Tables::RULE)->count());
        $this->assertSame(['hipaa', 'pci_dss'], BaselineService::adoptedIds());
        $this->assertSame(8, BaselineService::effectiveGrantMaxHours());
    }

    public function testListShowsScoresAndAdoption(): void
    {
        BaselineService::apply('gdpr');
        $list = BaselineService::list();
        $this->assertSame(['hipaa', 'pci_dss', 'glba', 'cjis', 'gdpr', 'soc2', 'iso27001'], array_column($list, 'id'));
        foreach ($list as $row) {
            $this->assertSame(['id', 'name', 'vertical', 'frameworks', 'summary', 'adopted', 'adopted_at', 'score'], array_keys($row));
            $this->assertSame($row['id'] === 'gdpr', $row['adopted']);
            $this->assertSame(
                $row['score']['pass'] + $row['score']['fail'] + $row['score']['manual'],
                $row['score']['total']
            );
        }
    }

    public function testForgetStopsTrackingButKeepsSettings(): void
    {
        BaselineService::apply('hipaa');
        $detail = BaselineService::forget('hipaa');
        $this->assertFalse($detail['adopted']);
        $this->assertNull($detail['adopted_at']);
        Settings::flush();
        $this->assertSame('masked', Settings::ai());
        $this->assertSame(3, DB::table(Tables::RULE)->count());
        $this->assertSame(
            'Stopped tracking the HIPAA baseline (settings unchanged)',
            DB::table(Tables::ACTIVITY)->where('kind', 'baseline')->orderBy('id', 'desc')->value('text')
        );
        // Forgetting something not adopted is a no-op.
        BaselineService::forget('soc2');
        $this->assertSame(1, DB::table(Tables::ACTIVITY)->where('text', 'like', 'Stopped tracking%')->count());
    }

    public function testRejectsUnknownBaselineAndMode(): void
    {
        try {
            BaselineService::apply('hipaa', 'off');
            $this->fail('mode off must be rejected');
        } catch (BadRequestException $e) {
            $this->assertStringContainsString("mode must be 'on'", $e->getMessage());
        }
        $this->assertSame(0, DB::table(Tables::BASELINE)->count(), 'nothing adopted');

        $this->expectException(NotFoundException::class);
        BaselineService::detail('sox');
    }

    public function testFailedApplyRollsBackEverything(): void
    {
        // Make the last write of the transaction (adoption) fail.
        DB::statement("CREATE TRIGGER dm_baseline_fail BEFORE INSERT ON dm_baseline BEGIN SELECT RAISE(ABORT, 'adoption failed'); END");
        try {
            BaselineService::apply('hipaa');
            $this->fail('apply must fail when adoption cannot be written');
        } catch (\Throwable $e) {
            $this->assertStringContainsString('adoption failed', $e->getMessage());
        }
        Settings::flush();
        $this->assertSame('same_as_admins', Settings::ai(), 'rolled back');
        $this->assertSame('all', Settings::adminsMode(), 'rolled back');
        $this->assertSame('token', DB::table(Tables::MASK_FORMAT)->where('class', 'date_of_birth')->value('format'));
        $this->assertSame('all', DB::table(Tables::ROLE_ACCESS)->where('role_id', 10)->value('scope'));
        $this->assertNull(DB::table(Tables::ADMIN_GRANT)->where('admin_id', 2)->value('expires_at'));
        $this->assertSame(1, DB::table(Tables::RULE)->count());
        $this->assertSame(0, DB::table(Tables::BASELINE)->count());
        $this->assertSame(0, DB::table(Tables::ACTIVITY)->where('kind', 'baseline')->count());
    }

    public function testApplyBeforeMigrationExplainsWhatToDo(): void
    {
        Schema::drop(Tables::BASELINE);
        try {
            BaselineService::apply('hipaa');
            $this->fail('apply must refuse without dm_baseline');
        } catch (ServiceUnavailableException $e) {
            $this->assertSame(503, $e->getStatusCode());
            $this->assertStringContainsString('php artisan df:masking setup', $e->getMessage());
        }
        Settings::flush();
        $this->assertSame('same_as_admins', Settings::ai(), 'nothing written');
        // Reads still work.
        $this->assertFalse(BaselineService::detail('hipaa')['adopted']);
        $this->assertCount(7, BaselineService::list());
    }

    public function testStateCaptureReadsTheInstance(): void
    {
        $state = State::capture();
        $this->assertSame('off', $state->mode);
        $this->assertSame('same_as_admins', $state->ai);
        $this->assertSame('all', $state->adminsMode);
        $this->assertSame('token', $state->formatOf('date_of_birth'));
        $this->assertSame('last4', $state->formatOf('card_number'));
        $this->assertSame([2, 3], array_column($state->grants, 'admin_id'));
        $this->assertSame('Priya Shah', $state->grants[0]['name']);
        $this->assertNull($state->grants[0]['expires_at']);
        $this->assertSame(['masked' => 1, 'review' => 1, 'clear' => 2], $state->verdicts);
        $this->assertSame(['national_id' => 1], $state->adminCleared);
        $this->assertSame(['^legacy_ssn$'], array_column($state->rules, 'pattern'));
        $this->assertSame(0, $state->platformValue('cors_wildcard'));
        $this->assertFalse($state->platformValue('app_url_https'));
        $this->assertSame(1440, $state->platformValue('jwt_ttl'));
        $this->assertSame([], $state->adopted);

        // Expired grants are not in effect.
        DB::table(Tables::ADMIN_GRANT)->where('admin_id', 3)->update(['expires_at' => now()->subMinute()]);
        DB::table('cors_config')->insert(['path' => '*', 'origin' => 'https://a.test, *', 'enabled' => true]);
        DB::table('cors_config')->insert(['path' => 'x', 'origin' => '*', 'enabled' => false]);
        $state = State::capture();
        $this->assertSame([2], array_column($state->grants, 'admin_id'));
        $this->assertSame(1, $state->platformValue('cors_wildcard'));
    }

    public function testReportHasEvidenceAndNoValues(): void
    {
        BaselineService::apply('hipaa');
        $report = BaselineService::report('hipaa');

        foreach (['report', 'generated_at', 'disclaimer', 'instance', 'baseline', 'score', 'controls', 'pending_changes', 'masking', 'access', 'activity'] as $key) {
            $this->assertArrayHasKey($key, $report);
        }
        $this->assertSame('hipaa', $report['baseline']['id']);
        $this->assertTrue($report['baseline']['adopted']);
        $this->assertMatchesRegularExpression('/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/', $report['generated_at']);
        $this->assertSame(['masked' => 1, 'review' => 1, 'clear' => 2, 'columns' => 4], $report['masking']['inventory']['totals']);
        $this->assertSame(['kept_masked' => 0, 'marked_not_sensitive' => 1], $report['masking']['inventory']['admin_decisions']);
        $this->assertSame('crm', $report['masking']['inventory']['services'][0]['service']);
        $classes = array_column($report['masking']['inventory']['classes'], null, 'class');
        $this->assertSame(1, $classes['date_of_birth']['masked']);
        $this->assertSame(1, $classes['free_text_pii']['review']);
        $this->assertSame('selected', $report['access']['admins_mode']);
        $this->assertSame(['Lee Chen', 'Priya Shah'], array_values(array_unique(array_merge(
            array_column(array_filter($report['access']['admin_grants'], fn ($g) => $g['admin'] === 'Lee Chen'), 'admin'),
            array_column(array_filter($report['access']['admin_grants'], fn ($g) => $g['admin'] === 'Priya Shah'), 'admin')
        ))));
        $this->assertSame([['role' => 'support', 'scope' => 'except_restricted']], $report['access']['roles_with_real_values']);
        $this->assertGreaterThanOrEqual(3, $report['activity']['total']);
        $this->assertFalse($report['activity']['truncated']);
        $kinds = array_column($report['activity']['by_kind'], 'count', 'kind');
        $this->assertSame(1, $kinds['baseline']);

        $json = json_encode($report);
        $this->assertStringNotContainsString(self::SENTINEL, $json, 'no data values in the JSON report');
        $this->assertStringNotContainsString('SENTINEL', $json);

        $csv = Report::csv($report);
        $this->assertStringNotContainsString('SENTINEL', $csv, 'no data values in the CSV report');
        $lines = array_values(array_filter(explode("\n", trim($csv))));
        $this->assertSame('baseline_id,baseline,control_id,title,status,detail,references,generated_at,frameworks,disclaimer', $lines[0]);
        $this->assertCount(count($report['controls']) + 1, $lines, 'one row per control');
        $rows = array_map(fn ($l) => str_getcsv($l, ',', '"', ''), $lines);
        $this->assertSame('masking.mode', $rows[1][2]);
        $this->assertSame('45 CFR 164.502(b); 45 CFR 164.514(d)', $rows[1][6]);
    }

    public function testCsvNeutralizesFormulas(): void
    {
        $csv = Report::csv([
            'baseline' => ['id' => 'x', 'name' => 'X'],
            'generated_at' => '2026-10-29T00:00:00Z',
            'controls' => [['id' => 'a', 'title' => '=HYPERLINK("x")', 'status' => 'pass', 'detail' => '@SUM(1)', 'refs' => ['r']]],
        ]);
        $this->assertStringContainsString("'=HYPERLINK", $csv);
        $this->assertStringContainsString("'@SUM", $csv);
    }

    /** Every export format carries the frameworks and the disclaimer. */
    public function testExportsCarryFrameworksAndDisclaimer(): void
    {
        $report = BaselineService::report('pci_dss');
        $this->assertSame(['PCI DSS v4.0.1'], $report['baseline']['frameworks']);
        $this->assertStringContainsString('not a certification', $report['disclaimer']);

        $rows = array_map(
            fn ($l) => str_getcsv($l, ',', '"', ''),
            array_values(array_filter(explode("\n", trim(BaselineService::reportCsv('pci_dss')))))
        );
        $header = array_flip($rows[0]);
        foreach (array_slice($rows, 1) as $row) {
            $this->assertSame('PCI DSS v4.0.1', $row[$header['frameworks']]);
            $this->assertSame(Report::DISCLAIMER, $row[$header['disclaimer']]);
        }
        $glba = array_map(fn ($l) => str_getcsv($l, ',', '"', ''), array_values(array_filter(explode("\n", trim(BaselineService::reportCsv('glba'))))));
        $this->assertStringContainsString('; Interagency Guidelines', $glba[1][array_flip($glba[0])['frameworks']]);
    }

    /**
     * Apply with mode on before the first completed scan is
     * refused with 409 and changes nothing (before: masking went On with nothing classified and
     * apps received real values until the background scan finished).
     */
    public function testModeOnBeforeTheFirstScanIsRefused(): void
    {
        $this->forgetScans();
        try {
            BaselineService::apply('hipaa', 'on');
            $this->fail('mode on before a scan must be refused');
        } catch (ConflictResourceException $e) {
            $this->assertSame(409, $e->getStatusCode());
            $this->assertSame('Scan your databases before turning masking on.', $e->getMessage());
        }
        Settings::flush();
        $this->assertSame('off', Settings::mode());
        $this->assertSame('same_as_admins', Settings::ai(), 'nothing written');
        $this->assertSame(0, DB::table(Tables::BASELINE)->count(), 'nothing adopted');
        $this->assertSame([], $this->scansStarted);
    }

    /**
     * Apply on a never-scanned instance starts the first scan and says so;
     * on a scanned instance it does not.
     */
    public function testApplyOnANeverScannedInstanceStartsTheFirstScan(): void
    {
        $this->forgetScans();
        $result = BaselineService::apply('hipaa');
        $this->assertTrue($result['scan_started']);
        $this->assertCount(1, $this->scansStarted);
        Settings::flush();
        $this->assertSame('preview', Settings::mode(), 'Preview never changes data, so it may be set before the scan');
        $this->assertSame(
            'Scan started by the HIPAA baseline',
            DB::table(Tables::ACTIVITY)->where('kind', 'scan')->orderBy('id', 'desc')->value('text')
        );
        // Masking checks wait for that scan.
        $controls = array_column($result['controls'], null, 'id');
        $this->assertSame('fail', $controls['masking.review']['status']);
        $this->assertSame('/api-security/data-masking', $controls['masking.review']['fix']['route']);
    }

    public function testApplyOnAScannedInstanceStartsNoScan(): void
    {
        $result = BaselineService::apply('hipaa');
        $this->assertFalse($result['scan_started']);
        $this->assertSame([], $this->scansStarted);
        $this->assertSame(0, DB::table(Tables::ACTIVITY)->where('kind', 'scan')->count());
    }

    public function testAScanThatCannotStartDoesNotFailApply(): void
    {
        $this->forgetScans();
        BaselineService::$scanStarter = function (): void {
            throw new \RuntimeException('no php binary');
        };
        $result = BaselineService::apply('gdpr');
        $this->assertFalse($result['scan_started']);
        $this->assertTrue($result['adopted']);
    }

    /**
     * Rejecting a low-confidence suggestion (score below the mask threshold, waiting for
     * review) is not an override of protected data; a confident detection still counts.
     */
    public function testOnlyConfidentDetectionsCountAsClearedProtectedData(): void
    {
        $row = $this->column('clientes', 'fecha_alta', 'clear', null, 'admin', 'date_of_birth');
        $row['detected_score'] = 45;
        DB::table(Tables::COLUMN)->insert($row);
        $state = State::capture();
        $this->assertSame(['national_id' => 1], $state->adminCleared, 'the score-45 date is not counted');

        DB::table(Tables::COLUMN)->where('column_name', 'fecha_alta')->update(['detected_score' => 70]);
        $this->assertSame(['date_of_birth' => 1, 'national_id' => 1], State::capture()->adminCleared);
    }

    /**
     * A service a scan could not read is not scanned. Before, an unreachable database with
     * no stored columns counted as scanned by any successful full scan and passed the check.
     */
    public function testAServiceTheScanCouldNotReadIsNotScanned(): void
    {
        if (!class_exists(ScanHistory::class) || !ScanHistory::supported()) {
            $this->markTestSkipped('dm_scan.failed_services is not in this build');
        }
        // The first scan ran two hours ago; warehouse was added an hour ago; the latest full scan
        // could not read it (and it has no stored columns, like an empty database).
        DB::table(Tables::SCAN)->update(['finished_at' => now()->subHours(2)]);
        DB::table(Tables::COLUMN)->update(['scanned_at' => now()->subHours(2)]);
        DB::table('service')->insert(['id' => 2, 'name' => 'warehouse', 'label' => 'Warehouse', 'type' => 'mysql', 'is_active' => true, 'created_date' => now()->subHour()]);
        \DreamFactory\Core\Masking\Support\Coverage::forget();
        DB::table(Tables::SCAN)->insert([
            'service_id' => null, 'status' => 'done', 'progress' => 100, 'started_at' => now(), 'finished_at' => now(),
            'created_at' => now(), 'updated_at' => now(),
            ScanHistory::FAILED_COLUMN => ScanHistory::encode([['service_id' => 2, 'service' => 'warehouse', 'label' => 'Warehouse', 'reason' => 'Could not connect (SQLSTATE HY000)']]),
        ]);
        $state = State::capture();
        $covered = array_column($state->covered, null, 'name');
        if (!isset($covered['warehouse'])) {
            $this->markTestSkipped('the harness does not classify mysql services as covered');
        }
        $this->assertNull($covered['warehouse']['last_scan_at']);
        $this->assertSame('Could not connect (SQLSTATE HY000)', $covered['warehouse']['scan_error']);
        $this->assertNotNull($covered['crm']['last_scan_at']);

        $scanned = array_column(BaselineService::detail('hipaa')['controls'], null, 'id')['masking.scanned'];
        $this->assertSame('fail', $scanned['status']);
        $this->assertStringContainsString("couldn't read Warehouse", $scanned['detail']);
        $report = BaselineService::report('hipaa');
        $services = array_column($report['masking']['inventory']['services'], null, 'service');
        $this->assertNull($services['warehouse']['last_scanned_at']);
        $this->assertSame('Could not connect (SQLSTATE HY000)', $services['warehouse']['scan_error']);
        $this->assertNull($services['crm']['scan_error']);
    }

    /**
     * When the scan history cannot be read, the masking checks say "Could not be
     * checked" (before: every database looked never scanned, a confident wrong answer).
     */
    public function testAnUnreadableScanHistoryIsCouldNotBeChecked(): void
    {
        Settings::set(Settings::MODE, 'on');
        Schema::drop(Tables::SCAN); // any read of the scan history now fails
        if (class_exists(ScanHistory::class)) {
            ScanHistory::forget();
        }
        $state = State::capture();
        $this->assertCount(1, $state->covered);
        $this->assertTrue($state->covered[0]['scan_unknown']);
        $this->assertNull($state->covered[0]['last_scan_at']);

        $controls = array_column(BaselineService::detail('hipaa', false, $state)['controls'], null, 'id');
        foreach (['masking.mode', 'masking.scanned'] as $check) {
            $this->assertSame('fail', $controls[$check]['status'], $check);
            $this->assertSame('Could not be checked: see the DreamFactory log.', $controls[$check]['detail'], $check);
            $this->assertSame(['kind' => 'link', 'route' => '/api-security/data-masking'], $controls[$check]['fix'], $check);
        }
        // Problems the column table shows on its own still fail with their own detail and fix.
        $this->assertSame('1 column waits for review (masked until decided).', $controls['masking.review']['detail']);
        $this->assertSame('/api-security/data-masking?filter=review', $controls['masking.review']['fix']['route']);
        $this->assertSame('fail', $controls['masking.classes']['status']);
        $this->assertStringContainsString('marked not sensitive', $controls['masking.classes']['detail']);
        // Checks that do not read the scan history are unaffected.
        $this->assertSame('fail', $controls['access.ai']['status']);
        $this->assertSame('AI and MCP sessions see the same values as admins.', $controls['access.ai']['detail']);

        $inventory = BaselineService::report('hipaa')['masking']['inventory'];
        $this->assertSame('The scan history could not be read.', $inventory['scan_history_error']);
    }

    /** ...while a readable, empty history is still "not scanned", named by label. */
    public function testANeverScannedInstanceIsNotUnknown(): void
    {
        $this->forgetScans();
        Settings::set(Settings::MODE, 'on');
        $state = State::capture();
        $this->assertFalse($state->covered[0]['scan_unknown']);
        $controls = array_column(BaselineService::detail('hipaa', false, $state)['controls'], null, 'id');
        $this->assertSame('1 of 1 SQL services not scanned in the last 30 days: CRM.', $controls['masking.scanned']['detail']);
        $this->assertSame('Masking is on, but no database has been scanned yet.', $controls['masking.mode']['detail']);
        $this->assertArrayNotHasKey('scan_history_error', BaselineService::report('hipaa')['masking']['inventory']);
    }

    /** Per-service read logging, from service_event_map and active Logstash services. */
    public function testLoggedReadsFollowDreamFactoryEventMatching(): void
    {
        DB::table('service')->insert([
            ['id' => 20, 'name' => 'logstash', 'label' => 'Logstash', 'type' => 'logstash', 'is_active' => true, 'created_date' => now()],
            ['id' => 21, 'name' => 'old_logs', 'label' => 'Old', 'type' => 'logstash', 'is_active' => false, 'created_date' => now()],
            ['id' => 22, 'name' => 'queue', 'label' => 'Queue', 'type' => 'amqp', 'is_active' => true, 'created_date' => now()],
            ['id' => 3, 'name' => 'hr', 'label' => 'HR', 'type' => 'pgsql', 'is_active' => true, 'created_date' => now()],
            ['id' => 4, 'name' => 'sales', 'label' => 'Sales', 'type' => 'pgsql', 'is_active' => true, 'created_date' => now()],
            ['id' => 5, 'name' => 'erp', 'label' => 'ERP', 'type' => 'pgsql', 'is_active' => true, 'created_date' => now()],
        ]);
        DB::table('service_event_map')->insert([
            ['service_id' => 20, 'event' => 'user.session.post'],                  // login only: no data reads
            ['service_id' => 20, 'event' => 'crm.*'],                              // wildcard: every crm event
            ['service_id' => 20, 'event' => 'hr._table.{table_name}.get'],         // lists only, not single records
            ['service_id' => 20, 'event' => 'sales._table.{table_name}.get'],
            ['service_id' => 20, 'event' => 'sales._table.{table_name}.{id}.get'],
            ['service_id' => 21, 'event' => 'erp.*'],                              // inactive Logstash
            ['service_id' => 22, 'event' => 'hr._table.{table_name}.{id}.get'],    // another service on the exact name hides the wildcard
            ['service_id' => 20, 'event' => 'hr.*'],
            ['service_id' => 20, 'event' => 'erp._table.{table_name}.get.post_process'], // never reaches the event map
        ]);
        $this->assertSame(
            ['crm' => true, 'hr' => false, 'sales' => true, 'erp' => false, 'nope' => false],
            State::loggedReads(['crm', 'hr', 'sales', 'erp', 'nope'])
        );
    }

    /** Admins and open registration are read from DreamFactory's tables. */
    public function testStateCapturesAdminsAndOpenRegistration(): void
    {
        DB::table('user')->where('id', 1)->update(['last_login_date' => now()->subDays(2), 'created_date' => now()->subDays(300)]);
        DB::table('user')->where('id', 3)->update(['is_active' => false]);
        DB::table('service')->insert(['id' => 9, 'name' => 'user', 'label' => 'User', 'type' => 'user', 'is_active' => true, 'created_date' => now()]);
        DB::table('user_config')->insert(['service_id' => 9, 'allow_open_registration' => true]);
        $state = State::capture();
        $this->assertSame([], $state->errors);
        $this->assertSame([1, 2], array_column($state->admins, 'id'), 'active sys admins only');
        $this->assertSame('Alex Admin', $state->admins[0]['name']);
        $this->assertNotNull($state->admins[0]['last_login_at']);
        $this->assertNull($state->admins[1]['last_login_at']);
        $this->assertSame(['user'], $state->platformValue('open_registration'));
        $this->assertSame(20160, $state->platformValue('jwt_refresh_ttl'));
        $this->assertSame(400, $state->platformValue('activity_retention_days'));
    }
}

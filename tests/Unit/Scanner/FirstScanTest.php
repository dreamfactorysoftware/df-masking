<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Scanner;

use Carbon\Carbon;
use DreamFactory\Core\Masking\Enforcement\InlineClassifier;
use DreamFactory\Core\Masking\Enforcement\TableTarget;
use DreamFactory\Core\Masking\Resources\Handlers\OverviewHandler;
use DreamFactory\Core\Masking\Scanner\Hooks;
use DreamFactory\Core\Masking\Scanner\ScanLauncher;
use DreamFactory\Core\Masking\Scanner\ScanRunner;
use DreamFactory\Core\Enums\LicenseLevel;
use DreamFactory\Core\Masking\Support\Coverage;
use DreamFactory\Core\Masking\Support\License;
use DreamFactory\Core\Masking\Support\PolicyVersion;
use DreamFactory\Core\Masking\Support\ScanHistory;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use Illuminate\Database\Capsule\Manager as Capsule;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\TestCase;

/**
 * A scan that found no column is not a first scan, services created after
 * one are still scanned on creation, unknown columns start a scan of their service right away
 * (60 s dedupe); scans of deleted services neither drive last_status nor count as full
 * scans; the scan history reports when it cannot be read.
 */
final class FirstScanTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Harness::boot();
        ScanHistory::forget();
        Carbon::setTestNow(Carbon::create(2026, 10, 29, 12, 0, 0, 'UTC'));
    }

    protected function tearDown(): void
    {
        Carbon::setTestNow();
        parent::tearDown();
    }

    private static function people(string $column = 'contact', int $n = 40): \PDO
    {
        $rows = [];
        for ($i = 1; $i <= $n; $i++) {
            $rows[] = ['id' => $i, $column => "person$i@example.org"];
        }
        return Harness::sqlite(["CREATE TABLE people (id integer primary key, $column text)"], ['people' => $rows]);
    }

    private static function scans(): int
    {
        return DB::table(Tables::SCAN)->count();
    }

    private static function column(int $serviceId, string $column): ?object
    {
        return DB::table(Tables::COLUMN)->where('service_id', $serviceId)->where('column_name', $column)->first();
    }

    /** The built-in empty `db` only. The scan finds nothing: no first scan, no On. */
    public function testAScanOfEmptyDatabasesIsNotAFirstScan(): void
    {
        Harness::addService('db', Harness::sqlite([]));
        Coverage::forget();

        $summary = (new ScanRunner())->run();

        $this->assertSame(['done', 0], [$summary['status'], $summary['columns']]);
        $this->assertFalse(ScanHistory::firstScanDone());
        $this->assertTrue(ScanHistory::anyScanFinished());
        (new OverviewHandler())->overview(); // the overview's reconcile must not record it either
        $this->assertFalse(Settings::has(Settings::FIRST_SCAN_AT));
        $this->assertSame('off', Settings::mode(), 'the mode is not switched to Preview by an empty scan');
    }

    /** A database added after a scan of empty databases is scanned on creation. */
    public function testAServiceAddedAfterAnEmptyScanIsScannedOnCreation(): void
    {
        Harness::addService('db', Harness::sqlite([]));
        Coverage::forget();
        (new ScanRunner())->run();
        $this->assertSame(1, self::scans());

        $vtest = Harness::addService('vtest', self::people('contact'));
        Coverage::forget();
        Hooks::onServiceModified((object)['service' => (object)['name' => 'vtest', 'type' => 'sqlite', 'is_active' => true]]);

        $this->assertSame(2, self::scans(), 'the new service was scanned at once');
        $contact = self::column($vtest, 'contact');
        $this->assertSame(['masked', 'email'], [$contact->verdict, $contact->class], 'classified from its values');
        $this->assertNotNull($contact->scanned_at);
        $this->assertTrue(ScanHistory::firstScanDone());
        $this->assertSame('preview', Settings::mode(), 'the first scan that found columns picks Preview');
    }

    /** Before anyone scanned (mode Off) nothing is scanned behind the admin's back; Preview or On allow it. */
    public function testBackgroundScansWaitForAScanOrAModeOtherThanOff(): void
    {
        Harness::addService('crm', self::people());
        Coverage::forget();
        Hooks::onServiceModified((object)['service' => (object)['name' => 'crm', 'type' => 'sqlite', 'is_active' => true]]);
        $this->assertSame(0, self::scans());
        $this->assertFalse(ScanLauncher::autoScansAllowed());

        Settings::set(Settings::MODE, 'preview');
        $this->assertTrue(ScanLauncher::autoScansAllowed());
        Hooks::onServiceModified((object)['service' => (object)['name' => 'crm', 'type' => 'sqlite', 'is_active' => true]]);
        $this->assertSame(1, self::scans());
    }

    /** Service changes start no background scan when the license level is not Gold. */
    public function testServiceChangesStartNoScanWithoutGold(): void
    {
        Harness::addService('crm', self::people());
        Coverage::forget();
        Settings::set(Settings::MODE, 'preview');
        License::resolveUsing(static fn () => LicenseLevel::SILVER);
        try {
            Hooks::onServiceModified((object)['service' => (object)['name' => 'crm', 'type' => 'sqlite', 'is_active' => true]]);
            $this->assertSame(0, self::scans());
        } finally {
            License::resolveUsing(static fn () => LicenseLevel::GOLD);
        }
        Hooks::onServiceModified((object)['service' => (object)['name' => 'crm', 'type' => 'sqlite', 'is_active' => true]]);
        $this->assertSame(1, self::scans());
    }

    /**
     * Unknown columns start a scan of their service right away, even 2 minutes after
     * the previous one (before: deferred to the end of a 10-minute window); at most one such scan
     * per service per 60 s, a request inside that minute runs at its end, never dropped.
     */
    public function testUnknownColumnsStartAScanAtOnceWithAOneMinuteDedupe(): void
    {
        $pdo = self::people();
        $crm = Harness::addService('crm', $pdo);
        Coverage::forget();
        (new ScanRunner())->run();
        $this->assertSame(1, self::scans());
        $this->assertTrue(Settings::has(Settings::FIRST_SCAN_AT));

        $target = static function (array $columns) use ($crm): TableTarget {
            $fields = ['id' => ['name' => 'id', 'column' => 'id', 'type' => 'id', 'db_type' => 'integer']];
            foreach ($columns as $c) {
                $fields[$c] = ['name' => $c, 'column' => $c, 'type' => 'string', 'db_type' => 'text'];
            }
            return new TableTarget('crm', $crm, 'sqlite', 'people', $fields, [], ['id']);
        };
        $known = static function () use ($crm): array {
            return array_fill_keys(DB::table(Tables::COLUMN)->where('service_id', $crm)->pluck('column_name')->all(), true);
        };

        // a DBA adds a column with an innocuous name holding emails
        $pdo->exec('ALTER TABLE people ADD COLUMN backup_ref text');
        $pdo->exec("UPDATE people SET backup_ref = 'alt' || id || '@example.net'");
        $verdicts = InlineClassifier::classifyUnknown($target(['contact', 'backup_ref']), $known());
        $this->assertSame(['review', 'free_text_pii'], [$verdicts['backup_ref']['verdict'], $verdicts['backup_ref']['class']],
            'span-masked until scanned');
        $this->assertSame(2, self::scans(), 'the scan started at once');
        $this->assertSame(['masked', 'email'], [self::column($crm, 'backup_ref')->verdict, self::column($crm, 'backup_ref')->class]);

        // two minutes later another one: scanned at once again
        Carbon::setTestNow(Carbon::now()->addMinutes(2));
        $pdo->exec('ALTER TABLE people ADD COLUMN extra text');
        InlineClassifier::classifyUnknown($target(['contact', 'backup_ref', 'extra']), $known());
        $this->assertSame(3, self::scans(), 'not deferred by an old throttle window');

        // 30 s later: inside the minute, deferred to its end, not dropped
        Carbon::setTestNow(Carbon::now()->addSeconds(30));
        $pdo->exec('ALTER TABLE people ADD COLUMN third text');
        InlineClassifier::classifyUnknown($target(['contact', 'backup_ref', 'extra', 'third']), $known());
        $this->assertSame(3, self::scans());
        $this->assertSame([], ScanLauncher::dueRequests());
        Carbon::setTestNow(Carbon::now()->addSeconds(31));
        $this->assertSame(['crm'], ScanLauncher::dueRequests());
        $this->assertNotNull(ScanLauncher::tick());
        $this->assertSame(4, self::scans());
        $this->assertNotNull(self::column($crm, 'third')->scanned_at);
    }

    /** Once every failed service is deleted, last_status falls back to the previous outcome. */
    public function testDeletedFailedServicesNoLongerDriveTheLastStatus(): void
    {
        Harness::addService('crm', self::people());
        $broken = Harness::addService('broken', Harness::sqlite([]));
        Harness::$services['broken']->failSchema = true;
        Coverage::forget();
        (new ScanRunner())->run('crm');
        (new ScanRunner())->run('broken');
        $this->assertSame('failed', ScanHistory::lastOutcome()['last_status']);
        $this->assertSame(['broken'], array_column(ScanHistory::lastOutcome()['failed'], 'service'));

        self::deleteService($broken);

        $this->assertSame(['last_status' => 'done', 'failed' => [], 'unknown' => false], ScanHistory::lastOutcome());
        $this->assertSame('done', OverviewHandler::scanStatus()['last_status']);
    }

    /** A full scan that failed on a service deleted since says nothing about the others. */
    public function testAFailedFullScanOfDeletedServicesIsSkipped(): void
    {
        $broken = Harness::addService('broken', Harness::sqlite([]));
        Harness::$services['broken']->failSchema = true;
        Coverage::forget();
        (new ScanRunner())->run(); // every covered service failed: status failed
        $this->assertSame('failed', ScanHistory::lastOutcome()['last_status']);

        self::deleteService($broken);

        $this->assertSame(['last_status' => null, 'failed' => [], 'unknown' => false], ScanHistory::lastOutcome(), 'nothing left that it concerned');
    }

    /** Single-service scans of a deleted service never count as full scans. */
    public function testScansOfADeletedServiceAreNotFullScans(): void
    {
        $empty = Harness::addService('empty', Harness::sqlite([])); // no tables, no stored columns
        $gone = Harness::addService('gone', self::people());
        Coverage::forget();
        (new ScanRunner())->run('gone');
        $this->assertSame(ScanHistory::SCOPE_SERVICE, DB::table(Tables::SCAN)->value(ScanHistory::SCOPE_COLUMN));

        self::deleteService($gone);

        $this->assertNull(ScanHistory::services([$empty])[$empty]['scanned_at'], "another service's scan does not scan this one");
        Carbon::setTestNow(Carbon::now()->addSeconds(5));
        (new ScanRunner())->run();
        $this->assertSame(ScanHistory::SCOPE_FULL, DB::table(Tables::SCAN)->orderByDesc('id')->value(ScanHistory::SCOPE_COLUMN));
        $this->assertNotNull(ScanHistory::services([$empty])[$empty]['scanned_at'], 'a full scan does');
    }

    /** Compliance needs to tell "could not be read" from "never scanned". */
    public function testAnUnreadableScanHistoryIsReportedAsUnknown(): void
    {
        $crm = Harness::addService('crm', self::people());
        Coverage::forget();
        (new ScanRunner())->run();
        $this->assertSame(false, ScanHistory::services([$crm])[$crm]['unknown']);
        $this->assertNotNull(ScanHistory::services([$crm])[$crm]['scanned_at']);

        Schema::drop(Tables::SCAN);

        $this->assertSame(['scanned_at' => null, 'scan_error' => null, 'unknown' => true], ScanHistory::services([$crm])[$crm]);
    }

    /** The scope migration is additive, backfills, and rolls back (SQLite here; DM_SYSDB_URLS for the others). */
    public function testScopeMigrationBackfillsAndRollsBack(): void
    {
        $migration = require dirname(__DIR__, 3) . '/database/migrations/2026_10_29_000004_dm_scan_scope.php';
        $migration->down();
        ScanHistory::forget();
        $this->assertFalse(ScanHistory::scoped());
        DB::table(Tables::SCAN)->insert([['service_id' => null, 'status' => 'done'], ['service_id' => 7, 'status' => 'done']]);
        $this->assertSame([], ScanHistory::scopeFor(7), 'no column, no value');

        $migration->up();
        ScanHistory::forget();
        $this->assertTrue(ScanHistory::scoped());
        $this->assertSame(['full', 'service'], DB::table(Tables::SCAN)->orderBy('id')->pluck(ScanHistory::SCOPE_COLUMN)->all());
        $migration->up(); // idempotent
        $migration->down();
        $this->assertFalse(Schema::hasColumn(Tables::SCAN, ScanHistory::SCOPE_COLUMN));
        $migration->up();
    }

    /** What the package's ServiceDeletedEvent listener does (ServiceProvider). */
    private static function deleteService(int $id): void
    {
        $name = (string)DB::table('service')->where('id', $id)->value('name');
        DB::table(Tables::COLUMN)->where('service_id', $id)->delete();
        DB::table(Tables::SCAN)->where('service_id', $id)->update(['service_id' => null]);
        Capsule::table('service')->where('id', $id)->delete();
        unset(Harness::$services[$name]);
        PolicyVersion::bump();
        Coverage::forget();
    }
}

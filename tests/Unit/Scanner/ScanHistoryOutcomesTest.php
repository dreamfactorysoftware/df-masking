<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Scanner;

use Carbon\Carbon;
use DreamFactory\Core\Masking\Resources\Handlers\ColumnHandler;
use DreamFactory\Core\Masking\Resources\Handlers\OverviewHandler;
use DreamFactory\Core\Masking\Scanner\ScanLauncher;
use DreamFactory\Core\Masking\Scanner\ScanRunner;
use DreamFactory\Core\Masking\Scanner\ScanState;
use DreamFactory\Core\Masking\Support\Coverage;
use DreamFactory\Core\Masking\Support\PolicyVersion;
use DreamFactory\Core\Masking\Support\ScanHistory;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\TestCase;

/**
 * Scan history:
 *  - a single-service scan whose service was deleted still drives the last outcome while
 *    a service it could not read still exists.
 *  - an empty database a running scan read as an extra counts as scanned
 *    (dm_scan.read_services).
 *  - an unreadable scan history is reported as unknown (overview scan.unknown,
 *    /table scan_unknown), not as a never-scanned instance.
 *  - scan activity names services by label (fallback name).
 */
final class ScanHistoryOutcomesTest extends TestCase
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

    private static function people(int $n = 40): \PDO
    {
        $rows = [];
        for ($i = 1; $i <= $n; $i++) {
            $rows[] = ['id' => $i, 'contact' => "person$i@example.org"];
        }
        return Harness::sqlite(['CREATE TABLE people (id integer primary key, contact text)'], ['people' => $rows]);
    }

    private static function scanRow(array $values): int
    {
        $now = Carbon::now();
        return (int) DB::table(Tables::SCAN)->insertGetId($values + [
            'status' => 'done', 'progress' => 100, 'columns_total' => 4, 'columns_done' => 4,
            'started_at' => $now, 'finished_at' => $now, 'created_at' => $now, 'updated_at' => $now,
        ]);
    }

    /** What the ServiceDeletedEvent listener does: the row goes, the policy version is bumped. */
    private static function deleteService(int $id): void
    {
        DB::table('service')->where('id', $id)->delete();
        PolicyVersion::bump();
        Coverage::forget();
    }

    /** A deleted service's scan keeps naming a failed service that still exists. */
    public function testADeletedServicesScanKeepsNamingAFailedServiceThatStillExists(): void
    {
        $big = Harness::addService('big2', self::people());
        $brk = Harness::addService('brk2', self::people());
        Coverage::forget();
        self::scanRow(['service_id' => null, 'scope' => 'full']);
        // big2's single-service scan took brk2's due request as an extra and could not read it.
        self::scanRow(['service_id' => $big, 'scope' => 'service', 'failed_services' => ScanHistory::encode([
            ['service_id' => $brk, 'service' => 'brk2', 'label' => 'Broken two', 'reason' => 'Could not connect (SQLSTATE 08006)'],
        ])]);
        $this->assertSame('partial', ScanHistory::lastOutcome()['last_status']);

        self::deleteService($big);
        $outcome = ScanHistory::lastOutcome();
        $this->assertSame('partial', $outcome['last_status'], 'brk2 still exists and was never read');
        $this->assertSame(['brk2'], array_column($outcome['failed'], 'service'));
        $this->assertSame('partial', OverviewHandler::scanStatus()['last_status']);

        // Once brk2 is gone too, the scan concerns nothing left: the older full scan decides.
        self::deleteService($brk);
        $this->assertSame(['last_status' => 'done', 'failed' => [], 'unknown' => false], ScanHistory::lastOutcome());
    }

    /** A failed single-service scan of a deleted service is skipped (nothing it failed on is left). */
    public function testAFailedScanOfADeletedServiceAloneIsSkipped(): void
    {
        $gone = Harness::addService('gone', self::people());
        Coverage::forget();
        self::scanRow(['service_id' => null, 'scope' => 'full']);
        self::scanRow(['service_id' => $gone, 'scope' => 'service', 'status' => 'failed', 'error' => 'Could not read gone.']);
        $this->assertSame('failed', ScanHistory::lastOutcome()['last_status']);
        self::deleteService($gone);
        $this->assertSame('done', ScanHistory::lastOutcome()['last_status']);
    }

    /** An empty database a running scan read as an extra counts as scanned. */
    public function testAnEmptyDatabaseReadAsAnExtraCountsAsScanned(): void
    {
        Carbon::setTestNow(); // the running scan's heartbeat is checked against the real clock
        $big = Harness::addService('big3', self::people());
        $empty = Harness::addService('emptytwo', Harness::sqlite([]));
        Coverage::forget();
        Settings::set(Settings::FIRST_SCAN_AT, '2026-10-29T00:00:00Z'); // background scans allowed
        $running = ScanState::create($big, 'test');
        // Created while big3's scan runs: its request waits for that scan, which takes it at its end.
        $this->assertSame($running->id, ScanLauncher::startThrottled('emptytwo', 'System', 0));
        $this->assertSame(['emptytwo'], ScanLauncher::dueRequests());

        $summary = (new ScanRunner())->run('big3', $running->id);

        $this->assertSame(['done', 2], [$summary['status'], $summary['services']], 'the extra was read');
        $this->assertSame(1, DB::table(Tables::SCAN)->count(), 'one scan row: big3');
        $row = DB::table(Tables::SCAN)->first();
        $this->assertSame([$big, $empty], json_decode((string) $row->{ScanHistory::READ_COLUMN}, true));
        $history = ScanHistory::services([$big, $empty]);
        $this->assertNotNull($history[$empty]['scanned_at'], 'an empty database the scan read counts as scanned');
        $this->assertNull($history[$empty]['scan_error']);
        $tables = array_column((new ColumnHandler())->tables()['resource'], null, 'service');
        $this->assertNotNull($tables['emptytwo']['scanned_at']);
        $this->assertSame([], $tables['emptytwo']['tables']);
    }

    /** read_services never names a service the scan could not read. */
    public function testAFailedExtraIsNotRecordedAsRead(): void
    {
        $big = Harness::addService('big4', self::people());
        Harness::addService('brk4', self::people());
        Harness::$services['brk4']->failSchema = true;
        Coverage::forget();
        (new ScanRunner())->run();
        $this->assertSame([$big], json_decode((string) DB::table(Tables::SCAN)->value(ScanHistory::READ_COLUMN), true));
    }

    /** An unreadable scan history is reported as unknown, not as never scanned. */
    public function testAnUnreadableScanHistoryIsReportedAsUnknown(): void
    {
        Harness::addService('crm', self::people());
        Coverage::forget();
        (new ScanRunner())->run();
        $this->assertFalse(OverviewHandler::scanStatus()['unknown']);
        $tables = (new ColumnHandler())->tables()['resource'];
        $this->assertFalse($tables[0]['scan_unknown']);
        $this->assertNotNull($tables[0]['scanned_at']);

        Schema::rename(Tables::SCAN, 'dm_scan_hidden');
        ScanHistory::forget();

        $scan = OverviewHandler::scanStatus();
        $this->assertTrue($scan['unknown'], 'not a never-scanned instance: the history could not be read');
        $this->assertSame(['idle', null, null, []], [$scan['status'], $scan['finished_at'], $scan['last_status'], $scan['failed']], 'other fields as before');
        $this->assertTrue(ScanHistory::lastOutcome()['unknown']);
        $this->assertTrue((new OverviewHandler())->overview()['scan']['unknown']);
        $tables = (new ColumnHandler())->tables()['resource'];
        $this->assertTrue($tables[0]['scan_unknown']);
        $this->assertNull($tables[0]['scanned_at']);
    }

    /** A scan that read nothing names the service by its label. */
    public function testScanFailureActivityUsesTheLabel(): void
    {
        $id = Harness::addService('wh_prod_02', self::people());
        DB::table('service')->where('id', $id)->update(['label' => 'Warehouse']);
        Harness::addService('nolabel', self::people());
        DB::table('service')->where('name', 'nolabel')->update(['label' => '']);
        Harness::$services['wh_prod_02']->failSchema = true;
        Harness::$services['nolabel']->failSchema = true;
        Coverage::forget();

        (new ScanRunner())->run('wh_prod_02');
        $this->assertSame('Scan failed: could not read Warehouse', DB::table(Tables::ACTIVITY)->where('kind', 'scan')->orderByDesc('id')->value('text'));
        (new ScanRunner())->run('nolabel');
        $this->assertSame('Scan failed: could not read nolabel', DB::table(Tables::ACTIVITY)->where('kind', 'scan')->orderByDesc('id')->value('text'), 'no label: the name');

        Harness::$services['nolabel']->failSchema = false;
        (new ScanRunner())->run();
        $this->assertSame(
            'Scan finished: 2 columns in 1 database (could not scan Warehouse)',
            DB::table(Tables::ACTIVITY)->where('kind', 'scan')->orderByDesc('id')->value('text')
        );
    }
}

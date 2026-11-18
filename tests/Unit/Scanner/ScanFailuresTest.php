<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Scanner;

use Carbon\Carbon;
use DreamFactory\Core\Masking\Classifier\TypeMap;
use DreamFactory\Core\Masking\Resources\Handlers\ColumnHandler;
use DreamFactory\Core\Masking\Resources\Handlers\OverviewHandler;
use DreamFactory\Core\Masking\Scanner\Hooks;
use DreamFactory\Core\Masking\Scanner\ScanLauncher;
use DreamFactory\Core\Masking\Scanner\ScanRunner;
use DreamFactory\Core\Masking\Support\Coverage;
use DreamFactory\Core\Masking\Support\ScanHistory;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\TestCase;

/**
 * Scan failures are first-class, unreadable values never yield a silent
 * "not sensitive", and throttled background re-scans are deferred, not dropped.
 */
final class ScanFailuresTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Harness::boot();
        ScanHistory::forget();
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
            $rows[] = ['id' => $i, 'contact' => "person$i@example.org", 'rv' => 'x' . $i, 'note' => 'n' . $i];
        }

        return Harness::sqlite(['CREATE TABLE people (id integer primary key, contact text, rv text, note text)'], ['people' => $rows]);
    }

    private static function column(int $serviceId, string $column): object
    {
        return DB::table(Tables::COLUMN)->where('service_id', $serviceId)->where('column_name', $column)->first();
    }

    /** One unreadable column (SQL Server rowversion) no longer hides every other column. */
    public function testAnUnreadableColumnIsReadAloneAndMarkedToReview(): void
    {
        $id = Harness::addService('crm', self::people());
        Harness::$services['crm']->unreadable = ['rv'];
        Coverage::forget();

        $summary = (new ScanRunner())->run('crm');

        $this->assertSame('done', $summary['status']);
        $contact = self::column($id, 'contact');
        $this->assertSame(['masked', 'email'], [$contact->verdict, $contact->class], 'the readable columns were sampled');
        $rv = self::column($id, 'rv');
        $this->assertSame('review', $rv->verdict, 'never clear on the strength of the name alone');
        $texts = array_column(json_decode($rv->evidence, true)['lines'], 'text');
        $this->assertContains('Values could not be read (SQLSTATE HY000); masked until a scan reads them or an admin decides', $texts);
        $this->assertSame(1, $summary['unreadable_columns']);
        $this->assertContains('Values of 1 column could not be read; they are marked to review.', $summary['errors']);
        $this->assertStringContainsString('values of 1 column could not be read',
            DB::table(Tables::ACTIVITY)->where('kind', 'scan')->orderByDesc('id')->value('text'));

        // once the values are readable, the next scan replaces the provisional review verdict
        Harness::$services['crm']->unreadable = [];
        (new ScanRunner())->run('crm');
        $this->assertSame('clear', self::column($id, 'rv')->verdict);
    }

    public function testATableWhoseValuesCannotBeReadIsMarkedToReview(): void
    {
        $id = Harness::addService('crm', self::people());
        Harness::$services['crm']->unreadable = ['contact', 'rv', 'note'];
        Coverage::forget();

        $summary = (new ScanRunner())->run('crm');

        $this->assertSame(3, $summary['unreadable_columns']);
        foreach (['contact', 'rv', 'note'] as $c) {
            $this->assertSame('review', self::column($id, $c)->verdict, $c);
        }
        $this->assertSame('clear', self::column($id, 'id')->verdict, 'the key was not unreadable');
    }

    public function testSqlServerRowversionIsNeverSampled(): void
    {
        $this->assertSame('binary', TypeMap::engineType('timestamp', 'bigint', 'sqlsrv'));
        $this->assertSame('binary', TypeMap::engineType('rowversion', null, 'sqlsrv'));
        $this->assertSame('timestamp', TypeMap::engineType('timestamp', null, 'pgsql'), 'a PostgreSQL timestamp is a date');
        $this->assertSame('timestamp', TypeMap::engineType('timestamp', null, 'mysql'));
    }

    /** A service that could not be read is recorded and is not "scanned". */
    public function testAFailedServiceIsRecordedAndNotCountedAsScanned(): void
    {
        $crm = Harness::addService('crm', self::people());
        $wh = Harness::addService('warehouse', Harness::sqlite([]));
        Harness::$services['warehouse']->failSchema = true;
        Coverage::forget();

        $summary = (new ScanRunner())->run();

        $this->assertSame('done', $summary['status']);
        $this->assertSame([['service_id' => $wh, 'service' => 'warehouse', 'label' => 'Warehouse',
            'reason' => 'Could not read the database (SQLSTATE HY000)']], $summary['failed']);
        $outcome = ScanHistory::lastOutcome();
        $this->assertSame('partial', $outcome['last_status']);
        $this->assertSame(['warehouse'], array_column($outcome['failed'], 'service'));
        $this->assertSame('partial', OverviewHandler::scanStatus()['last_status']);

        $tables = array_column((new ColumnHandler())->tables()['resource'], null, 'service');
        $this->assertNotNull($tables['crm']['scanned_at']);
        $this->assertNull($tables['crm']['scan_error']);
        $this->assertNull($tables['warehouse']['scanned_at'], 'an empty database the scan could not read is not scanned');
        $this->assertSame('Could not read the database (SQLSTATE HY000)', $tables['warehouse']['scan_error']);

        // a single-service scan that fails is a failed scan
        $summary = (new ScanRunner())->run('warehouse');
        $this->assertSame('failed', $summary['status']);
        $this->assertSame('failed', ScanHistory::lastOutcome()['last_status']);

        // retry once it can be read
        Carbon::setTestNow(Carbon::now()->addSeconds(5));
        Harness::$services['warehouse']->failSchema = false;
        (new ScanRunner())->run('warehouse');
        $this->assertSame(['last_status' => 'done', 'failed' => [], 'unknown' => false], ScanHistory::lastOutcome());
        $tables = array_column((new ColumnHandler())->tables()['resource'], null, 'service');
        $this->assertNull($tables['warehouse']['scan_error']);
        $this->assertNotNull($tables['warehouse']['scanned_at']);
    }

    public function testFailureReasonsCarryNoMessageText(): void
    {
        $e = new \PDOException("SQLSTATE[08006] could not connect to server at secret-host 'jane@example.org'");
        $e->errorInfo = ['08006', 7, 'x'];
        $this->assertSame('Could not connect (SQLSTATE 08006)', ScanHistory::reason($e));
        $login = new \PDOException('denied for user bob');
        $login->errorInfo = ['28000', 1045, 'x'];
        $this->assertSame('Login failed (SQLSTATE 28000)', ScanHistory::reason($login));
        $this->assertSame('Could not read the database (RuntimeException)', ScanHistory::reason(new \RuntimeException('host db.internal')));
    }

    /** A request inside the throttle window is deferred to its end, never dropped. */
    public function testAThrottledRescanRunsWhenTheWindowEnds(): void
    {
        $crm = Harness::addService('crm', self::people());
        Coverage::forget();
        Settings::set(Settings::FIRST_SCAN_AT, '2026-10-29T00:00:00Z');
        Carbon::setTestNow(Carbon::create(2026, 10, 29, 12, 0, 0, 'UTC'));

        // first automatic re-scan: runs now (in-process here) and opens the 10-minute window
        $this->assertNotNull(ScanLauncher::startThrottled('crm', 'System', 600));
        $this->assertSame(1, DB::table(Tables::SCAN)->count());

        // inside the window: not started, but kept
        Carbon::setTestNow(Carbon::now()->addMinutes(2));
        $this->assertNull(ScanLauncher::startThrottled('crm', 'System', 600));
        $this->assertSame(1, DB::table(Tables::SCAN)->count());
        $this->assertSame([], ScanLauncher::dueRequests(), 'deferred, not due yet');
        $this->assertNull(ScanLauncher::tick());

        // the first request after the window ends starts it
        Carbon::setTestNow(Carbon::now()->addMinutes(9));
        $this->assertSame(['crm'], ScanLauncher::dueRequests());
        $this->assertNotNull(ScanLauncher::tick());
        $this->assertSame(2, DB::table(Tables::SCAN)->count());
        $this->assertSame([], ScanLauncher::dueRequests(), 'the scan satisfied the request');
        $this->assertNull(ScanLauncher::tick());
    }

    /** A service configuration change re-scans right away, even inside the throttle window. */
    public function testAServiceChangeIsNotThrottled(): void
    {
        Harness::addService('crm', self::people());
        Coverage::forget();
        Settings::set(Settings::FIRST_SCAN_AT, '2026-10-29T00:00:00Z');
        ScanLauncher::startThrottled('crm', 'System', 600); // opens the window
        $this->assertSame(1, DB::table(Tables::SCAN)->count());

        Hooks::onServiceModified((object)['service' => (object)['name' => 'crm', 'type' => 'sqlite', 'is_active' => true]]);

        $this->assertSame(2, DB::table(Tables::SCAN)->count(), 'the change was scanned at once');
    }
}

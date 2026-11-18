<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Integration;

use DreamFactory\Core\Masking\Resources\Handlers\ColumnHandler;
use DreamFactory\Core\Masking\Scanner\ScanRunner;
use DreamFactory\Core\Masking\Support\Coverage;
use DreamFactory\Core\Masking\Support\PolicyVersion;
use DreamFactory\Core\Masking\Tests\Unit\Scanner\Harness;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\TestCase;

/**
 * GET system/data_masking/table lists a covered service with `tables: []` both when it was never
 * scanned and when it was scanned but holds no tables (DreamFactory's built-in `db` SQLite
 * service on a default install). Found on the live stack: the admin UI showed that service under
 * "Not scanned yet" forever, with a Scan button that could never change it. `scanned_at` tells
 * the two apart, by the same rule as the Compliance check masking.scanned.
 */
final class TableScannedAtTest extends TestCase
{
    protected function setUp(): void
    {
        Harness::boot();
        Schema::table('service', function (Blueprint $t) {
            $t->timestamp('created_date')->nullable();
        });
        Harness::addService('crm', Harness::sqlite(['CREATE TABLE customers (id INTEGER PRIMARY KEY, email varchar(100))']));
        Harness::addService('db', Harness::sqlite([]));
        DB::table('service')->update(['created_date' => '2026-10-01 00:00:00']);
        Coverage::forget();
        PolicyVersion::bump();
    }

    /** @return array<string, array> wire rows by service name */
    private function tables(): array
    {
        $out = [];
        foreach ((new ColumnHandler())->tables()['resource'] as $row) {
            $out[$row['service']] = $row;
        }

        return $out;
    }

    public function testNeverScannedServicesHaveNoScanTime(): void
    {
        $t = $this->tables();
        $this->assertSame(['crm', 'db'], array_keys($t));
        foreach ($t as $row) {
            $this->assertArrayHasKey('scanned_at', $row);
            $this->assertNull($row['scanned_at']);
            $this->assertSame([], $row['tables']);
        }
    }

    public function testAScannedEmptyDatabaseCarriesItsScanTime(): void
    {
        $summary = (new ScanRunner())->run();
        $this->assertSame('done', $summary['status'], (string)$summary['error']);

        $t = $this->tables();
        $this->assertCount(1, $t['crm']['tables']);
        $this->assertMatchesRegularExpression('/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/', (string)$t['crm']['scanned_at']);
        // Scanned, and empty: no tables, but a scan time, so it is not "never scanned".
        $this->assertSame([], $t['db']['tables']);
        $this->assertNotNull($t['db']['scanned_at']);
    }

    public function testAServiceAddedAfterTheLastFullScanIsNotScanned(): void
    {
        (new ScanRunner())->run();
        Harness::addService('later', Harness::sqlite([]));
        DB::table('service')->where('name', 'later')->update(['created_date' => '2999-01-01 00:00:00']);
        Coverage::forget();

        $t = $this->tables();
        $this->assertNotNull($t['db']['scanned_at']);
        $this->assertNull($t['later']['scanned_at']);
        $this->assertSame([], $t['later']['tables']);
    }
}

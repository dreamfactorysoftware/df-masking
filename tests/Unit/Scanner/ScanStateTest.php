<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Scanner;

use DreamFactory\Core\Masking\Scanner\ScanLauncher;
use DreamFactory\Core\Masking\Scanner\ScanState;
use DreamFactory\Core\Masking\Support\Tables;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\TestCase;

final class ScanStateTest extends TestCase
{
    protected function setUp(): void
    {
        Harness::boot();
    }

    public function testLifecycle(): void
    {
        $s = ScanState::create(null, 'Alex Admin');
        $s->claim(getmypid());
        $s->total(200);
        $s->beat(50, 200, true);
        $row = ScanState::find($s->id);
        $this->assertSame(['running', 25, 50, 200], [$row->status, (int) $row->progress, (int) $row->columns_done, (int) $row->columns_total]);
        $this->assertSame($s->id, (int) ScanState::running()->id);
        $status = ScanLauncher::status();
        $this->assertSame(['status' => 'running', 'progress' => 25, 'finished_at' => null, 'columns' => 0, 'last_status' => null, 'failed' => [], 'unknown' => false], $status);
        $s->finish(200, 200);
        $row = ScanState::find($s->id);
        $this->assertSame(['done', 100], [$row->status, (int) $row->progress]);
        $this->assertNull(ScanState::running());
        $this->assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/', ScanLauncher::status()['finished_at']);
    }

    public function testStaleScansAreMarkedFailed(): void
    {
        $s = ScanState::create(null, 'System');
        DB::table(Tables::SCAN)->where('id', $s->id)->update(['updated_at' => now()->subMinutes(6)]);
        $this->assertNull(ScanState::running());
        $row = ScanState::find($s->id);
        $this->assertSame('failed', $row->status);
        $this->assertNotEmpty($row->error);
    }

    public function testDeadLocalProcessIsDetectedAfterAMinute(): void
    {
        $s = ScanState::create(null, 'System');
        $s->claim(2147483646); // no such pid
        $this->assertNotNull(ScanState::running(), 'a fresh heartbeat keeps it alive (may run on another node)');
        DB::table(Tables::SCAN)->where('id', $s->id)->update(['updated_at' => now()->subSeconds(90)]);
        $this->assertNull(ScanState::running());
    }

    public function testPercent(): void
    {
        $this->assertSame(0, ScanState::percent(0, 0));
        $this->assertSame(50, ScanState::percent(5, 10));
        $this->assertSame(99, ScanState::percent(10, 10));
    }
}

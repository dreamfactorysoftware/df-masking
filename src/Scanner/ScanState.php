<?php

namespace DreamFactory\Core\Masking\Scanner;

use DreamFactory\Core\Masking\Support\ScanHistory;
use DreamFactory\Core\Masking\Support\Tables;
use DreamFactory\Core\Masking\Support\Time;
use Illuminate\Support\Facades\DB;

/**
 * dm_scan bookkeeping: one row per scan with status running|done|failed, progress, column
 * counts, pid and a heartbeat (updated_at).
 *
 * A running scan is considered dead (and marked failed) when its heartbeat is older than
 * df-masking.scan.stale_minutes (default 5), or when its process is gone on this host and the
 * heartbeat is older than LOCAL_DEAD_SECONDS (a scan running on another web node keeps
 * heartbeating, so a missing local pid alone is not proof). Nothing stays "running" forever.
 */
final class ScanState
{
    public const RUNNING = 'running';
    public const DONE = 'done';
    public const FAILED = 'failed';

    private const LOCAL_DEAD_SECONDS = 60;
    private const HEARTBEAT_EVERY_MS = 1000;

    private float $lastBeat = 0.0;

    public function __construct(public readonly int $id)
    {
    }

    public static function create(?int $serviceId, ?string $triggeredBy): self
    {
        $now = now();
        $id = DB::table(Tables::SCAN)->insertGetId([
            'service_id' => $serviceId,
            'status' => self::RUNNING,
            'progress' => 0,
            'columns_total' => 0,
            'columns_done' => 0,
            'started_at' => $now,
            'triggered_by' => $triggeredBy === null ? null : mb_substr($triggeredBy, 0, 255),
            'created_at' => $now,
            'updated_at' => $now,
        ] + ScanHistory::scopeFor($serviceId));
        return new self((int) $id);
    }

    public static function find(int $id): ?object
    {
        return DB::table(Tables::SCAN)->where('id', $id)->first();
    }

    public function claim(int $pid): void
    {
        DB::table(Tables::SCAN)->where('id', $this->id)->update([
            'status' => self::RUNNING, 'pid' => $pid, 'error' => null, 'finished_at' => null, 'updated_at' => now(),
        ] + (ScanHistory::supported() ? [ScanHistory::FAILED_COLUMN => null] : [])
          + (ScanHistory::tracked() ? [ScanHistory::READ_COLUMN => null] : []));
    }

    public function setPid(int $pid): void
    {
        DB::table(Tables::SCAN)->where('id', $this->id)->where('status', self::RUNNING)->whereNull('pid')->update(['pid' => $pid]);
    }

    public function total(int $columnsTotal): void
    {
        DB::table(Tables::SCAN)->where('id', $this->id)->update(['columns_total' => $columnsTotal, 'updated_at' => now()]);
        $this->lastBeat = microtime(true);
    }

    /** Progress + heartbeat, written at most once per second unless $force. */
    public function beat(int $done, int $total, bool $force = false): void
    {
        $now = microtime(true);
        if (!$force && ($now - $this->lastBeat) * 1000 < self::HEARTBEAT_EVERY_MS) {
            return;
        }
        $this->lastBeat = $now;
        DB::table(Tables::SCAN)->where('id', $this->id)->update($total > 0 ? [
            'columns_done' => $done,
            'progress' => self::percent($done, $total),
            'updated_at' => now(),
        ] : ['updated_at' => now()]);
    }

    /**
     * @param list<array{service_id:int|null,service:string,label:string,reason:string}> $failed services
     *        this scan could not read (stored in dm_scan.failed_services)
     * @param list<int> $read ids of every service this scan read, extras included (dm_scan.read_services)
     */
    public function finish(int $done, int $total, ?string $error = null, array $failed = [], array $read = []): void
    {
        DB::table(Tables::SCAN)->where('id', $this->id)->update(self::withFailed([
            'status' => self::DONE,
            'progress' => 100,
            'columns_done' => $done,
            'columns_total' => max($done, $total),
            'finished_at' => now(),
            'error' => $error === null ? null : mb_substr($error, 0, 1000),
            'updated_at' => now(),
        ] + ScanHistory::readServices($read), $failed));
    }

    /** @param list<array{service_id:int|null,service:string,label:string,reason:string}> $failed */
    public function fail(string $error, array $failed = []): void
    {
        DB::table(Tables::SCAN)->where('id', $this->id)->update(self::withFailed([
            'status' => self::FAILED,
            'finished_at' => now(),
            'error' => mb_substr($error, 0, 1000),
            'updated_at' => now(),
        ], $failed));
    }

    /** Adds failed_services when the column exists (an instance that has not run the upgrade migration yet still scans). */
    private static function withFailed(array $values, array $failed): array
    {
        if (ScanHistory::supported()) {
            $values[ScanHistory::FAILED_COLUMN] = ScanHistory::encode($failed);
        }

        return $values;
    }

    /** 0..99 while running (100 is written by finish()). */
    public static function percent(int $done, int $total): int
    {
        return $total <= 0 ? 0 : (int) min(99, intdiv($done * 100, $total));
    }

    /**
     * The scan that is running right now, or null. Dead "running" rows found on the way are
     * marked failed.
     */
    public static function running(): ?object
    {
        $rows = DB::table(Tables::SCAN)->where('status', self::RUNNING)->orderByDesc('id')->get();
        $alive = null;
        foreach ($rows as $row) {
            if (self::isAlive($row)) {
                $alive ??= $row;
                continue;
            }
            DB::table(Tables::SCAN)->where('id', $row->id)->where('status', self::RUNNING)->update([
                'status' => self::FAILED,
                'finished_at' => now(),
                'error' => 'The scan stopped unexpectedly (no progress for several minutes). Start it again.',
                'updated_at' => now(),
            ]);
        }
        return $alive;
    }

    public static function isAlive(object $row): bool
    {
        $beat = Time::ts($row->updated_at ?? null) ?? Time::ts($row->started_at ?? null) ?? 0;
        $age = time() - $beat;
        $staleMinutes = (int) config('df-masking.scan.stale_minutes', 5);
        if ($age > max(1, $staleMinutes) * 60) {
            return false;
        }
        $pid = (int) ($row->pid ?? 0);
        if ($pid > 0 && $age > self::LOCAL_DEAD_SECONDS && !self::pidAlive($pid)) {
            return false;
        }
        return true;
    }

    /** True when $pid exists on this host (EPERM = exists but owned by another user). */
    public static function pidAlive(int $pid): bool
    {
        if ($pid <= 0) {
            return false;
        }
        if (function_exists('posix_kill')) {
            if (@posix_kill($pid, 0)) {
                return true;
            }
            return function_exists('posix_get_last_error') && posix_get_last_error() === 1;
        }
        return is_dir('/proc/' . $pid);
    }

    /** Latest finished scan (done), or null. */
    public static function lastDone(): ?object
    {
        return DB::table(Tables::SCAN)->where('status', self::DONE)->orderByDesc('id')->first();
    }
}

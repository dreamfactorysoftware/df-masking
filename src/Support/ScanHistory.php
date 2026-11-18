<?php

namespace DreamFactory\Core\Masking\Support;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * What the dm_scan history says about scans: whether one ever completed, how the latest one
 * ended, and per covered service when it was last scanned successfully and why its latest
 * attempt failed.
 *
 * A scan that could not read a service records it in dm_scan.failed_services
 * ([{service_id, service, label, reason}]; reasons carry SQLSTATEs, never data values). A failed
 * service does not count as scanned: its scanned_at does not advance, and an empty database
 * only counts as scanned by a successful scan that read it.
 */
final class ScanHistory
{
    public const FAILED_COLUMN = 'failed_services';
    /** dm_scan.scope: 'full' (every covered service) or 'service' (migration 2026_10_29_000004). */
    public const SCOPE_COLUMN = 'scope';
    public const SCOPE_FULL = 'full';
    public const SCOPE_SERVICE = 'service';
    /** dm_scan.read_services: JSON ids of every service a finished scan read (migration 2026_10_29_000005). */
    public const READ_COLUMN = 'read_services';

    /** Finished scans looked at to find the latest outcome that still concerns a service. */
    private const OUTCOME_LOOKBACK = 50;

    /** Finished scans looked at per query (newest first); older history cannot change the answer much. */
    private const HISTORY_LIMIT = 500;

    private static ?bool $supported = null;
    private static ?bool $scoped = null;
    private static ?bool $tracked = null;

    private function __construct()
    {
    }

    /** True when dm_scan.failed_services exists (migration 2026_10_29_000003 ran). */
    public static function supported(): bool
    {
        if (self::$supported !== null) {
            return self::$supported;
        }
        try {
            return self::$supported = Schema::hasColumn(Tables::SCAN, self::FAILED_COLUMN);
        } catch (\Throwable $e) {
            return false; // not memoised: the next call retries
        }
    }

    /** True when dm_scan.scope exists (migration 2026_10_29_000004 ran). */
    public static function scoped(): bool
    {
        if (self::$scoped !== null) {
            return self::$scoped;
        }
        try {
            return self::$scoped = Schema::hasColumn(Tables::SCAN, self::SCOPE_COLUMN);
        } catch (\Throwable $e) {
            return false; // not memoised: the next call retries
        }
    }

    /** True when dm_scan.read_services exists (migration 2026_10_29_000005 ran). */
    public static function tracked(): bool
    {
        if (self::$tracked !== null) {
            return self::$tracked;
        }
        try {
            return self::$tracked = Schema::hasColumn(Tables::SCAN, self::READ_COLUMN);
        } catch (\Throwable $e) {
            return false; // not memoised: the next call retries
        }
    }

    /** Drops memos (tests, after a migration in the same process). */
    public static function forget(): void
    {
        self::$supported = null;
        self::$scoped = null;
        self::$tracked = null;
    }

    /**
     * dm_scan.read_services value of a finished scan (when the column exists).
     *
     * @param list<int> $ids services the scan read successfully
     * @return array<string,?string>
     */
    public static function readServices(array $ids): array
    {
        if (!self::tracked()) {
            return [];
        }
        $ids = array_values(array_unique(array_map('intval', $ids)));
        sort($ids);

        return [self::READ_COLUMN => $ids === [] ? null : json_encode($ids)];
    }

    /** @return list<int> */
    private static function decodeIds(mixed $json): array
    {
        if (!is_string($json) || $json === '') {
            return [];
        }
        $list = json_decode($json, true);

        return is_array($list) ? array_values(array_map('intval', array_filter($list, 'is_numeric'))) : [];
    }

    /**
     * True once a scan has completed that found at least one column: a finished
     * dm_scan row (status done, columns_done > 0). A scan of empty databases does not count: mode
     * On needs classified columns, before that apps would get real values. The first-scan marker
     * in dm_setting is not enough on its own: settings are cached, and a cached marker can outlive
     * the tables it was read from (package removed and reinstalled without cache:clear).
     * A database error answers true (never block on an unreadable history).
     */
    public static function firstScanDone(): bool
    {
        try {
            return DB::table(Tables::SCAN)->where('status', 'done')->where('columns_done', '>', 0)->exists();
        } catch (\Throwable $e) {
            return true;
        }
    }

    /**
     * True once any scan has finished (done or failed), even one that found no column: someone
     * has asked for scanning, so services created or changed later are scanned too.
     */
    public static function anyScanFinished(): bool
    {
        try {
            return DB::table(Tables::SCAN)->whereIn('status', ['done', 'failed'])->exists();
        } catch (\Throwable $e) {
            return false;
        }
    }

    /** The dm_scan scope value of a new scan row: 'service' for one service, 'full' for all of them. */
    public static function scopeFor(?int $serviceId): array
    {
        return self::scoped() ? [self::SCOPE_COLUMN => $serviceId === null ? self::SCOPE_FULL : self::SCOPE_SERVICE] : [];
    }

    /** Restricts a dm_scan query to full scans (rows from before the scope column: service_id NULL). */
    private static function whereFull($query)
    {
        if (!self::scoped()) {
            return $query->whereNull('service_id');
        }
        return $query->where(function ($q) {
            $q->where(self::SCOPE_COLUMN, self::SCOPE_FULL)->orWhere(function ($q) {
                $q->whereNull(self::SCOPE_COLUMN)->whereNull('service_id');
            });
        });
    }

    private static function isFull(object $row): bool
    {
        $scope = $row->{self::SCOPE_COLUMN} ?? null;
        return $scope !== null ? $scope === self::SCOPE_FULL : ($row->service_id ?? null) === null;
    }

    /**
     * @param list<array{service_id:int|null,service:string,label:string,reason:string}> $failed
     */
    public static function encode(array $failed): ?string
    {
        if ($failed === []) {
            return null;
        }
        $out = [];
        foreach ($failed as $f) {
            $out[] = [
                'service_id' => isset($f['service_id']) ? (int)$f['service_id'] : null,
                'service' => mb_substr((string)($f['service'] ?? ''), 0, 255),
                'label' => mb_substr((string)($f['label'] ?? ''), 0, 255),
                'reason' => mb_substr((string)($f['reason'] ?? ''), 0, 300),
            ];
        }

        return json_encode($out, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    }

    /** @return list<array{service_id:int|null,service:string,label:string,reason:string}> */
    public static function decode(mixed $json): array
    {
        if (!is_string($json) || $json === '') {
            return [];
        }
        $list = json_decode($json, true);
        if (!is_array($list)) {
            return [];
        }
        $out = [];
        foreach ($list as $f) {
            if (!is_array($f) || !isset($f['service'])) {
                continue;
            }
            $out[] = [
                'service_id' => isset($f['service_id']) && is_numeric($f['service_id']) ? (int)$f['service_id'] : null,
                'service' => (string)$f['service'],
                'label' => (string)($f['label'] ?? $f['service']),
                'reason' => (string)($f['reason'] ?? ''),
            ];
        }

        return $out;
    }

    /**
     * A failure reason for an exception thrown while reading a service: what went wrong plus the
     * SQLSTATE, never the driver message (it can echo data, host names, file paths).
     */
    public static function reason(\Throwable $e): string
    {
        $state = null;
        $code = null;
        for ($x = $e; $x !== null; $x = $x->getPrevious()) {
            if ($x instanceof \PDOException) {
                $s = $x->errorInfo[0] ?? null;
                if (is_string($s) && $s !== '' && $s !== '00000') {
                    $state = $s;
                } elseif (is_string($x->getCode()) && preg_match('/^[0-9A-Z]{5}$/', $x->getCode())) {
                    $state = $x->getCode();
                } elseif (preg_match('/SQLSTATE\[([0-9A-Z]{5})\]/', $x->getMessage(), $m)) {
                    $state = $m[1]; // only the code is taken from the message
                }
                $code = $x->errorInfo[1] ?? (is_int($x->getCode()) ? $x->getCode() : null);
                break;
            }
        }
        if ($state === null) {
            return 'Could not read the database (' . (new \ReflectionClass($e))->getShortName() . ')';
        }
        $what = match (true) {
            str_starts_with($state, '08'), in_array((int)$code, [2002, 2003, 2005, 2006, 2013], true) => 'Could not connect',
            str_starts_with($state, '28') => 'Login failed',
            $state === '3D000' => 'Database not found',
            $state === '42501' => 'Permission denied',
            default => 'Could not read the database',
        };

        return $what . ' (SQLSTATE ' . $state . ')';
    }

    /**
     * How the latest finished scan ended (overview `scan.last_status` and `scan.failed`):
     * 'done', 'partial' (done, some services could not be read), 'failed', or null (never).
     *
     * Scans that only concerned services deleted since (a single-service scan of a deleted
     * service none of whose failed services still exist, or a failed scan whose failed services
     * are all gone) say nothing about the instance any more: the outcome is that of the latest
     * scan before them that still does. A single-service scan of a deleted service that could not
     * read another service that still exists (an extra it picked up) keeps naming that service.
     *
     * unknown = true when the scan history could not be read (a database error): last_status is
     * then null because nothing could be checked, not because no scan ever ran.
     *
     * @return array{last_status:?string, failed:list<array{service_id:int,service:string,label:string,reason:string}>, unknown:bool}
     */
    public static function lastOutcome(): array
    {
        $none = ['last_status' => null, 'failed' => [], 'unknown' => false];
        try {
            $columns = ['id', 'service_id', 'status', 'error'];
            if (self::supported()) {
                $columns[] = self::FAILED_COLUMN;
            }
            if (self::scoped()) {
                $columns[] = self::SCOPE_COLUMN;
            }
            $rows = DB::table(Tables::SCAN)->whereIn('status', ['done', 'failed'])->orderByDesc('id')
                ->limit(self::OUTCOME_LOOKBACK)->get($columns);
        } catch (\Throwable $e) {
            return ['unknown' => true] + $none;
        }
        foreach ($rows as $row) {
            $serviceGone = !self::isFull($row) && ($row->service_id === null || Coverage::byId((int)$row->service_id) === null);
            $failed = self::failuresOf($row);
            $out = [];
            foreach ($failed as $f) {
                $info = $f['service_id'] !== null ? Coverage::byId($f['service_id']) : Coverage::byName($f['service']);
                if ($info === null) {
                    continue; // deleted since
                }
                $out[] = [
                    'service_id' => (int)$info['id'],
                    'service' => (string)$info['name'],
                    'label' => (string)($info['label'] ?: $info['name']),
                    'reason' => $f['reason'],
                ];
            }
            if ($serviceGone && $out === []) {
                continue; // one service, deleted since, and no service it failed on is left
            }
            if ($row->status === 'failed') {
                if ($failed !== [] && $out === []) {
                    continue; // every service it failed on is gone
                }
                return ['last_status' => 'failed', 'failed' => $out, 'unknown' => false];
            }

            return ['last_status' => $out !== [] ? 'partial' : 'done', 'failed' => $out, 'unknown' => false];
        }

        return $none;
    }

    /**
     * Per service: when it was last scanned successfully (unix seconds, null = never) and, when
     * a later scan could not read it, the reason (null otherwise).
     *
     * Last successful scan = its latest successful single-service scan, the latest finished scan
     * that recorded reading it (dm_scan.read_services: also the services a scan picked up as
     * extras), the latest scanned_at of its stored columns, or, for a service with no stored
     * columns (an empty database), the latest successful full scan that finished after the
     * service was created and did not fail it.
     *
     * unknown = true when the scan history could not be read (a database error): scanned_at and
     * scan_error are then null because nothing could be checked, not because it was never
     * scanned (Compliance says "Could not be checked").
     *
     * @param list<int> $ids service ids
     * @return array<int, array{scanned_at:?int, scan_error:?string, unknown:bool}>
     */
    public static function services(array $ids): array
    {
        $out = [];
        foreach ($ids as $id) {
            $out[(int)$id] = ['scanned_at' => null, 'scan_error' => null, 'unknown' => false];
        }
        if ($ids === []) {
            return $out;
        }
        $created = [];
        try {
            foreach (DB::table('service')->whereIn('id', $ids)->get(['id', 'created_date']) as $row) {
                $created[(int)$row->id] = Time::ts($row->created_date ?? null);
            }
        } catch (\Throwable $e) {
            // no created_date: any successful full scan counts for an empty database
        }
        try {
            $perService = [];
            foreach (DB::table(Tables::SCAN)
                         ->where('status', 'done')
                         ->whereIn('service_id', $ids)
                         ->groupBy('service_id')
                         ->get(['service_id', DB::raw('MAX(finished_at) as finished')]) as $row) {
                $perService[(int)$row->service_id] = Time::ts($row->finished);
            }
            if (self::tracked()) {
                // Every service a finished scan read, extras included (newest first).
                $wanted = array_fill_keys(array_keys($out), true);
                foreach (DB::table(Tables::SCAN)->where('status', 'done')->whereNotNull(self::READ_COLUMN)
                             ->orderByDesc('id')->limit(self::HISTORY_LIMIT)->get(['finished_at', self::READ_COLUMN]) as $row) {
                    $at = Time::ts($row->finished_at);
                    if ($at === null) {
                        continue;
                    }
                    foreach (self::decodeIds($row->{self::READ_COLUMN}) as $sid) {
                        if (isset($wanted[$sid])) {
                            $perService[$sid] = max($perService[$sid] ?? 0, $at);
                        }
                    }
                }
            }
            $columns = [];
            foreach (DB::table(Tables::COLUMN)
                         ->whereIn('service_id', $ids)
                         ->groupBy('service_id')
                         ->get(['service_id', DB::raw('MAX(scanned_at) as scanned'), DB::raw('COUNT(*) as n')]) as $row) {
                $columns[(int)$row->service_id] = ['scanned' => Time::ts($row->scanned), 'n' => (int)$row->n];
            }
            $select = ['id', 'service_id', 'status', 'finished_at', 'error'];
            if (self::supported()) {
                $select[] = self::FAILED_COLUMN;
            }
            // Full scans (all services), newest first; never a deleted service's own scans.
            $full = self::whereFull(DB::table(Tables::SCAN)->where('status', 'done'))
                ->orderByDesc('id')->limit(self::HISTORY_LIMIT)->get($select);
            // Scans that recorded failures, newest first.
            $failing = DB::table(Tables::SCAN)->whereIn('status', ['done', 'failed']);
            if (self::supported()) {
                $failing->where(function ($q) {
                    $q->whereNotNull(self::FAILED_COLUMN)->orWhere(function ($q) {
                        $q->where('status', 'failed')->whereNotNull('service_id');
                    });
                });
            } else {
                $failing->where('status', 'failed')->whereNotNull('service_id');
            }
            $failing = $failing->orderByDesc('id')->limit(self::HISTORY_LIMIT)->get($select);
        } catch (\Throwable $e) {
            foreach ($out as $id => $_) {
                $out[$id]['unknown'] = true;
            }
            return $out;
        }

        $fullScans = [];
        foreach ($full as $row) {
            $fullScans[] = ['at' => Time::ts($row->finished_at), 'failed' => array_column(self::failuresOf($row), 'service_id')];
        }
        $lastFail = [];
        foreach ($failing as $row) {
            $at = Time::ts($row->finished_at) ?? 0;
            foreach (self::failuresOf($row) as $f) {
                $sid = $f['service_id'];
                if ($sid !== null && isset($out[$sid]) && !isset($lastFail[$sid])) {
                    $lastFail[$sid] = ['at' => $at, 'reason' => $f['reason']];
                }
            }
        }

        foreach ($out as $id => $_) {
            $last = max($perService[$id] ?? 0, $columns[$id]['scanned'] ?? 0) ?: null;
            if ($last === null && ($columns[$id]['n'] ?? 0) === 0) {
                foreach ($fullScans as $scan) {
                    if ($scan['at'] === null || in_array($id, $scan['failed'], true)) {
                        continue;
                    }
                    if (($created[$id] ?? null) === null || $scan['at'] >= $created[$id]) {
                        $last = $scan['at'];
                    }
                    break;
                }
            }
            $error = null;
            if (isset($lastFail[$id]) && $lastFail[$id]['at'] > ($last ?? -1)) {
                $error = $lastFail[$id]['reason'] !== '' ? $lastFail[$id]['reason'] : 'Could not read the database';
            }
            $out[$id] = ['scanned_at' => $last, 'scan_error' => $error, 'unknown' => false];
        }

        return $out;
    }

    /**
     * Failed services of one dm_scan row; a failed single-service scan without a recorded list
     * (older rows, a scan that stopped) counts as a failure of that service with its error.
     *
     * @return list<array{service_id:int|null,service:string,label:string,reason:string}>
     */
    private static function failuresOf(object $row): array
    {
        $failed = self::decode($row->{self::FAILED_COLUMN} ?? null);
        if ($failed === [] && ($row->status ?? null) === 'failed' && ($row->service_id ?? null) !== null) {
            $info = Coverage::byId((int)$row->service_id);
            $failed[] = [
                'service_id' => (int)$row->service_id,
                'service' => (string)($info['name'] ?? ''),
                'label' => (string)(($info['label'] ?? '') ?: ($info['name'] ?? '')),
                'reason' => self::scrubbedError((string)($row->error ?? '')),
            ];
        }

        return $failed;
    }

    /** Stored scan errors are already value-free; keep them short. */
    private static function scrubbedError(string $error): string
    {
        $error = trim($error);

        return $error === '' ? 'The scan could not complete' : mb_substr($error, 0, 300);
    }
}

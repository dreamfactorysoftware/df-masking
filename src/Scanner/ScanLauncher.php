<?php

namespace DreamFactory\Core\Masking\Scanner;

use DreamFactory\Core\Masking\Support\Activity;
use DreamFactory\Core\Masking\Support\ScanHistory;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use DreamFactory\Core\Masking\Support\Time;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Symfony\Component\Process\PhpExecutableFinder;
use Symfony\Component\Process\Process;

/**
 * Starts scans in the background and reports their status.
 *
 * start() records a dm_scan row and spawns `php artisan df:masking scan --scan-id=N` detached
 * (nohup, stdio to /dev/null, reparented to init), so the scan survives the HTTP request that
 * asked for it. When processes cannot be spawned (proc_open disabled, no PHP CLI binary, no
 * artisan) it runs the scan synchronously instead. Starting while a scan runs is a no-op that
 * returns the running scan's id.
 */
final class ScanLauncher
{
    private const START_LOCK = 'df-masking:scan:start';
    /** Per service: unix time of the last throttled ("unknown columns") scan request run now. */
    private const AUTO_PREFIX = 'df-masking:scan:auto-at:';
    /** Default throttle window of startThrottled(), in seconds. */
    public const DEFAULT_THROTTLE_SECONDS = 60;
    /** Background scan requests: service name => {due, requested} (unix seconds). */
    private const WANTED_KEY = 'df-masking:scan:wanted';
    private const WANTED_LOCK = 'df-masking:scan:wanted-lock';
    private const WANTED_TTL = 604800;

    private function __construct()
    {
    }

    /**
     * @param ?string $service     one covered service name, or null for all
     * @param string  $triggeredBy who asked (activity/actor label)
     * @param bool    $sample      explicitly sample cost-bearing warehouses (Snowflake, ...) too
     * @return int dm_scan.id of the started (or already running) scan
     * @throws \InvalidArgumentException when $service is not an active covered service
     */
    public static function start(?string $service, string $triggeredBy, bool $sample = false): int
    {
        $serviceId = null;
        if ($service !== null && $service !== '') {
            $info = Services::covered($service)[0];
            [$serviceId, $service] = [$info['id'], $info['name']];
        } else {
            $service = null;
        }
        $create = static function () use ($serviceId, $triggeredBy): array {
            if (($running = ScanState::running()) !== null) {
                return [(int) $running->id, false];
            }
            return [ScanState::create($serviceId, $triggeredBy)->id, true];
        };
        [$id, $created] = self::locked($create);
        if (!$created) {
            return $id;
        }
        if (!self::spawn($id, $sample)) {
            Log::info("df-masking: running scan $id in-process (background processes are unavailable)");
            (new ScanRunner())->run($service, $id, null, $sample);
        }
        return $id;
    }

    /**
     * Background re-scan of one service on behalf of the system (service created or changed,
     * unknown columns seen by enforcement), never sampling warehouses. Allowed once scanning is
     * wanted at all (autoScansAllowed(): a scan has run, or the mode is not Off), so a database
     * added after a scan of empty databases is scanned on creation too.
     *
     * The request is recorded and run as soon as allowed: right away when no scan is running,
     * at the end of the running scan otherwise. With a throttle window ($seconds > 0, default
     * 60) a service gets at most one such scan per window: a request inside the window is
     * deferred to its end (and run by the first request after that, see tick()), never dropped.
     * $seconds = 0: no throttle (a service configuration change, which can rename every table).
     *
     * @return int|null the started or running scan id, or null when nothing started yet
     */
    public static function startThrottled(string $service, string $triggeredBy, ?int $seconds = null): ?int
    {
        try {
            if (!self::autoScansAllowed()) {
                return null;
            }
            $info = Services::covered($service)[0];
            $seconds ??= self::DEFAULT_THROTTLE_SECONDS;
            $now = self::clock();
            $due = $now;
            if ($seconds > 0) {
                $key = self::AUTO_PREFIX . strtolower($info['name']);
                $last = Cache::get($key);
                if (is_numeric($last) && (int) $last + $seconds > $now) {
                    $due = (int) $last + $seconds;
                } else {
                    Cache::put($key, $now, $seconds);
                }
            }
            self::want($info['name'], $due, $now);
            return self::tick($triggeredBy);
        } catch (\Throwable $e) {
            Log::debug("df-masking: background scan of '$service' not started: " . $e->getMessage());
            return null;
        }
    }

    /**
     * Background scans run once someone wants scanning: the first-scan marker is set, any scan
     * has finished (even one of empty databases), or the mode is not Off (Preview or On, or an
     * unreadable mode, which enforces as On). Before that nothing is scanned behind the
     * admin's back (the first scan picks Preview).
     */
    public static function autoScansAllowed(): bool
    {
        return Settings::has(Settings::FIRST_SCAN_AT) || Settings::mode() !== 'off' || ScanHistory::anyScanFinished();
    }

    /**
     * Runs due background scan requests: starts one when no scan is running (the scan takes the
     * other due requests at its end); with a scan running, that scan takes them. Cheap when
     * nothing is requested (one cache read). Called after every API request (ServiceProvider)
     * and by startThrottled().
     *
     * @return int|null the started or running scan id, or null
     */
    public static function tick(string $triggeredBy = Activity::SYSTEM): ?int
    {
        try {
            $wanted = self::wanted();
            if ($wanted === []) {
                return null;
            }
            $due = self::due($wanted, self::clock());
            if ($due === []) {
                return null;
            }
            if (($running = ScanState::running()) !== null) {
                return (int) $running->id;
            }
            foreach ($due as $name) {
                try {
                    $info = Services::covered($name)[0];
                } catch (\Throwable $e) {
                    self::forgetRequest($name, PHP_INT_MAX); // deleted, renamed or deactivated
                    continue;
                }
                return self::start($info['name'], $triggeredBy, false);
            }
            return null;
        } catch (\Throwable $e) {
            Log::debug('df-masking: background scan tick skipped: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Service names whose background scan is due now (requests recorded by startThrottled()),
     * sorted.
     *
     * @return list<string>
     */
    public static function dueRequests(): array
    {
        return self::due(self::wanted(), self::clock());
    }

    /**
     * A scan read $service's schema at $readAt: requests made up to then are satisfied (requests
     * made later stay, the change they report may postdate the read).
     */
    public static function forgetRequest(string $service, int $readAt): void
    {
        self::mutateWanted(static function (array $w) use ($service, $readAt): array {
            foreach ($w as $name => $entry) {
                if (strcasecmp((string) $name, $service) === 0 && (int) ($entry['requested'] ?? 0) <= $readAt) {
                    unset($w[$name]);
                }
            }
            return $w;
        });
    }

    /**
     * @return array{status:string, progress:int|null, finished_at:?string, columns:int, last_status:?string,
     *               failed:list<array{service_id:int,service:string,label:string,reason:string}>, unknown:bool}
     */
    public static function status(): array
    {
        try {
            $running = ScanState::running();
            $last = ScanState::lastDone();
            $columns = (int) DB::table(Tables::COLUMN)->count();
        } catch (\Throwable $e) {
            // The scan history could not be read: unknown, not "never scanned".
            return ['status' => 'idle', 'progress' => null, 'finished_at' => null, 'columns' => 0, 'last_status' => null, 'failed' => [], 'unknown' => true];
        }
        return [
            'status' => $running !== null ? 'running' : 'idle',
            'progress' => $running !== null ? (int) $running->progress : null,
            'finished_at' => $last !== null ? Time::iso($last->finished_at) : null,
            'columns' => $columns,
        ] + ScanHistory::lastOutcome();
    }

    // ------------------------------------------------------------------ background requests

    /** Current unix time (Carbon's clock: tests can freeze it). */
    public static function clock(): int
    {
        try {
            return now()->getTimestamp();
        } catch (\Throwable $e) {
            return time();
        }
    }

    /** @return array<string, array{due:int, requested:int}> */
    private static function wanted(): array
    {
        try {
            $w = Cache::get(self::WANTED_KEY);
        } catch (\Throwable $e) {
            return [];
        }
        return is_array($w) ? $w : [];
    }

    /** @return list<string> */
    private static function due(array $wanted, int $now): array
    {
        $out = [];
        foreach ($wanted as $name => $entry) {
            if ((int) ($entry['due'] ?? 0) <= $now) {
                $out[] = (string) $name;
            }
        }
        sort($out, SORT_STRING);
        return $out;
    }

    private static function want(string $service, int $due, int $now): void
    {
        self::mutateWanted(static function (array $w) use ($service, $due, $now): array {
            $entry = $w[$service] ?? null;
            $w[$service] = [
                // The earliest due time wins (an unthrottled request is not delayed by a throttled one).
                'due' => $entry === null ? $due : min((int) $entry['due'], $due),
                'requested' => $now,
            ];
            return $w;
        });
    }

    private static function mutateWanted(callable $change): void
    {
        $work = static function () use ($change): void {
            $w = $change(self::wanted());
            if ($w === []) {
                Cache::forget(self::WANTED_KEY);
            } else {
                Cache::put(self::WANTED_KEY, $w, self::WANTED_TTL);
            }
        };
        try {
            if (Cache::getStore() instanceof \Illuminate\Contracts\Cache\LockProvider) {
                Cache::lock(self::WANTED_LOCK, 5)->block(3, $work);
                return;
            }
        } catch (\Illuminate\Contracts\Cache\LockTimeoutException $e) {
            // fall through: best effort without the lock
        } catch (\Throwable $e) {
            // no lock support
        }
        $work();
    }

    /** Runs $fn under a short cache lock when the store supports locks (atomic check-and-create). */
    private static function locked(callable $fn): array
    {
        try {
            $store = Cache::getStore();
            if ($store instanceof \Illuminate\Contracts\Cache\LockProvider) {
                return Cache::lock(self::START_LOCK, 10)->block(5, $fn);
            }
        } catch (\Illuminate\Contracts\Cache\LockTimeoutException $e) {
            // fall through: run without the lock rather than refuse to scan
        } catch (\Throwable $e) {
            // no lock support
        }
        return $fn();
    }

    /** Spawns the detached scan process. False when that is not possible here. */
    private static function spawn(int $scanId, bool $sample): bool
    {
        if (!self::canSpawn()) {
            return false;
        }
        $php = self::phpBinary();
        try {
            $artisan = base_path('artisan');
        } catch (\Throwable $e) {
            return false; // no application base path (embedded use): run in-process
        }
        if ($php === null || !is_file($artisan)) {
            return false;
        }
        // The service is not passed: the runner reads it from the dm_scan row (one source of truth).
        $args = [$php, $artisan, 'df:masking', 'scan', '--scan-id=' . $scanId, '--no-interaction'];
        if ($sample) {
            $args[] = '--sample';
        }
        $command = implode(' ', array_map('escapeshellarg', $args));
        try {
            $process = Process::fromShellCommandline('nohup ' . $command . ' </dev/null >/dev/null 2>&1 & echo $!', base_path(), null, null, 15);
            $process->run();
            $pid = (int) trim($process->getOutput());
            if (!$process->isSuccessful() || $pid <= 0) {
                Log::warning('df-masking: could not start the background scan process (exit ' . $process->getExitCode() . ')');
                return false;
            }
            (new ScanState($scanId))->setPid($pid);
            return true;
        } catch (\Throwable $e) {
            Log::warning('df-masking: could not start the background scan process: ' . $e->getMessage());
            return false;
        }
    }

    private static function canSpawn(): bool
    {
        if (!function_exists('proc_open') || !class_exists(Process::class)) {
            return false;
        }
        $disabled = array_map('trim', explode(',', (string) ini_get('disable_functions')));
        return !in_array('proc_open', $disabled, true);
    }

    /** The PHP CLI binary (never php-fpm). */
    private static function phpBinary(): ?string
    {
        $configured = config('df-masking.scan.php_binary');
        if (is_string($configured) && $configured !== '' && is_executable($configured)) {
            return $configured;
        }
        if (PHP_SAPI === 'cli' && PHP_BINARY !== '' && is_executable(PHP_BINARY)) {
            return PHP_BINARY;
        }
        $found = (new PhpExecutableFinder())->find(false);
        if (is_string($found) && $found !== '' && !str_contains(basename($found), 'fpm')) {
            return $found;
        }
        foreach (['/usr/bin/php', '/usr/local/bin/php'] as $candidate) {
            if (is_executable($candidate)) {
                return $candidate;
            }
        }
        return null;
    }
}

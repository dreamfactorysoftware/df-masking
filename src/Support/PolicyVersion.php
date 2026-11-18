<?php

namespace DreamFactory\Core\Masking\Support;

use Illuminate\Support\Facades\Cache;

/**
 * One counter in the application cache that every df-masking cache entry (settings, per-table
 * policy, caller grants, ...) embeds in its key. bump() invalidates all of them in one step.
 *
 * - The value is seeded from the clock (milliseconds) whenever the key is missing, so a cache
 *   flush never restarts the counter at a value an older surviving entry might still carry.
 * - current() is memoised for at most one second per process: php-fpm requests start with an
 *   empty memo anyway; long-running console processes (the scanner) pick up changes quickly.
 * - Never throws: with a broken cache store, current() returns 0 and callers fall back to
 *   uncached reads.
 */
final class PolicyVersion
{
    public const CACHE_KEY = 'df-masking:policy-version';

    private const MEMO_SECONDS = 1.0;

    private static ?int $memo = null;
    private static float $memoAt = 0.0;

    private function __construct()
    {
    }

    public static function current(): int
    {
        $now = microtime(true);
        if (self::$memo !== null && ($now - self::$memoAt) < self::MEMO_SECONDS) {
            return self::$memo;
        }

        try {
            $value = Cache::get(self::CACHE_KEY);
            if (!is_numeric($value)) {
                $seed = self::seed();
                // add() only writes when the key is still missing; re-read to converge on
                // whichever process won the race.
                Cache::add(self::CACHE_KEY, $seed, self::ttl());
                $value = Cache::get(self::CACHE_KEY, $seed);
            }
            $value = (int)$value;
        } catch (\Throwable $e) {
            $value = 0;
        }

        self::$memo = $value;
        self::$memoAt = $now;

        return $value;
    }

    public static function bump(): void
    {
        try {
            $next = null;
            if (is_numeric(Cache::get(self::CACHE_KEY))) {
                $next = Cache::increment(self::CACHE_KEY);
            }
            if (!is_numeric($next) || (int)$next <= 0) {
                $next = self::seed();
                Cache::put(self::CACHE_KEY, $next, self::ttl());
            }
            self::$memo = (int)$next;
            self::$memoAt = microtime(true);
        } catch (\Throwable $e) {
            self::forget();
        }
    }

    /** Drops the per-process memo (tests, long-running processes). */
    public static function forget(): void
    {
        self::$memo = null;
        self::$memoAt = 0.0;
    }

    /** Clock-based seed: strictly larger than any counter seeded earlier on this instance. */
    private static function seed(): int
    {
        return (int)floor(microtime(true) * 1000);
    }

    /** Thirty days; entries keyed by an older version simply expire. */
    private static function ttl(): int
    {
        return 30 * 24 * 3600;
    }
}

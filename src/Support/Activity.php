<?php

namespace DreamFactory\Core\Masking\Support;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * The masking activity log (dm_activity), shown on the admin UI's Activity tab and exported by
 * the Compliance baseline evidence report.
 *
 * Text style follows the UI ("Masking set to Preview", "Kept masked as Username",
 * "Blocked an attempt to change access"). Callers MUST NOT put data values into text, target or
 * meta: only column/table/service names, class ids, counts and people's display names.
 *
 * log() never throws: a failure to record activity is reported to the application log and the
 * request carries on.
 */
final class Activity
{
    public const KINDS = ['mode', 'decision', 'access', 'scan', 'blocked', 'rule', 'baseline', 'preview'];

    /** Actor label for automatic changes (scans, first-scan mode switch, expiry). */
    public const SYSTEM = 'System';

    /** Actor label for changes made with `php artisan df:masking`. */
    public const CONSOLE = 'Command line';

    private const THROTTLE_PREFIX = 'df-masking:throttle:';

    /** One in N writes also prunes rows older than the retention window. */
    private const PRUNE_LOTTERY = 200;

    private function __construct()
    {
    }

    /**
     * @param string      $kind   one of KINDS
     * @param string      $text   human sentence, max 500 chars (longer is truncated)
     * @param string|null $target "service.table.column", a pattern, a baseline id, ...
     * @param array       $meta   small JSON-able context; never values
     * @param string|null $actor  null => Caller::current()->label()
     */
    public static function log(string $kind, string $text, ?string $target = null, array $meta = [], ?string $actor = null): void
    {
        try {
            if (!in_array($kind, self::KINDS, true)) {
                throw new \InvalidArgumentException("Unknown activity kind '$kind'.");
            }
            $actorId = null;
            if ($actor === null) {
                $caller = Caller::current();
                $actor = $caller->label();
                $actorId = $caller->userId();
            } elseif ($actor !== self::SYSTEM && $actor !== self::CONSOLE) {
                $actorId = Caller::current()->userId();
            }

            DB::table(Tables::ACTIVITY)->insert([
                'created_at' => now(),
                'actor' => self::clip($actor, 255),
                'actor_id' => $actorId,
                'kind' => $kind,
                'text' => self::clip($text, 500),
                'target' => $target === null ? null : self::clip($target, 255),
                'meta' => empty($meta) ? null : json_encode($meta, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR),
            ]);

            if (random_int(1, self::PRUNE_LOTTERY) === 1) {
                self::prune();
            }
        } catch (\Throwable $e) {
            try {
                Log::warning('df-masking: could not record activity (' . $kind . '): ' . $e->getMessage());
            } catch (\Throwable $ignored) {
            }
        }
    }

    /**
     * Logs at most once per $seconds for the same $key (e.g. one "would mask" row per caller and
     * table per hour). The key is hashed; it may contain names but never values.
     */
    public static function logThrottled(string $key, int $seconds, string $kind, string $text, ?string $target = null, array $meta = []): void
    {
        try {
            if (!Cache::add(self::THROTTLE_PREFIX . sha1($key), 1, max(1, $seconds))) {
                return;
            }
        } catch (\Throwable $e) {
            // No cache: log anyway rather than lose the event.
        }
        self::log($kind, $text, $target, $meta);
    }

    /** Deletes rows older than config df-masking.activity_retention_days (default 400). */
    public static function prune(): int
    {
        try {
            $days = (int)config('df-masking.activity_retention_days', 400);
            if ($days <= 0) {
                return 0;
            }

            return DB::table(Tables::ACTIVITY)->where('created_at', '<', now()->subDays($days))->delete();
        } catch (\Throwable $e) {
            return 0;
        }
    }

    private static function clip(string $value, int $max): string
    {
        return mb_strlen($value) > $max ? mb_substr($value, 0, $max - 1) . '…' : $value;
    }
}

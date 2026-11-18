<?php

namespace DreamFactory\Core\Masking\Baselines;

use Illuminate\Support\Carbon;

/**
 * Timestamp helpers for the baselines code: database values (written by Laravel in the
 * application timezone) to unix seconds, unix seconds to the ISO 8601 UTC strings the API
 * returns ("2026-10-29T14:03:00Z"), and short human durations for change texts. Same timezone
 * rules as Support\Time.
 */
final class Time
{
    private function __construct()
    {
    }

    /** Unix seconds for a database timestamp value; null for null/empty/unparseable. */
    public static function ts(mixed $value): ?int
    {
        if ($value === null || $value === '') {
            return null;
        }
        if ($value instanceof \DateTimeInterface) {
            return $value->getTimestamp();
        }
        try {
            return Carbon::parse((string)$value, self::tz())->getTimestamp();
        } catch (\Throwable $e) {
            return null;
        }
    }

    public static function iso(?int $ts): ?string
    {
        return $ts === null ? null : gmdate('Y-m-d\TH:i:s\Z', $ts);
    }

    /** A Carbon instance in the application timezone, for writing timestamps. */
    public static function carbon(int $ts): Carbon
    {
        return Carbon::createFromTimestamp($ts, self::tz());
    }

    /** The application timezone rows are written in (UTC on stock installs). */
    private static function tz(): string
    {
        try {
            $tz = config('app.timezone');
        } catch (\Throwable $e) {
            $tz = null;
        }

        return is_string($tz) && $tz !== '' ? $tz : 'UTC';
    }

    /** "8 hours", "1 hour", "45 minutes", "3 days" for a duration in seconds. */
    public static function duration(int $seconds): string
    {
        $seconds = max(0, $seconds);
        if ($seconds >= 2 * 86400) {
            $n = (int)round($seconds / 86400);

            return $n . ' days';
        }
        if ($seconds >= 2 * 3600) {
            return (int)round($seconds / 3600) . ' hours';
        }
        if ($seconds >= 3600) {
            return '1 hour';
        }
        $minutes = max(1, (int)round($seconds / 60));

        return $minutes . ($minutes === 1 ? ' minute' : ' minutes');
    }

    public static function hours(int $hours): string
    {
        return $hours === 1 ? '1 hour' : $hours . ' hours';
    }
}

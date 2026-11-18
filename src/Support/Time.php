<?php

namespace DreamFactory\Core\Masking\Support;

use Carbon\Carbon;

/**
 * Timestamp helpers. Rows are written with Laravel's now() (application timezone, UTC on every
 * stock DreamFactory install) and read back in that same timezone; the wire format is
 * ISO 8601 in UTC ("2026-10-29T14:03:00Z"), which the admin UI parses with Date.parse().
 */
final class Time
{
    private function __construct()
    {
    }

    /** Database timestamp (string or DateTimeInterface) -> unix seconds; null stays null. */
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

    /** Database timestamp or unix seconds -> "2026-10-29T14:03:00Z"; null stays null. */
    public static function iso(mixed $value): ?string
    {
        $ts = is_int($value) ? $value : self::ts($value);

        return $ts === null ? null : gmdate('Y-m-d\TH:i:s\Z', $ts);
    }

    /** Unix seconds -> a Carbon in the application timezone, for database writes. */
    public static function fromTs(?int $ts): ?Carbon
    {
        return $ts === null ? null : Carbon::createFromTimestamp($ts, self::tz());
    }

    private static function tz(): string
    {
        try {
            $tz = config('app.timezone');
        } catch (\Throwable $e) {
            $tz = null;
        }

        return is_string($tz) && $tz !== '' ? $tz : 'UTC';
    }
}

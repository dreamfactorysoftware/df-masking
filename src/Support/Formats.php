<?php

namespace DreamFactory\Core\Masking\Support;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

/**
 * Current mask format per class: the admin's choice from dm_mask_format, else the catalog
 * default. A stored format that is not (or no longer) allowed for its class falls back to the
 * default. Cached under PolicyVersion.
 */
final class Formats
{
    /** @var array<string,string>|null class => stored format */
    private static ?array $memo = null;
    private static ?int $memoVersion = null;

    private function __construct()
    {
    }

    /** The format applied to $classId now; null for an unknown class. */
    public static function current(string $classId): ?string
    {
        if (!Catalog::has($classId)) {
            return null;
        }
        $stored = self::stored()[$classId] ?? null;
        if ($stored !== null && in_array($stored, Catalog::formatsAllowed($classId), true)) {
            return $stored;
        }

        return Catalog::defaultFormat($classId);
    }

    /** @return array<string,string> every class => current format, in catalog order */
    public static function all(): array
    {
        $out = [];
        foreach (Catalog::ids() as $id) {
            $out[$id] = (string)self::current($id);
        }

        return $out;
    }

    public static function forget(): void
    {
        self::$memo = null;
        self::$memoVersion = null;
    }

    /** @return array<string,string> */
    private static function stored(): array
    {
        $version = PolicyVersion::current();
        if (self::$memo !== null && self::$memoVersion === $version) {
            return self::$memo;
        }
        $key = 'df-masking:formats:v' . $version;
        $stored = null;
        try {
            $cached = $version > 0 ? Cache::get($key) : null;
            $stored = is_array($cached) ? $cached : null;
        } catch (\Throwable $e) {
        }
        if ($stored === null) {
            $stored = [];
            try {
                foreach (DB::table(Tables::MASK_FORMAT)->get(['class', 'format']) as $row) {
                    $stored[(string)$row->class] = (string)$row->format;
                }
                if ($version > 0) {
                    Cache::put($key, $stored, 3600);
                }
            } catch (\Throwable $e) {
                $stored = [];
            }
        }
        self::$memo = $stored;
        self::$memoVersion = $version;

        return $stored;
    }
}

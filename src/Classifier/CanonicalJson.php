<?php
declare(strict_types=1);

namespace DreamFactory\Core\Masking\Classifier;

/** Canonical JSON: object keys sorted recursively, lists kept in order, no float noise. */
final class CanonicalJson
{
    public static function canon(mixed $x): mixed
    {
        if (!is_array($x)) {
            return $x;
        }
        if (array_is_list($x)) {
            return array_map([self::class, 'canon'], $x);
        }
        ksort($x, SORT_STRING);
        foreach ($x as $k => $v) {
            $x[$k] = self::canon($v);
        }
        return $x;
    }

    public static function encode(mixed $x, bool $pretty = false): string
    {
        $flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR;
        if ($pretty) {
            $flags |= JSON_PRETTY_PRINT;
        }
        // Empty assoc arrays must stay objects.
        return json_encode(self::objects(self::canon($x)), $flags);
    }

    private static function objects(mixed $x): mixed
    {
        if (!is_array($x)) {
            return $x;
        }
        if ($x === []) {
            return [];
        }
        $isList = array_is_list($x);
        $out = array_map([self::class, 'objects'], $x);
        return $isList ? $out : (object) $out;
    }
}

<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Enforcement;

/**
 * Values of the X-DreamFactory-Masked-Fields and X-DreamFactory-Masking-Rewrites response
 * headers: lists of field names (Masked-Fields) or "kind:field" items (Rewrites), joined
 * with ", ".
 *
 *  - Names are percent-encoded (RFC 3986, UTF-8 octets) outside visible ASCII, and so are "%"
 *    and "," (the list delimiter), so every value is plain ASCII and splits unambiguously on ","
 *    (then trim); decodeURIComponent() / rawurldecode() restore each item.
 *  - Each value is capped at MAX_BYTES: items that do not fit are replaced by ", +N more"
 *    (proxies such as nginx reject responses whose headers exceed a 4-8 KB buffer).
 */
final class Headers
{
    public const MAX_BYTES = 1024;
    public const SEPARATOR = ', ';

    private function __construct()
    {
    }

    public static function encodeName(string $name): string
    {
        $out = preg_replace_callback(
            '/[^\x21-\x24\x26-\x2B\x2D-\x7E]/',
            static fn (array $m): string => sprintf('%%%02X', ord($m[0])),
            $name
        );

        return $out ?? rawurlencode($name);
    }

    /** "filter:ssn" -> "filter:" + encoded column name. */
    public static function encodeItem(string $item): string
    {
        $at = strpos($item, ':');
        if ($at === false) {
            return self::encodeName($item);
        }

        return substr($item, 0, $at + 1) . self::encodeName(substr($item, $at + 1));
    }

    /**
     * @param list<string> $items already encoded items
     */
    public static function capList(array $items, int $max = self::MAX_BYTES): string
    {
        $items = array_values($items);
        $n = count($items);
        $full = implode(self::SEPARATOR, $items);
        if (strlen($full) <= $max) {
            return $full;
        }
        $sep = strlen(self::SEPARATOR);
        $kept = 0;
        $length = 0; // length of the first $kept items joined
        for ($k = 1; $k <= $n; $k++) {
            $next = $length + ($k > 1 ? $sep : 0) + strlen($items[$k - 1]);
            $rest = $n - $k;
            $suffix = $rest > 0 ? strlen(self::SEPARATOR . '+' . $rest . ' more') : 0;
            if ($next + $suffix > $max) {
                break;
            }
            $kept = $k;
            $length = $next;
        }
        $rest = $n - $kept;
        $more = '+' . $rest . ' more';

        return $kept === 0 ? $more : implode(self::SEPARATOR, array_slice($items, 0, $kept)) . self::SEPARATOR . $more;
    }

    /** @param list<string> $names raw field names */
    public static function names(array $names): string
    {
        return self::capList(array_map([self::class, 'encodeName'], array_values(array_unique($names))));
    }

    /** @param list<string> $items raw "kind:field" items */
    public static function items(array $items): string
    {
        return self::capList(array_map([self::class, 'encodeItem'], array_values(array_unique($items))));
    }
}

<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Enforcement\Filter;

use DreamFactory\Core\Masking\Enforcement\SqlIdentifiers;

/**
 * Normalizes a field token taken from a request parameter (filter, having, order, group,
 * fields) before it is matched against the columns a caller does not see in clear, so request
 * guards never depend on DreamFactory rejecting unusual spellings:
 *
 *  - "ssn", "SSN", "`ssn`", "\"ssn\"", "[ssn]", "customers.ssn", "`crm`.`customers`.`ssn`"
 *    all name the column ssn (bare);
 *  - anything else ("substr(ssn,1,3)", "lower(email)", "ssn || ''") is an expression; it is
 *    matched by the masked columns it mentions.
 */
final class FieldToken
{
    private const IDENT = '(?:[A-Za-z_\x80-\xFF][A-Za-z0-9_$#@\x80-\xFF]*|`[^`]+`|"[^"]+"|\[[^\]]+\])';

    private function __construct()
    {
    }

    /** Lower-cased column name when $token is a (quoted, qualified) identifier, else null. */
    public static function bare(string $token): ?string
    {
        $t = trim($token);
        if ($t === '' || preg_match('/^(?:' . self::IDENT . '\s*\.\s*)*(' . self::IDENT . ')$/', $t, $m) !== 1) {
            return null;
        }
        $last = $m[1];
        $first = $last[0];
        if ($first === '`' || $first === '"' || $first === '[') {
            $last = substr($last, 1, -1);
        }

        return strtolower($last);
    }

    /**
     * The first key of $hidden that $token refers to: as a bare identifier, or mentioned
     * anywhere inside an expression. Null when it refers to none.
     *
     * @param array<string,mixed> $hidden lower-cased field names (keys)
     */
    public static function hiddenKey(string $token, array $hidden): ?string
    {
        if ($hidden === []) {
            return null;
        }
        $lower = strtolower(trim($token));
        if (isset($hidden[$lower])) {
            return $lower; // as DreamFactory names the field (names may contain spaces: "Home Phone")
        }
        $bare = self::bare($token);
        if ($bare !== null) {
            return isset($hidden[$bare]) ? $bare : null;
        }
        $scan = SqlIdentifiers::scan($token, $hidden);
        foreach ($scan['refs'] as $ref) {
            if (isset($hidden[$ref])) {
                return $ref;
            }
        }
        // Names a tokenizer cannot see as one word ("home phone", "e-mail"), and unterminated
        // quotes: a plain search for the name between non-word characters.
        foreach ($hidden as $key => $_) {
            $key = (string)$key;
            if ($key === '' || ($scan['ok'] && preg_match('/^[A-Za-z_\x80-\xFF][A-Za-z0-9_$#@\x80-\xFF]*$/', $key) === 1)) {
                continue;
            }
            if (preg_match('/(?<![A-Za-z0-9_$#@\x80-\xFF])' . preg_quote($key, '/') . '(?![A-Za-z0-9_$#@\x80-\xFF])/', $lower) === 1) {
                return $key;
            }
        }

        return null;
    }

    /** True when $token is not a plain (quoted, qualified) identifier. */
    public static function isExpression(string $token): bool
    {
        return self::bare($token) === null;
    }
}

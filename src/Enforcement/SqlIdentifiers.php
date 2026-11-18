<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Enforcement;

/**
 * Finds the column references in a small SQL fragment: a DreamFactory db_function expression
 * ("CONCAT(first_name, ' ', email)") or a field token from a request parameter
 * ("customers.ssn", "`ssn`", "[ssn]", "substr(ssn,1,3)").
 *
 * Deliberately conservative, for masking decisions:
 *  - string literals ('...', with '' and backslash escapes; E'...', N'...') never reference anything;
 *  - a word followed by "(" is a function name, a word after "::" a type, SQL keywords are skipped;
 *  - a qualified name ("t.col", "`s`.`t`.`col`", "[dbo].[t].[col]") references its last part;
 *  - "..." is an identifier in standard SQL but a string in MySQL's default mode: it counts as a
 *    reference only when it names a known column;
 *  - SELECT anywhere means a subquery, and any other word that is not a known column is an
 *    unknown identifier: both make the result "unresolved" (callers fail closed).
 */
final class SqlIdentifiers
{
    /** Keywords, type names and date-part words that are never column references. */
    private const KEYWORDS = [
        'and', 'or', 'not', 'xor', 'null', 'is', 'in', 'like', 'ilike', 'between', 'case', 'when', 'then', 'else', 'end',
        'as', 'distinct', 'all', 'any', 'some', 'true', 'false', 'unknown', 'collate', 'escape', 'interval', 'from', 'for',
        'using', 'both', 'leading', 'trailing', 'at', 'time', 'zone', 'local', 'nulls', 'first', 'last', 'asc', 'desc',
        'over', 'partition', 'by', 'order', 'rows', 'range', 'unbounded', 'preceding', 'following', 'current', 'row',
        'filter', 'within', 'group', 'separator', 'div', 'mod', 'regexp', 'rlike', 'similar', 'to', 'binary', 'unsigned',
        'signed', 'char', 'character', 'varchar', 'varchar2', 'nvarchar', 'nvarchar2', 'nchar', 'text', 'ntext', 'int',
        'integer', 'bigint', 'smallint', 'tinyint', 'mediumint', 'decimal', 'numeric', 'number', 'float', 'real', 'double',
        'precision', 'date', 'datetime', 'datetime2', 'smalldatetime', 'datetimeoffset', 'timestamp', 'timestamptz',
        'timetz', 'boolean', 'bool', 'bit', 'money', 'json', 'jsonb', 'uuid', 'varying', 'with', 'without', 'array', 'bytea',
        'blob', 'clob', 'uniqueidentifier', 'xml', 'max', 'year', 'month', 'day', 'hour', 'minute', 'second', 'microsecond',
        'millisecond', 'milliseconds', 'microseconds', 'week', 'quarter', 'epoch', 'dow', 'doy', 'isodow', 'isoyear',
        'century', 'decade', 'millennium', 'timezone_hour', 'timezone_minute', 'year_month', 'day_hour', 'day_minute',
        'day_second', 'hour_minute', 'hour_second', 'minute_second', 'dayofyear', 'weekday', 'current_date',
        'current_time', 'current_timestamp', 'localtime', 'localtimestamp', 'current_user', 'session_user', 'user',
        'sysdate', 'systimestamp', 'unicode', 'utf8', 'utf8mb4', 'ascii', 'latin1',
    ];

    private function __construct()
    {
    }

    /**
     * @return array{refs:list<string>,unknown:list<string>,subquery:bool,ok:bool}
     *         refs: lower-cased names that may be columns (bare words and quoted identifiers,
     *         last part of a qualified name; known columns only for "..."), unknown: words that
     *         are neither keywords nor (when $columns is given) known columns, ok: false when
     *         the text could not be tokenized (unterminated literal or identifier)
     * @param array<string,mixed>|null $columns lower-cased known column names (keys), or null
     *                                         when every bare word may be a column
     */
    public static function scan(string $sql, ?array $columns = null): array
    {
        $out = ['refs' => [], 'unknown' => [], 'subquery' => false, 'ok' => true];
        $len = strlen($sql);
        $i = 0;
        $chain = [];        // parts of the current qualified name: [[text, quoted, dq], ...]
        $afterCast = false; // the previous token was "::"
        $flush = static function (bool $isCall) use (&$chain, &$out, &$afterCast, $columns): void {
            if ($chain === []) {
                return;
            }
            [$text, $quoted, $dq] = $chain[count($chain) - 1];
            $qualified = count($chain) > 1;
            $chain = [];
            $lower = strtolower($text);
            if ($afterCast) {
                $afterCast = false; // a type name

                return;
            }
            if (!$quoted && $isCall) {
                if ($lower === 'select') {
                    $out['subquery'] = true;
                }

                return; // function name (also schema-qualified: pg_catalog.lower(x))
            }
            if (!$quoted && $lower === 'select') {
                $out['subquery'] = true;

                return;
            }
            if ($columns !== null && isset($columns[$lower])) {
                // A known column wins over a keyword of the same name ("user", "date", "text"):
                // at worst something is masked or dropped that did not need to be.
                $out['refs'][] = $lower;

                return;
            }
            if (!$quoted && !$qualified && in_array($lower, self::KEYWORDS, true)) {
                return;
            }
            if ($dq && ($columns === null || !isset($columns[$lower]))) {
                return; // "...": a string literal in MySQL's default mode, or no known column
            }
            if ($columns !== null && !isset($columns[$lower])) {
                $out['unknown'][] = $lower;

                return;
            }
            $out['refs'][] = $lower;
        };

        while ($i < $len) {
            $c = $sql[$i];
            if (ctype_space($c)) {
                $i++;
                continue;
            }
            // String literal, optionally prefixed (E'..', N'..', X'..', B'..', U&'..').
            if ($c === "'") {
                $end = self::endOfLiteral($sql, $i);
                if ($end === null) {
                    $out['ok'] = false;

                    return self::finish($out);
                }
                $flush(false);
                $i = $end;
                continue;
            }
            if ($c === '`' || $c === '"' || $c === '[') {
                $close = $c === '[' ? ']' : $c;
                $end = strpos($sql, $close, $i + 1);
                if ($end === false) {
                    $out['ok'] = false;

                    return self::finish($out);
                }
                $inner = substr($sql, $i + 1, $end - $i - 1);
                $i = $end + 1;
                if ($c === '[' && ($inner === '' || ctype_digit(trim($inner)))) {
                    continue; // an array subscript, not an identifier
                }
                if ($chain !== [] && !self::endsWithDot($sql, $i - strlen($inner) - 2)) {
                    $flush(false);
                }
                $chain[] = [$inner, true, $c === '"'];
                continue;
            }
            if ($c === '.' && $chain !== []) {
                $i++; // qualifier separator: the next identifier continues the chain
                continue;
            }
            if ($c === ':' && ($sql[$i + 1] ?? '') === ':') {
                $flush(false);
                $afterCast = true;
                $i += 2;
                continue;
            }
            if (self::isWordStart($c)) {
                $start = $i;
                while ($i < $len && self::isWordChar($sql[$i])) {
                    $i++;
                }
                $word = substr($sql, $start, $i - $start);
                // A literal prefix: E'...', N'...', X'...', B'...', U&'...'
                if (($sql[$i] ?? '') === "'" && in_array(strtolower($word), ['e', 'n', 'x', 'b', 'u'], true)) {
                    continue;
                }
                if ($chain !== [] && !self::endsWithDot($sql, $start)) {
                    $flush(false);
                }
                $chain[] = [$word, false, false];
                continue;
            }
            if (ctype_digit($c)) {
                $flush(false);
                while ($i < $len && (ctype_alnum($sql[$i]) || $sql[$i] === '.')) {
                    $i++;
                }
                continue;
            }
            if ($c === '@') {
                // SQL Server / MySQL variables (@x, @@ROWCOUNT): unknown to masking.
                $flush(false);
                $start = $i;
                while ($i < $len && ($sql[$i] === '@' || self::isWordChar($sql[$i]))) {
                    $i++;
                }
                $out['unknown'][] = strtolower(substr($sql, $start, $i - $start));
                continue;
            }
            if ($c === '(') {
                $flush(true);
                $i++;
                continue;
            }
            $flush(false);
            $i++;
        }
        $flush(false);

        return self::finish($out);
    }

    /** True when the text before $pos (skipping spaces) ends with a qualifier dot. */
    private static function endsWithDot(string $sql, int $pos): bool
    {
        $j = $pos - 1;
        while ($j >= 0 && ctype_space($sql[$j])) {
            $j--;
        }

        return $j >= 0 && $sql[$j] === '.';
    }

    /** Index just past the closing quote of the literal starting at $start, or null. */
    private static function endOfLiteral(string $sql, int $start): ?int
    {
        $len = strlen($sql);
        $i = $start + 1;
        while ($i < $len) {
            $c = $sql[$i];
            if ($c === '\\') {
                $i += 2;
                continue;
            }
            if ($c === "'") {
                if (($sql[$i + 1] ?? '') === "'") {
                    $i += 2;
                    continue;
                }

                return $i + 1;
            }
            $i++;
        }

        return null;
    }

    private static function isWordStart(string $c): bool
    {
        return ctype_alpha($c) || $c === '_' || ord($c) >= 0x80;
    }

    private static function isWordChar(string $c): bool
    {
        return ctype_alnum($c) || $c === '_' || $c === '$' || $c === '#' || ord($c) >= 0x80;
    }

    private static function finish(array $out): array
    {
        $out['refs'] = array_values(array_unique($out['refs']));
        $out['unknown'] = array_values(array_unique($out['unknown']));

        return $out;
    }
}

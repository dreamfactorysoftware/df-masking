<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Enforcement;

/**
 * Removes data values from error responses of covered services (status >= 400, masking on),
 * so a failed write or a constraint violation never echoes a value of a masked column.
 *
 * Database errors that can carry row data are reduced to a fixed, language-independent text
 * that keeps only the SQLSTATE and the operation ("Database error during insert (SQLSTATE
 * 23505). Data Masking removed the details."): data exceptions and integrity violations
 * (SQLSTATE classes 22 and 23, plus 27, 38, 39, 44 and PL/pgSQL's P0, which echo rows or
 * arbitrary text) and any message carrying row data (PostgreSQL's secondary DETAIL/CONTEXT lines
 * in any server language, "key (...)=(...)"). Database servers translate their messages
 * (lc_messages, SET LANGUAGE), so this never depends on English wording.
 *
 * Everything else (DreamFactory's own validation messages, other database errors) keeps its
 * text, with values removed. In DreamFactory's own messages (no SQLSTATE, no SQL) a quoted field
 * name the caller sent ("Invalid field '1' in order by clause.", "Invalid or unparsable field in
 * filter request: 'nosuchcol'") stays: it is the caller's own request, not row data.
 * Database text never keeps it. DreamFactory error bodies are {"error": {"code", "message",
 * "context"}}; the message usually carries the database driver's text and Laravel's
 * "(Connection: x, SQL: ...)" suffix with the bound values substituted in. Replaced with "•••":
 *  - the SQL of Laravel's QueryException suffix ("SQL: insert into ... values (...)")
 *  - PostgreSQL  DETAIL: Key (email)=(jane@x.io) already exists / Failing row contains (...)
 *  - MySQL       Duplicate entry 'jane@x.io' for key ...
 *  - SQL Server  The duplicate key value is (jane@x.io).
 *  - every other quoted literal ('...', "...", &quot;...&quot;), except the names of the
 *    table, its columns and the service (kept so the message still says what failed)
 * Batch errors: context.resource holds the records that did succeed; they are masked like any
 * response records (callback), and every string in context.error is scrubbed.
 */
final class ErrorScrubber
{
    public const REPLACEMENT = "\u{2022}\u{2022}\u{2022}";

    /** Fixed text for reduced database errors: operation, then SQLSTATE. */
    public const REDUCED = 'Database error during %s (SQLSTATE %s). Data Masking removed the details.';
    public const REDUCED_NO_STATE = 'Database error during %s. Data Masking removed the details.';

    /** SQLSTATE classes whose messages can carry row data or submitted values. */
    private const REDUCE_CLASSES = ['22', '23', '27', '38', '39', '44', 'P0'];

    private const MAX_DEPTH = 8;

    private function __construct()
    {
    }

    /**
     * Words DreamFactory itself quotes in its own messages ("wrapped in a 'resource' tag",
     * "Invalid field requested: 'id'"); kept so its guidance stays readable. They are request
     * vocabulary, not data.
     */
    private const DF_VOCABULARY = [
        'resource', 'resources', 'record', 'records', 'id', 'ids', 'id_field', 'id_type', 'filter', 'fields',
        'related', 'order', 'group', 'having', 'limit', 'offset', 'params', 'continue', 'rollback',
        'count_only', 'include_count', 'include_schema', 'as_list', 'file', 'schema', 'table', 'field',
        'expression', 'value', 'name', 'type',
    ];

    /**
     * @param list<string>  $keep        identifiers that may stay quoted (lower-cased compare)
     * @param \Closure|null $maskRecords fn(array $records): array, for records inside a batch error
     * @param list<string>  $callerIdentifiers field names the caller sent (order, group, fields,
     *                      filter fields, id_field): kept quoted in DreamFactory's own messages only
     */
    public static function scrub(mixed $content, array $keep = [], ?\Closure $maskRecords = null, string $wrapper = 'resource', string $operation = 'request', array $callerIdentifiers = []): mixed
    {
        $keep = array_merge($keep, self::DF_VOCABULARY, [$wrapper]);
        $prev = [self::$operation, self::$callerIdentifiers];
        self::$operation = $operation;
        self::$callerIdentifiers = $callerIdentifiers;
        try {
            return self::scrubContent($content, $keep, $maskRecords, $wrapper);
        } finally {
            [self::$operation, self::$callerIdentifiers] = $prev;
        }
    }

    /** The operation named in reduced messages (set for the duration of scrub()). */
    private static string $operation = 'request';

    /** @var list<string> caller field names for DreamFactory's own messages (set for the duration of scrub()) */
    private static array $callerIdentifiers = [];

    private static function scrubContent(mixed $content, array $keep, ?\Closure $maskRecords, string $wrapper): mixed
    {
        if (is_string($content)) {
            return self::scrubText($content, $keep);
        }
        if (!is_array($content)) {
            return $content;
        }
        if (!isset($content['error']) || !is_array($content['error'])) {
            return self::walk($content, $keep, 0);
        }

        $error = $content['error'];
        $entries = null;
        if (isset($error['context']) && is_array($error['context']) && isset($error['context'][$wrapper])
            && is_array($error['context'][$wrapper])) {
            // Batch errors: context.<wrapper> lists, per submitted record, either the record that
            // succeeded (masked like any response record) or that record's error (scrubbed).
            $entries = [];
            foreach ($error['context'][$wrapper] as $i => $entry) {
                if (is_array($entry) && !self::isErrorEntry($entry) && $maskRecords !== null) {
                    $entries[$i] = $maskRecords([$entry])[0] ?? $entry;
                } elseif (is_array($entry)) {
                    $entries[$i] = self::walk($entry, $keep, 0);
                } elseif (is_string($entry)) {
                    $entries[$i] = self::scrubText($entry, $keep);
                } else {
                    $entries[$i] = $entry;
                }
            }
            unset($error['context'][$wrapper]);
        }
        $error = self::walk($error, $keep, 0);
        if ($entries !== null) {
            $error['context'][$wrapper] = $entries;
        }
        $content['error'] = $error;

        return $content;
    }

    private static function isErrorEntry(array $entry): bool
    {
        return array_key_exists('message', $entry) && (array_key_exists('code', $entry) || array_key_exists('status_code', $entry));
    }

    /** Replaces a whole message that could not be checked (fail closed). */
    public const UNCHECKED = 'The request failed. Data Masking removed the error details.';

    /**
     * @param string|null       $sqlState          SQLSTATE known from the error entry's "code" (the
     *                                             message may not repeat it)
     * @param list<string>|null $callerIdentifiers field names the caller sent (null: those given
     *                                             to scrub()), kept in DreamFactory's own messages
     */
    public static function scrubText(string $text, array $keep = [], ?string $sqlState = null, ?array $callerIdentifiers = null): string
    {
        if ($text === '') {
            return $text;
        }
        $reduced = self::reduced($text, $sqlState);
        if ($reduced !== null) {
            return $reduced;
        }
        $caller = [];
        if (self::isDreamFactoryOwn($text, $sqlState)) {
            foreach ($callerIdentifiers ?? self::$callerIdentifiers as $name) {
                $name = strtolower(trim((string)$name));
                if ($name !== '' && $name !== self::REPLACEMENT && strlen($name) <= 256) {
                    $caller[] = $name;
                }
            }
        }
        try {
            return self::scrubOrThrow($text, array_merge($keep, $caller));
        } catch (\RuntimeException $e) {
            return self::UNCHECKED;
        }
    }

    /**
     * A message DreamFactory wrote itself (validation), not database text: no SQLSTATE, no SQL,
     * no Laravel connection suffix, no SQLSTATE-shaped error code.
     */
    private static function isDreamFactoryOwn(string $text, ?string $sqlState): bool
    {
        if ($sqlState !== null && preg_match('/^[0-9A-Z]{5}$/', $sqlState) === 1) {
            return false;
        }

        return preg_match('/SQLSTATE|\bSQL:|\(Connection:|\bORA-\d|\[Microsoft\]|\[ODBC|\bPDOException\b/i', $text) !== 1;
    }

    /**
     * The fixed text for a database error that may carry row data, or null when the message
     * may keep its (scrubbed) text.
     */
    public static function reduced(string $text, ?string $sqlState = null): ?string
    {
        $state = null;
        if (preg_match('/SQLSTATE\[([0-9A-Z]{5})\]/', $text, $m) === 1) {
            $state = $m[1];
        } elseif ($sqlState !== null && preg_match('/^[0-9A-Z]{5}$/', $sqlState) === 1) {
            $state = $sqlState; // the entry's code ("23514", "23P01"); DreamFactory's own codes are 3-4 digits
        }
        $reduce = $state !== null && in_array(substr($state, 0, 2), self::REDUCE_CLASSES, true);
        if (!$reduce) {
            $reduce = self::carriesRowData($text);
        }
        if (!$reduce) {
            return null;
        }

        return $state !== null ? sprintf(self::REDUCED, self::$operation, $state) : sprintf(self::REDUCED_NO_STATE, self::$operation);
    }

    /**
     * Language-independent signs of row data: "key (...)=(...)" (any case), or a secondary
     * "LABEL:" line after the first (PostgreSQL DETAIL / CONTEXT / HINT, translated or not:
     * DETAIL, DÉTAIL, DETALLE, KONTEXT, ПОДРОБНОСТИ, 詳細, ...).
     */
    private static function carriesRowData(string $text): bool
    {
        if (preg_match('/\)\s*=\s*\(/', $text) === 1) {
            return true;
        }
        $lines = preg_split('/\R/', $text) ?: [];
        array_shift($lines);
        foreach ($lines as $line) {
            $line = ltrim($line);
            if ($line === '' || stripos($line, 'SQLSTATE[') === 0) {
                continue;
            }
            // DreamFactory html-encodes messages: "D&Eacute;TAIL&nbsp;: ..." is a label too.
            $letter = '(?:[\p{L}\p{N}]|&[A-Za-z]{2,8};|&#[0-9]{2,6};)';
            $space = '(?:[\s\x{00A0}\x{202F}]|&nbsp;)';
            $hit = preg_match('/^' . $letter . '(?:' . $letter . '| ){0,40}?' . $space . '?(?::|\x{FF1A})' . $space . '/u', $line);
            if ($hit === false) {
                // Not valid UTF-8: check the plain byte shape, else assume it may carry data.
                $hit = preg_match('/^[A-Za-z0-9\x80-\xFF&#;][A-Za-z0-9\x80-\xFF&#; ]{0,60}?\s?:\s/', $line);
                if ($hit === false) {
                    return true;
                }
            }
            if ($hit === 1) {
                return true;
            }
        }

        return false;
    }

    private static function scrubOrThrow(string $text, array $keep): string
    {
        $r = self::REPLACEMENT;
        $keepSet = [];
        foreach ($keep as $k) {
            $keepSet[strtolower((string)$k)] = true;
        }

        // Byte-oriented patterns (no /u): a message that is not valid UTF-8 is still scrubbed.
        $out = $text;
        // Laravel QueryException suffix: everything after "SQL: " carries bound values.
        $out = self::replace('/(\(Connection:[^\n]*?,\s*SQL:\s).*$/s', '${1}' . $r . ')', $out);
        $out = self::replace('/(\bSQL:\s)(?:select|insert|update|delete|merge|with|call|exec)\b.*$/is', '${1}' . $r, $out);
        // PostgreSQL
        $out = self::replace('/(\bKey \((?:[^()]|\([^()]*\))*\)=\().*?(\)\s+(?:already exists|is not present|is still referenced|conflicts with)\b)/is', '${1}' . $r . '${2}', $out);
        $out = self::replace('/(\bKey \((?:[^()]|\([^()]*\))*\)=\()(?!\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\))[^\n]*/i', '${1}' . $r . ')', $out);
        // Any "(...)=(...)" or ": (...)" / "= (...)" value list, in any language.
        $out = self::replace('/(\)\s*=\s*\()(?!\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\))[^)\n]*/', '${1}' . $r, $out);
        $out = self::replace('/([=:]\s*\()(?!\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\))[^)\n]*(\))/', '${1}' . $r . '${2}', $out);
        $out = self::replace('/(\bFailing row contains \()[^\n]*/i', '${1}' . $r . ').', $out);
        // MySQL
        $out = self::replace("/(\\bDuplicate entry ').*?(' for key\\b)/s", '${1}' . $r . '${2}', $out);
        // SQL Server
        $out = self::replace('/(\bduplicate key value is \()[^\n]*/i', '${1}' . $r . ').', $out);

        // Remaining quoted literals (DreamFactory html-encodes double quotes in messages).
        $quoted = static function (array $m) use ($keepSet, $r): string {
            $inner = $m[2];
            // French typography pads quotes: « staff », &laquo;&nbsp;staff&nbsp;&raquo;.
            $bare = strtolower(trim(str_replace(['&nbsp;', "\u{00A0}", "\u{202F}"], ' ', $inner)));
            if ($inner === '' || $inner === $r || $bare === $r || isset($keepSet[$bare])) {
                return $m[0];
            }

            return $m[1] . $r . $m[3];
        };
        $out = self::replaceCallback('/(&quot;)(.*?)(&quot;)/s', $quoted, $out);
        $out = self::replaceCallback('/(&#0?39;)(.*?)(&#0?39;)/s', $quoted, $out);
        // Typographic quotes of translated messages, raw and html-encoded: « », » «, „ “, “ ”, ‘ ’, ‹ ›, 「 」.
        $open = '&(?:laquo|raquo|bdquo|ldquo|rdquo|lsquo|rsquo|sbquo|lsaquo|rsaquo);|\xC2\xAB|\xC2\xBB|\xE2\x80[\x9A\x9C\x9D\x98\x99\xB9\xBA]|\xE3\x80\x8C';
        $out = self::replaceCallback('/(' . $open . ')(.*?)(' . $open . '|\xE3\x80\x8D)/s', $quoted, $out);
        // A quote right after a letter is an apostrophe ("d'insérer"), not an opening quote.
        $out = self::replaceCallback("/(?<![A-Za-z0-9\\x80-\\xFF])(')((?:[^'\\n]|'')*)(')/", $quoted, $out);

        return self::replaceCallback('/(")([^"\n]*)(")/', $quoted, $out);
    }

    private static function replace(string $pattern, string $replacement, string $subject): string
    {
        $out = preg_replace($pattern, $replacement, $subject);
        if ($out === null) {
            throw new \RuntimeException('pattern failed');
        }

        return $out;
    }

    private static function replaceCallback(string $pattern, \Closure $callback, string $subject): string
    {
        $out = preg_replace_callback($pattern, $callback, $subject);
        if ($out === null) {
            throw new \RuntimeException('pattern failed');
        }

        return $out;
    }

    private static function walk(array $node, array $keep, int $depth): array
    {
        if ($depth > self::MAX_DEPTH) {
            return [];
        }
        $state = isset($node['code']) && is_string($node['code']) ? $node['code'] : null;
        foreach ($node as $key => $value) {
            if ($key === 'code' || $key === 'status_code') {
                continue;
            }
            if (is_string($value)) {
                $node[$key] = self::scrubText($value, $keep, $key === 'message' ? $state : null);
            } elseif (is_array($value)) {
                $node[$key] = self::walk($value, $keep, $depth + 1);
            }
        }

        return $node;
    }
}

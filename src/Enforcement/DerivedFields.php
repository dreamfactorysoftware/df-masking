<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Enforcement;

use DreamFactory\Core\Masking\Support\Catalog;

/**
 * Fields whose value DreamFactory computes with a SELECT db_function (virtual fields, and real
 * columns with a SELECT override) inherit the masking of the columns their expression reads:
 *
 *  - the strictest tier among the masked (or review) columns it references wins, with that
 *    column's class; its format is kept when the expression reads a single masked column, or
 *    when the format hides the whole value (redact, token, null); a partial format (last4,
 *    initial, year, span) over several masked columns would reveal pieces of the others, so it
 *    becomes redact;
 *  - an expression with a subquery or an identifier that is not a column of the table cannot be
 *    checked: review (masked until an admin decides; redact);
 *  - an expression that reads only clear columns adds nothing (the field keeps its own verdict);
 *  - COUNT(...) on its own returns a number of rows, never a value: adds nothing.
 *
 * Used inline by enforcement (Policy::effective), when an unknown field is classified
 * (InlineClassifier) and by the scanner (applyToScan), so dm_column, the admin UI and
 * enforcement agree. Evidence line: "Built from: email, ssn".
 */
final class DerivedFields
{
    public const UNCHECKED_TEXT = 'Built from an expression that could not be checked';

    /** Strictest first. */
    private const TIER_RANK = [Catalog::TIER_RESTRICTED => 0, Catalog::TIER_FREE_TEXT => 1, Catalog::TIER_IDENTITY => 2, Catalog::TIER_QUASI => 3];
    private const WHOLE_VALUE_FORMATS = ['redact', 'token', 'null'];
    private const COUNT_ONLY = '/^\s*count\s*\((?:[^()]|\([^()]*\))*\)\s*$/i';

    private function __construct()
    {
    }

    /**
     * @param string               $expression SELECT db_function
     * @param array<string,string> $columns    lower-cased real column name => real name (DB columns of the table)
     * @return array{refs:list<string>,unresolved:bool} refs = real names of referenced columns
     */
    public static function references(string $expression, array $columns): array
    {
        if (trim($expression) === '' || preg_match(self::COUNT_ONLY, $expression) === 1) {
            return ['refs' => [], 'unresolved' => false];
        }
        $scan = SqlIdentifiers::scan($expression, $columns);
        $refs = [];
        foreach ($scan['refs'] as $lower) {
            $refs[] = $columns[$lower] ?? $lower;
        }

        return ['refs' => $refs, 'unresolved' => !$scan['ok'] || $scan['subquery'] || $scan['unknown'] !== []];
    }

    /**
     * The policy entry a computed field inherits, or null when it inherits nothing.
     *
     * @param array<string,string> $columns lower-cased real column name => real name
     * @param array<string,array{class:?string,tier:string,format:string,verdict:string}> $masked
     *        real column name => entry (masked and review columns)
     * @return array{entry:array{class:?string,tier:string,format:string,verdict:string},from:list<string>,unresolved:bool}|null
     */
    public static function derive(string $expression, array $columns, array $masked): ?array
    {
        $r = self::references($expression, $columns);
        $byLower = [];
        foreach ($masked as $column => $entry) {
            $byLower[strtolower((string)$column)] = $entry;
        }
        $hits = [];
        foreach ($r['refs'] as $ref) {
            $entry = $byLower[strtolower($ref)] ?? null;
            if ($entry !== null) {
                $hits[$ref] = $entry;
            }
        }
        if ($r['unresolved']) {
            return [
                'entry' => Policy::entry(null, null, 'review'),
                'from' => array_keys($hits),
                'unresolved' => true,
            ];
        }
        if ($hits === []) {
            return null;
        }

        return ['entry' => self::strictest($hits), 'from' => array_keys($hits), 'unresolved' => false];
    }

    /**
     * Scanner results for computed columns, inherited from the other columns' results in the
     * same table. Keeps a column's own result when it is at least as strict.
     *
     * @param array<string,array> $columns ScanRunner column name => [..., result => [verdict, class, tier, score, evidence, ...]]
     * @param list<array>         $plan    SchemaReader plan columns (name, select_fn, virtual, ...)
     * @return array<string,array>
     */
    public static function applyToScan(array $columns, array $plan): array
    {
        $real = [];
        $computed = [];
        foreach ($plan as $p) {
            $name = (string)($p['name'] ?? '');
            if ($name === '') {
                continue;
            }
            if (empty($p['virtual'])) {
                $real[strtolower($name)] = $name;
            }
            if (is_string($p['select_fn'] ?? null) && trim($p['select_fn']) !== '') {
                $computed[$name] = $p['select_fn'];
            }
        }
        if ($computed === []) {
            return $columns;
        }
        $masked = [];
        foreach ($columns as $name => $c) {
            $res = $c['result'] ?? null;
            if (!is_array($res) || isset($computed[$name]) || !in_array($res['verdict'] ?? null, ['masked', 'review'], true)) {
                continue;
            }
            $masked[$name] = [
                'class' => $res['class'] ?? null,
                'tier' => $res['tier'] ?? Catalog::TIER_RESTRICTED,
                'format' => 'redact',
                'verdict' => (string)$res['verdict'],
                'score' => (int)($res['score'] ?? 0),
            ];
        }
        foreach ($computed as $name => $expression) {
            if (!isset($columns[$name]['result']) || !is_array($columns[$name]['result'])) {
                continue;
            }
            $derived = self::derive($expression, $real, $masked);
            if ($derived === null) {
                continue;
            }
            $old = $columns[$name]['result'];
            $entry = $derived['entry'];
            if (!self::stricter($entry, $old)) {
                continue;
            }
            $score = $derived['unresolved'] ? 40 : 0;
            foreach ($derived['from'] as $from) {
                $score = max($score, (int)($masked[$from]['score'] ?? 0));
            }
            $score = max($score, $entry['verdict'] === 'masked' ? 70 : 40);
            $line = $derived['unresolved'] && $derived['from'] === []
                ? self::UNCHECKED_TEXT
                : self::evidenceText($derived['from'], $derived['unresolved']);
            $evidence = is_array($old['evidence'] ?? null) ? $old['evidence'] : [];
            $evidence['total'] = $score;
            $evidence['lines'] = array_merge(
                [['points' => $score, 'kind' => 'context', 'text' => $line]],
                array_values(array_filter((array)($evidence['lines'] ?? []), 'is_array'))
            );
            $columns[$name]['result'] = array_merge($old, [
                'verdict' => $entry['verdict'],
                'class' => $entry['class'],
                'tier' => $entry['class'] !== null ? $entry['tier'] : null,
                'score' => $score,
                'evidence' => $evidence,
            ]);
        }

        return $columns;
    }

    /** "Built from: email, ssn" (column names only, never values). */
    public static function evidenceText(array $from, bool $unresolved = false): string
    {
        if ($from === []) {
            return self::UNCHECKED_TEXT;
        }

        return 'Built from: ' . implode(', ', $from) . ($unresolved ? ' (and parts that could not be checked)' : '');
    }

    /**
     * The evidence line for a stored derived verdict the scanner keeps after its expression
     * changed or was removed (automatic rescans never remove masking): "Was built from: ssn", so
     * an admin sees why a plain column is still masked as National ID. Null when the stored
     * evidence (dm_column.evidence, JSON or decoded) does not come from an expression.
     */
    public static function wasBuiltFrom(mixed $evidence): ?string
    {
        $decoded = is_string($evidence) ? json_decode($evidence, true) : $evidence;
        $lines = is_array($decoded) && is_array($decoded['lines'] ?? null) ? $decoded['lines'] : [];
        foreach ($lines as $line) {
            $text = is_array($line) && is_string($line['text'] ?? null) ? $line['text'] : '';
            if (str_starts_with($text, 'Was built from')) {
                return $text; // kept again by a later rescan
            }
            if (str_starts_with($text, 'Built from: ')) {
                return 'Was built from: ' . substr($text, strlen('Built from: '));
            }
            if ($text === self::UNCHECKED_TEXT) {
                return 'Was built from an expression that could not be checked';
            }
        }

        return null;
    }

    /**
     * The strictest of several entries (a computed field reading several masked columns).
     *
     * @param array<string,array{class:?string,tier:string,format:string,verdict:string}> $entries
     * @return array{class:?string,tier:string,format:string,verdict:string}
     */
    public static function strictest(array $entries): array
    {
        $best = null;
        $anyMasked = false;
        foreach ($entries as $entry) {
            $anyMasked = $anyMasked || ($entry['verdict'] ?? '') === 'masked';
            if ($best === null || self::rank($entry) < self::rank($best)) {
                $best = $entry;
            }
        }
        $out = [
            'class' => $best['class'] ?? null,
            'tier' => $best['tier'] ?? Catalog::TIER_RESTRICTED,
            'format' => (string)($best['format'] ?? 'redact'),
            'verdict' => $anyMasked ? 'masked' : 'review',
        ];
        if (count($entries) > 1 && !in_array($out['format'], self::WHOLE_VALUE_FORMATS, true)) {
            $out['format'] = 'redact';
        }

        return $out;
    }

    /** True when entry $a masks at least as strictly as $b (a policy entry or a scan result). */
    public static function stricter(array $a, ?array $b): bool
    {
        if ($b === null || !in_array($b['verdict'] ?? 'clear', ['masked', 'review'], true)) {
            return true;
        }
        $ra = self::rank($a);
        $rb = self::rank($b);
        if ($ra !== $rb) {
            return $ra < $rb;
        }

        return ($a['verdict'] ?? '') === 'masked' || ($b['verdict'] ?? '') !== 'masked';
    }

    /** Tier rank; a masked entry without a class counts as restricted (Policy::entry fails closed). */
    private static function rank(array $entry): int
    {
        $tier = ($entry['class'] ?? null) === null ? Catalog::TIER_RESTRICTED : (string)($entry['tier'] ?? Catalog::TIER_RESTRICTED);

        return self::TIER_RANK[$tier] ?? 0;
    }
}

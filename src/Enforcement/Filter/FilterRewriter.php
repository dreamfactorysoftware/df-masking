<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Enforcement\Filter;

use DreamFactory\Core\Masking\Support\Catalog;

/**
 * Applies the request-side matrix to a DreamFactory filter,
 * for columns the caller does not see in clear:
 *
 * | tier                  | = != IN (<=25) | LIKE, CONTAINS, STARTS/ENDS WITH, < > <= >=, ALL | IS [NOT] NULL |
 * | identity, quasi       | allowed        | unknown                                          | allowed       |
 * | restricted, free_text | unknown        | unknown                                          | allowed       |
 *
 * IN lists longer than 25 values on a masked column, functions or expressions over a masked
 * column, and comparisons DreamFactory cannot split that mention one are unknown too.
 *
 * Reads: a comparison the caller may not evaluate is UNKNOWN, as SQL treats NULL,
 * and a row is returned only when the whole filter is TRUE under three-valued logic. The filter
 * DreamFactory receives is T(filter), built from:
 *
 *   T(unknown) = FALSE   T(A AND B) = T(A) AND T(B)   T(A OR B) = T(A) OR T(B)   T(NOT A) = F(A)
 *   F(unknown) = FALSE   F(A AND B) = F(A) OR F(B)    F(A OR B) = F(A) AND F(B)  F(NOT A) = T(A)
 *   F(clear c) = NOT c, written as the inverted comparison ("a != 1", "a >= 1", "a NOT IN (..)",
 *                "a NOT LIKE ..", "a IS NOT NULL"): identical in SQL's three-valued logic, and
 *                portable (DreamFactory only understands NOT at the very start of a filter)
 *   XOR and NOR are expanded the same way; constants are folded.
 *
 * So "ssn = 'x'" matches no rows, "(state = 'IL') AND (ssn = 'x')" matches no rows,
 * "(state = 'IL') OR (ssn = 'x')" matches the IL rows, "NOT (ssn = 'x')" matches no rows. The
 * masked literal never reaches DreamFactory and the result never depends on it.
 * When the whole filter folds to FALSE, DreamFactory gets a valid always-false filter on a real
 * column ("(id IS NULL) AND (id IS NOT NULL)"), so the response shape, counts, related records
 * and formats stay DreamFactory's own. A filter that cannot be parsed with certainty, but
 * mentions a masked column, matches no rows the same way. Parts of a filter that touch no
 * unknown comparison keep their comparisons (and any NOT, XOR or NOR) exactly as written.
 *
 * Writes (PUT/PATCH/DELETE with a filter): nothing is rewritten (that could hit the wrong rows);
 * any unknown comparison is a violation and the request is refused.
 *
 * Field tokens are normalized before matching (FieldToken): "customers.ssn", "`ssn`", "[ssn]"
 * and "\"ssn\"" are the column ssn; a function or expression over a masked column
 * ("substr(ssn,1,3) = '1'") never passes, whatever its operator; a comparison DreamFactory
 * cannot split (no operator) that mentions a masked column is treated the same way. So safety
 * never depends on DreamFactory rejecting an unusual spelling.
 *
 * Fast path: a filter whose text does not contain the name of any masked column cannot reference
 * one (DreamFactory needs the field name to build the WHERE clause) and is returned untouched,
 * without parsing. A filter that is not changed is always returned byte-for-byte as sent.
 */
final class FilterRewriter
{
    public const MAX_IN_VALUES = 25;

    public const DROP_ALL = '*';

    /** Upper bound on the size of a rewritten filter (XOR expansion doubles it); beyond it: no rows. */
    public const MAX_NODES = 400;

    private const EQUALITY_OPS = ['=', 'EQ', '!=', '<>', 'NE'];
    private const LIST_OPS = ['IN', 'NOT IN'];
    private const NULL_OPS = ['IS NULL', 'IS NOT NULL'];

    /** Comparison => the comparison that is TRUE exactly when it is FALSE (NULL stays NULL). */
    private const INVERSE = [
        '=' => '!=', '!=' => '=', '<>' => '=', 'EQ' => 'NE', 'NE' => 'EQ',
        '>' => '<=', '<=' => '>', '<' => '>=', '>=' => '<',
        'GT' => 'LTE', 'LTE' => 'GT', 'LT' => 'GTE', 'GTE' => 'LT',
        'IN' => 'NOT IN', 'NOT IN' => 'IN', 'IS NULL' => 'IS NOT NULL', 'IS NOT NULL' => 'IS NULL',
    ];

    /** Operators DreamFactory negates with "field NOT op value". */
    private const NEGATABLE = ['LIKE', 'CONTAINS', 'STARTS WITH', 'ENDS WITH'];

    /**
     * @param array<string,array{name:string,tier:string}> $hidden lower-cased field name (as the
     *        client writes it: DreamFactory alias or column name) => display name + tier, for
     *        columns the caller does not see in clear
     * @param list<string> $falseFields DreamFactory field names of real columns (no db_function)
     *        for the always-false filter, best first; the first hidden field when none fits
     */
    public function __construct(private readonly array $hidden, private readonly array $falseFields = [])
    {
    }

    /**
     * @return array{filter:?string,dropped:list<string>,changed:bool,uncertain:bool}
     *         filter = what DreamFactory gets (null = no filter); dropped = display names of
     *         masked columns whose comparisons were unknown ('*' when the filter could not be
     *         parsed); header item "filter:<name>" = "conditions on <name> matched no rows"
     */
    public function forRead(string $filter): array
    {
        $unchanged = ['filter' => $filter, 'dropped' => [], 'changed' => false, 'uncertain' => false];
        if (trim($filter) === '' || !$this->mentionsHidden($filter)) {
            return $unchanged;
        }
        $tree = FilterParser::parse($filter);
        if ($tree === null) {
            return ['filter' => $this->falseFilter(), 'dropped' => [self::DROP_ALL], 'changed' => true, 'uncertain' => true];
        }
        $unknown = [];
        $this->collectViolations($tree, $unknown);
        if ($unknown === []) {
            return $unchanged;
        }
        try {
            $result = $this->t($this->annotate($tree));
        } catch (\OverflowException $e) {
            $result = false; // too large to expand: no rows (never wider)
        }

        return [
            'filter' => match (true) {
                $result === false => $this->falseFilter(),
                $result === true => null,
                default => self::serialize($result),
            },
            'dropped' => array_values(array_unique($unknown)),
            'changed' => true,
            'uncertain' => false,
        ];
    }

    /**
     * A filter DreamFactory accepts on every SQL database and that matches no row:
     * "(f IS NULL) AND (f IS NOT NULL)" on a real column (IS [NOT] NULL is always allowed).
     */
    public function falseFilter(): string
    {
        $candidates = array_merge($this->falseFields, array_keys($this->hidden));
        foreach ($candidates as $field) {
            $field = trim((string)$field);
            if ($field === '' || strpbrk($field, "()'\"") !== false) {
                continue;
            }
            $null = FilterParser::splitComparison($field . ' IS NULL');
            $notNull = FilterParser::splitComparison($field . ' IS NOT NULL');
            if ($null !== null && $notNull !== null && $null['op'] === 'IS NULL' && $notNull['op'] === 'IS NOT NULL'
                && $null['field'] === $field && $notNull['field'] === $field && !$null['negate'] && !$notNull['negate']) {
                return '(' . $field . ' IS NULL) AND (' . $field . ' IS NOT NULL)';
            }
        }
        $field = (string)(array_key_first($this->hidden) ?? 'id');

        return '(' . $field . ' IS NULL) AND (' . $field . ' IS NOT NULL)';
    }

    /**
     * @return array{ok:bool,violations:list<string>,uncertain:bool}
     */
    public function forWrite(string $filter): array
    {
        if (trim($filter) === '' || !$this->mentionsHidden($filter)) {
            return ['ok' => true, 'violations' => [], 'uncertain' => false];
        }
        $tree = FilterParser::parse($filter);
        if ($tree === null) {
            return ['ok' => false, 'violations' => [], 'uncertain' => true];
        }
        $violations = [];
        $this->collectViolations($tree, $violations);
        $violations = array_values(array_unique($violations));

        return ['ok' => $violations === [], 'violations' => $violations, 'uncertain' => false];
    }

    /** True when there is any column to guard. */
    public function guardsAnything(): bool
    {
        return $this->hidden !== [];
    }

    /** Does a comparison on this (lower-cased) field with this operator survive? */
    public function allows(?string $field, ?string $op, int $count): bool
    {
        if ($field === null || $op === null) {
            return true; // see allowsTerm() for terms DreamFactory cannot split
        }
        $bare = isset($this->hidden[$field]) ? $field : FieldToken::bare($field);
        if ($bare === null) {
            // A function or expression over a masked column is never a plain comparison.
            return FieldToken::hiddenKey($field, $this->hidden) === null;
        }
        if (!isset($this->hidden[$bare])) {
            return true;
        }
        if (in_array($op, self::NULL_OPS, true)) {
            return true;
        }
        $tier = $this->hidden[$bare]['tier'];
        $exactAllowed = $tier === Catalog::TIER_IDENTITY || $tier === Catalog::TIER_QUASI;
        if (in_array($op, self::EQUALITY_OPS, true)) {
            return $exactAllowed;
        }
        if (in_array($op, self::LIST_OPS, true)) {
            return $exactAllowed && $count <= self::MAX_IN_VALUES;
        }

        return false; // ranges, LIKE family, ALL
    }

    /** allows() for a parsed term, including terms DreamFactory finds no operator in. */
    public function allowsTerm(array $node): bool
    {
        if ($node['field'] === null || $node['op'] === null) {
            return FieldToken::hiddenKey((string)$node['raw'], $this->hidden) === null;
        }

        return $this->allows($node['field'], $node['op'], (int)$node['count']);
    }

    /** Display name of the masked column a term touches (null when none). */
    private function hiddenName(array $node): ?string
    {
        $text = $node['field'] ?? null;
        $key = $text === null ? FieldToken::hiddenKey((string)$node['raw'], $this->hidden) : FieldToken::hiddenKey((string)$text, $this->hidden);

        return $key === null ? null : (string)$this->hidden[$key]['name'];
    }

    /** True when the filter text contains the name of any hidden column (case-insensitive). */
    public function mentionsHidden(string $text): bool
    {
        $lower = strtolower($text);
        foreach ($this->hidden as $field => $_) {
            if ($field !== '' && str_contains($lower, (string)$field)) {
                return true;
            }
        }

        return false;
    }

    // ------------------------------------------------------------------ three-valued rewrite

    /**
     * Copies the tree with two keys per node: 'u' (the subtree holds an unknown comparison) and
     * 'n' (its size in nodes, for the expansion budget).
     */
    private function annotate(array $node): array
    {
        if ($node['t'] === 'term') {
            return $node + ['u' => !$this->allowsTerm($node), 'n' => 1];
        }
        $u = false;
        $n = 1;
        foreach ($node['c'] as $i => $child) {
            $node['c'][$i] = $this->annotate($child);
            $u = $u || $node['c'][$i]['u'];
            $n += $node['c'][$i]['n'];
        }

        return ['u' => $u, 'n' => $n] + $node;
    }

    /** T(node): TRUE exactly for the rows where node is TRUE. */
    private function t(array $node): array|bool
    {
        if (!$node['u']) {
            return $node; // nothing unknown below: exactly as the client wrote it
        }
        switch ($node['t']) {
            case 'term':
                return false;
            case 'and':
                return $this->conj(array_map(fn (array $c) => $this->t($c), $node['c']));
            case 'or':
                return in_array('NOR', $node['ops'], true)
                    ? $this->chain($node)[0]
                    : $this->disj(array_map(fn (array $c) => $this->t($c), $node['c']));
            case 'xor':
                return $this->xorChain($node)[0];
            case 'not':
                return $this->f($node['c'][0]);
        }

        return false;
    }

    /** F(node): TRUE exactly for the rows where node is FALSE. */
    private function f(array $node): array|bool
    {
        switch ($node['t']) {
            case 'term':
                return $node['u'] ? false : $this->negateTerm($node);
            case 'and':
                return $this->disj(array_map(fn (array $c) => $this->f($c), $node['c']));
            case 'or':
                return in_array('NOR', $node['ops'], true)
                    ? $this->chain($node)[1]
                    : $this->conj(array_map(fn (array $c) => $this->f($c), $node['c']));
            case 'xor':
                return $this->xorChain($node)[1];
            case 'not':
                return $this->t($node['c'][0]);
        }

        return false;
    }

    /**
     * [T, F] of a group with NOR, left to right ("A OR B NOR C" = (A OR B) NOR C, the order the
     * parser reads them in; A NOR B = NOT (A OR B)).
     *
     * @return array{0:array|bool,1:array|bool}
     */
    private function chain(array $node): array
    {
        $first = $node['c'][0];
        $t = $this->t($first);
        $f = $this->f($first);
        foreach ($node['ops'] as $i => $op) {
            $next = $node['c'][$i + 1];
            $nt = $this->t($next);
            $nf = $this->f($next);
            [$t, $f] = $op === 'NOR'
                ? [$this->conj([$f, $nf]), $this->disj([$t, $nt])]
                : [$this->disj([$t, $nt]), $this->conj([$f, $nf])];
        }

        return [$t, $f];
    }

    /** [T, F] of an XOR group, left to right. @return array{0:array|bool,1:array|bool} */
    private function xorChain(array $node): array
    {
        $t = $this->t($node['c'][0]);
        $f = $this->f($node['c'][0]);
        foreach (array_slice($node['c'], 1) as $next) {
            $nt = $this->t($next);
            $nf = $this->f($next);
            [$t, $f] = [
                $this->disj([$this->conj([$t, $nf]), $this->conj([$f, $nt])]),
                $this->disj([$this->conj([$t, $nt]), $this->conj([$f, $nf])]),
            ];
        }

        return [$t, $f];
    }

    /** AND with constant folding (FALSE wins, TRUE drops out) and flattening. */
    private function conj(array $parts): array|bool
    {
        $kept = [];
        foreach ($parts as $p) {
            if ($p === false) {
                return false;
            }
            if ($p === true) {
                continue;
            }
            if ($p['t'] === 'and') {
                array_push($kept, ...$p['c']);
            } else {
                $kept[] = $p;
            }
        }

        return $this->group('and', $kept, true);
    }

    /** OR with constant folding (TRUE wins, FALSE drops out) and flattening. */
    private function disj(array $parts): array|bool
    {
        $kept = [];
        foreach ($parts as $p) {
            if ($p === true) {
                return true;
            }
            if ($p === false) {
                continue;
            }
            if ($p['t'] === 'or' && !in_array('NOR', $p['ops'], true)) {
                array_push($kept, ...$p['c']);
            } else {
                $kept[] = $p;
            }
        }

        return $this->group('or', $kept, false);
    }

    private function group(string $type, array $kept, bool $empty): array|bool
    {
        if ($kept === []) {
            return $empty;
        }
        if (count($kept) === 1) {
            return $kept[0];
        }
        $n = 1;
        foreach ($kept as $k) {
            $n += $k['n'] ?? 1;
        }
        if ($n > self::MAX_NODES) {
            throw new \OverflowException('filter too large to rewrite');
        }
        $node = ['t' => $type, 'c' => $kept, 'u' => false, 'n' => $n];
        if ($type === 'or') {
            $node['ops'] = array_fill(0, count($kept) - 1, 'OR');
        }

        return $node;
    }

    /**
     * NOT of a comparison the caller may evaluate, as the inverted comparison DreamFactory reads
     * the same way (checked with DreamFactory's own split). FALSE when it cannot be written
     * safely (the result is then narrower, never wider).
     */
    private function negateTerm(array $node): array|bool
    {
        if ($node['field'] === null || $node['op'] === null) {
            // DreamFactory rejects this comparison anyway; keep its text so it still does.
            return ['t' => 'not', 'c' => [$node], 'u' => false, 'n' => 2];
        }
        $raw = (string)$node['raw'];
        $original = FilterParser::splitComparison($raw);
        $pure = trim($raw, '()');
        $padded = FilterParser::padOperator((string)$node['op']);
        $at = stripos($pure, $padded);
        if ($original === null || $at === false) {
            return false;
        }
        $lead = strspn($raw, '()');
        $head = substr($raw, 0, $lead);
        $tail = (string)substr($raw, $lead + strlen($pure));
        $fieldText = rtrim(substr($pure, 0, $at));
        $value = ltrim((string)substr($pure, $at + strlen($padded)));
        $op = (string)$node['op'];
        if ($node['negate']) {
            $fieldText = rtrim(substr($fieldText, 0, -3)); // "field NOT op": drop the NOT
            $negate = false;
        } elseif (isset(self::INVERSE[$op])) {
            $op = self::INVERSE[$op];
            $negate = false;
        } elseif (in_array($op, self::NEGATABLE, true)) {
            $fieldText .= ' NOT';
            $negate = true;
        } else {
            return false; // ALL: no portable negation
        }
        $text = $head . $fieldText . ' ' . $op . ($value !== '' ? ' ' . $value : '') . $tail;
        $split = FilterParser::splitComparison($text);
        if ($split === null || strtolower($split['field']) !== $node['field'] || $split['op'] !== $op
            || $split['negate'] !== $negate || $split['value'] !== $original['value']) {
            return false; // a literal that would make DreamFactory split it differently
        }

        return ['t' => 'term', 'raw' => $text, 'field' => $node['field'], 'op' => $op, 'negate' => $negate,
            'count' => $node['count'], 'u' => false, 'n' => 1];
    }

    /** Display names of masked columns compared with an operator the matrix does not allow. */
    private function collectViolations(array $node, array &$out): void
    {
        if ($node['t'] === 'term') {
            if (!$this->allowsTerm($node)) {
                $out[] = $this->hiddenName($node) ?? self::DROP_ALL;
            }

            return;
        }
        foreach ($node['c'] as $child) {
            $this->collectViolations($child, $out);
        }
    }

    /**
     * Back to DreamFactory's documented filter form: "(a = 1) AND ((b = 2) OR (c = 3))".
     * Comparisons keep their original text. NOT is never wrapped in extra parentheses
     * (DreamFactory only recognizes NOT at the start of a parenthesized group).
     */
    public static function serialize(array $node): string
    {
        switch ($node['t']) {
            case 'term':
                return $node['raw'];
            case 'not':
                return 'NOT (' . self::serialize($node['c'][0]) . ')';
            case 'and':
                return implode(' AND ', array_map([self::class, 'wrap'], $node['c']));
            case 'xor':
                return implode(' XOR ', array_map([self::class, 'wrap'], $node['c']));
            case 'or':
                $out = self::wrap($node['c'][0]);
                foreach ($node['ops'] as $i => $op) {
                    $out .= ' ' . $op . ' ' . self::wrap($node['c'][$i + 1]);
                }

                return $out;
        }

        return '';
    }

    private static function wrap(array $node): string
    {
        return $node['t'] === 'not' ? self::serialize($node) : '(' . self::serialize($node) . ')';
    }
}

<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Enforcement\Filter;

/**
 * Parses a DreamFactory SQL filter string ("(email = 'a@b.c') AND (age > 30)") into a small
 * tree, so enforcement can see every column a filter touches and with which operator.
 *
 * The parser mirrors what df-sqldb executes (Table::parseFilterString, DbLogicalOperators):
 *
 *  - BETWEEN is expanded first, with DreamFactory's own regex, exactly as DreamFactory does it.
 *  - Logical structure follows SQL precedence (NOT > AND > XOR > OR/NOR), which is the
 *    precedence the database applies to the flat SQL DreamFactory generates.
 *  - Each comparison is then split into field / operator / value the way DreamFactory does it:
 *    the first operator found in DreamFactory's parsing order, the field being everything before
 *    it (with a trailing NOT meaning negation). So the field the decision is made on is exactly
 *    the field DreamFactory will put in the WHERE clause.
 *  - Quotes: '...' and "..." with no backslash escapes (DreamFactory has none; a doubled quote
 *    simply reads as two adjacent literals, as it does in DreamFactory).
 *
 * DreamFactory's own splitter also looks for ") AND (" style sequences without regard to quotes.
 * A literal containing such a sequence would be split differently by DreamFactory than by any
 * quote-aware parser, so the parse is reported as uncertain (null) and the caller fails safe.
 * Unbalanced parentheses, unterminated quotes and dangling operators are uncertain too.
 *
 * Node shapes (arrays, cheap to build and to test):
 *   ['t' => 'term', 'raw' => string, 'field' => ?string (lower-cased; null when DreamFactory
 *        would reject the comparison), 'op' => ?string, 'negate' => bool, 'count' => int]
 *   ['t' => 'and'|'xor', 'c' => list<node>]
 *   ['t' => 'or', 'c' => list<node>, 'ops' => list<'OR'|'NOR'>]
 *   ['t' => 'not', 'c' => [node]]
 */
final class FilterParser
{
    /** DreamFactory\Core\Enums\DbComparisonOperators::getParsingOrder() (order matters). */
    public const PARSING_ORDER = [
        '>=', '<=', '!=', '=', '<>', '>', '<',
        'GTE', 'LTE', 'NE', 'EQ', 'GT', 'LT',
        'NOT IN', 'IN', 'ALL', 'LIKE', 'STARTS WITH', 'ENDS WITH', 'CONTAINS',
        'IS NULL', 'IS NOT NULL',
    ];

    private const NO_VALUE_OPS = ['IS NULL', 'IS NOT NULL'];
    private const LIST_OPS = ['IN', 'NOT IN', 'ALL'];

    /** A literal DreamFactory's quote-blind splitter would cut through. */
    private const AMBIGUOUS_LITERAL = '/\)\s*(?:AND|OR|NOR|XOR|&&|\|\|)\s*\(/i';

    private const T_LP = 1;
    private const T_RP = 2;
    private const T_STR = 3;
    private const T_WORD = 4;

    /** @var list<array{0:int,1:string,2:int,3:int}> [type, text, start, end) */
    private array $tokens = [];
    private int $pos = 0;
    private string $src = '';

    private function __construct()
    {
    }

    /**
     * @return array|null the tree, or null when the filter cannot be parsed with certainty
     */
    public static function parse(string $filter): ?array
    {
        $src = self::expandBetween(trim($filter));
        if ($src === '') {
            return null;
        }
        $parser = new self();
        $parser->src = $src;
        if (!$parser->tokenize()) {
            return null;
        }
        $node = $parser->parseOr();
        if ($node === null || $parser->pos !== count($parser->tokens)) {
            return null;
        }

        return $node;
    }

    /** DreamFactory\Core\Enums\DbLogicalOperators::expandBetween(), verbatim. */
    public static function expandBetween(string $filter): string
    {
        if (false === stripos($filter, 'between')) {
            return $filter;
        }
        $bound = "('(?:[^']|'')*'|\"[^\"]*\"|[^\\s()]+)";
        $re = '/([A-Za-z_][\\w.]*)\\s+(NOT\\s+)?BETWEEN\\s+' . $bound . '\\s+AND\\s+' . $bound . '/i';

        return preg_replace_callback($re, function ($m) {
            return empty($m[2])
                ? "({$m[1]} >= {$m[3]}) AND ({$m[1]} <= {$m[4]})"
                : "({$m[1]} < {$m[3]}) OR ({$m[1]} > {$m[4]})";
        }, $filter) ?? $filter;
    }

    /**
     * Splits one comparison the way df-sqldb's Table::parseFilterString does.
     *
     * @return array{field:string,op:string,negate:bool,value:string}|null null = DreamFactory
     *         finds no operator and rejects the filter
     */
    public static function splitComparison(string $term): ?array
    {
        $pure = trim($term, '()');
        foreach (self::PARSING_ORDER as $op) {
            $padded = self::padOperator($op);
            $at = stripos($pure, $padded);
            if ($at === false) {
                continue;
            }
            $field = trim(substr($pure, 0, $at));
            $negate = false;
            if (str_contains($field, ' ')) {
                $parts = explode(' ', $field);
                $n = count($parts);
                if ($n > 1 && strcasecmp($parts[$n - 1], 'NOT') === 0) {
                    array_pop($parts);
                    $field = implode(' ', $parts);
                    $negate = true;
                }
            }

            return [
                'field' => $field,
                'op' => $op,
                'negate' => $negate,
                'value' => trim(substr($pure, $at + strlen($padded))),
            ];
        }

        return null;
    }

    /**
     * BaseDbTableResource::padOperator(), verbatim: only single-word operators ("IN", "LIKE",
     * "GTE") are padded with spaces; multi-word ones ("NOT IN", "IS NULL", "STARTS WITH") fail
     * ctype_alpha() there and are searched for unpadded, so they are here too.
     */
    public static function padOperator(string $op): string
    {
        if (ctype_alpha($op)) {
            return in_array($op, self::NO_VALUE_OPS, true) ? ' ' . $op : ' ' . $op . ' ';
        }

        return $op;
    }

    /**
     * Number of values in an IN list, counted both the way DreamFactory splits it (every comma)
     * and quote-aware; the larger count wins so the 25-value limit can't be dodged either way.
     */
    public static function listSize(string $value): int
    {
        $v = trim($value);
        if (str_starts_with($v, '(')) {
            $v = substr($v, 1);
        }
        if (str_ends_with($v, ')')) {
            $v = substr($v, 0, -1);
        }
        if (trim($v) === '') {
            return 0;
        }
        $naive = substr_count($v, ',') + 1;
        $aware = 1;
        $quote = null;
        $len = strlen($v);
        for ($i = 0; $i < $len; $i++) {
            $c = $v[$i];
            if ($quote !== null) {
                if ($c === $quote) {
                    $quote = null;
                }
            } elseif ($c === "'" || $c === '"') {
                $quote = $c;
            } elseif ($c === ',') {
                $aware++;
            }
        }

        return max($naive, $aware);
    }

    // ------------------------------------------------------------------------------ lexer

    private function tokenize(): bool
    {
        $s = $this->src;
        $len = strlen($s);
        $i = 0;
        while ($i < $len) {
            $c = $s[$i];
            if (ctype_space($c)) {
                $i++;
                continue;
            }
            if ($c === '(') {
                $this->tokens[] = [self::T_LP, '(', $i, $i + 1];
                $i++;
                continue;
            }
            if ($c === ')') {
                $this->tokens[] = [self::T_RP, ')', $i, $i + 1];
                $i++;
                continue;
            }
            if ($c === "'" || $c === '"') {
                $end = strpos($s, $c, $i + 1);
                if ($end === false) {
                    return false; // unterminated literal
                }
                $text = substr($s, $i, $end - $i + 1);
                if (preg_match(self::AMBIGUOUS_LITERAL, $text) === 1) {
                    return false;
                }
                $this->tokens[] = [self::T_STR, $text, $i, $end + 1];
                $i = $end + 1;
                continue;
            }
            $start = $i;
            while ($i < $len && !ctype_space($s[$i]) && !in_array($s[$i], ['(', ')', "'", '"'], true)) {
                $i++;
            }
            $this->tokens[] = [self::T_WORD, substr($s, $start, $i - $start), $start, $i];
        }

        return true;
    }

    // ------------------------------------------------------------------------------ grammar

    private function parseOr(): ?array
    {
        $first = $this->parseXor();
        if ($first === null) {
            return null;
        }
        $children = [$first];
        $ops = [];
        while (($op = $this->peekLogical()) === 'OR' || $op === 'NOR') {
            $this->pos++;
            $next = $this->parseXor();
            if ($next === null) {
                return null;
            }
            $children[] = $next;
            $ops[] = $op;
        }

        return count($children) === 1 ? $first : ['t' => 'or', 'c' => $children, 'ops' => $ops];
    }

    private function parseXor(): ?array
    {
        $first = $this->parseAnd();
        if ($first === null) {
            return null;
        }
        $children = [$first];
        while ($this->peekLogical() === 'XOR') {
            $this->pos++;
            $next = $this->parseAnd();
            if ($next === null) {
                return null;
            }
            $children[] = $next;
        }

        return count($children) === 1 ? $first : ['t' => 'xor', 'c' => $children];
    }

    private function parseAnd(): ?array
    {
        $first = $this->parseNot();
        if ($first === null) {
            return null;
        }
        $children = [$first];
        while ($this->peekLogical() === 'AND') {
            $this->pos++;
            $next = $this->parseNot();
            if ($next === null) {
                return null;
            }
            $children[] = $next;
        }

        return count($children) === 1 ? $first : ['t' => 'and', 'c' => $children];
    }

    private function parseNot(): ?array
    {
        $tok = $this->tokens[$this->pos] ?? null;
        $next = $this->tokens[$this->pos + 1] ?? null;
        // DreamFactory only treats NOT as a logical prefix in front of a parenthesis.
        if ($tok !== null && $tok[0] === self::T_WORD && strcasecmp($tok[1], 'NOT') === 0
            && $next !== null && $next[0] === self::T_LP) {
            $this->pos++;
            $child = $this->parsePrimary();

            return $child === null ? null : ['t' => 'not', 'c' => [$child]];
        }

        return $this->parsePrimary();
    }

    private function parsePrimary(): ?array
    {
        $tok = $this->tokens[$this->pos] ?? null;
        if ($tok === null) {
            return null;
        }
        if ($tok[0] === self::T_LP) {
            $this->pos++;
            $inner = $this->parseOr();
            $close = $this->tokens[$this->pos] ?? null;
            if ($inner === null || $close === null || $close[0] !== self::T_RP) {
                return null;
            }
            $this->pos++;

            return $inner;
        }
        if ($tok[0] === self::T_RP || $this->peekLogical() !== null) {
            return null; // ")" or an operator where an operand belongs
        }

        return $this->parseTerm();
    }

    private function parseTerm(): ?array
    {
        $startTok = $this->pos;
        $depth = 0;
        $count = count($this->tokens);
        while ($this->pos < $count) {
            $tok = $this->tokens[$this->pos];
            if ($depth === 0 && ($tok[0] === self::T_RP || $this->peekLogical() !== null)) {
                break;
            }
            if ($tok[0] === self::T_LP) {
                $depth++;
            } elseif ($tok[0] === self::T_RP) {
                $depth--;
            }
            $this->pos++;
        }
        if ($this->pos === $startTok || $depth !== 0) {
            return null;
        }
        $first = $this->tokens[$startTok];
        $last = $this->tokens[$this->pos - 1];
        $raw = substr($this->src, $first[2], $last[3] - $first[2]);

        $split = self::splitComparison($raw);
        if ($split === null) {
            return ['t' => 'term', 'raw' => $raw, 'field' => null, 'op' => null, 'negate' => false, 'count' => 0];
        }

        return [
            't' => 'term',
            'raw' => $raw,
            'field' => strtolower($split['field']),
            'op' => $split['op'],
            'negate' => $split['negate'],
            'count' => in_array($split['op'], self::LIST_OPS, true) ? self::listSize($split['value']) : 1,
        ];
    }

    /** 'AND' | 'OR' | 'NOR' | 'XOR' when the next token is a logical operator, else null. */
    private function peekLogical(): ?string
    {
        $tok = $this->tokens[$this->pos] ?? null;
        if ($tok === null || $tok[0] !== self::T_WORD) {
            return null;
        }

        return match (strtoupper($tok[1])) {
            'AND', '&&' => 'AND',
            'OR', '||' => 'OR',
            'NOR' => 'NOR',
            'XOR' => 'XOR',
            default => null,
        };
    }
}

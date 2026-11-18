<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Tests\Unit\Enforcement;

use DreamFactory\Core\Masking\Enforcement\Filter\FilterParser;
use DreamFactory\Core\Masking\Enforcement\Filter\FilterRewriter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class FilterRewriterTest extends TestCase
{
    /** Masked fields the caller does not see: lower-cased field => display name + tier. */
    private const HIDDEN = [
        'ssn' => ['name' => 'ssn', 'tier' => 'restricted'],
        'email' => ['name' => 'Email', 'tier' => 'identity'],
        'zip' => ['name' => 'zip', 'tier' => 'quasi'],
        'notes' => ['name' => 'notes', 'tier' => 'free_text'],
        'home phone' => ['name' => 'Home Phone', 'tier' => 'identity'],
        "pr\u{00E9}nom" => ['name' => "pr\u{00E9}nom", 'tier' => 'identity'],
    ];

    /** The always-false filter DreamFactory gets when a whole filter folds to FALSE. */
    private const NONE = '(id IS NULL) AND (id IS NOT NULL)';

    private function rewriter(): FilterRewriter
    {
        return new FilterRewriter(self::HIDDEN, ['id']);
    }

    /**
     * [filter, expected filter (same string = untouched, NONE = matches no rows), expected
     * dropped (display names of masked columns whose comparisons were unknown)]
     *
     * Three-valued logic: an unknown comparison is never TRUE and NOT of it is never TRUE either.
     */
    public static function readCases(): array
    {
        $in26 = 'email IN (' . implode(',', array_map(fn ($i) => "'a$i@x.io'", range(1, 26))) . ')';
        $in25 = 'email IN (' . implode(',', array_map(fn ($i) => "'a$i@x.io'", range(1, 25))) . ')';
        $none = self::NONE;

        return [
            // --- allowed comparisons stay byte-for-byte
            'identity equality' => ["(email = 'a@b.c')", "(email = 'a@b.c')", []],
            'identity not equal' => ["email != 'a@b.c'", "email != 'a@b.c'", []],
            'identity <>' => ["email <> 'a'", "email <> 'a'", []],
            'identity EQ word' => ["email EQ 'a'", "email EQ 'a'", []],
            'quasi equality' => ["zip = '94103'", "zip = '94103'", []],
            'identity IN 25' => [$in25, $in25, []],
            'IS NULL restricted' => ['ssn IS NULL', 'ssn IS NULL', []],
            'IS NOT NULL restricted' => ['(ssn IS NOT NULL)', '(ssn IS NOT NULL)', []],
            'whitespace kept when untouched' => ["  (email='a')  ", "  (email='a')  ", []],
            'no masked column mentioned' => ["(name = 'x') AND (age > 3)", "(name = 'x') AND (age > 3)", []],
            'not allowed kept' => ["NOT (email = 'a')", "NOT (email = 'a')", []],
            'xor allowed kept' => ["(name = 'x') XOR (email = 'a')", "(name = 'x') XOR (email = 'a')", []],
            'is null in or kept' => ["(ssn IS NULL) OR (name = 'x')", "(ssn IS NULL) OR (name = 'x')", []],
            'prefix column is not the masked one' => ['email_verified = true', 'email_verified = true', []],
            'masked name inside a value' => ["(name = 'ssn LIKE 1') OR (id = 1)", "(name = 'ssn LIKE 1') OR (id = 1)", []],
            'in list with quoted commas' => ["email IN ('a,b','c')", "email IN ('a,b','c')", []],

            // --- an unknown comparison alone matches no rows
            'like identity' => ["email like 'a%'", $none, ['Email']],
            'restricted equality' => ["ssn = '123-45-6789'", $none, ['ssn']],
            'free text equality' => ["notes = 'x'", $none, ['notes']],
            'quasi range' => ["zip > '9'", $none, ['zip']],
            'GT word' => ["email GT 'a'", $none, ['Email']],
            'contains' => ["email CONTAINS 'x'", $none, ['Email']],
            'starts with' => ["email STARTS WITH 'x'", $none, ['Email']],
            'ends with lower' => ["email ends with 'x'", $none, ['Email']],
            'negated like' => ["ssn NOT LIKE '1%'", $none, ['ssn']],
            'not in restricted' => ["ssn NOT IN ('1','2')", $none, ['ssn']],
            'IN 26' => [$in26, $none, ['Email']],
            'case insensitive field' => ["EMAIL LIKE 'x%'", $none, ['Email']],
            'between expanded' => ["ssn BETWEEN '1' AND '2'", $none, ['ssn']],
            'not between' => ['zip NOT BETWEEN 1 AND 5', $none, ['zip']],
            'nested parens' => ["(((ssn LIKE '1%')))", $none, ['ssn']],
            'unicode field' => ["pr\u{00E9}nom LIKE 'J%'", $none, ["pr\u{00E9}nom"]],
            'field with spaces' => ["Home Phone LIKE '415%'", $none, ['Home Phone']],

            // --- AND: one unknown operand makes the whole AND match no rows
            'and with unknown' => ["(name = 'x') AND (ssn = '123')", $none, ['ssn']],
            'and of three' => ['(a = 1) AND (ssn > 2) AND (b = 3)', $none, ['ssn']],
            'symbol and' => ["(name = 'x') && (ssn = '1')", $none, ['ssn']],
            'bare and' => ["name = 'x' and email like 'y%'", $none, ['Email']],
            'prefix column with masked one' => ["(email_verified = true) AND (email LIKE 'a%')", $none, ['Email']],

            // --- OR: the unknown operand drops out, the rest decides
            'or keeps the clear side' => ["(name = 'x') OR (ssn = '1')", "name = 'x'", ['ssn']],
            'symbol or' => ["(name='x') || (ssn='1')", "name='x'", ['ssn']],
            'bare or' => ["name = 'x' OR ssn > '5'", "name = 'x'", ['ssn']],
            'or of unknowns' => ["(ssn = '1') OR (notes LIKE '%x%')", $none, ['ssn', 'notes']],
            'or inside and' => ["(name = 'x') AND ((zip = '9') OR (ssn LIKE '1%'))", "(name = 'x') AND (zip = '9')", ['ssn']],
            'and inside or' => ["((name = 'x') AND (ssn = '1')) OR (id = 5)", 'id = 5', ['ssn']],
            'or keeps allowed masked comparisons' => ["(email = 'a') OR (ssn > 1) OR (name CONTAINS 'q')", "(email = 'a') OR (name CONTAINS 'q')", ['ssn']],
            'deep nesting keeps structure' => [
                "(a = 1) AND (((b = 2) AND (ssn = '1')) OR (c = 3)) AND (zip = '9')",
                "(a = 1) AND (c = 3) AND (zip = '9')",
                ['ssn'],
            ],
            'always-true tail' => ["ssn = '1' OR 1=1", '1=1', ['ssn']], // DreamFactory rejects "1=1" itself

            // --- NOT: NOT (unknown) is unknown too; NOT over a group is pushed down
            'not of unknown' => ["NOT (ssn LIKE '1%')", $none, ['ssn']],
            'not in and' => ["(name = 'x') AND NOT (email LIKE 'a%')", $none, ['Email']],
            'not over and' => ["NOT ((name = 'x') AND (ssn = '1'))", "name != 'x'", ['ssn']],
            'not over or' => ["NOT ((name = 'x') OR (ssn = '1'))", $none, ['ssn']],
            'or with not over and' => ["(a = 1) OR NOT ((b = 2) AND (ssn = '1'))", '(a = 1) OR (b != 2)', ['ssn']],
            'not inverts ranges' => ["NOT ((age > 3) AND (ssn = '1'))", 'age <= 3', ['ssn']],
            'not inverts >=' => ["NOT ((age >= 3) AND (ssn = '1'))", 'age < 3', ['ssn']],
            'not inverts word ops' => ['NOT ((age GT 3) AND (ssn = 1))', 'age LTE 3', ['ssn']],
            'not inverts like' => ["NOT ((name LIKE 'a%') AND (notes = 'x'))", "name NOT LIKE 'a%'", ['notes']],
            'not inverts not like' => ["NOT ((name NOT LIKE 'a%') AND (ssn = '1'))", "name LIKE 'a%'", ['ssn']],
            'not inverts starts with' => ["NOT ((name STARTS WITH 'a') AND (ssn = '1'))", "name NOT STARTS WITH 'a'", ['ssn']],
            'not inverts in' => ["NOT ((id IN (1,2)) AND (ssn = '1'))", 'id NOT IN (1,2)', ['ssn']],
            'not inverts is null' => ["NOT ((nick IS NULL) AND (ssn = '1'))", 'nick IS NOT NULL', ['ssn']],
            'not inverts allowed masked' => ["NOT ((email = 'a') AND (ssn = '1'))", "email != 'a'", ['ssn']],
            'not keeps a literal DreamFactory would split differently' => ["NOT ((b != 'x!=y') AND (ssn = '1'))", $none, ['ssn']],

            // --- XOR, NOR
            'xor with unknown' => ["(name = 'x') XOR (email LIKE 'a%')", $none, ['Email']],
            'clear xor kept' => ["((a = 1) XOR (b = 2)) OR (ssn = '1')", '(a = 1) XOR (b = 2)', ['ssn']],
            'not of xor with unknown' => ["NOT ((a = 1) XOR (ssn = '1'))", $none, ['ssn']],
            'nor with unknown' => ["(name = 'x') NOR (zip > 1)", $none, ['zip']],
            'or then nor' => ["(a = 1) OR (ssn = '1') NOR (b = 2)", $none, ['ssn']], // (a OR unknown) may be TRUE
            'nor over and' => ["(a = 1) NOR ((b = 2) AND (ssn = '1'))", '(a != 1) AND (b != 2)', ['ssn']],

            // --- prefixes, quotes, unicode, lookups: clear comparisons keep their text
            'doubled quote' => ["(name = 'O''Brien') OR (ssn = '1')", "name = 'O''Brien'", ['ssn']],
            'double quoted value' => ['(name = "a b") OR (ssn = "1")', 'name = "a b"', ['ssn']],
            'unicode value' => ["(name = 'J\u{00FC}rgen') OR (email LIKE '%\u{00FC}%')", "name = 'J\u{00FC}rgen'", ['Email']],
            'lookup kept' => ["(owner = {user.id}) OR (ssn = '1')", 'owner = {user.id}', ['ssn']],
            'params kept' => ['(email LIKE :e) OR (name = :n)', 'name = :n', ['Email']],
            'function value kept' => ["(created > NOW()) OR (ssn > '1')", 'created > NOW()', ['ssn']],

            // --- uncertain: matches no rows
            'literal with logical split' => ["name = ') OR (ssn LIKE ''1%'''", $none, ['*']],
            'literal with squashed split' => ["(name = 'x)AND(ssn LIKE 1') ", $none, ['*']],
            'between inside literal' => ["(nickname = 'ssn BETWEEN 1 AND 2')", $none, ['*']],
            'unbalanced' => ["(ssn = '1'))", $none, ['*']],
            'unterminated quote' => ["email = 'abc", $none, ['*']],
            'backslash quote' => ["(name = 'O\\'Brien') AND (email = 'a')", $none, ['*']],
            'dangling operator' => ["(email = 'a') AND", $none, ['*']],
            'empty group' => ["() AND (email = 'a')", $none, ['*']],
        ];
    }

    #[DataProvider('readCases')]
    public function testRead(string $filter, ?string $expected, array $dropped): void
    {
        $r = $this->rewriter()->forRead($filter);
        $this->assertSame($expected, $r['filter'], 'filter');
        $this->assertSame($dropped, $r['dropped'], 'dropped');
        $this->assertSame($dropped !== [], $r['changed']);
    }

    /** Whatever a rewrite produces must re-parse and must not compare a masked column badly. */
    #[DataProvider('readCases')]
    public function testRewrittenFilterIsSafeAndStable(string $filter, ?string $expected, array $dropped): void
    {
        $r = $this->rewriter()->forRead($filter);
        $this->assertNotNull($r['filter'], 'a read filter is never removed (that would widen the result)');
        if ($dropped === []) {
            $this->assertSame($filter, $r['filter']);

            return;
        }
        $this->assertNotNull(FilterParser::parse($r['filter']), 'DreamFactory gets a filter it can parse');
        $again = $this->rewriter()->forRead($r['filter']);
        $this->assertFalse($again['changed'], 'a rewritten filter needs no second rewrite');
        $this->assertTrue($this->rewriter()->forWrite($r['filter'])['ok'], 'no unknown comparison survives');
        $this->assertStringNotContainsStringIgnoringCase('NOT (', $r['filter'], 'negation is written into the comparison (DreamFactory reads NOT only at the start)');
    }

    /**
     * The filter DreamFactory gets never depends on the masked literal,
     * whatever the literal is (real-looking, wrong, empty, quoted).
     */
    public function testRewriteNeverDependsOnTheMaskedLiteral(): void
    {
        $templates = [
            "ssn = '%s'",
            "(state = 'IL') AND (ssn = '%s')",
            "(state = 'IL') OR (ssn = '%s')",
            "NOT (ssn = '%s')",
            "NOT ((state = 'IL') AND (ssn = '%s'))",
            "(state = 'IL') XOR (ssn != '%s')",
            "(state = 'IL') NOR (ssn IN ('%s','x'))",
            "(age > 3) AND ((ssn LIKE '%s%%') OR (city = 'Chicago'))",
            "(email LIKE '%s') OR (email = 'known@x.io')",
            "ssn BETWEEN '%s' AND '999-99-9999'",
            "(notes = '%s') OR NOT ((state = 'IL') AND (zip > '%s'))",
        ];
        $literals = ['123-45-6789', '000-00-0000', '987-65-4321', 'zq', 'O\'\'Brien', '1%', 'jane@example.com', "\u{00E9}t\u{00E9}"];
        foreach ($templates as $template) {
            $seen = null;
            foreach ($literals as $literal) {
                $r = $this->rewriter()->forRead(str_replace('%s', $literal, str_replace('%%', '%', $template)));
                $this->assertTrue($r['changed'], $template);
                $this->assertStringNotContainsString($literal, (string)$r['filter'], "$template: the masked literal reaches DreamFactory");
                $seen ??= [$r['filter'], $r['dropped']];
                $this->assertSame($seen, [$r['filter'], $r['dropped']], "rewrite of $template depends on the literal ($literal)");
            }
        }
    }

    /**
     * The rewrite is exactly three-valued logic: for random filters over clear comparisons (each
     * TRUE, FALSE or NULL in a row) and unknown masked comparisons, a row passes the rewritten
     * filter (evaluated the way SQL does) exactly when the original filter is TRUE with every
     * unknown comparison NULL, whatever the real masked values are.
     */
    public function testRewriteIsThreeValuedLogic(): void
    {
        // clear or allowed comparisons => the comparison TRUE exactly when they are FALSE
        $clear = [
            "name = 'x'" => "name != 'x'",
            'age > 3' => 'age <= 3',
            'id IN (1,2)' => 'id NOT IN (1,2)',
            "city LIKE 'a%'" => "city NOT LIKE 'a%'",
            'zip IS NULL' => 'zip IS NOT NULL',
            "email = 'a'" => "email != 'a'",
        ];
        $unknown = ["ssn = '1'", "email LIKE 'b%'", "notes = 'x'", 'zip > 3'];
        $terms = array_merge(array_keys($clear), $unknown);
        $ops = ['AND', 'OR', 'XOR', 'NOR', '&&', '||'];
        mt_srand(20261029);
        $nonTrivial = 0;
        for ($i = 0; $i < 400; $i++) {
            $filter = $this->randomFilter($terms, $ops, mt_rand(1, 3));
            $r = $this->rewriter()->forRead($filter);
            $tree = $r['filter'] === self::NONE ? null : FilterParser::parse((string)$r['filter']);
            if ($r['filter'] !== self::NONE) {
                $this->assertNotNull($tree, "unparsable rewrite for $filter: {$r['filter']}");
                $nonTrivial++;
            }
            for ($k = 0; $k < 12; $k++) {
                $row = [];
                foreach ($clear as $term => $inverse) {
                    $row[$term] = [true, false, null][mt_rand(0, 2)];
                    $row[$inverse] = $row[$term] === null ? null : !$row[$term];
                }
                foreach ($unknown as $term) {
                    $row[$term] = mt_rand(0, 1) === 1; // the real (hidden) outcome: must not matter
                }
                $original = $this->eval3(FilterParser::parse($filter), $row, $unknown, true);
                $passes = $tree !== null && $this->eval3($tree, $row, $unknown, false) === true;
                $this->assertSame($original === true, $passes, "filter: $filter\nrewrite: {$r['filter']}\nrow: " . json_encode($row));
            }
        }
        $this->assertGreaterThan(50, $nonTrivial, 'the random filters exercise real rewrites');
    }

    private function randomFilter(array $terms, array $ops, int $depth): string
    {
        if ($depth === 0 || mt_rand(0, 3) === 0) {
            $t = '(' . $terms[mt_rand(0, count($terms) - 1)] . ')';

            return mt_rand(0, 3) === 0 ? 'NOT ' . $t : $t;
        }
        $n = mt_rand(2, 3);
        $out = '(' . $this->randomFilter($terms, $ops, $depth - 1) . ')';
        for ($j = 1; $j < $n; $j++) {
            $out .= ' ' . $ops[mt_rand(0, count($ops) - 1)] . ' (' . $this->randomFilter($terms, $ops, $depth - 1) . ')';
        }

        return mt_rand(0, 4) === 0 ? 'NOT (' . $out . ')' : $out;
    }

    /** SQL's three-valued evaluation (null = unknown); masked comparisons are unknown when $maskUnknown. */
    private function eval3(array $node, array $row, array $unknown, bool $maskUnknown): ?bool
    {
        switch ($node['t']) {
            case 'term':
                $raw = trim($node['raw']);
                if ($maskUnknown && in_array($raw, $unknown, true)) {
                    return null;
                }
                $this->assertArrayHasKey($raw, $row, "unexpected comparison in a rewrite: $raw");

                return $row[$raw];
            case 'not':
                $v = $this->eval3($node['c'][0], $row, $unknown, $maskUnknown);

                return $v === null ? null : !$v;
            case 'and':
                $out = true;
                foreach ($node['c'] as $c) {
                    $v = $this->eval3($c, $row, $unknown, $maskUnknown);
                    if ($v === false) {
                        return false;
                    }
                    $out = $v === null ? null : $out;
                }

                return $out;
            case 'xor':
                $acc = $this->eval3($node['c'][0], $row, $unknown, $maskUnknown);
                foreach (array_slice($node['c'], 1) as $c) {
                    $v = $this->eval3($c, $row, $unknown, $maskUnknown);
                    $acc = ($acc === null || $v === null) ? null : ($acc xor $v);
                }

                return $acc;
            case 'or':
                $acc = $this->eval3($node['c'][0], $row, $unknown, $maskUnknown);
                foreach ($node['ops'] as $i => $op) {
                    $v = $this->eval3($node['c'][$i + 1], $row, $unknown, $maskUnknown);
                    $or = ($acc === true || $v === true) ? true : (($acc === null || $v === null) ? null : false);
                    $acc = $op === 'NOR' ? ($or === null ? null : !$or) : $or;
                }

                return $acc;
        }

        return null;
    }

    public function testHugeExpansionMatchesNoRows(): void
    {
        $chain = implode(' XOR ', array_map(fn ($i) => "(c$i = $i)", range(1, 14)));
        $r = $this->rewriter()->forRead("NOT (($chain) AND (ssn = '1'))");
        $this->assertSame(self::NONE, $r['filter'], 'too large to expand: no rows, never wider');
        $this->assertSame(['ssn'], $r['dropped']);
        // ... but a clear group that needs no expansion is kept as written
        $r = $this->rewriter()->forRead("($chain) OR (ssn = '1')");
        $this->assertSame($chain, $r['filter']);
    }

    public function testAlwaysFalseFilterUsesARealColumn(): void
    {
        $this->assertSame('(customer id IS NULL) AND (customer id IS NOT NULL)',
            (new FilterRewriter(self::HIDDEN, ['customer id']))->forRead("ssn = '1'")['filter']);
        // candidates DreamFactory would read differently are skipped
        $this->assertSame('(code IS NULL) AND (code IS NOT NULL)',
            (new FilterRewriter(self::HIDDEN, ['f(x)', "o'k", 'is_x = 1', 'code']))->forRead("ssn = '1'")['filter']);
        // without candidates: the first masked field (IS [NOT] NULL is allowed on it)
        $this->assertSame('(ssn IS NULL) AND (ssn IS NOT NULL)', (new FilterRewriter(self::HIDDEN))->forRead("notes LIKE 'x'")['filter']);
    }

    public static function writeCases(): array
    {
        return [
            ["email = 'a'", true, []],
            ["email IN ('a','b')", true, []],
            ["ssn IS NULL", true, []],
            ["(id = 5) AND (name = 'x')", true, []],
            ["email like 'a%'", false, ['Email']],
            ["ssn = '1'", false, ['ssn']],
            ["(id = 5) OR (email LIKE 'a')", false, ['Email']],
            ["(zip > 1) AND (notes = 'x')", false, ['zip', 'notes']],
        ];
    }

    #[DataProvider('writeCases')]
    public function testWrite(string $filter, bool $ok, array $violations): void
    {
        $r = $this->rewriter()->forWrite($filter);
        $this->assertSame($ok, $r['ok']);
        $this->assertSame($violations, $r['violations']);
        $this->assertFalse($r['uncertain']);
    }

    public function testWriteUncertainIsRefused(): void
    {
        $r = $this->rewriter()->forWrite("name = ') OR (ssn LIKE 1'");
        $this->assertFalse($r['ok']);
        $this->assertTrue($r['uncertain']);
        // ... but an uncertain filter that cannot name a masked column is fine.
        $this->assertTrue($this->rewriter()->forWrite("name = ') OR (age LIKE 1'")['ok']);
    }

    public function testNoHiddenColumnsMeansNoChange(): void
    {
        $r = (new FilterRewriter([], ['id']))->forRead("ssn LIKE '1%'");
        $this->assertFalse($r['changed']);
        $this->assertSame("ssn LIKE '1%'", $r['filter']);
    }

    // ------------------------------------------------------------------ parser details

    public static function comparisonCases(): array
    {
        // [term, field, op, negate]: DreamFactory's own split (Table::parseFilterString)
        return [
            ["email = 'a'", 'email', '=', false],
            ["age >= 3", 'age', '>=', false],
            ["age<=3", 'age', '<=', false],
            ["a != 1", 'a', '!=', false],
            ["a <> 1", 'a', '<>', false],
            ["a GTE 1", 'a', 'GTE', false],
            ["a IN (1,2)", 'a', 'IN', false],
            ["a NOT IN (1,2)", 'a', 'NOT IN', false],
            ["a IS NULL", 'a', 'IS NULL', false],
            ["a IS NOT NULL", 'a', 'IS NOT NULL', false],
            ["a NOT LIKE 'x'", 'a', 'LIKE', true],
            ["a STARTS WITH 'x'", 'a', 'STARTS WITH', false],
            ["name = 'a>=b'", "name = 'a", '>=', false], // DreamFactory would reject this field
            ["first name = 'x'", 'first name', '=', false],
        ];
    }

    #[DataProvider('comparisonCases')]
    public function testSplitComparisonMirrorsDreamFactory(string $term, string $field, string $op, bool $negate): void
    {
        $split = FilterParser::splitComparison($term);
        $this->assertNotNull($split);
        $this->assertSame($field, $split['field']);
        $this->assertSame($op, $split['op']);
        $this->assertSame($negate, $split['negate']);
    }

    public function testParserTreeShape(): void
    {
        $tree = FilterParser::parse("(a = 1) OR (b = 2) AND (c = 3)");
        $this->assertSame('or', $tree['t']);
        $this->assertSame('term', $tree['c'][0]['t']);
        $this->assertSame('and', $tree['c'][1]['t'], 'AND binds tighter than OR');
        $this->assertNull(FilterParser::parse(''));
        $this->assertNull(FilterParser::parse('(a = 1'));
    }

    public function testExpandBetweenMatchesDreamFactory(): void
    {
        $this->assertSame("(age >= 1) AND (age <= 5)", FilterParser::expandBetween('age BETWEEN 1 AND 5'));
        $this->assertSame("(d < '2020-01-01') OR (d > '2021-01-01')", FilterParser::expandBetween("d NOT BETWEEN '2020-01-01' AND '2021-01-01'"));
        $this->assertSame('a = 1', FilterParser::expandBetween('a = 1'));
    }

    public function testListSizeCountsBothWays(): void
    {
        $this->assertSame(3, FilterParser::listSize("('a','b','c')"));
        $this->assertSame(3, FilterParser::listSize("('a,b','c')"));
        $this->assertSame(0, FilterParser::listSize('()'));
    }

    public function testRandomFiltersNeverLeaveADisallowedComparison(): void
    {
        $terms = ["ssn LIKE '1%'", "email = 'a'", "name = 'x'", "zip > 3", "notes IS NULL", "email LIKE 'b%'", "id IN (1,2)", "ssn IS NOT NULL"];
        $ops = ['AND', 'OR', 'XOR', '&&', '||'];
        mt_srand(20261029);
        for ($i = 0; $i < 500; $i++) {
            $n = mt_rand(1, 5);
            $parts = [];
            for ($j = 0; $j < $n; $j++) {
                $t = '(' . $terms[mt_rand(0, count($terms) - 1)] . ')';
                if (mt_rand(0, 4) === 0) {
                    $t = 'NOT ' . $t;
                }
                $parts[] = $t;
            }
            $filter = $parts[0];
            for ($j = 1; $j < $n; $j++) {
                $filter = (mt_rand(0, 2) === 0 ? '(' . $filter . ')' : $filter) . ' ' . $ops[mt_rand(0, count($ops) - 1)] . ' ' . $parts[$j];
            }
            $r = $this->rewriter()->forRead($filter);
            $this->assertNotNull($r['filter'], "a read filter is never removed: $filter");
            $this->assertTrue($this->rewriter()->forWrite($r['filter'])['ok'], "unsafe survivor for: $filter => {$r['filter']}");
            $this->assertNotNull(FilterParser::parse($r['filter']), "unparsable survivor for: $filter => {$r['filter']}");
        }
    }
}

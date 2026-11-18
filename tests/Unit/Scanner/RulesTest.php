<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Scanner;

use DreamFactory\Core\Masking\Scanner\Rules;
use DreamFactory\Core\Masking\Support\RulePattern;
use PHPUnit\Framework\TestCase;

final class RulesTest extends TestCase
{
    protected function setUp(): void
    {
        Harness::boot();
    }

    private static function clear(): array
    {
        return ['verdict' => 'clear', 'class' => null, 'tier' => null, 'score' => 10,
            'evidence' => ['total' => 10, 'threshold_mask' => 70, 'threshold_review' => 40, 'lines' => [], 'shapes' => []]];
    }

    private static function masked(string $class, string $verdict = 'masked'): array
    {
        $r = self::clear();
        return array_replace($r, ['verdict' => $verdict, 'class' => $class, 'tier' => \DreamFactory\Core\Masking\Support\Catalog::tierOf($class), 'score' => 80]);
    }

    public function testNameRuleMasksAClearColumn(): void
    {
        $rules = new Rules([['id' => 1, 'match' => 'name', 'pattern' => '^emp_code$', 'class' => 'national_id', 'source' => 'admin']]);
        $r = $rules->apply('EMP_CODE', null, self::clear());
        $this->assertSame(['masked', 'national_id', 'restricted', 70, 'rule'], [$r['verdict'], $r['class'], $r['tier'], $r['score'], $r['source']]);
        $this->assertSame(['points' => 70, 'kind' => 'context', 'text' => 'Custom rule ^emp_code$'], end($r['evidence']['lines']));
        $untouched = $rules->apply('other', null, self::clear());
        $this->assertSame('clear', $untouched['verdict']);
        $this->assertSame('detected', $untouched['source']);
    }

    public function testBaselineRulesAreLabelled(): void
    {
        $rules = new Rules([['id' => 3, 'match' => 'name', 'pattern' => '(^|_)mrn$', 'class' => 'special_category', 'source' => 'baseline:hipaa']]);
        $r = $rules->apply('patient_mrn', null, self::clear());
        $this->assertSame('baseline', $r['source']);
        $this->assertSame('Baseline rule (^|_)mrn$ (hipaa)', end($r['evidence']['lines'])['text']);
    }

    public function testValueRulesNeedHalfTheValuesAndAtLeastThree(): void
    {
        $rules = new Rules([['id' => 1, 'match' => 'value', 'pattern' => '^EMP-\d{6}$', 'class' => 'national_id', 'source' => 'admin']]);
        $values = ['EMP-000001', 'EMP-000002', 'EMP-000003', 'x', 'y', 'z'];
        $r = $rules->apply('code', $values, self::clear());
        $this->assertSame('masked', $r['verdict']);
        $this->assertSame('Custom value rule ^EMP-\d{6}$: 3 of 6 values match', end($r['evidence']['lines'])['text']);
        $this->assertSame('clear', $rules->apply('code', ['EMP-000001', 'EMP-000002', 'x', 'y', 'z'], self::clear())['verdict']);
        $this->assertSame('clear', $rules->apply('code', ['EMP-000001', 'EMP-000002'], self::clear())['verdict'], 'fewer than 3 matches');
        $this->assertSame('clear', $rules->apply('code', null, self::clear())['verdict'], 'not sampled');
    }

    /** SQL Server and Oracle CHAR(n) values come space-padded: values are trimmed before matching. */
    public function testValueRulesMatchTrimmedValues(): void
    {
        $pattern = '^EMP-\d{6}$';
        $rules = new Rules([['id' => 1, 'match' => 'value', 'pattern' => $pattern, 'class' => 'national_id', 'source' => 'admin']]);
        $padded = ['EMP-000001    ', '  EMP-000002', "EMP-000003\t", 'EMP-0000044   '];
        $this->assertSame(3, Rules::countMatches(RulePattern::compile($pattern), $padded));
        $r = $rules->apply('emp_code', $padded, self::clear());
        $this->assertSame('masked', $r['verdict']);
        $this->assertSame('Custom value rule ^EMP-\d{6}$: 3 of 4 values match', end($r['evidence']['lines'])['text']);
        // A value that is only spaces is still a sampled value: it counts in "of", never as a match.
        $r = $rules->apply('emp_code', [...$padded, '   ', 'x'], self::clear());
        $this->assertSame('Custom value rule ^EMP-\d{6}$: 3 of 6 values match', end($r['evidence']['lines'])['text']);
        $this->assertSame('clear', $rules->apply('emp_code', [...$padded, '   ', 'x', 'y'], self::clear())['verdict'], '3 of 7 is under half');
    }

    public function testRulesOnlyAddMasking(): void
    {
        $rules = new Rules([['id' => 1, 'match' => 'name', 'pattern' => 'ssn', 'class' => 'username', 'source' => 'admin']]);
        $r = $rules->apply('ssn', null, self::masked('national_id'));
        $this->assertSame(['masked', 'national_id', 'detected'], [$r['verdict'], $r['class'], $r['source']]);
        $this->assertSame(['points' => 0, 'kind' => 'context', 'text' => 'Also matches: Custom rule ssn'], end($r['evidence']['lines']));
        // A review verdict of the same class is upgraded to masked.
        $rules2 = new Rules([['id' => 2, 'match' => 'name', 'pattern' => 'phone', 'class' => 'phone', 'source' => 'admin']]);
        $this->assertSame('masked', $rules2->apply('phone', null, self::masked('phone', 'review'))['verdict']);
    }

    public function testStrictestRuleWins(): void
    {
        $rules = new Rules([
            ['id' => 1, 'match' => 'name', 'pattern' => 'code', 'class' => 'postal_code', 'source' => 'admin'],
            ['id' => 2, 'match' => 'name', 'pattern' => 'code', 'class' => 'tax_id', 'source' => 'admin'],
        ]);
        $this->assertSame('tax_id', $rules->apply('code', null, self::clear())['class']);
    }

    public function testInvalidOrUnknownRulesAreIgnored(): void
    {
        $rules = new Rules([
            ['id' => 1, 'match' => 'name', 'pattern' => '(unclosed', 'class' => 'email', 'source' => 'admin'],
            ['id' => 2, 'match' => 'name', 'pattern' => 'x', 'class' => 'not_a_class', 'source' => 'admin'],
            ['id' => 3, 'match' => 'regex', 'pattern' => 'x', 'class' => 'email', 'source' => 'admin'],
            ['id' => 4, 'match' => 'name', 'pattern' => '(a+)+$', 'class' => 'email', 'source' => 'admin'],
        ]);
        $this->assertTrue($rules->isEmpty());
    }

    public function testRank(): void
    {
        $this->assertTrue(Rules::rank('masked', 'national_id') > Rules::rank('masked', 'email'));
        $this->assertTrue(Rules::rank('masked', 'email') > Rules::rank('review', 'email'));
        $this->assertTrue(Rules::rank('review', 'postal_code') > Rules::rank('clear', null));
        $this->assertTrue(Rules::rank('review', 'email') > Rules::rank('masked', 'free_text_pii'));
    }
}

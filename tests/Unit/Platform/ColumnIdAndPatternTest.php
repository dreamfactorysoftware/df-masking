<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Platform;

use DreamFactory\Core\Masking\Resources\Handlers\ColumnId;
use DreamFactory\Core\Masking\Support\RulePattern;
use PHPUnit\Framework\TestCase;

final class ColumnIdAndPatternTest extends TestCase
{
    public function testParsesServiceTableColumn(): void
    {
        $this->assertSame(
            ['service' => 'crm', 'table' => 'customers', 'column' => 'email'],
            ColumnId::parse('crm.customers.email')
        );
        // schema-qualified table: service = up to the first dot, column = after the last dot
        $this->assertSame(
            ['service' => 'crm', 'table' => 'sales.orders', 'column' => 'email'],
            ColumnId::parse('crm.sales.orders.email')
        );
        $this->assertSame('crm.sales.orders.email', ColumnId::format('crm', 'sales.orders', 'email'));
    }

    public function testRejectsMalformedIds(): void
    {
        foreach (['', 'crm', 'crm.customers', '.customers.email', 'crm..email', 'crm.customers.', 'crm.customers'] as $bad) {
            $this->assertNull(ColumnId::parse($bad), "'$bad' must not parse");
            $this->assertSame([], ColumnId::candidates($bad));
        }
    }

    public function testCandidatesCoverColumnsContainingDots(): void
    {
        $this->assertSame([
            ['service' => 'svc', 'table' => 'a.b', 'column' => 'c'],
            ['service' => 'svc', 'table' => 'a', 'column' => 'b.c'],
        ], ColumnId::candidates('svc.a.b.c'));
        $this->assertSame([['service' => 'svc', 'table' => 't', 'column' => 'c']], ColumnId::candidates('svc.t.c'));
    }

    public function testValidPatterns(): void
    {
        foreach (['(^|_)(ssn|nino|bsn)($|_)', '^emp_ssn$|social_sec', '^[A-Z]{2}\d{6}$', 'straße', '~', '/', '#'] as $p) {
            $this->assertNull(RulePattern::validate($p), "'$p' should be valid");
        }
    }

    public function testInvalidPatternsExplainWhy(): void
    {
        $this->assertSame('Enter a pattern.', RulePattern::validate(''));
        $this->assertSame('Enter a pattern.', RulePattern::validate('   '));
        $this->assertSame('Enter a pattern.', RulePattern::validate(null));
        $this->assertSame('Enter a pattern.', RulePattern::validate(['a']));
        $this->assertStringContainsString('at most 500', (string)RulePattern::validate(str_repeat('a', 501)));
        $this->assertNull(RulePattern::validate(str_repeat('a', 500)));
        $this->assertStringContainsString('control characters', (string)RulePattern::validate("ab\x01c"));
        $this->assertStringContainsString('UTF-8', (string)RulePattern::validate("\xff\xfe"));

        $error = (string)RulePattern::validate('(abc');
        $this->assertStringStartsWith('Not a valid pattern: ', $error);
        $this->assertStringContainsStringIgnoringCase('parenthesis', $error);
    }

    public function testCatastrophicPatternsAreRejected(): void
    {
        $this->assertStringContainsString('too complex', (string)RulePattern::validate('(a+)+$'));
        $this->assertStringContainsString('too complex', (string)RulePattern::validate('(a|aa)+$'));
    }

    public function testMatchingIsCaseInsensitiveUnicodeAndGuarded(): void
    {
        $re = RulePattern::compile('(^|_)ssn($|_)');
        $this->assertTrue(RulePattern::matches($re, 'EMP_SSN'));
        $this->assertTrue(RulePattern::matches($re, 'ssn'));
        $this->assertFalse(RulePattern::matches($re, 'lesson'));
        $this->assertTrue(RulePattern::matches(RulePattern::compile('^straße$'), 'STRASSE') || RulePattern::matches(RulePattern::compile('^straße$'), 'Straße'));
        // invalid UTF-8 subject: no match, no warning
        $this->assertFalse(RulePattern::matches($re, "\xff ssn"));

        // limits are restored after evaluation
        $before = ini_get('pcre.backtrack_limit');
        RulePattern::matches($re, 'ssn');
        $this->assertSame($before, ini_get('pcre.backtrack_limit'));
    }
}

<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Tests\Unit\Enforcement;

use DreamFactory\Core\Masking\Enforcement\Filter\FieldToken;
use DreamFactory\Core\Masking\Enforcement\Filter\FilterRewriter;
use DreamFactory\Core\Masking\Enforcement\RequestGuard;
use PHPUnit\Framework\TestCase;

/**
 * Red team suspicion (redteam-data): request guards must not rely on df-sqldb rejecting unusual
 * field spellings. Table/schema qualifiers, quote characters, function wrappers, DISTINCT and
 * "AS alias" are normalized before matching masked columns, and the real column name of an
 * aliased field is matched too.
 */
final class FieldTokenTest extends TestCase
{
    private function hidden(): array
    {
        return [
            'ssn' => ['name' => 'ssn', 'column' => 'ssn', 'class' => 'national_id', 'tier' => 'restricted', 'format' => 'redact'],
            'email' => ['name' => 'email', 'column' => 'email', 'class' => 'email', 'tier' => 'identity', 'format' => 'token'],
            // aliased field: clients write "contact", the database column is "contact_email_raw"
            'contact' => ['name' => 'contact', 'column' => 'contact_email_raw', 'class' => 'email', 'tier' => 'identity', 'format' => 'token'],
            'home phone' => ['name' => 'Home Phone', 'column' => 'Home Phone', 'class' => 'phone', 'tier' => 'identity', 'format' => 'token'],
        ];
    }

    /** @return array<string,array{0:string,1:?string}> */
    public static function bareCases(): array
    {
        return [
            'plain' => ['ssn', 'ssn'],
            'case' => ['SSN', 'ssn'],
            'backticks' => ['`ssn`', 'ssn'],
            'double quotes' => ['"ssn"', 'ssn'],
            'brackets' => ['[ssn]', 'ssn'],
            'table-qualified' => ['customers.ssn', 'ssn'],
            'schema-qualified quoted' => ['`crm`.`customers`.`ssn`', 'ssn'],
            'sql server qualified' => ['[dbo].[customers].[ssn]', 'ssn'],
            'spaces around dot' => ['customers . ssn', 'ssn'],
            'function' => ['substr(ssn,1,3)', null],
            'concatenation' => ["ssn || ''", null],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('bareCases')]
    public function testBare(string $token, ?string $expected): void
    {
        $this->assertSame($expected, FieldToken::bare($token));
    }

    /** @return array<string,array{0:string,1:?string,2:list<string>}> filter, result ('NONE' = the always-false filter: matches no rows), dropped */
    public static function readFilters(): array
    {
        return [
            'table-qualified equality on restricted' => ["customers.ssn = '123-45-6789'", 'NONE', ['ssn']],
            'backtick LIKE' => ["`ssn` LIKE '1%'", 'NONE', ['ssn']],
            'bracket range' => ['[ssn] > 5', 'NONE', ['ssn']],
            'double-quoted' => ["\"ssn\" = 'x'", 'NONE', ['ssn']],
            'function-wrapped equality' => ["substr(ssn,1,3) = '123'", 'NONE', ['ssn']],
            'length comparison' => ['length(ssn) = 11', 'NONE', ['ssn']],
            'function on identity (equality on a function is not equality on the value)' => ["lower(email) = 'jane@x.io'", 'NONE', ['email']],
            'qualified identity equality stays' => ["customers.email = 'jane@x.io'", "customers.email = 'jane@x.io'", []],
            // the masked term is unknown, so the AND matches no rows
            'operator-less term mentioning a masked column' => ["(\"ssn\" BETWEEN 'a' AND 'b') AND (id > 0)", 'NONE', ['ssn']],
            'real column name of an aliased field' => ["contact_email_raw LIKE '%x%'", 'NONE', ['contact']],
            'field name with a space' => ["Home Phone LIKE '415%'", 'NONE', ['Home Phone']],
            'leading NOT' => ["NOT ssn = 'x'", 'NONE', ['ssn']],
            'unrelated column untouched' => ["tier = 'gold'", "tier = 'gold'", []],
            'masked name inside a literal only' => ["tier = 'ssn'", "tier = 'ssn'", []],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('readFilters')]
    public function testReadFilters(string $filter, ?string $expected, array $dropped): void
    {
        $guard = new RequestGuard($this->hidden());
        $r = $guard->guardRead(['filter' => $filter]);
        $this->assertSame($expected === 'NONE' ? $guard->filters()->falseFilter() : $expected, $r['params']['filter'] ?? null);
        $this->assertSame(array_map(fn ($n) => 'filter:' . $n, $dropped), $r['dropped']);
    }

    public function testWriteFiltersWithUnusualSpellingsAreRefused(): void
    {
        $rewriter = new FilterRewriter($this->hidden() + ['contact_email_raw' => $this->hidden()['contact']]);
        foreach (["customers.ssn = '1'", "substr(ssn,1,3) = '1'", "`email` LIKE 'j%'", "lower(email) = 'x'"] as $filter) {
            $this->assertFalse($rewriter->forWrite($filter)['ok'], $filter);
        }
        $this->assertTrue($rewriter->forWrite("customers.email = 'jane@x.io'")['ok']);
    }

    /** @return array<string,array{0:string,1:array,2:array,3:list<string>}> param, value, expected params, dropped */
    public static function otherParams(): array
    {
        return [
            'order qualified' => ['order', 'customers.ssn desc', [], ['order:ssn']],
            'order quoted' => ['order', 'id, `email` asc', ['order' => 'id'], ['order:email']],
            'order function' => ['order', 'length(ssn) desc,id', ['order' => 'id'], ['order:ssn']],
            'order real column of an alias' => ['order', 'contact_email_raw', [], ['order:contact']],
            'group bracketed' => ['group', '[ssn],tier', ['group' => 'tier'], ['group:ssn']],
            'fields MAX(DISTINCT)' => ['fields', 'id,MAX(DISTINCT ssn)', ['fields' => 'id'], ['fields:ssn']],
            'fields MAX AS alias' => ['fields', 'id,MAX(ssn) AS m', ['fields' => 'id'], ['fields:ssn']],
            'fields MAX qualified' => ['fields', 'MIN(customers.email),id', ['fields' => 'id'], ['fields:email']],
            'fields function' => ['fields', 'id,upper(ssn)', ['fields' => 'id'], ['fields:ssn']],
            // DreamFactory splits on commas too and rejects the "CONCAT(tier" fragment itself
            'fields split CONCAT' => ['fields', 'id,CONCAT(tier,ssn)', ['fields' => 'id,CONCAT(tier'], ['fields:ssn']],
            'fields COUNT allowed' => ['fields', 'COUNT(DISTINCT ssn)', ['fields' => 'COUNT(DISTINCT ssn)'], []],
            'fields plain masked column (masked in the response)' => ['fields', 'id,ssn', ['fields' => 'id,ssn'], []],
            'fields plain masked column with a space' => ['fields', 'id,Home Phone', ['fields' => 'id,Home Phone'], []],
            'fields aggregate over a column with a space' => ['fields', 'id,MAX(Home Phone)', ['fields' => 'id'], ['fields:Home Phone']],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('otherParams')]
    public function testOrderGroupAndFields(string $param, string $value, array $expected, array $dropped): void
    {
        $r = (new RequestGuard($this->hidden()))->guardRead([$param => $value]);
        $this->assertSame($expected, $r['params']);
        $this->assertSame($dropped, $r['dropped']);
    }
}

<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Tests\Unit\Enforcement;

use DreamFactory\Core\Masking\Enforcement\RequestGuard;
use DreamFactory\Core\Masking\Masking\Masker;
use PHPUnit\Framework\TestCase;

final class RequestGuardTest extends TestCase
{
    private const G = "\u{2022}";

    private Masker $masker;

    protected function setUp(): void
    {
        $this->masker = new Masker(str_repeat("\x07", 32));
    }

    private function hidden(): array
    {
        return [
            'ssn' => ['name' => 'ssn', 'column' => 'ssn', 'class' => 'national_id', 'tier' => 'restricted', 'format' => 'last4', 'type' => 'string'],
            'email' => ['name' => 'email', 'column' => 'email', 'class' => 'email', 'tier' => 'identity', 'format' => 'token', 'type' => 'string'],
            'age' => ['name' => 'age', 'column' => 'age', 'class' => 'age', 'tier' => 'quasi', 'format' => 'redact', 'type' => 'integer'],
            'cvv' => ['name' => 'cvv', 'column' => 'cvv', 'class' => 'card_security', 'tier' => 'restricted', 'format' => 'null', 'type' => 'string'],
            'notes' => ['name' => 'Notes', 'column' => 'notes_col', 'class' => 'free_text_pii', 'tier' => 'free_text', 'format' => 'span', 'type' => 'text'],
        ];
    }

    private function guard(): RequestGuard
    {
        return new RequestGuard($this->hidden(), $this->masker);
    }

    // ------------------------------------------------------------------ reads

    public function testFilterOrderGroupFieldsAreGuarded(): void
    {
        $r = $this->guard()->guardRead([
            'filter' => "(name = 'x') OR (ssn LIKE '1%')",
            'order' => 'email desc, name asc',
            'group' => 'email,name',
            'fields' => 'name,MIN(ssn),COUNT(ssn),MAX( email ),SUM(age)',
            'ss_filters' => ['filters' => [['name' => 'ssn', 'operator' => '=', 'value' => '1']]],
            'limit' => 10,
        ]);
        $p = $r['params'];
        $this->assertTrue($r['changed']);
        $this->assertSame("name = 'x'", $p['filter']);
        $this->assertSame('name asc', $p['order']);
        $this->assertSame('name', $p['group']);
        $this->assertSame('name,COUNT(ssn)', $p['fields']);
        // Server-side (role) filters are the admin's access filters: never touched.
        $this->assertSame('ssn', $p['ss_filters']['filters'][0]['name']);
        $this->assertSame(10, $p['limit']);
        $this->assertSame(['filter:ssn', 'order:email', 'group:email', 'fields:ssn', 'fields:email', 'fields:age'], $r['dropped']);
    }

    /** A filter whose comparisons are all unknown matches no rows; order and group on masked columns are left out. */
    public function testUnknownFilterMatchesNoRowsWhileOrderAndGroupGo(): void
    {
        $g = new RequestGuard($this->hidden(), $this->masker, [], ['id']);
        $r = $g->guardRead(['filter' => "ssn = '1'", 'order' => 'ssn', 'group' => 'email', 'fields' => '*']);
        $this->assertSame('(id IS NULL) AND (id IS NOT NULL)', $r['params']['filter']);
        $this->assertSame(['filter:ssn', 'order:ssn', 'group:email'], $r['dropped']);
        $this->assertArrayNotHasKey('order', $r['params']);
        $this->assertArrayNotHasKey('group', $r['params']);
        $this->assertSame('*', $r['params']['fields']);
    }

    public function testDroppedGroupColumnLeavesTheSelectToo(): void
    {
        $r = $this->guard()->guardRead(['fields' => 'email,COUNT(*)', 'group' => 'email']);
        $this->assertArrayNotHasKey('group', $r['params']);
        $this->assertSame('COUNT(*)', $r['params']['fields']);
    }

    public function testFieldsWithOnlyDroppedFunctionsBecomeEmpty(): void
    {
        $r = $this->guard()->guardRead(['fields' => 'MIN(ssn)']);
        $this->assertSame('', $r['params']['fields'], 'empty fields: DreamFactory returns the key fields');
    }

    public function testFilterArraysAndHaving(): void
    {
        $r = $this->guard()->guardRead([
            'filter' => ["email = 'a'", "ssn like '1%'"],
            'having' => "SUM(x) > 3 OR email LIKE 'b%'",
        ]);
        // DreamFactory ignores a filter that is not a string, so it is left as sent.
        $this->assertSame(["email = 'a'", "ssn like '1%'"], $r['params']['filter']);
        $this->assertNotContains('filter:ssn', $r['dropped']);
        // A string `having` is still guarded.
        $this->assertSame('SUM(x) > 3', $r['params']['having']);
        $this->assertContains('having:email', $r['dropped']);
    }

    /**
     * `filter[]=ssn = '<real>'` gave X-DreamFactory-Masking-Rewrites:
     * filter:ssn although DreamFactory ignores array filters and returned every row. Array forms
     * of filter and having are not rewritten and not reported; string forms still are.
     */
    public function testArrayFormFiltersAreNotRewrittenOrReported(): void
    {
        $params = ['count_only' => 'true', 'filter' => ["ssn = '123-45-6789'"], 'having' => ["email LIKE 'b%'"]];
        $r = $this->guard()->guardRead($params);
        $this->assertFalse($r['changed']);
        $this->assertSame([], $r['dropped']);
        $this->assertSame($params, $r['params']);

        $keyed = $this->guard()->guardRead(['filter' => ['a' => "ssn = 'x'", 'b' => ['nested']]]);
        $this->assertSame([], $keyed['dropped']);

        $string = $this->guard()->guardRead(['filter' => "ssn = '123-45-6789'"]);
        $this->assertSame(['filter:ssn'], $string['dropped'], 'the string form is still guarded');
    }

    public function testUnparsableFilterMatchesNoRows(): void
    {
        $r = $this->guard()->guardRead(['filter' => "name = ') OR (ssn LIKE ''1'''"]);
        $this->assertSame('(ssn IS NULL) AND (ssn IS NOT NULL)', $r['params']['filter']);
        $this->assertSame(['filter:*'], $r['dropped']);
    }

    /** Unknown comparisons for by-id requests: id fields DreamFactory compares with "=" / IN. */
    public function testUnknownIdFields(): void
    {
        $g = $this->guard();
        $this->assertSame(['ssn'], $g->unknownIdFields(['ssn'], 1), 'restricted: never by value');
        $this->assertSame(['ssn'], $g->unknownIdFields([' SSN '], 1));
        $this->assertSame(['Notes'], $g->unknownIdFields(['notes_col'], 1), 'the real column of an aliased field');
        $this->assertSame([], $g->unknownIdFields(['email'], 25), 'identity: exact match up to 25 values');
        $this->assertSame(['email'], $g->unknownIdFields(['email'], 26));
        $this->assertSame([], $g->unknownIdFields(['age'], 3), 'quasi: exact match');
        $this->assertSame([], $g->unknownIdFields(['id', 'name'], 100), 'clear id fields');
        $this->assertSame(['ssn', 'cvv'], $g->unknownIdFields(['id', 'ssn', 'cvv'], 1));
        $this->assertSame([], (new RequestGuard([], $this->masker))->unknownIdFields(['ssn'], 1));
    }

    public function testNothingToDoLeavesParamsIdentical(): void
    {
        $params = ['filter' => "(email = 'a') AND (name like 'b%')", 'order' => 'name', 'fields' => 'name,email,COUNT(ssn)'];
        $r = $this->guard()->guardRead($params);
        $this->assertFalse($r['changed']);
        $this->assertSame($params, $r['params']);
        $this->assertSame([], $r['dropped']);
    }

    public function testOrderWithSemicolonIsLeftToDreamFactory(): void
    {
        $r = $this->guard()->guardRead(['order' => 'ssn; drop table x']);
        $this->assertFalse($r['changed']);
    }

    public function testNoHiddenColumnsIsANoOp(): void
    {
        $g = new RequestGuard([], $this->masker);
        $params = ['filter' => "ssn like '1%'", 'order' => 'ssn'];
        $this->assertSame($params, $g->guardRead($params)['params']);
        $this->assertFalse($g->hasExpression(['ssn' => ['expression' => 'x']], []));
        $this->assertTrue($g->checkWriteFilter(['filter' => "ssn like '1%'"])['ok']);
    }

    // ------------------------------------------------------------------ writes

    public function testWriteFilters(): void
    {
        $g = $this->guard();
        $this->assertTrue($g->checkWriteFilter(['filter' => "email = 'a@b.c'"])['ok']);
        $this->assertTrue($g->checkWriteFilter(['ids' => '1,2'])['ok']);
        $like = $g->checkWriteFilter(['filter' => "email LIKE 'a%'"]);
        $this->assertFalse($like['ok']);
        $this->assertSame(['email'], $like['violations']);
        $this->assertFalse($g->checkWriteFilter(['filter' => "ssn = '1'"])['ok']);
        $this->assertTrue($g->checkWriteFilter(['filter' => "ssn IS NULL"])['ok']);
        $uncertain = $g->checkWriteFilter(['filter' => "x = ') OR (email LIKE 1'"]);
        $this->assertFalse($uncertain['ok']);
        $this->assertTrue($uncertain['uncertain']);
    }

    public function testExpressions(): void
    {
        $g = $this->guard();
        $this->assertTrue($g->hasExpression(['resource' => [['name' => ['expression' => 'ssn']]]], []));
        $this->assertTrue($g->hasExpression(['notes' => ['expression' => ['value' => 'ssn']]], []));
        $this->assertTrue($g->hasExpression([['name' => 'x'], ['name' => ['expression' => 'NOW()']]], []));
        $this->assertTrue($g->hasExpression([], ['params' => [':x' => ['expression' => 'ssn']]]));
        $this->assertFalse($g->hasExpression(['resource' => [['name' => 'x', 'meta' => ['a' => 1]]]], ['params' => [':x' => 'y']]));
    }

    public function testWriteBackRemovesMaskedValues(): void
    {
        $m = $this->masker;
        $record = [
            'id' => 7,
            'ssn' => $m->mask('123-45-6789', 'national_id', 'last4'),
            'email' => $m->mask('jane@x.io', 'email', 'token'),
            'age' => null,                       // integer masked to null
            'cvv' => null,                       // null format
            'Notes' => 'Call ' . str_repeat(self::G, 6) . ' back',
            'name' => 'Jane',
        ];
        $r = $this->guard()->stripMaskedValues(['resource' => [$record]]);
        $this->assertSame([['id' => 7, 'name' => 'Jane']], $r['payload']['resource']);
        $this->assertSame(['ssn', 'email', 'age', 'cvv', 'Notes'], $r['removed']);
    }

    public function testWriteBackKeepsNewValues(): void
    {
        $r = $this->guard()->stripMaskedValues(['ssn' => '987-65-4320', 'email' => 'new@x.io', 'Notes' => "bullet \u{2022} list"]);
        $this->assertSame(['ssn' => '987-65-4320', 'email' => 'new@x.io', 'Notes' => "bullet \u{2022} list"], $r['payload']);
        $this->assertSame([], $r['removed']);
    }

    public function testWriteBackNullOnTextColumnIsADeliberateClear(): void
    {
        $r = $this->guard()->stripMaskedValues([['ssn' => null, 'email' => null]]);
        $this->assertSame([['ssn' => null, 'email' => null]], $r['payload']);
    }

    public function testWriteBackSingleRecordAndCaseInsensitiveKeys(): void
    {
        $token = $this->masker->mask('jane@x.io', 'email', 'token');
        $r = $this->guard()->stripMaskedValues(['EMAIL' => $token, 'name' => 'x']);
        $this->assertSame(['name' => 'x'], $r['payload']);
    }

    public function testRecordsHelper(): void
    {
        $this->assertSame([['a' => 1]], RequestGuard::records(['resource' => [['a' => 1], 'junk']]));
        $this->assertSame([['a' => 1], ['b' => 2]], RequestGuard::records([['a' => 1], ['b' => 2]]));
        $this->assertSame([['a' => 1]], RequestGuard::records(['a' => 1]));
        $this->assertSame([], RequestGuard::records(null));
        $this->assertSame([['x' => 1]], RequestGuard::records(['data' => [['x' => 1]]], 'data'));
    }
}

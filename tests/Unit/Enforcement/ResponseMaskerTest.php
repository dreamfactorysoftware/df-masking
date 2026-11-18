<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Tests\Unit\Enforcement;

use DreamFactory\Core\Masking\Enforcement\ErrorScrubber;
use DreamFactory\Core\Masking\Enforcement\ResponseMasker;
use DreamFactory\Core\Masking\Enforcement\SpecMasker;
use DreamFactory\Core\Masking\Masking\Masker;
use PHPUnit\Framework\TestCase;

final class ResponseMaskerTest extends TestCase
{
    private const G = "\u{2022}";

    private Masker $m;
    private ResponseMasker $rm;

    protected function setUp(): void
    {
        $this->m = new Masker(str_repeat("\x05", 32));
        $this->rm = new ResponseMasker($this->m);
    }

    private function hidden(): array
    {
        return [
            'ssn' => ['name' => 'ssn', 'class' => 'national_id', 'format' => 'last4'],
            'email' => ['name' => 'Email', 'class' => 'email', 'format' => 'token'],
            'salary' => ['name' => 'salary', 'class' => 'financial_personal', 'format' => 'redact'],
        ];
    }

    private function contact(int $id): array
    {
        return ['id' => $id, 'name' => 'Jane ' . $id, 'Email' => "jane$id@x.io", 'ssn' => "123-45-678$id", 'salary' => 84500 + $id];
    }

    /** The single pass gives exactly maskTable() and presentHidden() on every shape. */
    public function testMaskTableReportingEqualsMaskTableAndPresentHidden(): void
    {
        $orders = ['card' => ['name' => 'card', 'class' => 'card_number', 'format' => 'last4']];
        $relations = function (string $rel) use ($orders, &$relations): ?array {
            return $rel === 'orders_by_contact' ? ['hidden' => $orders, 'relations' => null] : null;
        };
        $withOrders = $this->contact(1) + ['orders_by_contact' => [['id' => 9, 'card' => '4111111111111111'], ['id' => 10, 'card' => null]]];
        $shapes = [
            'wrapped' => [['resource' => [$this->contact(1), $this->contact(2)], 'meta' => ['count' => 2]], null],
            'bare list' => [[$this->contact(1)], null],
            'single' => [$this->contact(3), null],
            'related' => [['resource' => [$withOrders, ['id' => 2, 'name' => 'x', 'orders_by_contact' => []]]], null],
            'related only' => [['resource' => [['id' => 1, 'orders_by_contact' => ['id' => 9, 'card' => '4111111111111111']]]], null],
            'as_list' => [['resource' => ['jane@x.io', 'joe@x.io']], ['email']],
            'as_list clear id' => [['resource' => [1, 2]], ['id']],
            'no masked key' => [['resource' => [['id' => 1, 'name' => 'x']]], null],
            'empty' => [['resource' => []], null],
            'count only' => [42, null],
            'other keys next to the wrapper' => [['resource' => [$this->contact(1)], 'extra' => 1], null],
        ];
        foreach ($shapes as $what => [$content, $asList]) {
            [$masked, $present] = $this->rm->maskTableReporting($content, $this->hidden(), $relations, $asList);
            $this->assertSame($this->rm->maskTable($content, $this->hidden(), $relations, $asList), $masked, $what);
            $expected = $this->rm->presentHidden($content, $this->hidden(), $relations, $asList);
            sort($expected);
            sort($present);
            $this->assertSame($expected, $present, $what);
        }
        // presentHidden() keeps working on its own afterwards (no collection left switched on)
        $this->assertSame(['ssn'], $this->rm->presentHidden(['ssn' => '1'], $this->hidden()));
    }

    public function testWrappedListKeepsMeta(): void
    {
        $content = ['resource' => [$this->contact(1), $this->contact(2)], 'meta' => ['count' => 2, 'schema' => ['name' => 'contacts']]];
        $out = $this->rm->maskTable($content, $this->hidden());
        $this->assertSame(['count' => 2, 'schema' => ['name' => 'contacts']], $out['meta']);
        $first = $out['resource'][0];
        $this->assertSame(1, $first['id']);
        $this->assertSame('Jane 1', $first['name']);
        $this->assertSame($this->m->mask('jane1@x.io', 'email', 'token'), $first['Email']);
        $this->assertSame(str_repeat(self::G, 3) . '-' . str_repeat(self::G, 2) . '-6781', $first['ssn']);
        $this->assertNull($first['salary'], 'a number under redact becomes null');
    }

    public function testBareListAndSingleRecord(): void
    {
        $list = $this->rm->maskTable([$this->contact(1)], $this->hidden());
        $this->assertStringStartsWith('EMAIL_', $list[0]['Email']);
        $single = $this->rm->maskTable($this->contact(3), $this->hidden());
        $this->assertStringStartsWith('EMAIL_', $single['Email']);
        $this->assertSame('Jane 3', $single['name']);
    }

    public function testCountOnlyAndEmptyAreLeftAlone(): void
    {
        $this->assertSame(42, $this->rm->maskTable(42, $this->hidden()));
        $this->assertSame(['resource' => []], $this->rm->maskTable(['resource' => []], $this->hidden()));
        $this->assertNull($this->rm->maskTable(null, $this->hidden()));
    }

    public function testNullsStayNullAndKeysAreCaseInsensitive(): void
    {
        $out = $this->rm->maskTable(['EMAIL' => null, 'SSN' => '123-45-6789'], $this->hidden());
        $this->assertNull($out['EMAIL']);
        $this->assertStringEndsWith('6789', $out['SSN']);
        $this->assertStringContainsString(self::G, $out['SSN']);
    }

    public function testAsListMasksIdValues(): void
    {
        $out = $this->rm->maskTable(['resource' => ['jane@x.io', 'joe@x.io']], $this->hidden(), null, ['email']);
        $this->assertSame([$this->m->mask('jane@x.io', 'email', 'token'), $this->m->mask('joe@x.io', 'email', 'token')], $out['resource']);
        $plain = $this->rm->maskTable(['resource' => [1, 2]], $this->hidden(), null, ['id']);
        $this->assertSame([1, 2], $plain['resource']);
        $composite = $this->rm->maskTable(['resource' => ['(1,jane@x.io)']], $this->hidden(), null, ['id', 'email']);
        $this->assertSame([Masker::redacted()], $composite['resource']);
    }

    public function testRelatedRecordsUseTheirOwnPolicy(): void
    {
        $orderHidden = ['card' => ['name' => 'card', 'class' => 'card_number', 'format' => 'last4']];
        $relations = function (string $rel) use ($orderHidden): ?array {
            return match ($rel) {
                'orders_by_contact_id' => ['hidden' => $orderHidden, 'relations' => null],
                'account_by_account_id' => ['hidden' => ['email' => ['name' => 'email', 'class' => 'email', 'format' => 'initial']], 'relations' => null],
                default => null,
            };
        };
        $record = $this->contact(1) + [
            'orders_by_contact_id' => [['id' => 9, 'card' => '4111 1111 1111 1234'], ['id' => 10, 'card' => null]],
            'account_by_account_id' => ['id' => 3, 'email' => 'acme@corp.io'],
            'tags' => ['a', 'b'],
        ];
        $out = $this->rm->maskTable(['resource' => [$record]], $this->hidden(), $relations)['resource'][0];
        $this->assertSame(str_repeat(self::G, 4) . ' ' . str_repeat(self::G, 4) . ' ' . str_repeat(self::G, 4) . ' 1234', $out['orders_by_contact_id'][0]['card']);
        $this->assertNull($out['orders_by_contact_id'][1]['card']);
        $this->assertSame('a' . str_repeat(self::G, 3) . '@' . str_repeat(self::G, 4) . '.io', $out['account_by_account_id']['email']);
        $this->assertSame(['a', 'b'], $out['tags'], 'not a relation: untouched');
    }

    public function testMaskingTwiceIsStable(): void
    {
        $content = ['resource' => [$this->contact(1)]];
        $once = $this->rm->maskTable($content, $this->hidden());
        $this->assertSame($once, $this->rm->maskTable($once, $this->hidden()));
    }

    public function testRoutineResultsBestEffort(): void
    {
        $content = [
            ['customer_email' => 'a@x.io', 'ssn' => '123-45-6789', 'note' => 'call 415-555-0132', 'total' => 42],
            ['out' => ['ssn' => ['111-22-3333', '444-55-6666']]],
            'free text jane@x.io',
        ];
        $out = $this->rm->maskRoutine($content, ['ssn' => ['class' => 'national_id', 'format' => 'redact']]);
        $this->assertSame(Masker::redacted(), $out[0]['ssn']);
        $this->assertSame(str_repeat(self::G, 6), $out[0]['customer_email'], 'unknown column: span masked');
        $this->assertSame('call ' . str_repeat(self::G, 6), $out[0]['note']);
        $this->assertSame(42, $out[0]['total']);
        $this->assertSame([Masker::redacted(), Masker::redacted()], $out[1]['out']['ssn']);
        $this->assertSame('free text ' . str_repeat(self::G, 6), $out[2]);
    }

    // ------------------------------------------------------------------ errors

    public function testPostgresUniqueViolationIsScrubbed(): void
    {
        $msg = "Failed to create records in 'contacts'.\nSQLSTATE[23505]: Unique violation: 7 ERROR:  duplicate key value violates unique constraint &quot;contacts_email_key&quot;\n"
            . "DETAIL:  Key (email)=(jane@example.com) already exists. (Connection: crm, Host: pg, Port: 5432, Database: corpus, SQL: insert into &quot;contacts&quot; (&quot;email&quot;) values (jane@example.com))";
        $out = ErrorScrubber::scrubText($msg, ['contacts', 'email']);
        $this->assertStringNotContainsString('jane@example.com', $out);
        // Integrity violation (class 23): reduced to a fixed text that keeps the SQLSTATE.
        $this->assertSame(sprintf(ErrorScrubber::REDUCED, 'request', '23505'), $out);

        // Other database errors keep their text, with values removed.
        $other = ErrorScrubber::scrubText("Failed to retrieve records from 'contacts'.\nSQLSTATE[42703]: Undefined column: 7 ERROR:  column &quot;emial&quot; does not exist "
            . "(Connection: crm, Host: pg, Port: 5432, Database: corpus, SQL: select * from &quot;contacts&quot; where &quot;email&quot; = 'jane@example.com')", ['contacts', 'email']);
        $this->assertStringNotContainsString('jane@example.com', $other);
        $this->assertStringContainsString("from 'contacts'", $other, 'table name kept');
        $this->assertStringContainsString('Undefined column', $other);
        $this->assertStringContainsString("SQL: \u{2022}\u{2022}\u{2022})", $other);
    }

    public function testMysqlAndSqlServerAndFailingRow(): void
    {
        $mysql = ErrorScrubber::scrubText("SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry 'jane@x.io' for key 'contacts.email'", ['contacts', 'email']);
        $this->assertStringNotContainsString('jane@x.io', $mysql);
        $this->assertSame(sprintf(ErrorScrubber::REDUCED, 'request', '23000'), $mysql);
        // Without SQLSTATE (some drivers, DreamFactory's own wrapping) the fragment is still scrubbed.
        $plain = ErrorScrubber::scrubText("Integrity constraint violation: 1062 Duplicate entry 'jane@x.io' for key 'contacts.email'", ['contacts', 'email']);
        $this->assertStringContainsString("Duplicate entry '\u{2022}\u{2022}\u{2022}' for key", $plain);

        $mssql = ErrorScrubber::scrubText("Cannot insert duplicate key row in object 'dbo.people' with unique index 'ix_ssn'. The duplicate key value is (123-45-6789).");
        $this->assertStringNotContainsString('6789', $mssql);

        $pg = ErrorScrubber::scrubText("null value in column &quot;name&quot; violates not-null constraint\nDETAIL:  Failing row contains (5, null, 123-45-6789, jane@x.io).", ['name']);
        $this->assertStringNotContainsString('6789', $pg);
        $this->assertStringNotContainsString('jane@x.io', $pg);
        $this->assertSame(sprintf(ErrorScrubber::REDUCED_NO_STATE, 'request'), $pg, 'a DETAIL line carries row data');
    }

    public function testQuotedLiteralsAndInvalidUtf8(): void
    {
        $out = ErrorScrubber::scrubText("Invalid value 'O''Brien' for field \"surname\": conversion of &#039;abc&#039; failed", ['surname']);
        $this->assertStringNotContainsString('Brien', $out);
        $this->assertStringNotContainsString('abc', $out);
        $this->assertStringContainsString('"surname"', $out);
        $bin = ErrorScrubber::scrubText("Duplicate entry '\xff\xfesecret' for key 'k'");
        $this->assertStringNotContainsString('secret', $bin);
    }

    public function testBatchErrorContextRecordsAreMasked(): void
    {
        $content = ['error' => [
            'code' => 1000,
            'message' => 'Batch Error: Not all requested records could be created.',
            'context' => [
                'error' => [1 => ['code' => 400, 'message' => "Duplicate entry 'joe@x.io' for key 'email'"]],
                'resource' => [0 => ['id' => 1, 'Email' => 'jane@x.io', 'ssn' => '123-45-6789']],
            ],
        ]];
        $out = ErrorScrubber::scrub($content, ['email'], fn (array $records) => $this->rm->maskTable($records, $this->hidden()));
        $this->assertSame(1000, $out['error']['code']);
        $this->assertStringNotContainsString('joe@x.io', $out['error']['context']['error'][1]['message']);
        $this->assertStringStartsWith('EMAIL_', $out['error']['context']['resource'][0]['Email']);
        $this->assertStringEndsWith('6789', $out['error']['context']['resource'][0]['ssn']);
        $this->assertStringContainsString(self::G, $out['error']['context']['resource'][0]['ssn']);
    }

    public function testBatchErrorEntriesInContextResourceAreScrubbed(): void
    {
        $content = ['error' => [
            'code' => 1000,
            'context' => [
                'error' => [1],
                'resource' => [
                    0 => ['id' => 4, 'Email' => 'ok@x.io'],
                    1 => ['code' => 400, 'context' => null, 'status_code' => 400,
                        'message' => "SQLSTATE[23000]: 1062 Duplicate entry 'dup@x.io' for key 'customers.email' (Connection: crm, SQL: insert into customers (email) values (dup@x.io))"],
                ],
            ],
            'message' => 'Batch Error: Not all requested records could be created.',
        ]];
        $out = ErrorScrubber::scrub($content, ['customers', 'email'], fn (array $records) => $this->rm->maskTable($records, $this->hidden()));
        $entries = $out['error']['context']['resource'];
        $this->assertStringStartsWith('EMAIL_', $entries[0]['Email']);
        $this->assertStringNotContainsString('dup@x.io', $entries[1]['message']);
        $this->assertSame(400, $entries[1]['code']);
    }

    public function testDreamFactoryGuidanceStaysReadable(): void
    {
        $content = ['error' => ['code' => 400, 'context' => null, 'message' => "No record(s) detected in request. Please make sure record(s) are wrapped in a 'resource' tag. Example: {&quot;resource&quot;:[{&quot;id&quot;:1},{&quot;id&quot;:2}]}"]];
        $out = ErrorScrubber::scrub($content, ['customers']);
        $this->assertSame($content, $out);
    }

    // ------------------------------------------------------------------ _spec model

    public function testSpecModelSamplesAndEnumsAreMasked(): void
    {
        $model = [
            'service' => 'crm',
            'tables' => [
                'contacts' => [
                    'columns' => [['name' => 'id', 'type' => 'integer'], ['name' => 'email', 'type' => 'string']],
                    'row_count' => 3,
                    'sample_data' => [['id' => 1, 'email' => 'jane@x.io', 'ssn' => '123-45-6789', 'status' => 'active']],
                    'enum_values' => ['status' => ['active', 'closed'], 'gender' => ['F', 'M']],
                ],
                'products' => ['columns' => [], 'sample_data' => [['sku' => 'A1']]],
            ],
            'relationships' => [],
        ];
        $hiddenFor = fn (string $t) => $t === 'contacts' ? [
            'email' => ['name' => 'email', 'class' => 'email', 'format' => 'token'],
            'ssn' => ['name' => 'ssn', 'class' => 'national_id', 'format' => 'redact'],
            'gender' => ['name' => 'gender', 'class' => 'gender', 'format' => 'redact'],
        ] : [];
        $r = (new SpecMasker($this->rm))->mask($model, $hiddenFor);
        $this->assertTrue($r['changed']);
        $c = $r['model']['tables']['contacts'];
        $this->assertStringStartsWith('EMAIL_', $c['sample_data'][0]['email']);
        $this->assertSame(Masker::redacted(), $c['sample_data'][0]['ssn']);
        $this->assertSame('active', $c['sample_data'][0]['status']);
        $this->assertSame(['status' => ['active', 'closed']], $c['enum_values']);
        $this->assertSame([['sku' => 'A1']], $r['model']['tables']['products']['sample_data']);
        $this->assertSame($model['tables']['contacts']['columns'], $c['columns']);
    }
}

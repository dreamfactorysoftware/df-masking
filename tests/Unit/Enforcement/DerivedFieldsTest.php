<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Tests\Unit\Enforcement;

use DreamFactory\Core\Database\Schema\ColumnSchema;
use DreamFactory\Core\Database\Schema\TableSchema;
use DreamFactory\Core\Masking\Enforcement\DerivedFields;
use DreamFactory\Core\Masking\Enforcement\Listener;
use DreamFactory\Core\Masking\Enforcement\Policy;
use DreamFactory\Core\Masking\Enforcement\TableTarget;
use DreamFactory\Core\Masking\Masking\Masker;
use DreamFactory\Core\Masking\Scanner\SchemaReader;
use DreamFactory\Core\Masking\Support\PolicyVersion;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use DreamFactory\Core\Utility\ServiceResponse;

/**
 * A field DreamFactory computes with a SELECT db_function
 * (virtual field, or a real column with a SELECT override) inherits the strictest masking of the
 * masked columns its expression reads; subqueries and unknown identifiers are "review" (masked,
 * redact). Applies inline (enforcement, unknown fields), at scan time and to FILTER functions.
 */
final class DerivedFieldsTest extends EnforcementHarness
{
    private function virtual(string $name, string $function, string $type = 'string'): array
    {
        return [$name, $type, null, null, null, ['is_virtual' => true, 'db_function' => [['use' => ['SELECT'], 'function' => $function]]]];
    }

    private function contacts(array $extra): void
    {
        $this->defineTable('contacts', array_merge([
            ['id', 'id', 'clear', null, null],
            ['first_name', 'string', 'masked', 'person_name', 'identity'],
            ['last_name', 'string', 'masked', 'person_name', 'identity'],
            ['email', 'string', 'masked', 'email', 'identity'],
            ['ssn', 'string', 'masked', 'national_id', 'restricted'],
            ['city', 'string', 'clear', null, null],
        ], $extra));
    }

    public function testVirtualFieldBuiltFromMaskedColumnsIsMasked(): void
    {
        // The reported case: contact_line = CONCAT(first_name,' ',last_name,' <',email,'> ',ssn).
        $this->contacts([$this->virtual('contact_line', "CONCAT(first_name,' ',last_name,' <',email,'> ',ssn)")]);
        $row = ['id' => 1, 'email' => 'jane@x.io', 'contact_line' => 'Jane Doe <jane@x.io> ' . self::SSN];
        $response = $this->tableFlow($this->request('GET', ['fields' => 'id,email,contact_line']), new ServiceResponse(['resource' => [$row]]), 'contacts');
        $out = $response->getContent()['resource'][0];
        $this->assertSame(Masker::redacted(), $out['contact_line'], 'restricted wins: redact');
        $this->assertStringStartsWith('EMAIL_', $out['email']);

        // Stored for the admin UI with its evidence, never a value.
        $stored = $this->db()->table(Tables::COLUMN)->where('table_name', 'contacts')->where('column_name', 'contact_line')->first();
        $this->assertSame('masked', $stored->verdict);
        $this->assertSame('national_id', $stored->class);
        $this->assertStringContainsString('Built from: first_name, last_name, email, ssn', (string)$stored->evidence);
        $this->assertStringNotContainsString('jane', (string)$stored->evidence);
    }

    public function testStoredClearVerdictDoesNotUnmaskAComputedField(): void
    {
        // dm_column says "clear" (e.g. a name-only verdict from before this fix, or a rescan):
        // enforcement still derives from the expression on every request.
        $this->contacts([$this->virtual('label', 'UPPER(email)')]);
        $this->db()->table(Tables::COLUMN)->insert(['service_id' => 10, 'table_name' => 'contacts', 'column_name' => 'label',
            'verdict' => 'clear', 'class' => null, 'tier' => null, 'score' => 0, 'source' => 'detected']);
        PolicyVersion::bump();
        $response = $this->tableFlow($this->request('GET'), new ServiceResponse([['id' => 1, 'label' => 'JANE@X.IO']]), 'contacts');
        $this->assertStringStartsWith('EMAIL_', $response->getContent()[0]['label'], 'single masked column: its format (token)');
    }

    public function testAdminDecisionsOnTheSourcesAndOnTheFieldAreHonored(): void
    {
        $this->contacts([$this->virtual('who', 'CONCAT(first_name, city)')]);
        $this->tableFlow($this->request('GET'), new ServiceResponse([['id' => 1]]), 'contacts'); // inline classification
        // An admin marks first_name not sensitive: the computed field follows at once.
        $this->db()->table(Tables::COLUMN)->where('table_name', 'contacts')->where('column_name', 'first_name')
            ->update(['verdict' => 'clear', 'class' => null, 'tier' => null, 'source' => 'admin']);
        $this->db()->table(Tables::COLUMN)->where('table_name', 'contacts')->where('column_name', 'who')
            ->update(['verdict' => 'clear', 'class' => null, 'tier' => null, 'source' => 'admin']);
        PolicyVersion::bump();
        Policy::forget();
        $this->listener = new Listener(new Masker(str_repeat("\x03", 32)));
        $response = $this->tableFlow($this->request('GET'), new ServiceResponse([['id' => 1, 'who' => 'Jane Paris']]), 'contacts');
        $this->assertSame('Jane Paris', $response->getContent()[0]['who'], 'admin decisions stand');
    }

    public function testUncheckableExpressionsAreReview(): void
    {
        $this->contacts([
            $this->virtual('sub', '(SELECT MAX(x) FROM other)'),
            $this->virtual('unknown', 'CONCAT(city, secret_col)'),
            $this->virtual('plain', "CONCAT(city, '-', id)"),
            $this->virtual('n', 'COUNT(ssn)', 'integer'),
        ]);
        $response = $this->tableFlow($this->request('GET'), new ServiceResponse([['id' => 1, 'sub' => 'a', 'unknown' => 'b', 'plain' => 'Paris-1', 'n' => 3]]), 'contacts');
        $row = $response->getContent()[0];
        $this->assertSame(Masker::redacted(), $row['sub'], 'subquery: review, redact');
        $this->assertSame(Masker::redacted(), $row['unknown'], 'unknown identifier: review, redact');
        $this->assertSame('Paris-1', $row['plain'], 'only clear columns: clear');
        $this->assertSame(3, $row['n'], 'COUNT returns a number of rows');
        $stored = $this->db()->table(Tables::COLUMN)->where('table_name', 'contacts')->where('column_name', 'sub')->first();
        $this->assertSame('review', $stored->verdict);
        $this->assertStringContainsString(DerivedFields::UNCHECKED_TEXT, (string)$stored->evidence);
    }

    public function testSelectOverrideOnARealColumnIsCovered(): void
    {
        // A clear column whose SELECT db_function reads ssn.
        $this->contacts([['ref', 'string', 'clear', null, null, ['db_function' => [['use' => ['SELECT'], 'function' => 'RIGHT(ssn, 4)']]]]]);
        $response = $this->tableFlow($this->request('GET'), new ServiceResponse([['id' => 1, 'ref' => '6789']]), 'contacts');
        $this->assertSame(Masker::redacted(), $response->getContent()[0]['ref']);
    }

    public function testPartialFormatsOverSeveralColumnsBecomeRedact(): void
    {
        $entries = [
            'first_name' => ['class' => 'person_name', 'tier' => 'identity', 'format' => 'initial', 'verdict' => 'masked'],
            'email' => ['class' => 'email', 'tier' => 'identity', 'format' => 'initial', 'verdict' => 'review'],
        ];
        $this->assertSame('redact', DerivedFields::strictest($entries)['format']);
        $this->assertSame('masked', DerivedFields::strictest($entries)['verdict']);
        $this->assertSame('initial', DerivedFields::strictest(['email' => $entries['email']])['format']);
        $this->assertSame('review', DerivedFields::strictest(['email' => $entries['email']])['verdict']);
    }

    /** @return array<string,array{0:string,1:list<string>,2:bool}> */
    public static function expressions(): array
    {
        return [
            'concat' => ["CONCAT(first_name, ' ', last_name)", ['first_name', 'last_name'], false],
            'qualified and quoted' => ['`contacts`.`email` || "ssn" || [city]', ['email', 'ssn', 'city'], false],
            'pg cast and literal prefix' => ["email::text || E'\\n' || ssn::character varying", ['email', 'ssn'], false],
            'extract from' => ['EXTRACT(YEAR FROM dob)', ['dob'], false],
            'case' => ["CASE WHEN ssn IS NULL THEN 'none' ELSE 'has' END", ['ssn'], false],
            'keyword-named column' => ['UPPER(user)', ['user'], false],
            'literal only' => ["'ssn' || 'email'", [], false],
            'subquery' => ['(SELECT ssn FROM t)', ['ssn'], true],
            'unknown' => ['CONCAT(email, nothing_here)', ['email'], true],
            'variable' => ['@secret', [], true],
            'unterminated' => ["CONCAT(email, 'x)", ['email'], true],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('expressions')]
    public function testReferences(string $expression, array $refs, bool $unresolved): void
    {
        $columns = [];
        foreach (['first_name', 'last_name', 'email', 'ssn', 'city', 'dob', 'user'] as $c) {
            $columns[$c] = $c;
        }
        $r = DerivedFields::references($expression, $columns);
        $this->assertSame($refs, $r['refs']);
        $this->assertSame($unresolved, $r['unresolved']);
    }

    public function testScanTimeDerivation(): void
    {
        $plan = [
            ['name' => 'id', 'virtual' => false, 'select_fn' => null],
            ['name' => 'email', 'virtual' => false, 'select_fn' => null],
            ['name' => 'ssn', 'virtual' => false, 'select_fn' => null],
            ['name' => 'contact_line', 'virtual' => true, 'select_fn' => 'CONCAT(email, ssn)'],
            ['name' => 'plain', 'virtual' => true, 'select_fn' => 'id + 1'],
        ];
        $result = fn (string $v, ?string $class, ?string $tier, int $score) => ['result' => ['verdict' => $v, 'class' => $class, 'tier' => $tier, 'score' => $score,
            'evidence' => ['total' => $score, 'lines' => [['points' => 0, 'kind' => 'name', 'text' => 'Column name']]], 'source' => 'detected']];
        $columns = [
            'id' => $result('clear', null, null, 0),
            'email' => $result('masked', 'email', 'identity', 90),
            'ssn' => $result('masked', 'national_id', 'restricted', 95),
            'contact_line' => $result('clear', null, null, 0),
            'plain' => $result('clear', null, null, 0),
        ];
        $out = DerivedFields::applyToScan($columns, $plan);
        $cl = $out['contact_line']['result'];
        $this->assertSame('masked', $cl['verdict']);
        $this->assertSame('national_id', $cl['class']);
        $this->assertSame('restricted', $cl['tier']);
        $this->assertSame(95, $cl['score']);
        $this->assertSame('Built from: email, ssn', $cl['evidence']['lines'][0]['text']);
        $this->assertSame($columns['plain'], $out['plain']);
        $this->assertSame($columns['email'], $out['email']);
    }

    public function testSchemaReaderPlanCarriesTheSelectFunction(): void
    {
        $ts = new TableSchema(['name' => 'contacts']);
        $ts->addColumn(new ColumnSchema(['name' => 'email', 'type' => 'string', 'db_type' => 'varchar']));
        $ts->addColumn(new ColumnSchema(['name' => 'contact_line', 'type' => 'string', 'is_virtual' => true,
            'db_function' => [['use' => ['SELECT'], 'function' => 'CONCAT(email, ssn)']]]));
        $plan = SchemaReader::describe($ts, 'mysql')['plan']['columns'];
        $this->assertSame([null, 'CONCAT(email, ssn)'], array_column($plan, 'select_fn'));
        $this->assertSame([false, true], array_column($plan, 'virtual'));
        $this->assertSame([true, false], array_column($plan, 'sampled'));
    }

    public function testFilterFunctionsReadingMaskedColumnsAreGuarded(): void
    {
        // tier is clear, but DreamFactory filters it through a function of ssn.
        $this->defineTable('accounts', [
            ['id', 'id', 'clear', null, null],
            ['ssn', 'string', 'masked', 'national_id', 'restricted'],
            ['tier', 'string', 'clear', null, null, ['db_function' => [['use' => ['FILTER'], 'function' => 'SUBSTR(ssn, 1, 3)']]]],
        ]);
        $request = $this->request('GET', ['filter' => "(tier = '123') OR (id > 0)"]);
        $response = $this->tableFlow($request, new ServiceResponse([['id' => 1, 'tier' => 'gold']]), 'accounts');
        $this->assertSame('id > 0', $request->getParameter('filter'), 'the comparison through the function is unknown');
        $this->assertSame('filter:tier', $response->getHeaders()[Listener::HEADER_REWRITES]);
        $this->assertSame('gold', $response->getContent()[0]['tier'], 'values of tier are not masked');
    }

    public function testComputedFieldsAreSkippedInPreviewAndOffLikeAnyOther(): void
    {
        $this->contacts([$this->virtual('contact_line', 'CONCAT(email, ssn)')]);
        Settings::set('mode', 'off');
        $content = [['id' => 1, 'contact_line' => 'jane@x.io' . self::SSN]];
        $response = $this->tableFlow($this->request('GET'), new ServiceResponse($content), 'contacts');
        $this->assertSame($content, $response->getContent());
        $this->assertSame([], $response->getHeaders());
        $this->assertFalse(TableTarget::resolve('crm', 'contacts')->fields['contact_line']['select_fn'] === null);
    }
}

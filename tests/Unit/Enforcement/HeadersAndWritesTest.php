<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Tests\Unit\Enforcement;

use DreamFactory\Core\Events\PreProcessApiEvent;
use DreamFactory\Core\Exceptions\BadRequestException;
use DreamFactory\Core\Exceptions\ForbiddenException;
use DreamFactory\Core\Masking\Enforcement\Headers;
use DreamFactory\Core\Masking\Enforcement\Listener;
use DreamFactory\Core\Masking\Masking\Masker;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use DreamFactory\Core\Utility\ServiceResponse;
use Illuminate\Http\Request;

/**
 * Masking headers name only masked columns present in the
 * response, are capped at 1024 bytes and percent-encode names; Preview adds no header and its
 * activity counts present columns only. Inserts of masked placeholders are refused. A package
 * export of covered table data by a masked caller is refused.
 */
final class HeadersAndWritesTest extends EnforcementHarness
{
    // ------------------------------------------------------------------ masking headers

    public function testPreviewAddsNoHeadersAndLogsOnlyPresentColumns(): void
    {
        Settings::set('mode', 'preview');
        $none = $this->tableFlow($this->request('GET', ['fields' => 'id,tier']), new ServiceResponse(['resource' => [['id' => 1, 'tier' => 'gold']]]), 'customers');
        $this->assertSame([], $none->getHeaders(), 'no masked column in the response: no headers');
        $this->assertSame(0, $this->db()->table(Tables::ACTIVITY)->where('kind', 'preview')->count(), 'and no activity row');

        $some = $this->tableFlow($this->request('GET', ['fields' => 'id,ssn']), new ServiceResponse(['resource' => [['id' => 1, 'ssn' => self::SSN]]]), 'customers');
        $this->assertSame([], $some->getHeaders(), 'Preview adds no headers');
        $row = $this->db()->table(Tables::ACTIVITY)->where('kind', 'preview')->first();
        $this->assertSame('Would mask 1 column', $row->text);
        $this->assertSame(['columns' => ['ssn']], json_decode((string)$row->meta, true));
        $this->assertSame(self::SSN, $some->getContent()['resource'][0]['ssn'], 'preview never changes values');
    }

    public function testOnSendsItsHeaderOnlyWhenSomethingMaskedIsPresent(): void
    {
        $none = $this->tableFlow($this->request('GET', ['fields' => 'id,tier']), new ServiceResponse(['resource' => [['id' => 1, 'tier' => 'gold']]]), 'customers');
        $this->assertArrayNotHasKey(Listener::HEADER_MASKED_FIELDS, $none->getHeaders());
        $count = $this->tableFlow($this->request('GET', ['count_only' => true]), new ServiceResponse(42), 'customers');
        $this->assertSame([], $count->getHeaders());
        $some = $this->tableFlow($this->request('GET', ['fields' => 'id,email']), new ServiceResponse(['resource' => [['id' => 1, 'email' => 'jane@x.io']]]), 'customers');
        $this->assertSame('email', $some->getHeaders()[Listener::HEADER_MASKED_FIELDS]);
    }

    public function testMaskedFieldsListsPresentFieldsEvenWhenTheValueIsNull(): void
    {
        $response = $this->tableFlow(
            $this->request('GET', ['fields' => 'id,email,ssn,tier']),
            new ServiceResponse(['resource' => [['id' => 1, 'email' => null, 'ssn' => null, 'tier' => 'gold']]]),
            'customers'
        );
        $this->assertSame('email, ssn', $response->getHeaders()[Listener::HEADER_MASKED_FIELDS]);
    }

    public function testRewritesIsReportedEvenWhenTheResponseHasNoMaskedColumn(): void
    {
        $request = $this->request('GET', ['fields' => 'id', 'filter' => "ssn LIKE '1%'", 'order' => 'email']);
        $response = $this->tableFlow($request, new ServiceResponse(['resource' => [['id' => 1]]]), 'customers');
        $this->assertSame('filter:ssn, order:email', $response->getHeaders()[Listener::HEADER_REWRITES]);
        $this->assertArrayNotHasKey(Listener::HEADER_MASKED_FIELDS, $response->getHeaders());
    }

    public function testWideTableHeaderIsCappedAndBodyUnchanged(): void
    {
        // 120 masked columns; a default nginx proxy_buffer_size is 4-8 KB for all headers.
        $columns = [['id', 'id', 'clear', null, null]];
        $record = ['id' => 1];
        for ($i = 1; $i <= 120; $i++) {
            $name = sprintf('customer_secondary_email_address_%03d', $i);
            $columns[] = [$name, 'string', 'masked', 'email', 'identity'];
            $record[$name] = "user$i@example.org";
        }
        $this->defineTable('wide_pii', $columns);
        $only = $this->tableFlow($this->request('GET', ['fields' => 'id']), new ServiceResponse(['resource' => [['id' => 1]]]), 'wide_pii');
        $this->assertSame([], $only->getHeaders(), 'fields=id: nothing masked is present');

        $all = $this->tableFlow($this->request('GET'), new ServiceResponse(['resource' => [$record]]), 'wide_pii');
        $header = $all->getHeaders()[Listener::HEADER_MASKED_FIELDS];
        $this->assertLessThanOrEqual(Headers::MAX_BYTES, strlen($header));
        $this->assertMatchesRegularExpression('/^customer_secondary_email_address_001, .*, \+\d+ more$/', $header);
        preg_match('/, \+(\d+) more$/', $header, $m);
        $listed = count(explode(',', $header)) - 1;
        $this->assertSame(120, $listed + (int)$m[1], 'listed + omitted = present');
        $this->assertSame(1, $all->getContent()['resource'][0]['id']);
        $this->assertStringStartsWith('EMAIL_', $all->getContent()['resource'][0]['customer_secondary_email_address_120'], 'every value masked, listed or not');
    }

    public function testNonAsciiNamesArePercentEncoded(): void
    {
        // Header values must be ASCII; names with "," or "%" must not break the list.
        $this->defineTable('kunden', [
            ['id', 'id', 'clear', null, null],
            ['Téléphone', 'string', 'masked', 'phone', 'identity'],
            ['Straße', 'string', 'masked', 'street_address', 'identity'],
            ['a,b%c', 'string', 'masked', 'email', 'identity'],
        ]);
        $rec = ['id' => 1, 'Téléphone' => '+33 1 23 45 67 89', 'Straße' => 'Hauptstraße 1', 'a,b%c' => 'x@y.z'];
        $masked = $this->tableFlow($this->request('GET'), new ServiceResponse([$rec]), 'kunden');
        $header = $masked->getHeaders()[Listener::HEADER_MASKED_FIELDS];
        $this->assertSame('T%C3%A9l%C3%A9phone, Stra%C3%9Fe, a%2Cb%25c', $header);
        $this->assertSame(['Téléphone', 'Straße', 'a,b%c'], array_map(fn ($i) => rawurldecode(trim($i)), explode(',', $header)));

        $request = $this->request('GET', ['fields' => 'id', 'filter' => "Téléphone like '+33%'", 'order' => 'Straße']);
        $on = $this->tableFlow($request, new ServiceResponse([['id' => 1]]), 'kunden');
        $this->assertSame('filter:T%C3%A9l%C3%A9phone, order:Stra%C3%9Fe', $on->getHeaders()[Listener::HEADER_REWRITES]);
        foreach ($on->getHeaders() as $value) {
            $this->assertMatchesRegularExpression('/^[\x20-\x7E]*$/', (string)$value);
        }
    }

    public function testHeaderCapHelper(): void
    {
        $this->assertSame('a, b', Headers::capList(['a', 'b'], 10));
        $this->assertSame('aaaa, +2 more', Headers::capList(['aaaa', 'bbbb', 'cccc'], 13));
        $this->assertSame('+3 more', Headers::capList(['aaaa', 'bbbb', 'cccc'], 12), 'the separator counts two bytes');
        $this->assertSame('aaaa, bbbb, cccc', Headers::capList(['aaaa', 'bbbb', 'cccc'], 16), 'fits exactly');
        $this->assertSame('aaaa, bbbb, +2 more', Headers::capList(['aaaa', 'bbbb', 'cccc', 'dddd'], 19));
        $this->assertSame('+1 more', Headers::capList([str_repeat('x', 50)], 10));
        $this->assertSame('filter:%E2%82%AC', Headers::items(['filter:€']));
        $this->assertSame('filter:*', Headers::items(['filter:*']));
    }

    // ------------------------------------------------------------------ masked placeholders in writes

    public function testInsertOfMaskedPlaceholdersIsRefused(): void
    {
        $m = new Masker(str_repeat("\x03", 32));
        foreach ([
            ['resource' => [['name' => 'Copy', 'email' => $m->mask('jane@x.io', 'email', 'token'), 'tier' => 'gold']]],
            ['resource' => [['name' => 'Copy', 'ssn' => Masker::redacted()]]],
            ['name' => 'Copy', 'ssn' => "\u{2022}\u{2022}\u{2022}-\u{2022}\u{2022}-6789"],
        ] as $payload) {
            try {
                $this->tableFlow($this->request('POST', [], $payload), null, 'customers');
                $this->fail('a masked placeholder must not be inserted');
            } catch (BadRequestException $e) {
                $this->assertSame(Listener::INSERT_MESSAGE, $e->getMessage());
            }
        }
        $this->assertGreaterThan(0, $this->db()->table(Tables::ACTIVITY)->where('kind', 'blocked')->count());
    }

    public function testInsertOfRealValuesAndNullsPasses(): void
    {
        $payload = ['resource' => [['name' => 'New Person', 'email' => 'new@x.io', 'ssn' => null, 'tier' => 'gold']]];
        $request = $this->request('POST', [], $payload);
        $this->tableFlow($request, null, 'customers');
        $this->assertSame($payload, $request->getPayloadData(), 'inserts are never rewritten');
    }

    public function testUpdatesStillTreatPlaceholdersAsUnchanged(): void
    {
        $request = $this->request('PATCH', [], ['tier' => 'silver', 'ssn' => Masker::redacted()]);
        $this->tableFlow($request, null, 'customers/1');
        $this->assertSame(['tier' => 'silver'], $request->getPayloadData());
    }

    // ------------------------------------------------------------------ package export

    private function exportRequest(array $manifest): void
    {
        $this->app->instance('request', Request::create('/api/v2/system/package', 'POST'));
        $none = null;
        $this->listener->onPreProcess(new PreProcessApiEvent('system.package', $this->request('POST', [], $manifest), $none, ''));
    }

    public function testPackageExportOfMaskedTableDataIsRefused(): void
    {
        try {
            $this->exportRequest(['service' => ['crm' => ['_table' => ['customers']]]]);
            $this->fail('expected a 403');
        } catch (ForbiddenException $e) {
            $this->assertSame(Listener::EXPORT_MESSAGE, $e->getMessage());
        }
        $this->assertSame(1, $this->db()->table(Tables::ACTIVITY)->where('kind', 'blocked')->where('text', 'Blocked a package export of masked table data')->count());
    }

    public function testPackageExportWithoutCoveredTableDataPasses(): void
    {
        $this->defineTable('lookup', [['id', 'id', 'clear', null, null], ['label', 'string', 'clear', null, null]]);
        $this->exportRequest(['service' => ['system' => ['role' => ['support']], 'crm' => ['_schema' => ['customers'], '_table' => ['lookup']]]]);
        Settings::set('mode', 'preview');
        $this->exportRequest(['service' => ['crm' => ['_table' => ['customers']]]]);
        $this->assertTrue(true, 'nothing masked is exported: allowed');
    }

    public function testInternalTableReadsDuringAnExportAreRefused(): void
    {
        // Defense in depth: the exporter reads _table data with internal requests.
        $this->app->instance('request', Request::create('/api/v2/system/package', 'POST'));
        $this->expectException(ForbiddenException::class);
        $this->expectExceptionMessage(Listener::EXPORT_MESSAGE);
        $this->tableFlow($this->request('GET'), null, 'customers');
    }
}

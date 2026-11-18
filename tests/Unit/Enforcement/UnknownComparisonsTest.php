<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Tests\Unit\Enforcement;

use DreamFactory\Core\Exceptions\BadRequestException;
use DreamFactory\Core\Exceptions\BatchException;
use DreamFactory\Core\Exceptions\NotFoundException;
use DreamFactory\Core\Masking\Enforcement\ErrorScrubber;
use DreamFactory\Core\Masking\Enforcement\Listener;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Utility\ServiceResponse;

/**
 * Unknown comparisons at the listener: comparisons a masked caller may not make are unknown and match
 * no rows, never more rows, and the answer never depends on the hidden values:
 * filters, related-record filters, and lookups by id (path id, ids, records) on a masked column.
 */
final class UnknownComparisonsTest extends EnforcementHarness
{
    private const NONE = '(id IS NULL) AND (id IS NOT NULL)';

    protected function setUp(): void
    {
        parent::setUp();
        $this->defineTable('orders', [
            ['id', 'id', 'clear', null, null],
            ['customer_id', 'integer', 'clear', null, null],
            ['card', 'string', 'review', 'card_number', 'restricted'],
        ]);
        $this->installServiceManager();
    }

    /** @return array<string,array{0:string,1:string}> filter => what DreamFactory gets */
    public static function filters(): array
    {
        return [
            "ssn = 'x'" => ["ssn = 'x'", self::NONE],
            "state = 'IL' AND ssn = 'x'" => ["(tier = 'IL') AND (ssn = 'x')", self::NONE],
            "state = 'IL' OR ssn = 'x'" => ["(tier = 'IL') OR (ssn = 'x')", "tier = 'IL'"],
            "NOT (ssn = 'x')" => ["NOT (ssn = 'x')", self::NONE],
            'identity exact match stays' => ["email = 'jane@x.io'", "email = 'jane@x.io'"],
            'IS NULL stays' => ['ssn IS NULL', 'ssn IS NULL'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('filters')]
    public function testFiltersOnMaskedColumns(string $filter, string $expected): void
    {
        foreach (['an app without a role' => null, 'an AI session' => 'ai'] as $who => $as) {
            if ($as === 'ai') {
                $this->asAiSession();
            }
            $request = $this->request('GET', ['filter' => $filter, 'include_count' => true]);
            $this->tableFlow($request, null, 'customers');
            $this->assertSame($expected, $request->getParameter('filter'), $who);
            $this->assertTrue($request->getParameter('include_count'), 'count options are DreamFactory\'s own');
        }
    }

    public function testPreviewAndOffNeverChangeFilters(): void
    {
        foreach (['preview', 'off'] as $mode) {
            Settings::set('mode', $mode);
            $request = $this->request('GET', ['filter' => "(tier = 'IL') AND (ssn = 'x')", 'ids' => '1', 'id_field' => 'ssn']);
            $this->tableFlow($request, null, 'customers');
            $this->assertSame(['filter' => "(tier = 'IL') AND (ssn = 'x')", 'ids' => '1', 'id_field' => 'ssn'], $request->getParameters(), $mode);
        }
    }

    public function testRelatedRecordFiltersOnMaskedColumns(): void
    {
        // DreamFactory reads related records with its own internal request and filter.
        $byCard = $this->request('GET', ['filter' => "(card IN ('4111111111111111','x'))", 'fields' => '*']);
        $this->tableFlow($byCard, null, 'orders');
        $this->assertSame(self::NONE, $byCard->getParameter('filter'));
        $byKey = $this->request('GET', ['filter' => '(customer_id IN (1,2,3))', 'fields' => '*']);
        $this->tableFlow($byKey, null, 'orders');
        $this->assertSame('(customer_id IN (1,2,3))', $byKey->getParameter('filter'), 'clear join keys are untouched');
    }

    /** The ids / id_field case: a real and a wrong SSN must get the same answer, without a lookup. */
    public function testLookupsByARestrictedIdFieldFindNothing(): void
    {
        $answers = [];
        foreach ([self::SSN, '000-00-0000'] as $ssn) {
            $answers[] = $this->thrown(fn () => $this->tableFlow($this->request('GET', ['id_field' => 'ssn']), null, 'customers/' . $ssn));
            $answers[] = $this->thrown(fn () => $this->tableFlow($this->request('GET', ['ids' => $ssn . ',1', 'id_field' => 'SSN']), null, 'customers'));
            $answers[] = $this->thrown(fn () => $this->tableFlow($this->request('GET', ['id_field' => 'ssn'], ['resource' => [['ssn' => $ssn]]]), null, 'customers'));
        }
        [$path, $ids, $records] = $answers;
        $this->assertSame([NotFoundException::class, 404, "Record with identifier '" . ErrorScrubber::REPLACEMENT . "' not found."], $path);
        $this->assertSame(BatchException::class, $ids[0]);
        $this->assertSame(400, $ids[1]);
        $this->assertSame('Batch Error: Not all requested records could be retrieved.', $ids[2]);
        // DreamFactory 7.7.1 answers unknown payload records with the same batch error as ids
        // (retrieveRecords -> retrieveRecordsByIds), not df-sqldb's "No records were found ...".
        $this->assertSame([BatchException::class, 400, 'Batch Error: Not all requested records could be retrieved.'], $records);
        $this->assertSame(array_slice($answers, 0, 3), array_slice($answers, 3), 'same answer for a real and a wrong value');
    }

    /**
     * Payload records are recognized the way DreamFactory reads them (ResourcesWrapper::
     * unwrapResources: the wrapper or a JSON list; a bare object carries no records, so a tunneled
     * GET lists rows), and a lookup DreamFactory would run is answered with its own batch error:
     * the first missing record only, every record with continue=true (verified live on 7.7.1).
     */
    public function testRecordLookupsAreAnsweredLikeDreamFactory(): void
    {
        $bare = $this->request('GET', ['id_field' => 'ssn', 'filter' => "tier = 'IL'"], ['ssn' => self::SSN, 'limit' => 5]);
        $this->tableFlow($bare, null, 'customers');
        $this->assertSame("tier = 'IL'", $bare->getParameter('filter'), 'a bare object is no lookup by id: DreamFactory lists rows');

        $answers = [];
        foreach ([self::SSN, '000-00-0000'] as $ssn) {
            foreach ([['resource' => [['ssn' => $ssn], ['ssn' => 'y']]], [['ssn' => $ssn], ['ssn' => 'y']]] as $payload) {
                foreach ([[], ['continue' => 'true']] as $extra) {
                    try {
                        $this->tableFlow($this->request('GET', ['id_field' => 'ssn'] + $extra, $payload), null, 'customers');
                        $this->fail('expected a batch error');
                    } catch (BatchException $e) {
                        $this->assertSame(400, $e->getStatusCode());
                        $this->assertSame('Batch Error: Not all requested records could be retrieved.', $e->getMessage());
                        $this->assertSame($extra === [] ? [0] : [0, 1], array_keys($e->getResponses()));
                        $this->assertSame(['error' => $extra === [] ? [0] : [0, 1]], array_intersect_key($e->toArray()['context'], ['error' => 1]));
                        $first = $e->pickResponse(0);
                        $this->assertInstanceOf(NotFoundException::class, $first);
                        $this->assertSame("Record with identifier '" . ErrorScrubber::REPLACEMENT . "' not found.", $first->getMessage());
                        $answers[] = json_encode($e->toArray());
                    }
                }
            }
        }
        $this->assertSame(array_slice($answers, 0, 4), array_slice($answers, 4), 'same answer for a real and a wrong value');

        // ids follow the same continue rule
        $ids = $this->thrownBatch(fn () => $this->tableFlow($this->request('GET', ['ids' => self::SSN . ',1', 'id_field' => 'ssn']), null, 'customers'));
        $this->assertSame([0], array_keys($ids->getResponses()));
        $ids = $this->thrownBatch(fn () => $this->tableFlow($this->request('GET', ['ids' => self::SSN . ',1', 'id_field' => 'ssn', 'continue' => true]), null, 'customers'));
        $this->assertSame([0, 1], array_keys($ids->getResponses()));
    }

    private function thrownBatch(\Closure $call): BatchException
    {
        try {
            $call();
        } catch (BatchException $e) {
            return $e;
        }
        $this->fail('expected a batch error');
    }

    public function testLookupsByIdentityIdFieldsStayExactMatches(): void
    {
        $request = $this->request('GET', ['ids' => implode(',', array_map(fn ($i) => "u$i@x.io", range(1, 25))), 'id_field' => 'email']);
        $this->tableFlow($request, null, 'customers');
        $this->assertSame('email', $request->getParameter('id_field'), '25 values: allowed');
        $this->tableFlow($this->request('GET', ['id_field' => 'email']), null, 'customers/jane@x.io');
        $this->tableFlow($this->request('GET'), null, 'customers/1'); // the clear primary key

        $tooMany = $this->thrown(fn () => $this->tableFlow($this->request('GET', ['ids' => implode(',', range(1, 26)), 'id_field' => 'email']), null, 'customers'));
        $this->assertSame(BatchException::class, $tooMany[0], 'more than 25 values: unknown');
    }

    public function testWritesByAMaskedIdFieldAreRefused(): void
    {
        $cases = [
            'PATCH path id' => [$this->request('PATCH', ['id_field' => 'ssn'], ['tier' => 'x']), 'customers/' . self::SSN],
            'DELETE ids' => [$this->request('DELETE', ['ids' => self::SSN, 'id_field' => 'ssn']), 'customers'],
            'PUT records' => [$this->request('PUT', ['id_field' => 'ssn'], ['resource' => [['ssn' => self::SSN, 'tier' => 'x']]]), 'customers'],
            'DELETE records' => [$this->request('DELETE', ['id_field' => 'ssn', 'filter' => "tier = 'x'"], ['resource' => [['ssn' => self::SSN]]]), 'customers'],
        ];
        foreach ($cases as $what => [$request, $path]) {
            $answer = $this->thrown(fn () => $this->tableFlow($request, null, $path));
            $this->assertSame(BadRequestException::class, $answer[0], $what);
            $this->assertStringContainsString('(ssn)', $answer[2], $what);
        }
        // An update by a clear filter with a record to write is not a lookup by id.
        $update = $this->request('PATCH', ['id_field' => 'ssn', 'filter' => "tier = 'x'"], ['resource' => [['tier' => 'y']]]);
        $this->tableFlow($update, null, 'customers');
        $this->assertSame("tier = 'x'", $update->getParameter('filter'));
    }

    public function testHeaderNamesTheColumnWhoseConditionsMatchedNothing(): void
    {
        $request = $this->request('GET', ['filter' => "(tier = 'IL') OR (ssn = 'x')"]);
        $response = $this->tableFlow($request, new ServiceResponse(['resource' => []]), 'customers');
        $this->assertSame('filter:ssn', $response->getHeaders()[Listener::HEADER_REWRITES]);
    }

    public function testResourceIdIsReadLikeDreamFactory(): void
    {
        $this->assertSame('5', Listener::resourceId('crm._table.{table_name}.{id}', 'crm', 'customers/5'));
        $this->assertSame('5', Listener::resourceId('crm._table.customers.{id}', 'crm', '5'));
        $this->assertSame('5', Listener::resourceId('crm._table', 'crm', 'customers/5/x/'));
        $this->assertNull(Listener::resourceId('crm._table.customers', 'crm', 'customers'));
        $this->assertNull(Listener::resourceId('crm._table.{table_name}', 'crm', 'customers'));
        $this->assertNull(Listener::resourceId('crm._table', 'crm', 'customers//x'));
        $this->assertNull(Listener::resourceId('crm._proc.{id}', 'crm', 'p/5'));
    }

    /** @return array{0:class-string,1:int,2:string} */
    private function thrown(\Closure $call): array
    {
        try {
            $call();
        } catch (\Throwable $e) {
            return [get_class($e), (int)($e instanceof \DreamFactory\Core\Exceptions\RestException ? $e->getStatusCode() : $e->getCode()), $e->getMessage()];
        }
        $this->fail('expected the request to be answered without a lookup');
    }
}

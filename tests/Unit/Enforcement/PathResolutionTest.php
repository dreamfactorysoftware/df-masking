<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Tests\Unit\Enforcement;

use DreamFactory\Core\Events\ApiEvent;
use DreamFactory\Core\Events\PostProcessApiEvent;
use DreamFactory\Core\Events\PreProcessApiEvent;
use DreamFactory\Core\Exceptions\BadRequestException;
use DreamFactory\Core\Masking\Enforcement\Listener;
use DreamFactory\Core\Masking\Enforcement\RequestContext;
use DreamFactory\Core\Masking\Masking\Masker;
use DreamFactory\Core\Utility\ServiceResponse;

/**
 * DreamFactory adds "{table_name}" to the event name only for
 * one or two path segments, but serves "_table/customers/1/x" (record 1) and
 * "_table/customers//x" (the whole table) too. The table must be resolved from the event's
 * resource path for every _table / _proc / _func event, whatever the segment count.
 * Covers the path shapes DreamFactory serves for table events.
 */
final class PathResolutionTest extends EnforcementHarness
{
    public function testControlTwoSegmentIdIsMasked(): void
    {
        $response = $this->tableFlow($this->request('GET', ['fields' => '*']), new ServiceResponse($this->record()), 'customers/1');
        $this->assertSame(Masker::redacted(), $response->getContent()['ssn']);
    }

    public function testThreeSegmentRecordReadIsMasked(): void
    {
        $response = $this->tableFlow($this->request('GET', ['fields' => '*']), new ServiceResponse($this->record()), 'customers/1/x');
        $this->assertSame(Masker::redacted(), $response->getContent()['ssn'], 'GET _table/customers/1/x returned the real ssn');
        $this->assertStringStartsWith('EMAIL_', $response->getContent()['email']);
        $this->assertSame('name, email, ssn', $response->getHeaders()[Listener::HEADER_MASKED_FIELDS]);
    }

    public function testDoubleSlashTableListIsMasked(): void
    {
        $response = $this->tableFlow($this->request('GET', ['fields' => '*']), new ServiceResponse(['resource' => [$this->record()]]), 'customers//x');
        $this->assertSame(Masker::redacted(), $response->getContent()['resource'][0]['ssn']);
    }

    public function testManySegmentsAndTrailingSlashesAreMasked(): void
    {
        foreach (['customers/1/x/y/z', 'customers///', 'customers/1/'] as $path) {
            $response = $this->tableFlow($this->request('GET', ['fields' => '*']), new ServiceResponse($this->record()), $path);
            $this->assertSame(Masker::redacted(), $response->getContent()['ssn'], $path);
        }
    }

    public function testThreeSegmentFilterGuardRuns(): void
    {
        $request = $this->request('GET', ['fields' => '*', 'filter' => "ssn LIKE '1%'", 'order' => 'email']);
        $this->tableFlow($request, null, 'customers//x');
        $this->assertSame('(id IS NULL) AND (id IS NOT NULL)', $request->getParameter('filter'), 'a LIKE on a restricted column matches no rows');
        $this->assertNull($request->getParameter('order'));
    }

    public function testThreeSegmentWriteBackStripsMaskedValues(): void
    {
        // A client PATCHes back what it read: the masked ssn is "unchanged", never written.
        $request = $this->request('PATCH', [], ['tier' => 'silver', 'ssn' => Masker::redacted()]);
        $this->tableFlow($request, null, 'customers/2/x');
        $this->assertSame(['tier' => 'silver'], $request->getPayloadData(), 'the glyphs would be written into customers.ssn');
    }

    public function testThreeSegmentWriteFilterAndExpressionGuardsRun(): void
    {
        try {
            $this->tableFlow($this->request('PATCH', ['filter' => "ssn LIKE '1%'"], ['resource' => [['tier' => 'x']]]), null, 'customers//x');
            $this->fail('a LIKE write filter on a restricted column must be refused');
        } catch (BadRequestException $e) {
            $this->assertStringContainsString('ssn', $e->getMessage());
        }
        $this->expectException(BadRequestException::class);
        $this->expectExceptionMessage(Listener::EXPRESSION_MESSAGE);
        $this->tableFlow($this->request('PATCH', [], ['tier' => ['expression' => 'ssn']]), null, 'customers/1/x/y');
    }

    public function testFunctionAndProcedureWithExtraSegmentsAreMasked(): void
    {
        foreach ([['_func', '{function_name}'], ['_proc', '{procedure_name}']] as [$resource, $identifier]) {
            $request = $this->request($resource === '_func' ? 'GET' : 'POST');
            $response = new ServiceResponse([['email' => 'jane@x.io', 'note' => 'call 415-555-0132']]);
            $this->tableFlow($request, $response, 'top_customers/x', $resource, $identifier);
            $json = json_encode($response->getContent());
            $this->assertStringNotContainsString('555-0132', $json, $resource);
            $this->assertStringNotContainsString('jane@x.io', $json, $resource);
            $this->assertSame('*', $response->getHeaders()[Listener::HEADER_MASKED_FIELDS], $resource);
        }
    }

    public function testLeadingEmptySegmentIsTheTableList(): void
    {
        // "_table//customers": DreamFactory's resource is "" (it lists table names); nothing to mask.
        $content = ['resource' => [['name' => 'customers'], ['name' => 'orders']]];
        $response = $this->tableFlow($this->request('GET'), new ServiceResponse($content), '/customers');
        $this->assertSame($content, $response->getContent());
        $this->assertSame([], $response->getHeaders());
    }

    public function testTableListIsUntouched(): void
    {
        $content = ['resource' => [['name' => 'customers']]];
        $response = $this->tableFlow($this->request('GET'), new ServiceResponse($content), '');
        $this->assertSame($content, $response->getContent());
    }

    public function testSpecificEventAloneResolvesTheTable(): void
    {
        // Specific events name the table; for two segments their resource is only the id.
        $request = $this->request('GET', ['fields' => '*']);
        $response = new ServiceResponse($this->record());
        $none = null;
        $this->listener->onPreProcess(new PreProcessApiEvent('crm._table.customers.{id}', $request, $none, '1'));
        $this->listener->onPostProcess(new PostProcessApiEvent('crm._table.customers.{id}', $request, $response, '1'));
        $this->assertSame(Masker::redacted(), $response->getContent()['ssn']);
    }

    public function testAliasedTableResolvesLikeDreamFactory(): void
    {
        // A table with an alias is addressed by its alias (BaseDbTableResource::doesTableExist).
        $people = $this->defineTable('people_raw', [
            ['id', 'id', 'clear', null, null],
            ['ssn', 'string', 'masked', 'national_id', 'restricted'],
        ]);
        $people->alias = 'people';
        $response = $this->tableFlow($this->request('GET', ['fields' => '*']), new ServiceResponse(['resource' => [['id' => 1, 'ssn' => self::SSN]]]), 'people/1/x');
        $this->assertSame(Masker::redacted(), $response->getContent()['resource'][0]['ssn']);
    }

    public function testUnresolvableCoveredTableIsWithheldWhenDreamFactoryServesIt(): void
    {
        // Insurance: should DreamFactory ever serve a table enforcement cannot resolve, a masked
        // caller gets nothing (DreamFactory normally answers 404 itself).
        $response = $this->tableFlow($this->request('GET'), new ServiceResponse(['resource' => [['secret' => self::SSN]]]), 'no_such_table/1/x');
        $this->assertSame(500, $response->getStatusCode());
        $this->assertStringNotContainsString(self::SSN, json_encode($response->getContent()));
        $notFound = $this->tableFlow($this->request('GET'), new ServiceResponse(['error' => ['code' => 404, 'message' => 'Table "no_such_table" does not exist in the database.']], null, 404), 'no_such_table');
        $this->assertSame(404, $notFound->getStatusCode(), 'a 404 passes through');
    }

    /** @return array<string,array{0:string,1:mixed,2:?array}> */
    public static function addressedCases(): array
    {
        return [
            'one segment generic' => ['crm._table.{table_name}', 'customers', [RequestContext::TABLE, 'customers']],
            'one segment specific' => ['crm._table.customers', 'customers', [RequestContext::TABLE, 'customers']],
            'two segments generic' => ['crm._table.{table_name}.{id}', 'customers/1', [RequestContext::TABLE, 'customers']],
            'two segments specific (resource = id)' => ['crm._table.customers.{id}', '1', [RequestContext::TABLE, 'customers']],
            'three segments' => ['crm._table', 'customers/1/x', [RequestContext::TABLE, 'customers']],
            'double slash' => ['crm._table', 'customers//x', [RequestContext::TABLE, 'customers']],
            'schema-qualified table' => ['crm._table.sales.customers.{id}', '7', [RequestContext::TABLE, 'sales.customers']],
            'table named like a verb' => ['crm._table.get', 'get', [RequestContext::TABLE, 'get']],
            'leading empty segment' => ['crm._table.{table_name}.{id}', '/customers', null],
            'table list' => ['crm._table', '', null],
            'procedure extra segment' => ['crm._proc', 'p/x', [RequestContext::ROUTINE, 'p']],
            'function specific' => ['crm._func.f', 'f', [RequestContext::ROUTINE, 'f']],
            'schema resource' => ['crm._schema.{table_name}', 'customers', null],
            'other service resource' => ['crm', '', null],
            'another service' => ['crmx._table', 'customers', null],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('addressedCases')]
    public function testAddressed(string $path, mixed $resource, ?array $expected): void
    {
        $this->assertSame($expected, Listener::addressed($path, 'crm', $resource));
    }

    public function testAiIsBlockedOnEveryEventOfAnUncoveredDatabase(): void
    {
        // The service root ("mongo", no resource) as well as its resources.
        foreach (['mongo', 'mongo._table', 'mongo._table.{table_name}', 'mongo._schema'] as $name) {
            $this->asAiSession('/api/v2/mongo');
            $none = null;
            try {
                $this->listener->onPreProcess(new PreProcessApiEvent($name, $this->request('GET'), $none, 'people'));
                $this->fail("$name: expected a 403");
            } catch (\DreamFactory\Core\Exceptions\ForbiddenException $e) {
                $this->assertSame(Listener::AI_BLOCKED_MESSAGE . Listener::AI_TRACE_SUFFIX, $e->getMessage());
            }
        }
    }

    public function testEventPathStripsTheVerbSuffix(): void
    {
        $this->assertSame('crm._table.customers', Listener::eventPath('crm._table.customers.get.pre_process', 'GET'));
        $this->assertSame('crm._table', Listener::eventPath('crm._table.patch.post_process', 'PATCH'));
        $this->assertSame('crm._table.{table_name}', Listener::eventPath('crm._table.{table_name}.delete', 'DELETE'));
        $this->assertSame('crm._table.get', Listener::eventPath('crm._table.get.get.pre_process', 'GET'), 'a table named "get"');
    }

    public function testEventsAreRealDreamFactoryNames(): void
    {
        // Guard against harness drift: DreamFactory appends ".{verb}.pre_process".
        $none = null;
        $event = new PreProcessApiEvent('crm._table', $this->request('GET'), $none, 'customers/1/x');
        $this->assertSame('crm._table.get.pre_process', $event->name);
        $this->assertSame('crm._table.get', (new ApiEvent('crm._table', $this->request('GET'), null, ''))->name);
    }
}

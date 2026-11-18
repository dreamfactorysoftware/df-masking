<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Tests\Unit\Enforcement;

use DreamFactory\Core\Components\InternalServiceRequest;
use DreamFactory\Core\Database\Schema\ColumnSchema;
use DreamFactory\Core\Database\Schema\RelationSchema;
use DreamFactory\Core\Database\Schema\TableSchema;
use DreamFactory\Core\Events\ApiEvent;
use DreamFactory\Core\Events\PostProcessApiEvent;
use DreamFactory\Core\Events\PreProcessApiEvent;
use DreamFactory\Core\Exceptions\BadRequestException;
use DreamFactory\Core\Exceptions\ForbiddenException;
use DreamFactory\Core\Masking\Enforcement\Listener;
use DreamFactory\Core\Masking\Enforcement\Policy;
use DreamFactory\Core\Masking\Enforcement\ServiceClass;
use DreamFactory\Core\Masking\Enforcement\SpecMiddleware;
use DreamFactory\Core\Masking\Enforcement\TableTarget;
use DreamFactory\Core\Masking\Masking\Masker;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use DreamFactory\Core\Masking\Tests\TestCase;
use DreamFactory\Core\Utility\ServiceResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Symfony\Component\HttpFoundation\StreamedResponse;

/**
 * The listener end to end with DreamFactory's real API event and request/response classes, an
 * in-memory system database (policy, settings, activity) and a fake service manager whose
 * "crm" service is a df-sqldb service (covered) and "mongo" a non-SQL database (uncovered).
 * The caller is an anonymous app with no role: masked for every tier.
 */
final class ListenerFlowTest extends TestCase
{
    private const SQLDB = 'DreamFactory\\Core\\SqlDb\\Services\\SqlDb';
    private const NOSQL = 'DreamFactory\\Core\\Database\\Services\\BaseDbService';
    private const G = "\u{2022}";

    private Listener $listener;

    protected function setUp(): void
    {
        if (!class_exists(self::SQLDB) || !class_exists(PreProcessApiEvent::class)) {
            $this->markTestSkipped('needs DreamFactory core and df-sqldb (run inside the DreamFactory image)');
        }
        $this->bootHarness();
        ServiceClass::forget();
        TableTarget::forget();
        Policy::forget();

        $this->db()->table('service')->insert([
            ['id' => 10, 'name' => 'crm', 'type' => 'mysql'],
            ['id' => 11, 'name' => 'mongo', 'type' => 'mongodb'],
        ]);
        $this->app->instance('df.service', $this->fakeServiceManager());
        $this->app->instance('request', Request::create('/api/v2/crm/_table/customers'));

        $rows = [
            ['customers', 'id', 'clear', null, null], ['customers', 'name', 'masked', 'person_name', 'identity'],
            ['customers', 'email', 'masked', 'email', 'identity'], ['customers', 'ssn', 'masked', 'national_id', 'restricted'],
            ['customers', 'tier', 'clear', null, null], ['orders', 'id', 'clear', null, null],
            ['orders', 'customer_id', 'clear', null, null], ['orders', 'card', 'review', 'card_number', 'restricted'],
        ];
        foreach ($rows as [$table, $column, $verdict, $class, $tier]) {
            $this->db()->table(Tables::COLUMN)->insert([
                'service_id' => 10, 'table_name' => $table, 'column_name' => $column, 'verdict' => $verdict,
                'class' => $class, 'tier' => $tier, 'score' => 80, 'source' => 'detected',
            ]);
        }
        Settings::set('mode', 'on');
        $this->listener = new Listener(new Masker(str_repeat("\x03", 32)));
    }

    // ------------------------------------------------------------------ helpers

    private function fakeServiceManager(): object
    {
        $customers = new TableSchema(['name' => 'customers']);
        foreach ([['id', 'id'], ['name', 'string'], ['email', 'string'], ['ssn', 'string'], ['tier', 'string']] as [$n, $t]) {
            $customers->addColumn(new ColumnSchema(['name' => $n, 'type' => $t, 'db_type' => $t === 'id' ? 'int' : 'varchar']));
        }
        $customers->addRelation(new RelationSchema(['type' => 'has_many', 'field' => 'id', 'ref_service_id' => 10, 'ref_table' => 'orders', 'ref_field' => 'customer_id']));
        $orders = new TableSchema(['name' => 'orders']);
        foreach ([['id', 'id'], ['customer_id', 'integer'], ['card', 'string'], ['phone_backup', 'string']] as [$n, $t]) {
            $orders->addColumn(new ColumnSchema(['name' => $n, 'type' => $t, 'db_type' => 'varchar']));
        }
        $crm = $this->createMock(self::SQLDB);
        $crm->method('getTableSchema')->willReturnCallback(fn ($name) => match (strtolower($name)) {
            'customers' => $customers, 'orders' => $orders, default => null,
        });
        $crm->method('getTableNames')->willReturn([]);
        $mongo = $this->createMock(self::NOSQL);

        return new class($crm, $mongo) {
            public function __construct(private $crm, private $mongo)
            {
            }

            public function getServiceTypeByName($name)
            {
                return ['crm' => 'mysql', 'mongo' => 'mongodb', 'system' => 'system'][$name] ?? null;
            }

            public function getServiceIdByName($name)
            {
                return ['crm' => 10, 'mongo' => 11, 'system' => 1][$name] ?? null;
            }

            public function getServiceNameById($id)
            {
                return [10 => 'crm', 11 => 'mongo'][$id] ?? null;
            }

            public function getServiceNameTypeMap($onlyActive = false)
            {
                return ['crm' => 'mysql', 'mongo' => 'mongodb', 'system' => 'system'];
            }

            public function getServiceType($type)
            {
                $group = in_array($type, ['mysql', 'mongodb'], true) ? 'Database' : 'System';

                return new class($group) {
                    public function __construct(private string $group)
                    {
                    }

                    public function getGroup()
                    {
                        return $this->group;
                    }

                    public function getConfigHandler()
                    {
                        return '';
                    }
                };
            }

            public function getService($name)
            {
                return ['crm' => $this->crm, 'mongo' => $this->mongo][$name] ?? throw new \RuntimeException('no service');
            }
        };
    }

    private function request(string $verb, array $params = [], ?array $payload = null): InternalServiceRequest
    {
        $r = new InternalServiceRequest();
        $r->setMethod($verb);
        $r->setParameters($params);
        if ($payload !== null) {
            $r->setContent($payload);
        }

        return $r;
    }

    /** Runs pre-process (generic + specific), then post-process and final events, like RestHandler. */
    private function flow(InternalServiceRequest $request, ?ServiceResponse $response, string $table = 'customers', ?string $id = null): ?ServiceResponse
    {
        $generic = 'crm._table.{table_name}' . ($id !== null ? '.{id}' : '');
        $specific = 'crm._table.' . $table . ($id !== null ? '.{id}' : '');
        $resource = $table . ($id !== null ? '/' . $id : '');
        $none = null;
        $this->listener->onPreProcess(new PreProcessApiEvent($generic, $request, $none, $resource));
        $this->listener->onPreProcess(new PreProcessApiEvent($specific, $request, $none, $id ?? $resource));
        if ($response === null) {
            return null;
        }
        $this->listener->onPostProcess(new PostProcessApiEvent($generic, $request, $response, $resource));
        $this->listener->onPostProcess(new PostProcessApiEvent($specific, $request, $response, $id ?? $resource));
        $this->listener->onFinal(new ApiEvent($generic, $request, $response, $resource));
        $this->listener->onFinal(new ApiEvent($specific, $request, $response, $id ?? $resource));

        return $response;
    }

    private function customers(): array
    {
        return ['resource' => [
            ['id' => 1, 'name' => 'Jane Doe', 'email' => 'jane@x.io', 'ssn' => '123-45-6789', 'tier' => 'gold',
                'orders_by_customer_id' => [['id' => 7, 'customer_id' => 1, 'card' => '4111111111111234', 'phone_backup' => '+1 415-555-0132']]],
        ], 'meta' => ['count' => 1]];
    }

    // ------------------------------------------------------------------ tests

    public function testReadIsMaskedIncludingRelatedRecords(): void
    {
        $response = $this->flow($this->request('GET', ['fields' => '*', 'related' => 'orders_by_customer_id']), new ServiceResponse($this->customers()));
        $rec = $response->getContent()['resource'][0];
        $this->assertSame(1, $rec['id']);
        $this->assertSame('gold', $rec['tier']);
        $this->assertStringStartsWith('EMAIL_', $rec['email']);
        $this->assertStringStartsWith('NAME_', $rec['name']);
        $this->assertSame(Masker::redacted(), $rec['ssn']);
        $this->assertSame(['count' => 1], $response->getContent()['meta']);
        $order = $rec['orders_by_customer_id'][0];
        $this->assertSame(str_repeat(self::G, 12) . '1234', $order['card'], 'review verdict is masked (fail closed) with the class default (last4)');
        // orders.phone_backup was never scanned: classified inline by name and enforced at once
        $this->assertNotSame('+1 415-555-0132', $order['phone_backup']);
        $this->assertSame('name, email, ssn, orders_by_customer_id.card, orders_by_customer_id.phone_backup', $response->getHeaders()[Listener::HEADER_MASKED_FIELDS]);
        $stored = $this->db()->table(Tables::COLUMN)->where('table_name', 'orders')->where('column_name', 'phone_backup')->first();
        $this->assertNotNull($stored);
        $this->assertSame('detected', $stored->source);
        $this->assertNull($stored->scanned_at);
        $this->assertStringNotContainsString('555-0132', (string)$stored->evidence);
    }

    /** Conditions on masked columns are unknown; the AND matches no rows (it used to widen). */
    public function testUnknownFiltersMatchNoRowsAndAreReported(): void
    {
        $request = $this->request('GET', ['filter' => "(tier = 'gold') AND (ssn LIKE '1%')", 'order' => 'email', 'fields' => '*']);
        $response = $this->flow($request, new ServiceResponse(['resource' => []]));
        $this->assertSame('(id IS NULL) AND (id IS NOT NULL)', $request->getParameter('filter'), 'always false, on a real clear column');
        $this->assertNull($request->getParameter('order'));
        $this->assertSame('filter:ssn, order:email', $response->getHeaders()[Listener::HEADER_REWRITES]);
        $activity = $this->db()->table(Tables::ACTIVITY)->where('kind', 'blocked')->pluck('text')->all();
        $this->assertContains('Masked columns could not be used to filter, sort or group', $activity);

        $or = $this->request('GET', ['filter' => "(tier = 'gold') OR (ssn LIKE '1%')"]);
        $this->flow($or, new ServiceResponse(['resource' => []]));
        $this->assertSame("tier = 'gold'", $or->getParameter('filter'), 'OR: the unknown side drops out');
    }

    public function testReadFiltersAreNeverRemoved(): void
    {
        $request = $this->request('GET', ['filter' => "ssn = '1'"]);
        $this->flow($request, null);
        $this->assertSame(['filter' => '(id IS NULL) AND (id IS NOT NULL)'], $request->getParameters());
    }

    public function testWriteBackIgnoresMaskedValues(): void
    {
        $m = new Masker(str_repeat("\x03", 32));
        $payload = ['id' => 1, 'email' => $m->mask('jane@x.io', 'email', 'token'), 'ssn' => Masker::redacted(), 'tier' => 'silver'];
        $request = $this->request('PUT', [], $payload);
        $this->flow($request, null, 'customers', '1');
        $this->assertSame(['id' => 1, 'tier' => 'silver'], $request->getPayloadData());
    }

    public function testOnlyMaskedValuesIsRefused(): void
    {
        $this->expectException(BadRequestException::class);
        $this->flow($this->request('PATCH', [], ['ssn' => Masker::redacted()]), null, 'customers', '1');
    }

    public function testExpressionsAreRefused(): void
    {
        $this->expectException(BadRequestException::class);
        $this->expectExceptionMessage(Listener::EXPRESSION_MESSAGE);
        $this->flow($this->request('PATCH', [], ['tier' => ['expression' => 'ssn']]), null, 'customers', '1');
    }

    public function testLikeInAWriteFilterIsRefused(): void
    {
        $this->expectException(BadRequestException::class);
        $this->flow($this->request('PATCH', ['filter' => "email LIKE '%x%'"], ['resource' => [['tier' => 'x']]]), null);
    }

    public function testEqualityInAWriteFilterIsAllowed(): void
    {
        $request = $this->request('PATCH', ['filter' => "email = 'jane@x.io'"], ['resource' => [['tier' => 'x']]]);
        $this->flow($request, null);
        $this->assertSame("email = 'jane@x.io'", $request->getParameter('filter'));
    }

    public function testErrorsAreScrubbed(): void
    {
        $error = new ServiceResponse(['error' => ['code' => 400, 'context' => null,
            'message' => "Failed to create records in 'customers'.\nSQLSTATE[23000]: 1062 Duplicate entry 'jane@x.io' for key 'customers.email'"]], null, 400);
        $response = $this->flow($this->request('POST', [], ['resource' => [['email' => 'jane@x.io']]]), $error);
        $message = $response->getContent()['error']['message'];
        $this->assertStringNotContainsString('jane@x.io', $message);
        // Integrity violation: a fixed text with the SQLSTATE and the operation.
        $this->assertSame('Database error during insert (SQLSTATE 23000). Data Masking removed the details.', $message);

        // DreamFactory's own messages stay readable (values removed, identifiers kept).
        $own = new ServiceResponse(['error' => ['code' => 400, 'context' => null,
            'message' => "Invalid value 'jane@x.io' for field 'email' in table 'customers'"]], null, 400);
        $message = $this->flow($this->request('PATCH', [], ['tier' => 'x']), $own, 'customers', '1')->getContent()['error']['message'];
        $this->assertStringNotContainsString('jane@x.io', $message);
        $this->assertStringContainsString("'customers'", $message);
        $this->assertStringContainsString("'email'", $message);
    }

    /** DreamFactory's own validation messages name the field the caller sent. */
    public function testValidationMessagesKeepTheCallersFieldNames(): void
    {
        $cases = [
            [['order' => '1', 'limit' => 5], "Invalid field '1' in order by clause."],
            [['filter' => 'nosuchcol=1'], "Invalid or unparsable field in filter request: 'nosuchcol'"],
            [['group' => 'zz'], "Invalid or unknown field 'zz' in group by clause."],
        ];
        foreach ($cases as [$params, $message]) {
            $error = new ServiceResponse(['error' => ['code' => 400, 'context' => null, 'message' => $message]], null, 400);
            $this->assertSame($message, $this->flow($this->request('GET', $params), $error)->getContent()['error']['message']);
        }
        // the database's own text is still reduced: values removed, even a name the caller sent
        $db = new ServiceResponse(['error' => ['code' => 500, 'context' => null,
            'message' => "Failed to retrieve records from 'customers'.\nSQLSTATE[42S22]: Column not found: 1054 Unknown column 'nosuchcol' in 'where clause'"]], null, 500);
        $message = $this->flow($this->request('GET', ['filter' => 'nosuchcol=1']), $db)->getContent()['error']['message'];
        $this->assertStringNotContainsString('nosuchcol', $message);
        $this->assertStringContainsString("'customers'", $message);
    }

    public function testFinalEventRemasksScriptRewrites(): void
    {
        $request = $this->request('GET', ['fields' => '*']);
        $response = new ServiceResponse(['resource' => [['id' => 1, 'email' => 'jane@x.io']]]);
        $none = null;
        $this->listener->onPreProcess(new PreProcessApiEvent('crm._table.{table_name}', $request, $none, 'customers'));
        $this->listener->onPostProcess(new PostProcessApiEvent('crm._table.{table_name}', $request, $response, 'customers'));
        // a post-process script swaps the raw value back in under the masked key
        $response->setContent(['resource' => [['id' => 1, 'email' => 'jane@x.io', 'extra' => 'ok']]]);
        $this->listener->onFinal(new ApiEvent('crm._table.{table_name}', $request, $response, 'customers'));
        $this->assertStringStartsWith('EMAIL_', $response->getContent()['resource'][0]['email']);
        $this->assertSame('ok', $response->getContent()['resource'][0]['extra']);
    }

    public function testPreviewChangesNothingAndOnlyLogs(): void
    {
        Settings::set('mode', 'preview');
        $request = $this->request('GET', ['filter' => "ssn LIKE '1%'", 'fields' => '*']);
        $content = $this->customers();
        $response = $this->flow($request, new ServiceResponse($content));
        $this->assertSame($content, $response->getContent());
        $this->assertSame("ssn LIKE '1%'", $request->getParameter('filter'));
        $this->assertSame([], $response->getHeaders(), 'Preview adds no headers');
        // Present columns only, related records included.
        $row = $this->db()->table(Tables::ACTIVITY)->where('kind', 'preview')->first();
        $this->assertSame('Would mask 5 columns', $row->text);
        $this->assertSame(['name', 'email', 'ssn', 'orders_by_customer_id.card', 'orders_by_customer_id.phone_backup'], json_decode((string)$row->meta, true)['columns']);
        $this->assertSame(1, $this->db()->table(Tables::ACTIVITY)->where('kind', 'preview')->count());
        $this->flow($this->request('GET', ['fields' => '*']), new ServiceResponse($content));
        $this->assertSame(1, $this->db()->table(Tables::ACTIVITY)->where('kind', 'preview')->count(), 'throttled');
    }

    public function testOffIsANoOp(): void
    {
        Settings::set('mode', 'off');
        $request = $this->request('GET', ['filter' => "ssn LIKE '1%'"]);
        $content = $this->customers();
        $response = $this->flow($request, new ServiceResponse($content));
        $this->assertSame($content, $response->getContent());
        $this->assertSame([], $response->getHeaders());
        $this->assertSame(['filter' => "ssn LIKE '1%'"], $request->getParameters());
    }

    public function testAiSessionIsBlockedFromUncoveredDatabases(): void
    {
        $this->app->instance('request', Request::create('/api/v2/mongo/_table/people', 'GET', [], [], [], ['HTTP_X_DREAMFACTORY_TRACE_ID' => 'trace-abcdef12']));
        $none = null;
        $request = $this->request('GET');
        try {
            $this->listener->onPreProcess(new PreProcessApiEvent('mongo._table.{table_name}', $request, $none, 'people'));
            $this->fail('expected a 403');
        } catch (ForbiddenException $e) {
            $this->assertSame(Listener::AI_BLOCKED_MESSAGE . Listener::AI_TRACE_SUFFIX, $e->getMessage());
        }
        $this->assertSame(1, $this->db()->table(Tables::ACTIVITY)->where('kind', 'blocked')->where('target', 'mongo')->count());
    }

    public function testHumansAreNotBlockedFromUncoveredDatabases(): void
    {
        $none = null;
        $this->listener->onPreProcess(new PreProcessApiEvent('mongo._table.{table_name}', $this->request('GET'), $none, 'people'));
        $this->assertTrue(true);
    }

    public function testAiSessionCannotChangeMaskingSettings(): void
    {
        Settings::set('mode', 'off'); // blocked in every mode
        $this->app->instance('request', Request::create('/api/v2/system/data_masking', 'PATCH', [], [], [], ['HTTP_X_DREAMFACTORY_TRACE_ID' => 'trace-abcdef12']));
        $none = null;
        $this->expectException(ForbiddenException::class);
        $this->listener->onPreProcess(new PreProcessApiEvent('system.data_masking', $this->request('PATCH', [], ['mode' => 'off']), $none, 'access'));
    }

    public function testAiSessionMayReadMaskingSettings(): void
    {
        $this->app->instance('request', Request::create('/api/v2/system/data_masking', 'GET', [], [], [], ['HTTP_X_DREAMFACTORY_TRACE_ID' => 'trace-abcdef12']));
        $none = null;
        $this->listener->onPreProcess(new PreProcessApiEvent('system.data_masking', $this->request('GET'), $none, ''));
        $this->assertTrue(true);
    }

    public function testRoutineResultsAreMaskedBestEffort(): void
    {
        $request = $this->request('POST');
        $response = new ServiceResponse([['email' => 'jane@x.io', 'note' => 'call 415-555-0132', 'n' => 3]]);
        $none = null;
        $this->listener->onPreProcess(new PreProcessApiEvent('crm._proc.{procedure_name}', $request, $none, 'top_customers'));
        $this->listener->onPostProcess(new PostProcessApiEvent('crm._proc.{procedure_name}', $request, $response, 'top_customers'));
        $row = $response->getContent()[0];
        $this->assertStringStartsWith('EMAIL_', $row['email']);
        $this->assertSame('call ' . str_repeat(self::G, 6), $row['note']);
        $this->assertSame(3, $row['n']);
    }

    public function testSpecModelSamplesAreMasked(): void
    {
        $request = Request::create('/api/v2/crm/_spec', 'GET', ['model' => 'true']);
        $this->app->instance('request', $request);
        $model = ['service' => 'crm', 'tables' => ['customers' => [
            'columns' => [['name' => 'email', 'type' => 'string']],
            'sample_data' => [['id' => 1, 'email' => 'jane@x.io', 'ssn' => '123-45-6789', 'tier' => 'gold']],
            'enum_values' => ['tier' => ['gold'], 'name' => ['Jane Doe']],
        ]]];
        $json = json_encode($model);
        $calls = 0;
        $stream = new StreamedResponse(function () use ($json, &$calls) {
            $calls++;
            echo $json;
        }, 200, ['Content-Type' => 'application/json; charset=utf-8', 'Cache-Control' => 'no-store']);
        $out = (new SpecMiddleware())->handle($request, fn () => $stream);
        $this->assertInstanceOf(Response::class, $out);
        $this->assertSame(1, $calls, 'the stream callback ran once');
        $this->assertSame('*', $out->headers->get(Listener::HEADER_MASKED_FIELDS));
        $this->assertStringContainsString('no-store', (string)$out->headers->get('Cache-Control'));
        $body = json_decode($out->getContent(), true);
        $t = $body['tables']['customers'];
        $this->assertStringStartsWith('EMAIL_', $t['sample_data'][0]['email']);
        $this->assertSame(Masker::redacted(), $t['sample_data'][0]['ssn']);
        $this->assertSame('gold', $t['sample_data'][0]['tier']);
        $this->assertSame(['tier' => ['gold']], $t['enum_values']);
        $this->assertSame(['name', 'email', 'ssn'], $t['masked_columns']);
        $this->assertStringNotContainsString('jane@x.io', $out->getContent());
    }

    public function testSpecIsUntouchedWhenNotOnOrNotAModel(): void
    {
        $passthrough = new Response('{"openapi":"3.0.0"}');
        $plain = Request::create('/api/v2/crm/_spec', 'GET');
        $this->assertSame($passthrough, (new SpecMiddleware())->handle($plain, fn () => $passthrough));
        Settings::set('mode', 'preview');
        $model = Request::create('/api/v2/crm/_spec', 'GET', ['model' => '1']);
        $this->assertSame($passthrough, (new SpecMiddleware())->handle($model, fn () => $passthrough));
        $other = Request::create('/api/v2/crm/_table/customers', 'GET');
        $this->assertSame($passthrough, (new SpecMiddleware())->handle($other, fn () => $passthrough));
    }

    public function testAiSpecOfAnUncoveredDatabaseIsBlocked(): void
    {
        $request = Request::create('/api/v2/mongo/_spec', 'GET', ['model' => 'true'], [], [], ['HTTP_X_DREAMFACTORY_TRACE_ID' => 'trace-abcdef12']);
        $this->app->instance('request', $request);
        $ran = false;
        $out = (new SpecMiddleware())->handle($request, function () use (&$ran) {
            $ran = true;

            return new Response('{"tables":{"people":{"sample_data":[{"ssn":"123"}]}}}');
        });
        $this->assertFalse($ran, 'the model is never built');
        $this->assertSame(403, $out->getStatusCode());
        $this->assertStringContainsString(Listener::AI_BLOCKED_MESSAGE, $out->getContent());
    }

    public function testNonDatabaseEventsAreIgnored(): void
    {
        $request = $this->request('GET');
        $response = new ServiceResponse(['resource' => [['email' => 'jane@x.io']]]);
        $none = null;
        $this->listener->onPreProcess(new PreProcessApiEvent('files._file.{file_path}', $request, $none, 'a.txt'));
        $this->listener->onPostProcess(new PostProcessApiEvent('files._file.{file_path}', $request, $response, 'a.txt'));
        $this->assertSame('jane@x.io', $response->getContent()['resource'][0]['email']);
    }
}

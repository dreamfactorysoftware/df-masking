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
use DreamFactory\Core\Masking\Enforcement\Listener;
use DreamFactory\Core\Masking\Enforcement\Policy;
use DreamFactory\Core\Masking\Enforcement\ServiceClass;
use DreamFactory\Core\Masking\Enforcement\TableTarget;
use DreamFactory\Core\Masking\Masking\Masker;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use DreamFactory\Core\Masking\Tests\TestCase;
use DreamFactory\Core\Utility\ServiceResponse;
use Illuminate\Http\Request;

/**
 * Shared harness for listener-level regression tests: DreamFactory's real event, request and
 * response classes, the in-memory system database, and a fake service manager whose "crm"
 * service is a df-sqldb service (covered) built from table specs, and "mongo" a non-SQL
 * database (uncovered). The caller is an anonymous app without a role (masked for every tier)
 * unless a test changes the session.
 *
 * Events are fired exactly as DreamFactory fires them (RestHandler / BaseDbTableResource):
 * generic event with the resource path, then the specific event for one or two segments.
 */
abstract class EnforcementHarness extends TestCase
{
    protected const SQLDB = 'DreamFactory\\Core\\SqlDb\\Services\\SqlDb';
    protected const NOSQL = 'DreamFactory\\Core\\Database\\Services\\BaseDbService';
    protected const G = "\u{2022}";
    protected const SSN = '123-45-6789';

    protected Listener $listener;

    /** @var array<string,TableSchema> lower-cased real name => schema */
    protected array $schemas = [];

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
        $this->defineTable('customers', [
            ['id', 'id', 'clear', null, null],
            ['name', 'string', 'masked', 'person_name', 'identity'],
            ['email', 'string', 'masked', 'email', 'identity'],
            ['ssn', 'string', 'masked', 'national_id', 'restricted'],
            ['tier', 'string', 'clear', null, null],
        ]);
        $this->installServiceManager();
        $this->app->instance('request', Request::create('/api/v2/crm/_table/customers'));
        Settings::set('mode', 'on');
        $this->listener = new Listener(new Masker(str_repeat("\x03", 32)));
    }

    /**
     * @param list<array{0:string,1:string,2:?string,3:?string,4:?string,5?:array}> $columns
     *        [name, DreamFactory type, verdict (null = not in dm_column), class, tier, extra column settings]
     */
    protected function defineTable(string $table, array $columns, array $relations = []): TableSchema
    {
        $schema = new TableSchema(['name' => $table]);
        foreach ($columns as $c) {
            [$name, $type, $verdict, $class, $tier] = $c;
            $schema->addColumn(new ColumnSchema(array_merge(
                ['name' => $name, 'type' => $type, 'db_type' => $type === 'id' ? 'int' : 'varchar'],
                $c[5] ?? []
            )));
            if ($verdict !== null) {
                $this->db()->table(Tables::COLUMN)->insert([
                    'service_id' => 10, 'table_name' => $table, 'column_name' => $name, 'verdict' => $verdict,
                    'class' => $class, 'tier' => $tier, 'score' => 80, 'source' => 'detected',
                ]);
            }
        }
        foreach ($relations as $r) {
            $schema->addRelation(new RelationSchema($r));
        }
        $this->schemas[strtolower($table)] = $schema;

        return $schema;
    }

    protected function installServiceManager(): void
    {
        $schemas = &$this->schemas;
        $crm = $this->createMock(self::SQLDB);
        $crm->method('getTableSchema')->willReturnCallback(function ($name) use (&$schemas) {
            return $schemas[strtolower((string)$name)] ?? null;
        });
        $crm->method('getTableNames')->willReturnCallback(function () use (&$schemas) {
            return $schemas;
        });
        $mongo = $this->createMock(self::NOSQL);
        $this->app->instance('df.service', new class ($crm, $mongo) {
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

                return new class ($group) {
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
        });
    }

    protected function request(string $verb, array $params = [], ?array $payload = null): InternalServiceRequest
    {
        $r = new InternalServiceRequest();
        $r->setMethod($verb);
        $r->setParameters($params);
        if ($payload !== null) {
            $r->setContent($payload);
        }

        return $r;
    }

    /**
     * Fires the events DreamFactory fires for "{service}/_table/{$resourcePath}": the generic
     * event (name suffix by segment count, as BaseDbTableResource::getEventName does) with the
     * resource path, then, for one or two segments, the specific event.
     */
    protected function tableFlow(InternalServiceRequest $request, ?ServiceResponse $response, string $resourcePath, string $resource = '_table', string $identifier = '{table_name}'): ?ServiceResponse
    {
        $path = rtrim($resourcePath, '/');
        $segments = $path === '' ? [] : explode('/', $path);
        $base = 'crm.' . $resource;
        $generic = $base . match (count($segments)) {
            1 => '.' . $identifier,
            2 => $resource === '_table' ? '.' . $identifier . '.{id}' : '',
            default => '',
        };
        $events = [[$generic, $path]];
        if (count($segments) === 1) {
            $events[] = [str_replace($identifier, $segments[0], $generic), $path];
        } elseif (count($segments) === 2 && $resource === '_table') {
            $events[] = [str_replace($identifier, $segments[0], $generic), $segments[1]];
        }
        $none = null;
        foreach ($events as [$name, $res]) {
            $this->listener->onPreProcess(new PreProcessApiEvent($name, $request, $none, $res));
        }
        if ($response === null) {
            return null;
        }
        foreach ($events as [$name, $res]) {
            $this->listener->onPostProcess(new PostProcessApiEvent($name, $request, $response, $res));
        }
        foreach ($events as [$name, $res]) {
            $this->listener->onFinal(new ApiEvent($name, $request, $response, $res));
        }

        return $response;
    }

    protected function record(): array
    {
        return ['id' => 1, 'name' => 'Jane Doe', 'email' => 'jane@x.io', 'ssn' => self::SSN, 'tier' => 'gold'];
    }

    protected function asAiSession(string $url = '/api/v2/crm/_table/customers', string $method = 'GET'): void
    {
        $this->app->instance('request', Request::create($url, $method, [], [], [], ['HTTP_X_DREAMFACTORY_TRACE_ID' => 'trace-abcdef12']));
    }
}

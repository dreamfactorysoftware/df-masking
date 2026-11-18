<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Baselines;

use DreamFactory\Core\Components\InternalServiceRequest;
use DreamFactory\Core\Utility\ResponseFactory;
use DreamFactory\Core\Masking\Baselines\BaselineService;
use DreamFactory\Core\Masking\Resources\SecurityBaseline;
use DreamFactory\Core\Masking\Support\Caller;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use DreamFactory\Core\Masking\Tests\TestCase;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Facades\Schema;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\StreamedResponse;

/**
 * system/security_baseline through DreamFactory's RestHandler: who may call it (sys
 * admins only, for reads too), the 409 for mode On before the first scan, and the CSV
 * export (columns, and text/csv whatever the Accept header says).
 */
final class SecurityBaselineResourceTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->bootHarness();
        Schema::table('service', function (Blueprint $t) {
            $t->timestamp('created_date')->nullable();
        });
        Schema::create('service_event_map', function (Blueprint $t) {
            $t->increments('id');
            $t->unsignedInteger('service_id');
            $t->string('event');
        });
        Schema::create('cors_config', function (Blueprint $t) {
            $t->increments('id');
            $t->string('origin');
            $t->boolean('enabled')->default(true);
        });
        DB::table('user')->insert([
            ['id' => 1, 'name' => 'Alex Admin', 'email' => 'k@example.test', 'is_sys_admin' => true],
            ['id' => 5, 'name' => 'App User', 'email' => 'u@example.test', 'is_sys_admin' => false],
        ]);
        BaselineService::$scanStarter = function (): void {
        };
    }

    protected function tearDown(): void
    {
        BaselineService::$scanStarter = null;
        parent::tearDown();
    }

    /** A DreamFactory session with the keys df-core's Session helper reads. */
    private function actAs(?int $userId, bool $sysAdmin, ?int $roleId = null): void
    {
        if (!class_exists('Session', false)) {
            class_alias(\Illuminate\Support\Facades\Session::class, 'Session');
        }
        $store = new Store('df-test', new ArraySessionHandler(60));
        if ($userId !== null) {
            $store->put('user', ['id' => $userId, 'is_sys_admin' => $sysAdmin, 'name' => 'User ' . $userId]);
        }
        $store->put('has_role', $roleId !== null);
        if ($roleId !== null) {
            $store->put('role', ['id' => $roleId]);
        }
        $this->app->instance('session', $store);
        Facade::clearResolvedInstance('session');
        Caller::forget();
    }

    private function call(string $verb, string $path, array $payload = [], array $params = []): array
    {
        $request = new InternalServiceRequest();
        $request->setMethod($verb);
        $request->setParameters($params);
        $request->setPayloadData($payload);
        $response = (new SecurityBaseline(['name' => 'security_baseline']))->handleRequest($request, $path);

        return [$response->getStatusCode(), $response instanceof StreamedResponse ? self::streamed($response) : $response->getContent()];
    }

    private static function streamed(StreamedResponse $response): string
    {
        ob_start();
        try {
            $response->sendContent();
        } finally {
            $body = (string)ob_get_clean();
        }

        return $body;
    }

    /**
     * A GET as DreamFactory's RestController answers it over HTTP: Redirect and Streamed
     * responses go out as they are; anything else goes through ResponseFactory::sendResponse(),
     * which renegotiates the body against the Accept header (null = no Accept header, so
     * DreamFactory's default response type applies).
     *
     * @return array{0:int,1:?string,2:?string,3:string} status, Content-Type, Content-Disposition, body
     */
    private function deliver(string $path, array $params, ?string $accept): array
    {
        if (!class_exists('Request', false)) {
            class_alias(\Illuminate\Support\Facades\Request::class, 'Request');
        }
        $server = $accept === null ? [] : ['HTTP_ACCEPT' => $accept];
        $this->app->instance('request', \Illuminate\Http\Request::create('/api/v2/system/security_baseline/' . $path, 'GET', $params, [], [], $server));
        Facade::clearResolvedInstance('request');
        $this->app['config']->set('df.default_response_type', 'application/json');

        $request = new InternalServiceRequest();
        $request->setMethod('GET');
        $request->setParameters($params);
        if ($accept !== null) {
            $request->setHeaders(['accept' => $accept]);
        }
        $response = (new SecurityBaseline(['name' => 'security_baseline']))->handleRequest($request, $path);
        if (!($response instanceof StreamedResponse || $response instanceof RedirectResponse)) {
            $response = ResponseFactory::sendResponse($response, $request);
        }
        $body = $response instanceof StreamedResponse ? self::streamed($response) : (string)$response->getContent();

        return [
            $response->getStatusCode(),
            $response->headers->get('Content-Type'),
            $response->headers->get('Content-Disposition'),
            $body,
        ];
    }

    private static function message(mixed $body): string
    {
        return is_array($body) ? (string)($body['error']['message'] ?? json_encode($body)) : (string)$body;
    }

    /** A role given system access is still not a sys admin (reads included). */
    public function testOnlySysAdminsCanReadOrWrite(): void
    {
        $this->actAs(5, false, 3);
        [$status, $body] = $this->call('GET', '');
        $this->assertSame(403, $status);
        $this->assertStringContainsString('Only a system administrator can view Compliance baselines', self::message($body));
        $this->assertSame(403, $this->call('GET', 'hipaa/report', [], ['format' => 'csv'])[0]);

        [$status, $body] = $this->call('POST', 'hipaa/apply');
        $this->assertSame(403, $status);
        $this->assertStringContainsString('Only a system administrator can change Compliance baselines', self::message($body));
        $this->assertSame(403, $this->call('DELETE', 'hipaa')[0]);
        $this->assertSame(0, DB::table(Tables::BASELINE)->count(), 'nothing adopted');

        $this->actAs(null, false);
        $this->assertSame(403, $this->call('GET', 'hipaa')[0], 'no session at all');

        $this->actAs(1, true);
        [$status, $body] = $this->call('GET', '');
        $this->assertSame(200, $status);
        $this->assertCount(7, $body['resource']);
    }

    /** Apply with mode on before the first completed scan is a 409. */
    public function testModeOnBeforeTheFirstScanIs409(): void
    {
        $this->actAs(1, true);
        [$status, $body] = $this->call('POST', 'gdpr/apply', ['mode' => 'on']);
        $this->assertSame(409, $status);
        $this->assertSame('Scan your databases before turning masking on.', self::message($body));
        $this->assertSame(0, DB::table(Tables::BASELINE)->count());

        // A finished scan that found columns (the cached first-scan marker alone is not enough).
        DB::table(Tables::SCAN)->insert(['status' => 'done', 'progress' => 100, 'columns_total' => 3, 'columns_done' => 3,
            'started_at' => now(), 'finished_at' => now(), 'created_at' => now(), 'updated_at' => now()]);
        [$status, $body] = $this->call('POST', 'gdpr/apply', ['mode' => 'on']);
        $this->assertSame(200, $status, self::message($body));
        $this->assertFalse($body['scan_started']);
        Settings::flush();
        $this->assertSame('on', Settings::mode());
    }

    /** The CSV export carries the frameworks and the disclaimer. */
    public function testCsvExportCarriesFrameworksAndDisclaimer(): void
    {
        $this->actAs(1, true);
        [$status, $body] = $this->call('GET', 'cjis/report', [], ['format' => 'csv']);
        $this->assertSame(200, $status);
        $rows = array_map(fn ($l) => str_getcsv($l, ',', '"', ''), array_values(array_filter(explode("\n", trim((string)$body)))));
        $this->assertSame(['frameworks', 'disclaimer'], array_slice($rows[0], -2));
        $this->assertSame('FBI CJIS Security Policy v6.1', $rows[1][8]);
        $this->assertStringContainsString('not a certification', $rows[1][9]);
    }

    /**
     * With format=csv the export is CSV whatever the Accept header says (before: Accept:
     * application/json, or no Accept header at all, turned it into JSON rows).
     */
    public function testCsvIgnoresTheAcceptHeader(): void
    {
        $this->actAs(1, true);
        foreach (['application/json', null, '*/*', 'text/csv', 'application/xml'] as $accept) {
            $label = 'Accept: ' . ($accept ?? '(none)');
            [$status, $type, $disposition, $body] = $this->deliver('hipaa/report', ['format' => 'csv'], $accept);
            $this->assertSame(200, $status, $label);
            $this->assertMatchesRegularExpression('#^text/csv(;|$)#', (string)$type, $label);
            $this->assertMatchesRegularExpression('#^attachment; filename="dreamfactory-hipaa-baseline-\d{4}-\d{2}-\d{2}\.csv"$#', (string)$disposition, $label);
            $this->assertStringStartsWith('baseline_id,baseline,control_id,title,status,detail,references,generated_at,frameworks,disclaimer', $body, $label);
            $this->assertNull(json_decode($body, true), $label . ': not JSON');
        }

        // JSON stays DreamFactory's ordinary response.
        [$status, $type, , $body] = $this->deliver('hipaa/report', [], 'application/json');
        $this->assertSame(200, $status);
        $this->assertSame('application/json', $type);
        $this->assertSame('hipaa', json_decode($body, true)['baseline']['id'] ?? null);
        // Errors stay JSON errors.
        [$status, , , $body] = $this->deliver('hipaa/report', ['format' => 'xml'], null);
        $this->assertSame(400, $status);
        $this->assertStringContainsString("format must be 'json' or 'csv'", $body);
    }
}

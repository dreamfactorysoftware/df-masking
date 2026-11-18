<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Tests\Unit\Enforcement;

use DreamFactory\Core\Masking\Enforcement\Listener;
use DreamFactory\Core\Masking\Enforcement\SpecMasker;
use DreamFactory\Core\Masking\Enforcement\SpecMiddleware;
use DreamFactory\Core\Masking\Enforcement\ResponseMasker;
use DreamFactory\Core\Masking\Masking\Masker;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Routing\Route;
use Symfony\Component\HttpFoundation\StreamedResponse;

/**
 * Every request DreamFactory answers as a _spec model (to_bool
 * semantics for model, any route shape, any service case, decoded paths, ".." removed) must be
 * masked in mode On; the same matcher gates the AI block for uncovered databases.
 */
final class SpecRequestTest extends EnforcementHarness
{
    /** @return array<string,array{0:string}> */
    public static function modelUrls(): array
    {
        return [
            'control model=true' => ['/api/v2/crm/_spec?model=true'],
            'model=t (to_bool true)' => ['/api/v2/crm/_spec?model=t'],
            'model=y (to_bool true)' => ['/api/v2/crm/_spec?model=y'],
            'model=YES' => ['/api/v2/crm/_spec?model=YES'],
            'model=on' => ['/api/v2/crm/_spec?model=on'],
            'model=1' => ['/api/v2/crm/_spec?model=1'],
            'upper-case service (RestController lower-cases it)' => ['/api/v2/CRM/_spec?model=true'],
            'unversioned route {service}/{resource?}' => ['/api/crm/_spec?model=true'],
            'version v2.0 (route pattern v[0-9.]+)' => ['/api/v2.0/crm/_spec?model=true'],
            'percent-encoded resource (router decodes)' => ['/api/v2/crm/%5Fspec?model=true'],
            'dots removed by RestController' => ['/api/v2/crm/_sp..ec?model=true'],
            'leading dots removed by RestController' => ['/api/v2/crm/.._spec?model=true'],
        ];
    }

    private function model(): array
    {
        return ['tables' => ['customers' => [
            'sample_data' => [$this->record()],
            'enum_values' => ['tier' => ['gold'], 'ssn' => [self::SSN]],
        ]]];
    }

    private function serve(string $url, ?Request $request = null, bool $withRoute = false): string
    {
        $request ??= Request::create($url);
        if ($withRoute) {
            $this->bindRoute($request);
        }
        $this->app->instance('request', $request);
        $model = $this->model();
        $next = fn () => new StreamedResponse(function () use ($model) {
            echo json_encode($model);
        }, 200, ['Content-Type' => 'application/json']);
        $response = (new SpecMiddleware())->handle($request, $next);
        if ($response instanceof StreamedResponse) {
            ob_start();
            ($response->getCallback())();

            return (string)ob_get_clean();
        }

        return (string)$response->getContent();
    }

    /** Binds DreamFactory's API routes (df-core routes.php patterns) to the request, like the router does. */
    private function bindRoute(Request $request): void
    {
        $resource = '[0-9a-zA-ZÀ-ÿ-_@&\#\!=,:;\/\^\$\.\|\{\}\[\]\(\)\*\+\?\' ]+';
        $versioned = (new Route(['GET'], 'api/{version}/{service}/{resource?}', []))
            ->where(['version' => 'v[0-9.]+', 'service' => '[_0-9a-zA-Z-.]+', 'resource' => $resource]);
        $plain = (new Route(['GET'], 'api/{service}/{resource?}', []))
            ->where(['service' => '[_0-9a-zA-Z-.]+', 'resource' => $resource]);
        foreach ([$versioned, $plain] as $route) {
            if ($route->matches($request)) {
                $route->bind($request);
                $request->setRouteResolver(fn () => $route);

                return;
            }
        }
        $this->fail('no DreamFactory route matches ' . $request->getRequestUri());
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('modelUrls')]
    public function testSpecModelSamplesAreMasked(string $url): void
    {
        foreach ([false, true] as $withRoute) {
            $body = $this->serve($url, null, $withRoute);
            $this->assertStringNotContainsString(self::SSN, $body, "$url serves raw sample_data in mode on" . ($withRoute ? ' (routed)' : ''));
            $this->assertStringNotContainsString('jane@x.io', $body);
            $decoded = json_decode($body, true);
            $this->assertSame(['tier' => ['gold']], $decoded['tables']['customers']['enum_values']);
        }
    }

    public function testNonModelRequestsPassThrough(): void
    {
        $passthrough = new Response('{"openapi":"3.0.0"}');
        foreach (['/api/v2/crm/_spec', '/api/v2/crm/_spec?model=false', '/api/v2/crm/_spec?model=f', '/api/v2/crm/_spec?model=n',
                     '/api/v2/crm/_table/customers', '/api/v2/crm/_spec/x?model=true', '/api/v2/crm/x/_spec?model=true'] as $url) {
            $request = Request::create($url);
            $this->app->instance('request', $request);
            $this->assertSame($passthrough, (new SpecMiddleware())->handle($request, fn () => $passthrough), $url);
        }
    }

    public function testDreamFactoryReadsTheseAsModelRequests(): void
    {
        $this->assertTrue(to_bool('t'));
        $this->assertTrue(to_bool('y'));
        foreach (['t', 'y', 'yes', 'on', '1', 'TRUE', true] as $v) {
            $this->assertSame(to_bool($v), SpecMiddleware::toBool($v), var_export($v, true));
        }
        foreach (['f', 'n', 'no', 'off', '0', '', null, 'maybe', ['1']] as $v) {
            $this->assertFalse(SpecMiddleware::toBool($v), var_export($v, true));
        }
        $this->assertSame(['crm', true], SpecMiddleware::specRequest(Request::create('/api/crm/_spec?model=true')));
        $this->assertSame(['crm', true], SpecMiddleware::specRequest(Request::create('/api/v2/crm/_spec?model=t')));
        $this->assertSame(['crm', true], SpecMiddleware::specRequest(Request::create('/api/v2/CRM/_spec?model=y')));
        $this->assertSame(['crm', false], SpecMiddleware::specRequest(Request::create('/api/v2/crm/_spec')));
        $this->assertNull(SpecMiddleware::specRequest(Request::create('/api/v2/crm/_table/x')));
    }

    /** @return array<string,array{0:string}> */
    public static function aiUrls(): array
    {
        return [
            'versioned' => ['/api/v2/mongo/_spec?model=true'],
            'model=t' => ['/api/v2/mongo/_spec?model=t'],
            'upper-case service' => ['/api/v2/MONGO/_spec?model=true'],
            'unversioned' => ['/api/mongo/_spec?model=true'],
            'not a model' => ['/api/v2/mongo/_spec'],
            'encoded' => ['/api/v2.0/mongo/%5Fspec'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('aiUrls')]
    public function testAiSpecOfAnUncoveredDatabaseIsBlockedOnEveryRoute(string $url): void
    {
        $request = Request::create($url, 'GET', [], [], [], ['HTTP_X_DREAMFACTORY_TRACE_ID' => 'trace-abcdef12']);
        $this->app->instance('request', $request);
        $ran = false;
        $out = (new SpecMiddleware())->handle($request, function () use (&$ran) {
            $ran = true;

            return new Response('{"tables":{"people":{"sample_data":[{"ssn":"1"}]}}}');
        });
        $this->assertFalse($ran, "$url: the model is never built");
        $this->assertSame(403, $out->getStatusCode());
        $this->assertStringContainsString(Listener::AI_BLOCKED_MESSAGE, $out->getContent());
    }

    public function testUnresolvableTableLosesItsSamples(): void
    {
        $model = ['tables' => [
            'ghost' => ['sample_data' => [['ssn' => self::SSN]], 'enum_values' => ['ssn' => [self::SSN]], 'columns' => [['name' => 'ssn']]],
            'plain' => ['sample_data' => [['tier' => 'gold']]],
        ]];
        $result = (new SpecMasker(new ResponseMasker(new Masker(str_repeat("\x03", 32)))))->mask(
            $model,
            fn (string $t) => $t === 'ghost' ? null : []
        );
        $this->assertTrue($result['changed']);
        $this->assertArrayNotHasKey('sample_data', $result['model']['tables']['ghost']);
        $this->assertArrayNotHasKey('enum_values', $result['model']['tables']['ghost']);
        $this->assertSame([['name' => 'ssn']], $result['model']['tables']['ghost']['columns']);
        $this->assertSame([['tier' => 'gold']], $result['model']['tables']['plain']['sample_data']);
    }
}

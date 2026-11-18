<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Tests\Unit\Enforcement;

use DreamFactory\Core\Events\PostProcessApiEvent;
use DreamFactory\Core\Events\PreProcessApiEvent;
use DreamFactory\Core\Exceptions\ForbiddenException;
use DreamFactory\Core\Masking\Enforcement\Listener;
use DreamFactory\Core\Masking\Masking\Masker;
use DreamFactory\Core\Masking\Support\Caller;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Tests\Unit\Platform\ActsAsCaller;
use DreamFactory\Core\Utility\ServiceResponse;
use Illuminate\Http\Request;

/**
 * The masking headers are response-only receipts: X-DreamFactory-Masked-Fields names masked
 * fields present in the response (mode On, masked callers only), X-DreamFactory-Masking-Rewrites
 * names what masking changed in the request. No request header changes what a caller gets.
 */
final class HeaderContractTest extends EnforcementHarness
{
    use ActsAsCaller;

    private const IGNORED = [
        'masking off' => ['X-DreamFactory-Masking' => 'off'],
        'view real' => ['X-DreamFactory-Masking-View' => 'real'],
        'view masked' => ['X-DreamFactory-Masking-View' => 'masked'],
        'masked fields' => ['X-DreamFactory-Masked-Fields' => 'tier'],
        'rewrites' => ['X-DreamFactory-Masking-Rewrites' => 'filter:tier'],
        'all' => [
            'X-DreamFactory-Masking' => 'off',
            'X-DreamFactory-Masking-View' => 'real',
            'X-DreamFactory-Masked-Fields' => '',
            'X-DreamFactory-Masking-Rewrites' => '',
        ],
    ];

    /** @return array{0:int,1:mixed,2:array,3:array} status, body, headers, request parameters */
    private function send(array $headers, array $params): array
    {
        $server = [];
        foreach ($headers as $name => $value) {
            $server['HTTP_' . strtoupper(str_replace('-', '_', $name))] = $value;
        }
        $this->app->instance('request', Request::create('/api/v2/crm/_table/customers', 'GET', [], [], [], $server));
        Caller::forget();
        $this->listener = new Listener(new Masker(str_repeat("\x03", 32)));
        $request = $this->request('GET', $params);
        $request->setHeaders($headers);
        $response = $this->tableFlow($request, new ServiceResponse(['resource' => [$this->record()]]), 'customers');

        return [$response->getStatusCode(), $response->getContent(), $response->getHeaders(), $request->getParameters()];
    }

    private function assertIgnored(array $params, string $scenario): array
    {
        $baseline = $this->send([], $params);
        foreach (self::IGNORED as $name => $headers) {
            $this->assertSame($baseline, $this->send($headers, $params), "$scenario: $name");
        }

        return $baseline;
    }

    public function testRequestHeadersNeverChangeTheResponseOfAMaskedCaller(): void
    {
        [$status, $body, $headers] = $this->assertIgnored(['fields' => '*', 'filter' => "ssn LIKE '1%'", 'order' => 'email'], 'mode On, masked');
        $this->assertSame(200, $status);
        $this->assertSame(Masker::redacted(), $body['resource'][0]['ssn']);
        $this->assertSame('name, email, ssn', $headers[Listener::HEADER_MASKED_FIELDS]);
        $this->assertSame('filter:ssn, order:email', $headers[Listener::HEADER_REWRITES]);
    }

    public function testRequestHeadersNeverChangeTheResponseOfACallerWithRealValues(): void
    {
        $this->actAs(1, true);
        Settings::set(Settings::ADMINS_MODE, 'all');
        [, $body, $headers] = $this->assertIgnored(['fields' => '*'], 'mode On, admin with real values');
        $this->assertSame(self::SSN, $body['resource'][0]['ssn']);
        $this->assertSame([], $headers, 'a caller with real-value access gets no header');
    }

    public function testRequestHeadersNeverChangeTheResponseInPreview(): void
    {
        Settings::set('mode', 'preview');
        [, $body, $headers] = $this->assertIgnored(['fields' => '*'], 'Preview');
        $this->assertSame($this->record(), $body['resource'][0]);
        $this->assertSame([], $headers);
    }

    public function testRoutineWithANullMaskedKeyStillGetsTheHeader(): void
    {
        foreach ([
            'null' => [['email' => null, 'n' => 3]],
            'value' => [['email' => 'jane@x.io', 'n' => 3]],
            'span' => [['note' => 'call 415-555-0132']],
        ] as $case => $content) {
            $response = $this->routine($content);
            $this->assertSame('*', $response->getHeaders()[Listener::HEADER_MASKED_FIELDS] ?? null, $case);
        }
        $clear = $this->routine([['n' => 3, 'note' => 'ok']]);
        $this->assertArrayNotHasKey(Listener::HEADER_MASKED_FIELDS, $clear->getHeaders(), 'nothing masked: no header');
    }

    public function testAiBlockSaysWhenTheTraceHeaderWasTheReason(): void
    {
        $this->asAiSession('/api/v2/mongo/_table/people');
        $this->assertSame(Listener::AI_BLOCKED_MESSAGE . Listener::AI_TRACE_SUFFIX, $this->blockedMessage());

        $this->app->instance('request', Request::create('/api/v2/mongo/_table/people'));
        $this->app->instance('df.agent', (object)['name' => 'Ops']);
        Caller::forget();
        $this->assertSame(Listener::AI_BLOCKED_MESSAGE, $this->blockedMessage(), 'another AI signal: no trace header sentence');
    }

    private function routine(array $content): ServiceResponse
    {
        $request = $this->request('POST');
        $response = new ServiceResponse($content);
        $none = null;
        $this->listener->onPreProcess(new PreProcessApiEvent('crm._proc.{procedure_name}', $request, $none, 'top_customers'));
        $this->listener->onPostProcess(new PostProcessApiEvent('crm._proc.{procedure_name}', $request, $response, 'top_customers'));

        return $response;
    }

    private function blockedMessage(): string
    {
        $none = null;
        try {
            $this->listener->onPreProcess(new PreProcessApiEvent('mongo._table.{table_name}', $this->request('GET'), $none, 'people'));
        } catch (ForbiddenException $e) {
            return $e->getMessage();
        }
        $this->fail('expected a 403');
    }
}

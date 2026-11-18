<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Enforcement;

use DreamFactory\Core\Masking\Masking\Masker;
use DreamFactory\Core\Masking\Support\Activity;
use DreamFactory\Core\Masking\Support\Caller;
use DreamFactory\Core\Masking\Support\Settings;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\StreamedResponse;

/**
 * Masks GET /api/v2/{service}/_spec?model=true on covered services when masking is on.
 *
 * A request counts as a _spec model request exactly when DreamFactory treats it as one
 * (specRequest()): the service and resource come from the matched route (any version, v2.0,
 * no version; the router decodes %5F), the service lower-cased (RestController), ".." removed
 * from the resource as RestController does, and model read with DreamFactory's to_bool()
 * (true, 1, yes, on, t, y).
 *
 * df-core answers _spec before any API event fires (BaseRestService::handleRequest intercepts
 * it) and returns a StreamedResponse whose callback echoes the already-encoded model. This
 * middleware (in DreamFactory's df.api group, after authentication) runs that callback into a
 * buffer, decodes the model, masks sample rows and drops enum value lists of masked columns
 * (SpecMasker), and returns an ordinary JSON response with the same status and headers.
 *
 * Because _spec skips the API events, this middleware also enforces the AI block for database
 * services masking cannot cover (403, any _spec of such a service, when masking is on).
 *
 * Every other request passes through after one path comparison; with masking off, after one
 * settings read. If the model cannot be decoded the response is withheld (500), never served
 * unmasked. Limitation: an internal (non-HTTP) call to _spec, e.g. from a server-side script,
 * is not intercepted (documented in the README).
 */
final class SpecMiddleware
{
    public function handle(Request $request, \Closure $next): mixed
    {
        $spec = self::specRequest($request);
        if ($spec === null) {
            return $next($request);
        }
        [$service, $model] = $spec;
        try {
            if (Settings::mode() !== 'on') {
                return $next($request);
            }
            $kind = ServiceClass::kindOf($service);
            // _spec skips the API events, so the uncovered-database AI block is enforced here.
            if ($kind === ServiceClass::UNCOVERED && Caller::current()->isAi()) {
                Activity::logThrottled(
                    'ai-uncovered-spec|' . $service . '|' . (Caller::current()->userId() ?? '-') . '|' . (Caller::current()->appId() ?? '-'),
                    600,
                    'blocked',
                    'Blocked AI access to a database Data Masking cannot mask',
                    $service
                );

                return self::error(403, Listener::aiBlockedMessage(Caller::current()));
            }
        } catch (\Throwable $e) {
            Log::error('df-masking: _spec check failed: ' . get_class($e) . ': ' . $e->getMessage());

            return self::withheld();
        }

        $response = $next($request);
        if (!$model || $kind !== ServiceClass::COVERED) {
            return $response;
        }
        try {
            if (!is_object($response) || !method_exists($response, 'getStatusCode') || $response->getStatusCode() !== 200) {
                return $response;
            }

            return $this->mask($service, $response);
        } catch (\Throwable $e) {
            Log::error('df-masking: _spec model masking failed: ' . get_class($e) . ': ' . $e->getMessage());

            return self::withheld();
        }
    }

    /**
     * [service (lower-cased), model?] when DreamFactory would answer the request from its _spec
     * handler (BaseRestService::handleRequest: resource === '_spec'), else null.
     *
     * Any method counts: a non-GET _spec request is routed like any other resource and fails
     * there, so treating it as a spec request only ever adds checks.
     *
     * @return array{0:string,1:bool}|null
     */
    public static function specRequest(Request $request): ?array
    {
        $raw = rawurldecode($request->path());
        if (stripos(str_replace('..', '', $raw), '_spec') === false) {
            return null; // fast path: every other request
        }
        [$service, $resource] = self::routeOf($request);
        if ($service === null || $resource === null) {
            return null;
        }
        // RestController::handleServiceRequest(): strtolower($service), str_replace('..', '', $resource).
        $resource = rtrim(str_replace('..', '', $resource), '/');
        if ($resource !== '_spec') {
            return null;
        }

        return [strtolower($service), self::toBool($request->query('model'))];
    }

    /**
     * Service and resource of a request on DreamFactory's API routes: the matched route's
     * parameters (decoded by the router), or the same split of the decoded path when no route
     * is bound (routes {prefix}/{version}/{service}/{resource?} and {prefix}/{service}/{resource?}).
     *
     * @return array{0:?string,1:?string}
     */
    private static function routeOf(Request $request): array
    {
        try {
            $route = $request->route();
        } catch (\Throwable $e) {
            $route = null;
        }
        if (is_object($route) && method_exists($route, 'parameter')) {
            $service = $route->parameter('service');
            $resource = $route->parameter('resource');
            if (is_string($service) && $service !== '') {
                return [$service, is_string($resource) ? $resource : null];
            }
        }
        $prefix = trim((string)config('df.api_route_prefix', 'api'), '/');
        $path = trim(rawurldecode($request->path()), '/');
        if ($prefix !== '') {
            if (stripos($path . '/', $prefix . '/') !== 0) {
                return [null, null];
            }
            $path = (string)substr($path, strlen($prefix) + 1);
        }
        $parts = explode('/', $path, 3);
        if (count($parts) >= 3 && preg_match('/^v[0-9.]+$/', $parts[0]) === 1) {
            return [$parts[1], $parts[2]];
        }
        $parts = explode('/', $path, 2);

        return [$parts[0] !== '' ? $parts[0] : null, $parts[1] ?? null];
    }

    /** DreamFactory's to_bool() (ServiceRequest::getParameterAsBool). */
    public static function toBool(mixed $value): bool
    {
        if (function_exists('to_bool')) {
            try {
                return (bool)to_bool(is_array($value) ? '' : $value);
            } catch (\Throwable $e) {
            }
        }
        if (is_bool($value)) {
            return $value;
        }
        if (!is_scalar($value)) {
            return false;
        }
        $v = strtolower((string)$value);
        $v = ['y' => 'yes', 'n' => 'no', 't' => 'true', 'f' => 'false'][$v] ?? $v;

        return (bool)filter_var($v, FILTER_VALIDATE_BOOLEAN);
    }

    private function mask(string $service, object $response): mixed
    {
        $body = self::bodyOf($response);
        if ($body === null) {
            return $response;
        }
        $headers = [];
        foreach (['Content-Type', 'Cache-Control'] as $name) {
            $value = $response->headers->get($name);
            if ($value !== null) {
                $headers[$name] = $value;
            }
        }
        $headers['Content-Type'] ??= 'application/json; charset=utf-8';
        $model = json_decode($body, true);
        if (!is_array($model)) {
            return self::withheld();
        }
        $caller = Caller::current();
        $memo = [];
        $hiddenFor = function (string $table) use ($service, $caller, &$memo): ?array {
            if (array_key_exists($table, $memo)) {
                return $memo[$table];
            }
            $target = TableTarget::resolve($service, $table, true);
            if ($target === null) {
                return $memo[$table] = null; // SpecMasker withholds its sample rows
            }
            $hidden = Listener::hiddenFor($target, Policy::effective($target), $caller);
            // sample_data rows use database column names; responses use field names (aliases).
            $byBoth = [];
            foreach ($hidden as $key => $entry) {
                $byBoth[$key] = $entry;
                $byBoth[strtolower((string)$entry['column'])] = $entry;
            }

            return $memo[$table] = $byBoth;
        };

        $result = (new SpecMasker(new ResponseMasker(new Masker())))->mask($model, $hiddenFor);
        if (!$result['changed']) {
            // The stream was consumed: answer with its body rather than running it twice.
            return new Response($body, 200, $headers);
        }
        foreach ($result['model']['tables'] as $table => $entry) {
            $hidden = $hiddenFor((string)$table);
            if (is_array($hidden) && $hidden !== [] && is_array($entry)) {
                $names = [];
                foreach ($hidden as $h) {
                    $names[$h['name']] = true;
                }
                $result['model']['tables'][$table]['masked_columns'] = array_keys($names);
            }
        }

        $headers[Listener::HEADER_MASKED_FIELDS] = '*';

        return new Response(
            (string)json_encode($result['model'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            200,
            $headers
        );
    }

    /** The body of a streamed or plain response, without sending it. */
    private static function bodyOf(object $response): ?string
    {
        if ($response instanceof StreamedResponse) {
            $callback = $response->getCallback();
            if ($callback === null) {
                return null;
            }
            ob_start();
            try {
                $callback();
            } finally {
                $body = (string)ob_get_clean();
            }

            return $body;
        }
        if (method_exists($response, 'getContent')) {
            $content = $response->getContent();

            return is_string($content) ? $content : null;
        }

        return null;
    }

    private static function withheld(): Response
    {
        return self::error(500, Listener::WITHHELD_MESSAGE);
    }

    /** DreamFactory's error envelope. */
    private static function error(int $status, string $message): Response
    {
        return new Response(
            (string)json_encode(['error' => ['code' => $status, 'context' => null, 'message' => $message, 'status_code' => $status]]),
            $status,
            ['Content-Type' => 'application/json']
        );
    }
}

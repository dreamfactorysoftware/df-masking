<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Enforcement;

use DreamFactory\Core\Contracts\ServiceResponseInterface;
use DreamFactory\Core\Enums\DataFormats;
use DreamFactory\Core\Exceptions\BadRequestException;
use DreamFactory\Core\Exceptions\BatchException;
use DreamFactory\Core\Exceptions\DfException;
use DreamFactory\Core\Exceptions\ForbiddenException;
use DreamFactory\Core\Exceptions\InternalServerErrorException;
use DreamFactory\Core\Exceptions\NotFoundException;
use DreamFactory\Core\Exceptions\RestException;
use DreamFactory\Core\Masking\Enforcement\Filter\FilterParser;
use DreamFactory\Core\Masking\Enforcement\Filter\FilterRewriter;
use DreamFactory\Core\Masking\Masking\Masker;
use DreamFactory\Core\Masking\Support\Access;
use DreamFactory\Core\Masking\Support\Activity;
use DreamFactory\Core\Masking\Support\Caller;
use DreamFactory\Core\Masking\Support\Catalog;
use DreamFactory\Core\Masking\Support\Settings;
use Illuminate\Support\Facades\Log;

/**
 * Data Masking enforcement on DreamFactory's API events.
 *
 * Registered from ServiceProvider::register() (see Registrar), so for every event it runs
 * before df-core's ServiceEventHandler and df-script's ScriptableEventHandler: event scripts,
 * df-logger and notifications only ever see masked data.
 *
 *  - PreProcessApiEvent: blocks AI sessions from uncovered database services and from changing
 *    masking/baseline settings; resolves the table, its policy and what this caller may see
 *    (classifying never-scanned columns inline); applies the request guards (filters, order,
 *    group, aggregates; write filters, expressions, write-back).
 *  - PostProcessApiEvent: masks the response in place (records, related records, as_list,
 *    procedure results), scrubs error bodies, and in mode On adds the Masked-Fields header
 *    (only naming masked fields the response contains) and the Rewrites header (what the
 *    request guards changed); Headers caps and encodes both. Preview adds no header.
 *  - ApiEvent (final, before the response leaves the handler and before df-logger and
 *    notifications get it): the same again. Masking is idempotent and a response object whose
 *    content is unchanged since it was masked is skipped, so this costs nothing unless a
 *    script rewrote the response in between.
 *
 * The table or routine is resolved from the event the way DreamFactory routes the request
 * (addressed()): for every "{service}._table", "._proc" and "._func" event, whatever the number
 * of path segments (DreamFactory adds "{table_name}" to the event name only for one or two
 * segments, but serves "_table/customers/1/x" and "_table/customers//x" too).
 *
 * Off mode: one settings read (memoized, cached) and return; no context is ever created, so the
 * post-process and final stages return after a WeakMap lookup.
 */
final class Listener
{
    /** Response only, mode On: masked fields present in the response ("*" for routines). Never read from requests. */
    public const HEADER_MASKED_FIELDS = 'X-DreamFactory-Masked-Fields';
    /** Response only, mode On: "kind:field" items for what masking changed in the request. Never read from requests. */
    public const HEADER_REWRITES = 'X-DreamFactory-Masking-Rewrites';

    public const AI_BLOCKED_MESSAGE = 'Data Masking blocks AI access to services it cannot mask.';
    public const AI_TRACE_SUFFIX = ' This request counts as an AI session because it carries X-DreamFactory-Trace-Id.';
    public const EXPRESSION_MESSAGE = 'Expressions are not allowed on tables with masked columns';
    public const WITHHELD_MESSAGE = 'Data Masking could not mask this response, so it was withheld.';
    public const INSERT_MESSAGE = "Masked values can't be inserted. Send real values or leave the field out.";
    public const EXPORT_MESSAGE = 'Exporting table data needs real-value access. Ask the super admin for a grant, or export without table data.';

    /** Database resources whose requests carry table data, by the resource segment of the event name. */
    private const ROUTED = ['_table' => RequestContext::TABLE, '_proc' => RequestContext::ROUTINE, '_func' => RequestContext::ROUTINE];
    private const MASKING_RESOURCE = 'system.data_masking';
    private const BASELINE_RESOURCE = 'system.security_baseline';
    private const PACKAGE_RESOURCE = 'system.package';

    private const READ_VERBS = ['GET', 'HEAD', 'OPTIONS'];
    private const FILTERED_WRITE_VERBS = ['PUT', 'PATCH', 'MERGE', 'DELETE'];
    private const PAYLOAD_WRITE_VERBS = ['POST', 'PUT', 'PATCH', 'MERGE'];

    /** @var \WeakMap<object,RequestContext> service request => context */
    private \WeakMap $contexts;
    /** @var \WeakMap<object,mixed> service response => content right after masking */
    private \WeakMap $masked;
    /** @var \WeakMap<object,true> contexts whose preview activity was recorded */
    private \WeakMap $previewLogged;
    /**
     * @var \WeakMap<object,\ArrayObject> outermost (HTTP) request => dropped items of every
     *      table request served for it, as list<array{0:int,1:string}> [sequence, item]
     */
    private \WeakMap $collectors;
    /** Collector when no HTTP request is bound (console, queue). */
    private ?\ArrayObject $fallbackCollector = null;
    private int $collectSeq = 0;

    private ?Masker $masker = null;
    private ?ResponseMasker $responseMasker = null;

    /** When a Preview failure was last logged (unix seconds; once a minute per process). */
    private static ?int $previewFailureLoggedAt = null;

    public function __construct(?Masker $masker = null)
    {
        $this->contexts = new \WeakMap();
        $this->masked = new \WeakMap();
        $this->previewLogged = new \WeakMap();
        $this->collectors = new \WeakMap();
        $this->masker = $masker;
    }

    // ------------------------------------------------------------------------------ events

    public function onPreProcess(object $event): void
    {
        $name = isset($event->name) && is_string($event->name) ? $event->name : null;
        $request = $event->request ?? null;
        if ($name === null || !is_object($request)) {
            return;
        }
        if (str_starts_with($name, self::MASKING_RESOURCE . '.') || str_starts_with($name, self::BASELINE_RESOURCE . '.')) {
            $this->guardSettingsWrite($event, $name, $request);

            return;
        }

        $mode = Settings::mode();
        if ($mode === 'off') {
            return;
        }

        try {
            $verb = strtoupper((string)$request->getMethod());
            $path = self::eventPath($name, $verb);
            if ($mode === 'on' && $path === self::PACKAGE_RESOURCE && $verb === 'POST') {
                $this->guardPackageExport($request);

                return;
            }
            $service = str_contains($path, '.') ? (string)strstr($path, '.', true) : $path;
            if ($mode === 'on') {
                $this->blockAiOnUncovered($service);
            }
            $ctx = $this->contexts[$request] ?? null;
            if ($ctx === null) {
                $ctx = $this->buildContext($event, $path, $service, $mode);
                if ($ctx === null) {
                    return;
                }
                $ctx->collectFrom = $this->collectSeq;
                $this->contexts[$request] = $ctx;
            }
            if ($ctx->kind === RequestContext::TABLE && $ctx->enforcing() && ($ctx->hidden !== [] || $ctx->filterGuard !== [])) {
                $this->guardRequest($request, $ctx, self::resourceId($path, $service, $event->resource ?? null));
            }
        } catch (\Throwable $e) {
            if ($mode === 'preview') {
                // Preview only reports and never changes what apps receive: a failure to check
                // the request (policy tables unreadable or dropped, ...) passes it through
                // unchanged. Fail closed belongs to mode On (and to an unreadable mode, which
                // Settings reports as On).
                $this->previewFailed('request check', $e);

                return;
            }
            if ($e instanceof RestException) {
                throw $e; // our own 400/403 (and DreamFactory's), already worded for the client
            }
            Log::error('df-masking: request check failed: ' . get_class($e) . ': ' . $e->getMessage());
            Settings::revalidate();
            throw new InternalServerErrorException('Data Masking could not check this request.');
        }
    }

    public function onPostProcess(object $event): void
    {
        $this->onResponse($event, false);
    }

    public function onFinal(object $event): void
    {
        $this->onResponse($event, true);
    }

    // ------------------------------------------------------------------------------ pre-process

    private function guardSettingsWrite(object $event, string $name, object $request): void
    {
        $verb = strtoupper((string)$request->getMethod());
        if (in_array($verb, self::READ_VERBS, true)) {
            return;
        }
        $caller = Caller::current();
        if (!$caller->isAi()) {
            return;
        }
        $baseline = str_starts_with($name, self::BASELINE_RESOURCE . '.');
        $resource = is_string($event->resource ?? null) ? trim($event->resource, '/') : '';
        $path = ($baseline ? 'system/security_baseline' : 'system/data_masking') . ($resource !== '' ? '/' . $resource : '');
        if ($baseline) {
            $text = 'Blocked an attempt to change compliance baselines';
        } elseif (str_starts_with($resource, 'access')) {
            $text = 'Blocked an attempt to change access';
        } else {
            $text = 'Blocked an attempt to change Data Masking settings';
        }
        Activity::log('blocked', $text, $path);

        throw new ForbiddenException($baseline
            ? 'AI sessions cannot change compliance baselines.'
            : 'AI sessions cannot change Data Masking settings.');
    }

    /**
     * POST system/package with a manifest (an export; imports upload a file or name a URL): a
     * caller who does not see real values of a covered table listed under "_table" is refused,
     * before the exporter writes masked records into a package that would be imported as data.
     */
    private function guardPackageExport(object $request): void
    {
        try {
            if (method_exists($request, 'getFile') && !empty($request->getFile('files'))) {
                return; // import
            }
        } catch (\Throwable $e) {
        }
        $payload = $request->getPayloadData();
        if (!is_array($payload) || !empty($payload['import_url']) || !empty($request->getParameter('import_url'))
            || !isset($payload['service']) || !is_array($payload['service'])) {
            return;
        }
        $caller = Caller::current();
        if (!self::masksAnyTier($caller)) {
            return;
        }
        foreach ($payload['service'] as $service => $resources) {
            if (!is_array($resources) || empty($resources['_table'])) {
                continue;
            }
            $service = strtolower((string)$service);
            if (ServiceClass::kindOf($service) !== ServiceClass::COVERED) {
                continue;
            }
            foreach ((array)$resources['_table'] as $table) {
                $target = is_string($table) && $table !== '' && $table !== '*' ? TableTarget::resolve($service, $table) : null;
                if ($target === null && is_string($table) && $table !== '*') {
                    continue; // not a table DreamFactory can export either
                }
                if ($target === null || self::hiddenFor($target, Policy::effective($target), $caller) !== []) {
                    Activity::logThrottled(
                        'export|' . self::callerKey() . '|' . $service,
                        60,
                        'blocked',
                        'Blocked a package export of masked table data',
                        $service . ($target !== null ? '.' . $target->table : '')
                    );

                    throw new ForbiddenException(self::EXPORT_MESSAGE);
                }
            }
        }
    }

    /** True while DreamFactory's package exporter (POST system/package) is running. */
    private static function isPackageExport(): bool
    {
        try {
            $http = app()->bound('request') ? app('request') : null;
        } catch (\Throwable $e) {
            return false;
        }
        if (!is_object($http) || !method_exists($http, 'path') || strtoupper((string)$http->getMethod()) !== 'POST') {
            return false;
        }
        $prefix = trim((string)config('df.api_route_prefix', 'api'), '/');

        return preg_match('#^' . preg_quote($prefix, '#') . '/(?:v[0-9.]+/)?system/package/?$#i', (string)$http->path()) === 1;
    }

    private function blockAiOnUncovered(string $service): void
    {
        if ($service === '' || $service === 'system') {
            return;
        }
        $caller = Caller::current();
        if (!$caller->isAi() || ServiceClass::kindOf($service) !== ServiceClass::UNCOVERED) {
            return;
        }
        Activity::logThrottled(
            'ai-uncovered|' . self::callerKey() . '|' . $service,
            600,
            'blocked',
            'Blocked AI access to a database Data Masking cannot mask',
            $service
        );

        throw new ForbiddenException(self::aiBlockedMessage($caller));
    }

    /** The 403 text for an AI session on an uncovered service; says so when the trace header was the reason. */
    public static function aiBlockedMessage(Caller $caller): string
    {
        return self::AI_BLOCKED_MESSAGE . ($caller->aiFromTraceHeader() ? self::AI_TRACE_SUFFIX : '');
    }

    private function buildContext(object $event, string $path, string $service, string $mode): ?RequestContext
    {
        $addressed = self::addressed($path, $service, $event->resource ?? null);
        if ($addressed === null) {
            return null;
        }
        [$kind, $item] = $addressed;

        if ($kind === RequestContext::TABLE) {
            $target = TableTarget::resolve($service, $item);
            $caller = Caller::current();
            if ($target === null) {
                // DreamFactory answers 404 for a table it does not find either. Should it ever find
                // one that enforcement could not resolve, a masked caller's data is withheld.
                if ($mode === 'on' && ServiceClass::kindOf($service) === ServiceClass::COVERED && self::masksAnyTier($caller)) {
                    return new RequestContext(RequestContext::UNRESOLVED, $mode, $service, (int)(ServiceClass::idOf($service) ?? 0), null, [], null, true, $item);
                }

                return null;
            }
            $hidden = self::hiddenFor($target, Policy::effective($target), $caller);

            $ctx = new RequestContext(
                RequestContext::TABLE,
                $mode,
                $service,
                $target->serviceId,
                $target,
                $hidden,
                $target->relations === [] ? null : $this->relationResolver($target, $caller),
                $hidden !== [] || self::masksAnyTier($caller),
                $target->table
            );
            $ctx->filterGuard = self::filterGuard($target, $hidden);

            return $ctx;
        }

        if (ServiceClass::kindOf($service) !== ServiceClass::COVERED) {
            return null;
        }
        $serviceId = (int)(ServiceClass::idOf($service) ?? 0);
        $caller = Caller::current();
        $maskedCaller = self::masksAnyTier($caller);
        $byColumn = [];
        if ($maskedCaller) {
            foreach (Policy::forService($serviceId) as $column => $entry) {
                if (!Access::callerSeesRealValues($caller, $entry['tier'])) {
                    $byColumn[$column] = $entry + ['name' => $column];
                }
            }
        }

        return new RequestContext(RequestContext::ROUTINE, $mode, $service, $serviceId, null, $byColumn, null, $maskedCaller, $item);
    }

    /**
     * The table or routine a database-service event addresses, resolved the way DreamFactory
     * routes the request: RestHandler::setResourceMembers() takes the first segment of the
     * resource path (after trimming trailing slashes; an empty first segment means "no table":
     * DreamFactory then lists table names), whatever follows it. Generic events
     * ("crm._table", "crm._table.{table_name}[.{id}]") carry the resource path; the specific ones
     * ("crm._table.customers[.{id}]") name the table and may carry only the id.
     *
     * @param string $path event name without its ".{verb}[.pre_process|.post_process]" suffix
     * @return array{0:string,1:string}|null [RequestContext::TABLE|ROUTINE, table or routine name]
     */
    public static function addressed(string $path, string $service, mixed $resource): ?array
    {
        if ($service === '' || !str_starts_with($path, $service . '.')) {
            return null;
        }
        $rest = substr($path, strlen($service) + 1);
        foreach (self::ROUTED as $segment => $kind) {
            if ($rest === $segment) {
                $tail = null;
            } elseif (str_starts_with($rest, $segment . '.')) {
                $tail = substr($rest, strlen($segment) + 1);
            } else {
                continue;
            }
            if ($tail === null || str_starts_with($tail, '{')) {
                $item = self::firstSegment($resource);
            } else {
                $item = str_ends_with($tail, '.{id}') ? substr($tail, 0, -5) : $tail;
            }

            return $item === null || $item === '' ? null : [$kind, $item];
        }

        return null;
    }

    /** "crm._table.customers.get.pre_process" -> "crm._table.customers" (DreamFactory ApiEvent naming). */
    public static function eventPath(string $name, string $verb): string
    {
        $v = '.' . strtolower($verb);
        foreach ([$v . '.pre_process', $v . '.post_process', $v] as $suffix) {
            if ($verb !== '' && str_ends_with($name, $suffix)) {
                return substr($name, 0, -strlen($suffix));
            }
        }

        return preg_replace('/\.[a-z]+(?:\.(?:pre|post)_process)?$/', '', $name) ?? $name;
    }

    /**
     * Fields whose FILTER db_function reads masked columns: DreamFactory compares the function,
     * not the field, so filters on them are guarded like filters on those columns.
     *
     * @param array<string,array> $hidden
     * @return array<string,array>
     */
    private static function filterGuard(TableTarget $target, array $hidden): array
    {
        if ($hidden === []) {
            return [];
        }
        $byColumn = null;
        $out = [];
        foreach ($target->fields as $key => $field) {
            $fn = $field['filter_fn'] ?? null;
            if (!is_string($fn)) {
                continue;
            }
            if ($byColumn === null) {
                $byColumn = [];
                foreach ($hidden as $entry) {
                    $byColumn[(string)$entry['column']] = $entry;
                }
            }
            $derived = DerivedFields::derive($fn, $target->realColumns(), $byColumn);
            if ($derived === null) {
                continue;
            }
            $entry = isset($hidden[$key]) ? DerivedFields::strictest([$hidden[$key], $derived['entry']]) : $derived['entry'];
            $out[$key] = $entry + ['name' => $field['name'], 'column' => $field['column'], 'type' => $field['type']];
        }

        return $out;
    }

    /**
     * @param array<string,array{class:?string,tier:string,format:string,verdict:string}> $masked
     * @return array<string,array> lower-cased field name => entry + name/column/type
     */
    public static function hiddenFor(TableTarget $target, array $masked, Caller $caller): array
    {
        if ($masked === []) {
            return [];
        }
        $byColumn = $target->fieldsByColumn();
        $sees = [];
        $hidden = [];
        foreach ($masked as $column => $entry) {
            $field = $byColumn[strtolower((string)$column)] ?? null;
            if ($field === null) {
                continue; // the column no longer exists
            }
            $tier = $entry['tier'];
            $sees[$tier] ??= Access::callerSeesRealValues($caller, $tier);
            if ($sees[$tier]) {
                continue;
            }
            $hidden[strtolower($field['name'])] = $entry + [
                'name' => $field['name'],
                'column' => $field['column'],
                'type' => $field['type'],
            ];
        }
        // Table order, so headers list columns the way the table does.
        $ordered = [];
        foreach ($target->fields as $key => $_) {
            if (isset($hidden[$key])) {
                $ordered[$key] = $hidden[$key];
            }
        }

        return $ordered;
    }

    /** Resolves relation name => policy of its target table (memoized per request). */
    private function relationResolver(TableTarget $target, Caller $caller): \Closure
    {
        $memo = [];

        return function (string $relation) use ($target, $caller, &$memo): ?array {
            if (array_key_exists($relation, $memo)) {
                return $memo[$relation];
            }
            $memo[$relation] = null;
            $info = $target->relations[$relation] ?? null;
            if ($info === null || empty($info['ref_table'])) {
                return null;
            }
            $refId = $info['ref_service_id'] ?? null;
            $refService = ($refId === null || $refId === $target->serviceId)
                ? $target->service
                : app('df.service')->getServiceNameById($refId);
            if (!is_string($refService) || $refService === '') {
                return null;
            }
            $refTarget = TableTarget::resolve($refService, (string)$info['ref_table']);
            if ($refTarget === null) {
                return null; // not covered: nothing to mask (AI sessions are blocked there)
            }

            return $memo[$relation] = [
                'hidden' => self::hiddenFor($refTarget, Policy::effective($refTarget), $caller),
                'relations' => $refTarget->relations === [] ? null : $this->relationResolver($refTarget, $caller),
            ];
        };
    }

    private function guardRequest(object $request, RequestContext $ctx, ?string $resourceId = null): void
    {
        $verb = strtoupper((string)$request->getMethod());
        $guard = new RequestGuard($ctx->hidden, $this->masker(), $ctx->filterGuard, self::falseFields($ctx->target));
        $params = (array)$request->getParameters();

        if (in_array($verb, self::READ_VERBS, true)) {
            if ($ctx->hidden !== [] && self::isPackageExport()) {
                // The package exporter reads table data through internal requests: masked
                // records in a package would be imported as data.
                $this->logRefused($ctx, 'export', 'Blocked a package export of masked table data');

                throw new ForbiddenException(self::EXPORT_MESSAGE);
            }
            $this->guardIdLookup($request, $ctx, $guard, $verb, $params, $resourceId);
            $result = $guard->guardRead($params);
            if ($result['changed']) {
                // Never leave the parameters empty: DreamFactory would fall back to the raw query.
                $request->setParameters($result['params'] !== [] ? $result['params'] : ['fields' => '*']);
                $new = array_values(array_diff($result['dropped'], $ctx->dropped));
                $ctx->dropped = array_values(array_unique(array_merge($ctx->dropped, $result['dropped'])));
                if ($new !== []) {
                    $this->collect($new);
                    $this->logDropped($ctx, $new);
                }
            }

            return;
        }

        $payload = $request->getPayloadData();
        if ($guard->hasExpression($payload, $params)) {
            $this->logRefused($ctx, 'expression', 'Blocked an expression on a table with masked columns');

            throw new BadRequestException(self::EXPRESSION_MESSAGE);
        }

        if (in_array($verb, self::FILTERED_WRITE_VERBS, true)) {
            $this->guardIdLookup($request, $ctx, $guard, $verb, $params, $resourceId);
            $check = $guard->checkWriteFilter($params);
            if (!$check['ok']) {
                $this->logRefused($ctx, 'write-filter', 'Blocked a write that filtered on a masked column', $check['violations'][0] ?? null);

                throw new BadRequestException($check['uncertain']
                    ? 'Data Masking could not verify the filter of this write. Use simple comparisons, or filter on columns that are not masked.'
                    : 'Writes may filter masked columns (' . implode(', ', $check['violations']) . ') only by exact match (=, IN), and never restricted or free-text columns.');
            }
        }

        if ($verb === 'POST' && is_array($payload) && $payload !== []) {
            // Inserts: "unchanged" means nothing for a new record, so a masked placeholder would
            // silently store NULL (or the placeholder itself). Refuse instead.
            $placeholders = $guard->maskedValuesIn($payload, self::wrapper());
            if ($placeholders !== []) {
                $this->logRefused($ctx, 'insert', 'Blocked an insert of masked values', $placeholders[0]);

                throw new BadRequestException(self::INSERT_MESSAGE);
            }

            return;
        }

        if (in_array($verb, self::PAYLOAD_WRITE_VERBS, true) && is_array($payload) && $payload !== []) {
            $stripped = $guard->stripMaskedValues($payload, self::wrapper());
            if ($stripped['removed'] !== []) {
                if ($stripped['payload'] === []) {
                    // An empty payload would make DreamFactory re-read the raw request body.
                    throw new BadRequestException('Nothing to write: the request only sent back masked values, and masked values are never written.');
                }
                $request->setPayloadData($stripped['payload']);
            }
        }
    }

    /**
     * Records addressed by id compare their id fields (id_field, else the primary key) with the
     * values sent. On a masked column the caller may not compare that way a read
     * finds no record, answered the way DreamFactory answers ids it does not find, without
     * running the lookup (so the answer never depends on the data); a write is refused.
     *
     * @param array<string,mixed> $params
     */
    private function guardIdLookup(object $request, RequestContext $ctx, RequestGuard $guard, string $verb, array $params, ?string $resourceId): void
    {
        $byId = self::byId($request, $verb, $params, $resourceId);
        if ($byId === null) {
            return;
        }
        [$how, $values] = $byId;
        $idField = $params['id_field'] ?? null;
        if (is_array($idField)) {
            $fields = array_map('strval', $idField);
        } elseif (is_string($idField) && trim($idField) !== '') {
            $fields = explode(',', $idField);
        } else {
            $fields = $ctx->target?->primaryKey ?? [];
        }
        $unknown = $guard->unknownIdFields($fields, max(1, count($values)));
        if ($unknown === []) {
            return;
        }
        if (!in_array($verb, self::READ_VERBS, true)) {
            $this->logRefused($ctx, 'write-filter', 'Blocked a write that filtered on a masked column', $unknown[0]);

            throw new BadRequestException('Writes may filter masked columns (' . implode(', ', $unknown) . ') only by exact match (=, IN), and never restricted or free-text columns.');
        }
        $dropped = array_map(fn ($name) => 'filter:' . $name, $unknown);
        $new = array_values(array_diff($dropped, $ctx->dropped));
        $ctx->dropped = array_values(array_unique(array_merge($ctx->dropped, $dropped)));
        if ($new !== []) {
            $this->collect($new);
            $this->logDropped($ctx, $new);
        }
        // DreamFactory's own "not found" answers (BaseDbTableResource / df-sqldb), with the id
        // shown the way Data Masking shows any value in an error.
        $notFound = fn () => new NotFoundException("Record with identifier '" . ErrorScrubber::REPLACEMENT . "' not found.");
        if ($how === 'path') {
            throw $notFound();
        }
        // ids and payload records both go through BaseDbTableResource::retrieveRecordsByIds: a
        // batch error that stops at the first missing record unless continue=true.
        $continue = $params['continue'] ?? false;
        $continue = function_exists('to_bool') ? to_bool($continue) : (bool)filter_var($continue, FILTER_VALIDATE_BOOLEAN);
        $out = [];
        foreach (array_slice(array_keys($values), 0, $continue ? null : 1) as $i) {
            $out[$i] = $notFound();
        }

        throw new BatchException($out, 'Batch Error: Not all requested records could be retrieved.');
    }

    /**
     * How a table request addresses records by id, in DreamFactory's dispatch order
     * (BaseDbTableResource::handleGET/PUT/PATCH/DELETE): a path id, then "ids", then records in
     * the payload (GET and DELETE always; PUT, PATCH and MERGE only without a filter).
     *
     * @return array{0:string,1:list<mixed>}|null ['path'|'ids'|'records', the values], or null
     */
    private static function byId(object $request, string $verb, array $params, ?string $resourceId): ?array
    {
        if ($resourceId !== null) {
            return ['path', [$resourceId]];
        }
        $ids = $params['ids'] ?? null;
        if ($ids !== null && $ids !== '' && $ids !== []) {
            $list = is_array($ids) ? array_values($ids) : explode(',', (string)$ids);

            return ['ids', array_values($list)];
        }
        if ($verb === 'POST' || $verb === 'HEAD' || $verb === 'OPTIONS') {
            return null;
        }
        $filter = $params['filter'] ?? null;
        if (!in_array($verb, ['GET', 'DELETE'], true) && $filter !== null && $filter !== '' && $filter !== []) {
            return null; // update by filter (checked as a write filter)
        }
        try {
            // Read like ResourcesWrapper::unwrapResources(): the wrapper, or a JSON list. A bare
            // object carries no records for DreamFactory (a tunneled GET then lists rows).
            $payload = $request->getPayloadData();
            $wrapper = self::wrapper();
            $records = !is_array($payload) ? [] : (array_key_exists($wrapper, $payload)
                ? (is_array($payload[$wrapper]) ? $payload[$wrapper] : [])
                : (isset($payload[0]) ? $payload : []));
            $records = array_values(array_filter($records, 'is_array'));
        } catch (\Throwable $e) {
            $records = [];
        }

        return $records === [] ? null : ['records', $records];
    }

    /**
     * The record id a table event addresses ("crm._table.{table_name}.{id}" carries
     * "customers/5", "crm._table.customers.{id}" carries "5", "crm._table" carries the whole
     * path), resolved like RestHandler::setResourceMembers(): the second path segment.
     */
    public static function resourceId(string $path, string $service, mixed $resource): ?string
    {
        if (!is_string($resource) || $service === '' || !str_starts_with($path, $service . '._table')) {
            return null;
        }
        $rest = substr($path, strlen($service) + 7); // after "{service}._table"
        if ($rest !== '' && $rest[0] !== '.') {
            return null;
        }
        $segments = explode('/', rtrim($resource, '/'));
        if ($rest === '' || str_starts_with($rest, '.{table_name}')) {
            $id = $segments[1] ?? null;
        } elseif (str_ends_with($rest, '.{id}')) {
            $id = $segments[0];
        } else {
            return null; // "crm._table.customers": the resource names the table
        }

        return $id === null || $id === '' ? null : $id;
    }

    /**
     * Real columns (no db_function, not virtual) for the always-false filter, primary key first.
     *
     * @return list<string> DreamFactory field names
     */
    private static function falseFields(?TableTarget $target): array
    {
        if ($target === null) {
            return [];
        }
        $out = [];
        foreach (array_merge($target->primaryKey, array_keys($target->fields)) as $key) {
            $field = $target->fields[$key] ?? null;
            if ($field !== null && empty($field['virtual']) && ($field['filter_fn'] ?? null) === null && ($field['select_fn'] ?? null) === null) {
                $out[$field['name']] = true;
            }
        }

        return array_keys($out);
    }

    /**
     * Field names the caller sent (order, group, fields, filter, having, id_field, related):
     * DreamFactory's own validation messages quote them back ("Invalid field '1' in order by
     * clause."), and they are not row data.
     *
     * @return list<string>
     */
    private static function callerIdentifiers(object $request): array
    {
        try {
            $params = (array)$request->getParameters();
        } catch (\Throwable $e) {
            return [];
        }
        $out = [];
        foreach (['order', 'group', 'fields', 'id_field', 'related'] as $key) {
            $value = $params[$key] ?? null;
            $items = is_array($value) ? $value : (is_string($value) ? explode(',', $value) : []);
            foreach ($items as $item) {
                if (!is_string($item)) {
                    continue;
                }
                $item = trim($item);
                $out[] = $item;
                if ($key === 'order') {
                    $out[] = explode(' ', $item)[0]; // DreamFactory validates the first word
                }
            }
        }
        foreach (['filter', 'having'] as $key) {
            $value = $params[$key] ?? null;
            foreach (is_array($value) ? $value : [$value] as $filter) {
                if (!is_string($filter) || trim($filter) === '') {
                    continue;
                }
                $tree = FilterParser::parse($filter);
                if ($tree !== null) {
                    self::termFields($tree, $out);
                }
            }
        }

        return array_values(array_unique(array_filter($out, fn ($v) => $v !== '')));
    }

    /** @param list<string> $out */
    private static function termFields(array $node, array &$out): void
    {
        if ($node['t'] === 'term') {
            $split = FilterParser::splitComparison((string)$node['raw']);
            if ($split !== null) {
                $out[] = $split['field'];
            }

            return;
        }
        foreach ($node['c'] as $child) {
            self::termFields($child, $out);
        }
    }

    // ------------------------------------------------------------------------------ responses

    private function onResponse(object $event, bool $final): void
    {
        $request = $event->request ?? null;
        if (!is_object($request)) {
            return;
        }
        $ctx = $this->contexts[$request] ?? null;
        $response = $event->response ?? null;
        if ($ctx === null || !$response instanceof ServiceResponseInterface) {
            return; // not a covered table/routine request, or a stream/redirect (no table data)
        }
        try {
            if ($ctx->kind === RequestContext::UNRESOLVED) {
                $this->unresolved($ctx, $response, $request);

                return;
            }
            if ($ctx->mode === 'preview') {
                $this->preview($ctx, $response, $request);

                return;
            }
            $this->enforce($ctx, $response, $request);
        } catch (\Throwable $e) {
            $this->failClosed($ctx, $response, $e);
        }
    }

    private function enforce(RequestContext $ctx, ServiceResponseInterface $response, object $request): void
    {
        if (!$ctx->enforcing() || !$ctx->maskedCaller) {
            return;
        }
        $content = $response->getContent();
        if (isset($this->masked[$response]) && $this->masked[$response] === $content) {
            return; // masked already and untouched since (headers were set then)
        }
        $masker = $this->responseMasker();
        $status = (int)$response->getStatusCode();
        $present = [];

        if ($status >= 400) {
            if ($content instanceof \Throwable) {
                $content = self::exceptionContent($content, $status);
            }
            if ($ctx->kind === RequestContext::TABLE && is_array($content)) {
                $present = $masker->presentHidden($content['error']['context'][self::wrapper()] ?? null, $ctx->hidden, $ctx->relations);
            }
            $new = ErrorScrubber::scrub(
                $content,
                $ctx->keepIdentifiers(),
                $ctx->kind === RequestContext::TABLE
                    ? fn (array $records) => $masker->maskTable($records, $ctx->hidden, $ctx->relations)
                    : fn (array $records) => $masker->maskRoutine($records, $ctx->hidden),
                self::wrapper(),
                self::operation($request, $ctx),
                self::callerIdentifiers($request)
            );
        } elseif ($ctx->kind === RequestContext::ROUTINE) {
            // From what was masked, not from whether the output changed: a masked key holding
            // null must still be reported.
            [$new, $hit] = $masker->maskRoutineReporting($content, $ctx->hidden);
            $present = $hit ? ['*'] : [];
        } else {
            [$new, $present] = $masker->maskTableReporting($content, $ctx->hidden, $ctx->relations, self::asListIds($request, $ctx));
        }

        $headers = [];
        if ($present !== []) {
            $headers[self::HEADER_MASKED_FIELDS] = Headers::names($present);
        }
        $dropped = $this->droppedFor($ctx);
        if ($dropped !== []) {
            // Always reported: the request was changed, whatever the response contains. Includes
            // what internal requests made for this one dropped (related records joined on a
            // masked key match no rows there, and that answer reaches the caller only here).
            $headers[self::HEADER_REWRITES] = Headers::items($dropped);
        }
        if ($headers !== []) {
            self::addHeaders($response, $headers);
        }

        if ($new !== $response->getContent()) {
            $response->setContent($new);
            if (is_array($new)) {
                $response->setDataFormat(DataFormats::PHP_ARRAY);
            }
        }
        $this->masked[$response] = $response->getContent();
    }

    private function preview(RequestContext $ctx, ServiceResponseInterface $response, object $request): void
    {
        if ($ctx->kind !== RequestContext::TABLE || $ctx->hidden === [] && $ctx->relations === null) {
            return;
        }
        if ((int)$response->getStatusCode() >= 400) {
            return;
        }
        $names = $this->responseMasker()->presentHidden($response->getContent(), $ctx->hidden, $ctx->relations, self::asListIds($request, $ctx));
        if ($names === []) {
            return;
        }
        if (isset($this->previewLogged[$ctx])) {
            return;
        }
        $this->previewLogged[$ctx] = true;
        $target = $ctx->service . '.' . $ctx->resourceName;
        $n = count($names);
        Activity::logThrottled(
            'preview|' . self::callerKey() . '|' . $target,
            3600,
            'preview',
            'Would mask ' . $n . ' column' . ($n === 1 ? '' : 's'),
            $target,
            ['columns' => $names]
        );
    }

    /**
     * A covered table enforcement could not resolve (DreamFactory normally answers 404 then):
     * any successful response is withheld from a masked caller.
     */
    private function unresolved(RequestContext $ctx, ServiceResponseInterface $response, object $request): void
    {
        if (!$ctx->enforcing() || (int)$response->getStatusCode() >= 300 || strtoupper((string)$request->getMethod()) === 'OPTIONS') {
            return;
        }
        throw new \RuntimeException("table '{$ctx->resourceName}' of '{$ctx->service}' could not be resolved");
    }

    /** What the request did, for reduced database errors: insert, update, delete, read or call. */
    private static function operation(object $request, RequestContext $ctx): string
    {
        if ($ctx->kind === RequestContext::ROUTINE) {
            return 'call';
        }

        return match (strtoupper((string)$request->getMethod())) {
            'POST' => 'insert',
            'PUT', 'PATCH', 'MERGE' => 'update',
            'DELETE' => 'delete',
            'GET', 'HEAD' => 'read',
            default => 'request',
        };
    }

    private function failClosed(RequestContext $ctx, ServiceResponseInterface $response, \Throwable $e): void
    {
        if (!$ctx->enforcing()) {
            $this->previewFailed('response check', $e);

            return; // preview never changes a response
        }
        Log::error('df-masking: response masking failed: ' . get_class($e) . ': ' . $e->getMessage());
        $response->setStatusCode(500);
        $response->setContent(['error' => ['code' => 500, 'context' => null, 'message' => self::WITHHELD_MESSAGE]]);
        $response->setDataFormat(DataFormats::PHP_ARRAY);
        $this->masked[$response] = $response->getContent();
    }

    /**
     * A failure while the mode is Preview: logged once per process and minute (a broken policy
     * store would otherwise log on every event of every request), and the settings cache is
     * re-checked, so a dropped dm_setting stops being reported as Preview.
     */
    private function previewFailed(string $stage, \Throwable $e): void
    {
        $now = time();
        if (self::$previewFailureLoggedAt === null || $now - self::$previewFailureLoggedAt >= 60) {
            self::$previewFailureLoggedAt = $now;
            Log::error('df-masking: ' . $stage . ' failed in Preview; the request was passed through unchanged: '
                . get_class($e) . ': ' . $e->getMessage());
        }
        Settings::revalidate();
    }

    // ------------------------------------------------------------------------------ activity

    private function logDropped(RequestContext $ctx, array $dropped): void
    {
        $kinds = [];
        $first = null;
        foreach ($dropped as $item) {
            [$kind, $column] = array_pad(explode(':', $item, 2), 2, '');
            $kinds[$kind === 'having' ? 'filter' : $kind] = true;
            if ($first === null && $column !== '' && $column !== FilterRewriter::DROP_ALL) {
                $first = $column;
            }
        }
        // Filters: conditions on masked columns are unknown and match no rows;
        // sorting, grouping and functions on them are left out.
        $text = match (true) {
            count($kinds) > 1 => 'Masked columns could not be used to filter, sort or group',
            isset($kinds['order']) => 'Sorting by a masked column was left out',
            isset($kinds['group']) => 'Grouping by a masked column was left out',
            isset($kinds['fields']) => 'A function on a masked column was left out',
            $first === null => 'A filter Data Masking could not check matched no rows',
            default => 'Conditions on a masked column matched no rows',
        };
        $target = $ctx->service . '.' . $ctx->resourceName . ($first !== null ? '.' . $first : '');
        Activity::logThrottled('dropped|' . self::callerKey() . '|' . $target . '|' . implode(',', $dropped), 600, 'blocked', $text, $target, ['dropped' => $dropped]);
    }

    private function logRefused(RequestContext $ctx, string $why, string $text, ?string $column = null): void
    {
        $target = $ctx->service . '.' . $ctx->resourceName . ($column !== null ? '.' . $column : '');
        Activity::logThrottled($why . '|' . self::callerKey() . '|' . $target, 60, 'blocked', $text, $target);
    }

    // ------------------------------------------------------------------------------ dropped collector

    /**
     * The collector of the outermost request: the HTTP request DreamFactory is serving (internal
     * requests it makes for related records share it), or one per process without one.
     */
    private function collector(): \ArrayObject
    {
        try {
            $http = app()->bound('request') ? app('request') : null;
        } catch (\Throwable $e) {
            $http = null;
        }
        if (!is_object($http)) {
            return $this->fallbackCollector ??= new \ArrayObject();
        }

        return $this->collectors[$http] ??= new \ArrayObject();
    }

    /** @param list<string> $items "filter:ssn", ... */
    private function collect(array $items): void
    {
        $collector = $this->collector();
        foreach ($items as $item) {
            $collector->append([++$this->collectSeq, $item]);
        }
        if ($collector->count() > 1000) {
            // Long-running processes without an HTTP request: keep the newest items only.
            $collector->exchangeArray(array_slice($collector->getArrayCopy(), -500));
        }
    }

    /**
     * Dropped items to report for this context: its own, plus those collected from internal
     * requests made after it was created (while DreamFactory served it).
     *
     * @return list<string>
     */
    private function droppedFor(RequestContext $ctx): array
    {
        $out = $ctx->dropped;
        if ($this->collectSeq > $ctx->collectFrom) {
            foreach ($this->collector() as [$seq, $item]) {
                if ($seq > $ctx->collectFrom) {
                    $out[] = $item;
                }
            }
        }

        return array_values(array_unique($out));
    }

    // ------------------------------------------------------------------------------ helpers

    private function masker(): Masker
    {
        return $this->masker ??= new Masker();
    }

    private function responseMasker(): ResponseMasker
    {
        return $this->responseMasker ??= new ResponseMasker($this->masker(), self::wrapper());
    }

    /**
     * Identifies the caller for activity throttling without resolving a display label (that
     * costs a lookup; Activity resolves it only when a row is actually written).
     */
    private static function callerKey(): string
    {
        $c = Caller::current();

        return 'u' . ($c->userId() ?? '-') . ':r' . ($c->roleId() ?? '-') . ':a' . ($c->appId() ?? '-') . ':' . ($c->isAi() ? 'ai' : 'h');
    }

    private static function masksAnyTier(Caller $caller): bool
    {
        foreach (Catalog::tiers() as $tier) {
            if (!Access::callerSeesRealValues($caller, $tier)) {
                return true;
            }
        }

        return false;
    }

    /** @return list<string>|null lower-cased id fields when the response is an as_list */
    private static function asListIds(object $request, RequestContext $ctx): ?array
    {
        if (!$request->getParameterAsBool('as_list')) {
            return null;
        }
        $idField = $request->getParameter('id_field');
        if (is_string($idField) && trim($idField) !== '') {
            return array_map(fn ($f) => strtolower(trim($f)), explode(',', $idField));
        }

        return $ctx->target?->primaryKey ?? [];
    }

    /**
     * RestHandler::setResourceMembers(): trailing slashes trimmed, then the first segment; an
     * empty first segment ("/customers") means no table.
     */
    private static function firstSegment(mixed $resource): ?string
    {
        if (!is_string($resource)) {
            return null;
        }
        $segment = explode('/', rtrim($resource, '/'), 2)[0];

        return $segment === '' ? null : $segment;
    }

    private static function addHeaders(ServiceResponseInterface $response, array $headers): void
    {
        $current = $response->getHeaders();
        $current = is_array($current) ? $current : [];
        foreach ($headers as $key => $value) {
            $current[$key] = $value;
        }
        $response->setHeaders($current);
    }

    private static function exceptionContent(\Throwable $e, int $status): array
    {
        return ['error' => [
            'code' => $e->getCode() ?: $status,
            'context' => $e instanceof DfException ? $e->getContext() : null,
            'message' => htmlentities($e->getMessage(), ENT_COMPAT),
        ]];
    }

    private static function wrapper(): string
    {
        try {
            $wrapper = config('df.resources_wrapper', 'resource');
        } catch (\Throwable $e) {
            $wrapper = null;
        }

        return is_string($wrapper) && $wrapper !== '' ? $wrapper : 'resource';
    }
}

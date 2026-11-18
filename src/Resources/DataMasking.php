<?php

namespace DreamFactory\Core\Masking\Resources;

use DreamFactory\Core\Enums\Verbs;
use DreamFactory\Core\Exceptions\BadRequestException;
use DreamFactory\Core\Exceptions\NotFoundException;
use DreamFactory\Core\Exceptions\ServiceUnavailableException;
use DreamFactory\Core\Masking\Resources\Handlers\AccessHandler;
use DreamFactory\Core\Masking\Resources\Handlers\ActivityHandler;
use DreamFactory\Core\Masking\Resources\Handlers\ColumnHandler;
use DreamFactory\Core\Masking\Resources\Handlers\Guard;
use DreamFactory\Core\Masking\Resources\Handlers\MaskHandler;
use DreamFactory\Core\Masking\Resources\Handlers\OverviewHandler;
use DreamFactory\Core\Masking\Resources\Handlers\RuleHandler;
use DreamFactory\Core\Masking\Support\Tables;
use DreamFactory\Core\Resources\BaseRestResource;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Schema;

/**
 * System resource `data_masking` (Gold): /api/v2/system/data_masking[/...].
 *
 *   GET    /                          overview
 *   PATCH  /                          {mode}
 *   GET    /table                     classified tables per covered service
 *   GET    /column?service=&table=    classified columns
 *   PATCH  /column/{svc.table.col}    {class: id|null}   (or PATCH /column {id, class})
 *   POST   /scan                      {service?, sample?}
 *   GET    /access   PATCH /access    who sees real values
 *   GET    /mask     PATCH /mask      mask format per class
 *   GET    /rule     POST /rule       custom detection rules
 *   DELETE /rule/{id}
 *   POST   /rule/test                 {match, pattern}
 *   GET    /rule/builtin
 *   GET    /activity?kind=&limit=&before=
 *
 * Every request needs a full sys admin (Guard::requireSysAdminAccess). Wire format is
 * snake_case; data (class ids, column names) is never used as an object key. PUT is accepted as
 * an alias of PATCH.
 */
class DataMasking extends BaseRestResource
{
    public function __construct($settings = [])
    {
        $settings = (array)$settings;
        $settings['verbAliases'] = [Verbs::PUT => Verbs::PATCH];
        parent::__construct($settings);
    }

    protected function handleGET()
    {
        Guard::requireSysAdminAccess(false);

        return $this->guarded(fn () => $this->routeGet());
    }

    private function routeGet(): mixed
    {
        $id = $this->rest();

        return match ($this->resource) {
            null, '' => (new OverviewHandler())->overview(),
            'table' => $this->only($id === '', fn () => (new ColumnHandler())->tables()),
            'column' => $this->only($id === '', fn () => (new ColumnHandler())->columns(
                $this->stringParam('service'),
                $this->stringParam('table')
            )),
            'access' => $this->only($id === '', fn () => (new AccessHandler())->get()),
            'mask' => $this->only($id === '', fn () => (new MaskHandler())->list()),
            'rule' => match ($id) {
                '' => (new RuleHandler())->list(),
                'builtin' => (new RuleHandler())->builtin(),
                default => $this->unsupported(),
            },
            'activity' => $this->only($id === '', fn () => (new ActivityHandler())->list(
                $this->request->getParameter('kind'),
                $this->request->getParameter('limit'),
                $this->request->getParameter('before')
            )),
            default => throw new NotFoundException("Resource '{$this->resource}' not found."),
        };
    }

    protected function handlePATCH()
    {
        Guard::requireSysAdminAccess(true);

        return $this->guarded(fn () => $this->routePatch());
    }

    private function routePatch(): mixed
    {
        $id = $this->rest();

        return match ($this->resource) {
            null, '' => (new OverviewHandler())->setMode($this->payload()),
            'column' => (new ColumnHandler())->decide($this->columnId($id), $this->payload()),
            'access' => $this->only($id === '', fn () => (new AccessHandler())->patch($this->payload())),
            'mask' => $this->only($id === '', fn () => (new MaskHandler())->patch($this->payload())),
            default => $this->unsupported(),
        };
    }

    protected function handlePOST()
    {
        Guard::requireSysAdminAccess(true);

        return $this->guarded(fn () => $this->routePost());
    }

    private function routePost(): mixed
    {
        $id = $this->rest();

        return match ($this->resource) {
            'scan' => $this->only($id === '', fn () => (new OverviewHandler())->startScan($this->payload())),
            'rule' => match ($id) {
                '' => (new RuleHandler())->create($this->payload()),
                'test' => (new RuleHandler())->test($this->payload()),
                default => $this->unsupported(),
            },
            default => $this->unsupported(),
        };
    }

    protected function handleDELETE()
    {
        Guard::requireSysAdminAccess(true);

        return $this->guarded(fn () => $this->routeDelete());
    }

    private function routeDelete(): mixed
    {
        $id = $this->rest();

        return match ($this->resource) {
            'rule' => $id === '' || str_contains($id, '/')
                ? $this->unsupported()
                : (new RuleHandler())->delete($id),
            default => $this->unsupported(),
        };
    }

    /**
     * A database error while the df-masking tables are missing (package installed, migrations
     * not run yet) becomes a clear 503 instead of an SQL error.
     */
    private function guarded(\Closure $fn): mixed
    {
        try {
            return $fn();
        } catch (QueryException $e) {
            $migrated = true;
            try {
                $migrated = Schema::hasTable(Tables::COLUMN) && Schema::hasTable(Tables::SETTING);
            } catch (\Throwable $ignored) {
            }
            if (!$migrated) {
                throw new ServiceUnavailableException('Data Masking is not set up yet. Run: php artisan df:masking setup');
            }
            throw $e;
        }
    }

    /**
     * The column id of PATCH column: the path form (column/{service.table.column}), or the body
     * form {"id": "service.table.column"} for names DreamFactory's route pattern rejects (CJK,
     * Polish, Cyrillic, %, quotes ...). The admin UI always sends the body form.
     *
     * @throws BadRequestException
     */
    private function columnId(string $pathId): string
    {
        if ($pathId !== '') {
            return $pathId;
        }
        $id = $this->payload()['id'] ?? null;
        if (!is_string($id) || trim($id) === '') {
            throw new BadRequestException('Send the column id (service.table.column) as id in the body, with class.');
        }

        return $id;
    }

    /** Everything after the first path segment ("column/crm.t.c" -> "crm.t.c"), slashes kept. */
    private function rest(): string
    {
        $parts = (array)$this->resourceArray;
        array_shift($parts);

        return trim(implode('/', $parts));
    }

    private function payload(): array
    {
        $data = $this->request->getPayloadData();

        return is_array($data) ? $data : [];
    }

    private function stringParam(string $name): ?string
    {
        $value = $this->request->getParameter($name);
        if ($value === null || is_array($value)) {
            return null;
        }
        $value = trim((string)$value);

        return $value === '' ? null : $value;
    }

    private function only(bool $ok, \Closure $fn): mixed
    {
        return $ok ? $fn() : $this->unsupported();
    }

    /** @throws BadRequestException */
    private function unsupported(): never
    {
        $path = trim('data_masking/' . $this->resourcePath, '/');
        throw new BadRequestException(ucfirst(strtolower($this->getRequestedAction())) . " is not supported on system/$path.");
    }

    protected function getApiDocPaths()
    {
        $base = '/' . $this->name;
        $op = fn (string $id, string $summary, array $extra = []) => array_merge([
            'summary' => $summary,
            'operationId' => $id,
            'tags' => ['system'],
            'responses' => ['200' => ['description' => 'Success']],
        ], $extra);
        $body = fn (array $properties) => [
            'requestBody' => [
                'content' => ['application/json' => ['schema' => ['type' => 'object', 'properties' => $properties]]],
            ],
        ];
        $query = fn (string $name, string $description) => [
            'name' => $name, 'in' => 'query', 'required' => false, 'description' => $description,
            'schema' => ['type' => 'string'],
        ];

        return [
            $base => [
                'get' => $op('getDataMaskingOverview', 'Data Masking overview: mode, scan state, counts, your access, coverage.'),
                'patch' => $op('setDataMaskingMode', 'Set the masking mode (off, preview, on).', $body([
                    'mode' => ['type' => 'string', 'enum' => ['off', 'preview', 'on']],
                ])),
            ],
            $base . '/table' => [
                'get' => $op('getDataMaskingTables', 'Classified tables per covered database service.'),
            ],
            $base . '/column' => [
                'get' => $op('getDataMaskingColumns', 'Classified columns with evidence and masked examples.', [
                    'parameters' => [$query('service', 'Service name.'), $query('table', 'Table name.')],
                ]),
                'patch' => $op('decideDataMaskingColumnById', 'Decide a column given by id in the body (any column name).', $body([
                    'id' => ['type' => 'string', 'description' => 'service.table.column'],
                    'class' => ['type' => 'string', 'nullable' => true],
                ])),
            ],
            $base . '/column/{id}' => [
                'patch' => $op('decideDataMaskingColumn', 'Decide a column: a class id masks it, null marks it not sensitive.', $body([
                    'class' => ['type' => 'string', 'nullable' => true],
                ]) + ['parameters' => [[
                    'name' => 'id', 'in' => 'path', 'required' => true, 'description' => 'service.table.column',
                    'schema' => ['type' => 'string'],
                ]]]),
            ],
            $base . '/scan' => [
                'post' => $op('startDataMaskingScan', 'Start a background classification scan.', $body([
                    'service' => ['type' => 'string'],
                    'sample' => ['type' => 'boolean', 'description' => 'Also sample services that bill per query (Snowflake).'],
                ])),
            ],
            $base . '/access' => [
                'get' => $op('getDataMaskingAccess', 'Who sees real values: admins, AI sessions, roles.'),
                'patch' => $op('setDataMaskingAccess', 'Change who sees real values (loosening needs the super admin).'),
            ],
            $base . '/mask' => [
                'get' => $op('getDataMaskingFormats', 'Mask format per class.'),
                'patch' => $op('setDataMaskingFormats', 'Change mask formats.'),
            ],
            $base . '/rule' => [
                'get' => $op('getDataMaskingRules', 'Custom detection rules.'),
                'post' => $op('addDataMaskingRule', 'Add a custom detection rule.', $body([
                    'match' => ['type' => 'string', 'enum' => ['name', 'value']],
                    'pattern' => ['type' => 'string', 'maxLength' => 500],
                    'class' => ['type' => 'string'],
                ])),
            ],
            $base . '/rule/{id}' => [
                'delete' => $op('deleteDataMaskingRule', 'Delete a custom detection rule.', ['parameters' => [[
                    'name' => 'id', 'in' => 'path', 'required' => true, 'schema' => ['type' => 'integer'],
                ]]]),
            ],
            $base . '/rule/test' => [
                'post' => $op('testDataMaskingRule', 'Show which columns a pattern would match.'),
            ],
            $base . '/rule/builtin' => [
                'get' => $op('getDataMaskingBuiltinRules', 'Built-in detectors per class.'),
            ],
            $base . '/activity' => [
                'get' => $op('getDataMaskingActivity', 'Masking activity, newest first.', [
                    'parameters' => [
                        $query('kind', 'One kind or a comma list.'),
                        $query('limit', 'Max rows (default 200, max 1000).'),
                        $query('before', 'Only rows older than this activity id (paging).'),
                    ],
                ]),
            ],
        ];
    }
}

<?php

namespace DreamFactory\Core\Masking\Resources;

use DreamFactory\Core\Contracts\ServiceResponseInterface;
use DreamFactory\Core\Exceptions\BadRequestException;
use DreamFactory\Core\Exceptions\ForbiddenException;
use DreamFactory\Core\Exceptions\NotFoundException;
use DreamFactory\Core\Masking\Baselines\BaselineRegistry;
use DreamFactory\Core\Masking\Baselines\BaselineService;
use DreamFactory\Core\Masking\Baselines\Report;
use DreamFactory\Core\Masking\Resources\Handlers\Guard;
use DreamFactory\Core\Masking\Support\Caller;
use DreamFactory\Core\Resources\BaseRestResource;
use DreamFactory\Core\Utility\ResponseFactory;
use Symfony\Component\HttpFoundation\StreamedResponse;

/**
 * System resource `security_baseline` (Gold, "Compliance baselines").
 *
 *   GET    system/security_baseline                     every baseline with its live score
 *   GET    system/security_baseline/{id}[?mode=on]      controls + `changes` Apply would make now
 *   POST   system/security_baseline/{id}/apply          {mode?: 'on'} adopt + apply; returns the detail
 *   DELETE system/security_baseline/{id}               stop tracking (settings stay)
 *   GET    system/security_baseline/{id}/report[?format=json|csv][&download=true]  evidence
 *          (format=csv is always text/csv as an attachment, whatever the Accept header says)
 *
 * DreamFactory's access check has already run (sys admins, or roles given system access). On
 * top of it every read and write needs a sys admin (403 otherwise), and AI and MCP sessions can
 * read but never write (403 + activity `blocked`). Apply with mode 'on' before the first
 * completed scan is refused with 409.
 */
class SecurityBaseline extends BaseRestResource
{
    private const SUB_APPLY = 'apply';
    private const SUB_REPORT = 'report';


    protected static function getResourceIdentifier()
    {
        return 'id';
    }

    protected function handleGET()
    {
        self::requireSysAdmin(false);
        if (empty($this->resource)) {
            return ['resource' => BaselineService::list()];
        }
        $id = $this->baselineId();
        $sub = $this->subResource();

        if ($sub === null) {
            $mode = $this->request->getParameter('mode');

            return BaselineService::detail($id, is_string($mode) && strtolower($mode) === 'on');
        }
        if ($sub === self::SUB_REPORT) {
            return $this->report($id);
        }

        throw new NotFoundException("Resource '{$this->resourcePath}' not found for service '{$this->getServiceName()}'.");
    }

    protected function handlePOST()
    {
        self::requireSysAdmin(true);
        $id = $this->baselineId();
        if ($this->subResource() !== self::SUB_APPLY) {
            throw new BadRequestException('Use POST system/security_baseline/{id}/apply to apply a baseline.');
        }
        $baseline = BaselineRegistry::get($id);
        Guard::denyAi('Blocked an AI session from applying the ' . $baseline['name'] . ' baseline', $id);

        $mode = $this->request->getPayloadData('mode');
        if ($mode !== null && !is_string($mode)) {
            throw new BadRequestException("mode must be 'on' or left out.");
        }

        return BaselineService::apply($id, $mode === null ? null : strtolower(trim($mode)));
    }

    protected function handleDELETE()
    {
        self::requireSysAdmin(true);
        $id = $this->baselineId();
        if ($this->subResource() !== null) {
            throw new BadRequestException('Use DELETE system/security_baseline/{id} to stop tracking a baseline.');
        }
        $baseline = BaselineRegistry::get($id);
        Guard::denyAi('Blocked an AI session from changing the ' . $baseline['name'] . ' baseline', $id);

        return BaselineService::forget($id);
    }

    /**
     * Compliance baselines show and change who sees real values: sys admins only, even when a
     * role was given access to the system service (same rule and wording as system/data_masking).
     *
     * @throws ForbiddenException
     */
    public static function requireSysAdmin(bool $write): void
    {
        if (method_exists(Guard::class, 'requireSysAdminAccess')) {
            Guard::requireSysAdminAccess($write, 'Compliance baselines');

            return;
        }
        if (!Caller::current()->isSysAdmin()) {
            throw new ForbiddenException('Only a system administrator can ' . ($write ? 'change' : 'view') . ' Compliance baselines.');
        }
    }

    /** @throws NotFoundException|BadRequestException */
    private function baselineId(): string
    {
        $id = (string)$this->resource;
        if ($id === '') {
            throw new BadRequestException('A baseline id is required.');
        }
        if (BaselineRegistry::get($id) === null) {
            throw new NotFoundException("Compliance baseline '$id' not found.");
        }

        return $id;
    }

    /** The segment after the baseline id ("apply", "report"); null when there is none. */
    private function subResource(): ?string
    {
        $parts = $this->resourceArray ?? [];
        if (count($parts) > 2) {
            throw new NotFoundException("Resource '{$this->resourcePath}' not found for service '{$this->getServiceName()}'.");
        }
        $sub = $parts[1] ?? null;

        return ($sub === null || $sub === '') ? null : strtolower((string)$sub);
    }

    private function report(string $id)
    {
        $format = strtolower((string)$this->request->getParameter('format', 'json'));
        if (!in_array($format, ['json', 'csv'], true)) {
            throw new BadRequestException("format must be 'json' or 'csv'.");
        }
        $download = $this->request->getParameterAsBool('download');
        $report = BaselineService::report($id);
        $now = strtotime((string)$report['generated_at']) ?: time();

        if ($format === 'csv') {
            return self::csvResponse(Report::csv($report), Report::filename($id, $now, 'csv'));
        }

        if ($download) {
            return ResponseFactory::create(
                $report,
                null,
                ServiceResponseInterface::HTTP_OK,
                ['Content-Disposition' => 'attachment; filename="' . Report::filename($id, $now, 'json') . '"']
            );
        }

        return $report;
    }

    /**
     * The CSV report as a StreamedResponse, which DreamFactory passes through as it is. A
     * ServiceResponse would be renegotiated against the Accept header: with Accept:
     * application/json, or no Accept header (DreamFactory's default response type), the CSV came
     * back as JSON rows.
     */
    private static function csvResponse(string $csv, string $filename): StreamedResponse
    {
        return new StreamedResponse(
            function () use ($csv): void {
                echo $csv;
            },
            ServiceResponseInterface::HTTP_OK,
            [
                'Content-Type' => 'text/csv; charset=utf-8',
                'Content-Disposition' => 'attachment; filename="' . $filename . '"',
            ]
        );
    }

    protected function getApiDocPaths()
    {
        $service = $this->getServiceName();
        $capitalized = camelize($service);
        $path = '/' . strtolower($this->name);
        $idParam = [
            'name' => 'id',
            'description' => 'Baseline id: ' . implode(', ', BaselineRegistry::ids()) . '.',
            'schema' => ['type' => 'string', 'enum' => BaselineRegistry::ids()],
            'in' => 'path',
            'required' => true,
        ];
        $ok = ['200' => ['description' => 'Success']];

        return [
            $path => [
                'get' => [
                    'summary' => 'List Compliance baselines with their live scores.',
                    'description' => 'Each baseline maps DreamFactory-owned controls (masking, real-value access, platform settings) '
                        . 'to framework references. A baseline is not a certification.',
                    'operationId' => 'get' . $capitalized . 'SecurityBaselines',
                    'responses' => $ok,
                ],
            ],
            $path . '/{id}' => [
                'get' => [
                    'summary' => 'Retrieve one baseline: controls with live status and the changes Apply would make now.',
                    'operationId' => 'get' . $capitalized . 'SecurityBaseline',
                    'parameters' => [
                        $idParam,
                        [
                            'name' => 'mode',
                            'description' => "Set to 'on' to list the changes Apply with mode 'on' would make.",
                            'schema' => ['type' => 'string', 'enum' => ['on']],
                            'in' => 'query',
                        ],
                    ],
                    'responses' => $ok,
                ],
                'delete' => [
                    'summary' => 'Stop tracking a baseline. Settings it applied stay as they are.',
                    'operationId' => 'delete' . $capitalized . 'SecurityBaseline',
                    'parameters' => [$idParam],
                    'responses' => $ok,
                ],
            ],
            $path . '/{id}/apply' => [
                'post' => [
                    'summary' => 'Adopt a baseline and apply the DreamFactory settings it requires.',
                    'description' => 'Only tightens: mask formats, AI masking, admin grant limits, role scopes, detection rules, '
                        . "and mode raised to at least Preview (On only with mode 'on'). Never clears masking or admin decisions. "
                        . "On an instance that was never scanned, Apply starts the first scan (scan_started: true) and mode 'on' "
                        . 'is refused with 409 until a scan has completed.',
                    'operationId' => 'apply' . $capitalized . 'SecurityBaseline',
                    'parameters' => [$idParam],
                    'requestBody' => [
                        'content' => [
                            'application/json' => [
                                'schema' => [
                                    'type' => 'object',
                                    'properties' => [
                                        'mode' => ['type' => 'string', 'enum' => ['on'], 'description' => 'Also turn masking on.'],
                                    ],
                                ],
                            ],
                        ],
                    ],
                    'responses' => $ok,
                ],
            ],
            $path . '/{id}/report' => [
                'get' => [
                    'summary' => 'Evidence report: controls, masking inventory, access summary, 90 days of masking activity.',
                    'description' => 'Contains no data values. CSV has one row per control, each with the frameworks '
                        . 'the baseline maps to and the disclaimer (a baseline is not a certification).',
                    'operationId' => 'get' . $capitalized . 'SecurityBaselineReport',
                    'parameters' => [
                        $idParam,
                        [
                            'name' => 'format',
                            'description' => 'csv: always text/csv as a file attachment, whatever the Accept header says.',
                            'schema' => ['type' => 'string', 'enum' => ['json', 'csv']],
                            'in' => 'query',
                        ],
                        [
                            'name' => 'download',
                            'description' => 'Send the JSON report as a file attachment.',
                            'schema' => ['type' => 'boolean'],
                            'in' => 'query',
                        ],
                    ],
                    'responses' => $ok,
                ],
            ],
        ];
    }
}

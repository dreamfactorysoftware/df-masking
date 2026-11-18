<?php

namespace DreamFactory\Core\Masking\Baselines;

use DreamFactory\Core\Masking\Support\Catalog;
use DreamFactory\Core\Masking\Support\Tables;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * Evidence report for one baseline: instance facts, the evaluated controls, the masking
 * inventory (counts only), who can see real values, and the masking activity of the last 90
 * days. Contains no data values: only settings, counts, names of services, roles, classes and
 * admins, and activity sentences (which never carry values by contract).
 */
final class Report
{
    public const ACTIVITY_DAYS = 90;

    /** Activity entries included in full; counts per kind always cover the whole window. */
    public const ACTIVITY_MAX_ENTRIES = 5000;

    public const DISCLAIMER = 'A baseline checks the DreamFactory settings that support these framework requirements. '
        . 'It is not a certification and does not cover controls outside DreamFactory.';

    /** frameworks and disclaimer repeat on every row, so each row stands on its own when filtered. */
    private const CSV_HEADER = [
        'baseline_id', 'baseline', 'control_id', 'title', 'status', 'detail', 'references', 'generated_at',
        'frameworks', 'disclaimer',
    ];

    private function __construct()
    {
    }

    /**
     * @param array $detail BaselineService::detail() output for the same snapshot
     */
    public static function build(array $baseline, State $state, array $detail): array
    {
        return [
            'report' => 'DreamFactory Compliance baseline evidence',
            'generated_at' => Time::iso($state->now),
            'disclaimer' => self::DISCLAIMER,
            'instance' => self::instance(),
            'baseline' => [
                'id' => $baseline['id'],
                'name' => $baseline['name'],
                'vertical' => $baseline['vertical'],
                'frameworks' => $baseline['frameworks'],
                'adopted' => $detail['adopted'],
                'adopted_at' => $detail['adopted_at'],
                'adopted_by' => $detail['adopted_by'],
                'applied_at' => $detail['applied_at'],
            ],
            'score' => $detail['score'],
            'controls' => array_map(fn (array $c) => [
                'id' => $c['id'],
                'title' => $c['title'],
                'refs' => $c['refs'],
                'status' => $c['status'],
                'detail' => $c['detail'],
            ], $detail['controls']),
            'pending_changes' => $detail['changes'],
            'masking' => [
                'mode' => $state->mode,
                'ai' => $state->ai,
                'formats' => self::formats($state),
                'inventory' => self::inventory($state),
            ],
            'access' => self::access($state),
            'activity' => self::activity($state),
        ];
    }

    /**
     * One row per control, RFC 4180, with a header row. Every row carries the frameworks the
     * baseline maps to and the disclaimer (a baseline is not a certification).
     */
    public static function csv(array $report): string
    {
        $frameworks = implode('; ', (array)($report['baseline']['frameworks'] ?? []));
        $disclaimer = (string)($report['disclaimer'] ?? self::DISCLAIMER);
        $out = fopen('php://temp', 'r+');
        fputcsv($out, self::CSV_HEADER, ',', '"', '');
        foreach ($report['controls'] as $control) {
            fputcsv($out, array_map([self::class, 'cell'], [
                $report['baseline']['id'],
                $report['baseline']['name'],
                $control['id'],
                $control['title'],
                $control['status'],
                (string)($control['detail'] ?? ''),
                implode('; ', $control['refs']),
                $report['generated_at'],
                $frameworks,
                $disclaimer,
            ]), ',', '"', '');
        }
        rewind($out);
        $csv = stream_get_contents($out);
        fclose($out);

        return (string)$csv;
    }

    public static function filename(string $baselineId, int $now, string $extension): string
    {
        return sprintf('dreamfactory-%s-baseline-%s.%s', $baselineId, gmdate('Y-m-d', $now), $extension);
    }

    /** Keeps a CSV cell from being read as a spreadsheet formula. */
    private static function cell(string $value): string
    {
        return ($value !== '' && in_array($value[0], ['=', '+', '-', '@', "\t", "\r"], true)) ? "'" . $value : $value;
    }

    // ------------------------------------------------------------------------------------------

    private static function instance(): array
    {
        $info = [
            'url' => self::safe(fn () => config('app.url')),
            'version' => self::safe(fn () => config('app.version')),
            'license' => self::safe(fn () => \DreamFactory\Core\Utility\Environment::getLicenseLevel()),
            'install_type' => self::safe(fn () => env('DF_INSTALL')),
            'host' => self::safe(fn () => php_uname('n')),
            'system_db_driver' => self::safe(fn () => config('database.default')),
            'php' => PHP_VERSION,
            'df_masking' => self::safe(function () {
                $version = class_exists(\Composer\InstalledVersions::class)
                    && \Composer\InstalledVersions::isInstalled('dreamfactory/df-masking')
                    ? \Composer\InstalledVersions::getPrettyVersion('dreamfactory/df-masking')
                    : null;
                $provider = 'DreamFactory\\Core\\Masking\\ServiceProvider';
                if ((!is_string($version) || $version === '' || str_starts_with($version, 'dev-'))
                    && defined($provider . '::VERSION')) {
                    $version = constant($provider . '::VERSION');
                }

                return $version;
            }),
        ];

        return array_map(fn ($v) => is_scalar($v) ? $v : null, $info);
    }

    /** @return list<array{class:string,label:string,tier:string,format:string}> */
    private static function formats(State $state): array
    {
        $out = [];
        foreach (Catalog::classes() as $class) {
            $format = $state->formatOf($class['id']);
            $out[] = [
                'class' => $class['id'],
                'label' => Catalog::label($class['id']),
                'tier' => $class['tier'],
                'format' => $format,
            ];
        }

        return $out;
    }

    private static function inventory(State $state): array
    {
        $totals = ['masked' => 0, 'review' => 0, 'clear' => 0, 'columns' => 0];
        $services = [];
        $classes = [];
        $tiers = [];
        $decisions = ['kept_masked' => 0, 'marked_not_sensitive' => 0];

        try {
            $rows = DB::table(Tables::COLUMN . ' as c')
                ->join('service as s', 's.id', '=', 'c.service_id')
                ->groupBy('c.service_id', 's.name', 's.label', 's.type', 'c.verdict', 'c.class', 'c.tier', 'c.source')
                ->orderBy('s.name')
                ->get([
                    'c.service_id', 's.name', 's.label', 's.type', 'c.verdict', 'c.class', 'c.tier', 'c.source',
                    DB::raw('COUNT(*) as n'),
                ]);
        } catch (\Throwable $e) {
            self::warn('inventory', $e);

            return ['error' => 'The masking inventory could not be read.'];
        }

        $lastScan = [];
        $scanError = [];
        foreach ($state->covered ?? [] as $svc) {
            $lastScan[$svc['id']] = $svc['last_scan_at'];
            $scanError[$svc['id']] = $svc['scan_error'] ?? null;
        }

        foreach ($rows as $row) {
            $n = (int)$row->n;
            $verdict = (string)$row->verdict;
            if (!isset($totals[$verdict])) {
                continue;
            }
            $sid = (int)$row->service_id;
            $services[$sid] ??= [
                'service' => (string)$row->name,
                'label' => is_string($row->label) && $row->label !== '' ? $row->label : (string)$row->name,
                'type' => (string)$row->type,
                'masked' => 0,
                'review' => 0,
                'clear' => 0,
                'last_scanned_at' => Time::iso($lastScan[$sid] ?? null),
                'scan_error' => $scanError[$sid] ?? null,
            ];
            $services[$sid][$verdict] += $n;
            $totals[$verdict] += $n;
            $totals['columns'] += $n;

            if ($row->source === 'admin') {
                $decisions[$verdict === 'clear' ? 'marked_not_sensitive' : 'kept_masked'] += $n;
            }
            if ($verdict === 'clear' || !is_string($row->class) || $row->class === '') {
                continue;
            }
            $class = $row->class;
            $classes[$class] ??= [
                'class' => $class,
                'label' => Catalog::label($class),
                'tier' => Catalog::tierOf($class) ?? (string)$row->tier,
                'masked' => 0,
                'review' => 0,
            ];
            $classes[$class][$verdict] += $n;
            $tier = $classes[$class]['tier'];
            $tiers[$tier] ??= ['tier' => $tier, 'label' => Catalog::tierLabel($tier), 'masked' => 0, 'review' => 0];
            $tiers[$tier][$verdict] += $n;
        }

        // Covered services never scanned still belong in the inventory.
        foreach ($state->covered ?? [] as $svc) {
            $services[$svc['id']] ??= [
                'service' => $svc['name'],
                'label' => $svc['label'],
                'type' => $svc['type'],
                'masked' => 0,
                'review' => 0,
                'clear' => 0,
                'last_scanned_at' => Time::iso($svc['last_scan_at']),
                'scan_error' => $svc['scan_error'] ?? null,
            ];
        }

        // Catalog order for classes and tiers; services by name.
        $classOrder = array_flip(Catalog::ids());
        uksort($classes, fn ($a, $b) => ($classOrder[$a] ?? 999) <=> ($classOrder[$b] ?? 999));
        $tierOrder = array_flip(Catalog::tiers());
        uksort($tiers, fn ($a, $b) => ($tierOrder[$a] ?? 999) <=> ($tierOrder[$b] ?? 999));
        $services = array_values($services);
        usort($services, fn ($a, $b) => strcmp($a['service'], $b['service']));

        $inventory = [
            'totals' => $totals,
            'admin_decisions' => $decisions,
            'services' => $services,
            'classes' => array_values($classes),
            'tiers' => array_values($tiers),
        ];
        // last_scanned_at null then means "unknown", not "never scanned".
        if (array_filter($state->covered ?? [], fn ($svc) => !empty($svc['scan_unknown'])) !== []) {
            $inventory['scan_history_error'] = 'The scan history could not be read.';
        }

        return $inventory;
    }

    private static function access(State $state): array
    {
        $grants = [];
        foreach ($state->grants ?? [] as $grant) {
            $grants[] = [
                'admin' => $grant['name'],
                'email' => $grant['email'],
                'expires_at' => Time::iso($grant['expires_at']),
            ];
        }
        $roles = [];
        foreach ($state->roles ?? [] as $role) {
            if ($role['enabled']) {
                $roles[] = ['role' => $role['name'], 'scope' => $role['scope']];
            }
        }

        return [
            'admins_mode' => $state->adminsMode,
            'admin_grants' => $state->adminsMode === 'selected' ? $grants : [],
            'ai' => $state->ai,
            'roles_with_real_values' => $roles,
            'root_admin_designated' => $state->platformValue('root_admin'),
        ];
    }

    private static function activity(State $state): array
    {
        $since = $state->now - self::ACTIVITY_DAYS * 86400;
        $sinceAt = Time::carbon($since);
        $result = [
            'since' => Time::iso($since),
            'total' => 0,
            'by_kind' => [],
            'entries' => [],
            'truncated' => false,
        ];

        try {
            $byKind = DB::table(Tables::ACTIVITY)
                ->where('created_at', '>=', $sinceAt)
                ->groupBy('kind')
                ->orderBy('kind')
                ->get(['kind', DB::raw('COUNT(*) as n')]);
            foreach ($byKind as $row) {
                $result['by_kind'][] = ['kind' => (string)$row->kind, 'count' => (int)$row->n];
                $result['total'] += (int)$row->n;
            }

            $rows = DB::table(Tables::ACTIVITY)
                ->where('created_at', '>=', $sinceAt)
                ->orderBy('created_at', 'desc')
                ->orderBy('id', 'desc')
                ->limit(self::ACTIVITY_MAX_ENTRIES)
                ->get(['id', 'created_at', 'actor', 'kind', 'text', 'target']);
            foreach ($rows as $row) {
                $result['entries'][] = [
                    'id' => (int)$row->id,
                    'at' => Time::iso(Time::ts($row->created_at)),
                    'actor' => (string)$row->actor,
                    'kind' => (string)$row->kind,
                    'text' => (string)$row->text,
                    'target' => $row->target !== null ? (string)$row->target : null,
                ];
            }
            $result['truncated'] = $result['total'] > count($result['entries']);
        } catch (\Throwable $e) {
            self::warn('activity', $e);
            $result['error'] = 'The masking activity could not be read.';
        }

        return $result;
    }

    private static function safe(callable $fn): mixed
    {
        try {
            return $fn();
        } catch (\Throwable $e) {
            return null;
        }
    }

    private static function warn(string $part, \Throwable $e): void
    {
        try {
            Log::warning('df-masking baselines: evidence report could not read ' . $part . ': ' . $e->getMessage());
        } catch (\Throwable $ignored) {
        }
    }
}

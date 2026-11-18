<?php

namespace DreamFactory\Core\Masking\Resources\Handlers;

use DreamFactory\Core\Exceptions\BadRequestException;
use DreamFactory\Core\Exceptions\ConflictResourceException;
use DreamFactory\Core\Exceptions\NotFoundException;
use DreamFactory\Core\Exceptions\NotImplementedException;
use DreamFactory\Core\Masking\Support\Access;
use DreamFactory\Core\Masking\Support\Activity;
use DreamFactory\Core\Masking\Support\Caller;
use DreamFactory\Core\Masking\Support\Coverage;
use DreamFactory\Core\Masking\Support\ScanHistory;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use DreamFactory\Core\Masking\Support\Time;
use Illuminate\Support\Facades\DB;

/**
 * GET/PATCH system/data_masking (overview, mode) and POST system/data_masking/scan.
 */
final class OverviewHandler
{
    public const SCAN_LAUNCHER = 'DreamFactory\\Core\\Masking\\Scanner\\ScanLauncher';

    public const SCAN_FIRST_MESSAGE = 'Scan your databases before turning masking on.';

    private const MODE_LABELS = ['off' => 'Off', 'preview' => 'Preview', 'on' => 'On'];

    public function overview(): array
    {
        // Settings are cached for up to an hour: never report a mode read from tables that are gone.
        Settings::revalidate();
        $scan = self::scanStatus();
        if ($scan['status'] === 'idle' && !Settings::has(Settings::FIRST_SCAN_AT) && self::anyScanFoundColumns()) {
            // The scanner normally records the first scan itself; this covers a scanner that
            // finished without doing so (idempotent). A scan that found no column is not a first
            // scan: it never switches the mode or allows On.
            Settings::afterScanCompleted();
        }

        $caller = Caller::current();
        $seesReal = false;
        $expires = null;
        if ($caller->isSysAdmin() && $caller->userId() !== null) {
            $seesReal = Access::adminSeesRealValues($caller->userId())
                && (!$caller->isAi() || Settings::ai() === 'same_as_admins');
            if ($seesReal && Settings::adminsMode() === 'selected') {
                $grant = Access::activeGrant($caller->userId());
                $expires = $grant ? Time::iso($grant['expires_at']) : null;
            }
        }

        $wire = fn (array $s) => ['service' => $s['name'], 'label' => $s['label'], 'type' => $s['type']];

        return [
            'mode' => Settings::mode(),
            'scan' => $scan,
            'counts' => self::counts(),
            'you' => [
                'can_grant' => $caller->isSuperAdmin(),
                'sees_real_values' => $seesReal,
                'grant_expires_at' => $expires,
            ],
            'coverage' => [
                'covered' => array_map($wire, Coverage::covered()),
                'uncovered' => array_map($wire, Coverage::uncovered()),
            ],
        ];
    }

    /**
     * Raising the mode is always allowed (On needs a completed scan first); lowering it from On
     * (to Preview or Off) loosens masking and needs the super admin. Preview <-> Off is not
     * loosening: neither changes what apps receive.
     *
     * @throws BadRequestException|ConflictResourceException|\DreamFactory\Core\Exceptions\ForbiddenException
     */
    public function setMode(array $payload): array
    {
        Guard::denyAi('Blocked an attempt to change the masking mode');
        $mode = $payload['mode'] ?? null;
        if (!is_string($mode) || !in_array($mode, Settings::MODES, true)) {
            throw new BadRequestException("Invalid mode. Use 'off', 'preview' or 'on'.");
        }
        $current = Settings::mode();
        if ($mode === 'on' && $current !== 'on' && !ScanHistory::firstScanDone()) {
            // Before a first scan nothing is classified: On would serve real values as masked.
            throw new ConflictResourceException(self::SCAN_FIRST_MESSAGE);
        }
        if (self::lowers($current, $mode)) {
            Guard::requireSuperAdmin('Blocked an attempt to lower the masking mode', null, Guard::LOWER_MODE_MESSAGE);
        }
        if ($mode !== $current || !Settings::has(Settings::MODE)) {
            $changed = $mode !== Settings::mode();
            Settings::set(Settings::MODE, $mode);
            if ($changed) {
                Activity::log('mode', 'Masking set to ' . self::MODE_LABELS[$mode]);
            }
        }

        return $this->overview();
    }

    /** True when going from $from to $to lowers masking (On to Preview or Off). */
    public static function lowers(string $from, string $to): bool
    {
        return $from === 'on' && $to !== 'on';
    }

    /**
     * @throws BadRequestException|NotFoundException|NotImplementedException
     */
    public function startScan(array $payload): array
    {
        Guard::denyAi('Blocked an attempt to start a scan');

        $service = $payload['service'] ?? null;
        if ($service !== null) {
            if (!is_string($service) || trim($service) === '') {
                throw new BadRequestException('Invalid service.');
            }
            $info = Coverage::byName(trim($service));
            if ($info === null || !$info['covered']) {
                throw new NotFoundException("'" . trim($service) . "' is not a database service Data Masking covers.");
            }
            if (!$info['is_active']) {
                throw new BadRequestException("Service '{$info['name']}' is not active.");
            }
            $service = $info['name'];
            $serviceLabel = trim((string)($info['label'] ?? '')) !== '' ? trim((string)$info['label']) : $info['name'];
        }
        $sample = $payload['sample'] ?? null;
        if ($sample !== null && !is_bool($sample)) {
            $sample = filter_var($sample, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
            if ($sample === null) {
                throw new BadRequestException('Invalid sample flag; use true or false.');
            }
        }

        if (self::scanStatus()['status'] === 'running') {
            return $this->overview(); // idempotent
        }
        if (!class_exists(self::SCAN_LAUNCHER)) {
            throw new NotImplementedException('Scanning is not available in this build of df-masking.');
        }
        if (Coverage::covered(true) === []) {
            throw new BadRequestException('There are no active database services to scan. Add a SQL database service first.');
        }

        $scanId = call_user_func([self::SCAN_LAUNCHER, 'start'], $service, Caller::current()->label(), $sample === true);
        Activity::log(
            'scan',
            $service === null ? 'Scan started' : 'Scan started for ' . ($serviceLabel ?? $service),
            $service,
            ['scan_id' => is_numeric($scanId) ? (int)$scanId : null, 'sample' => $sample === true]
        );

        return $this->overview();
    }

    /**
     * finished_at: the latest successful scan; last_status: how the latest finished scan ended
     * ('done', 'partial' = some services could not be read, 'failed', null = never);
     * failed: the services it could not read, with a value-free reason; unknown: true when the
     * scan history could not be read (the other fields then say nothing about past scans, the
     * admin UI shows "Could not read the scan history" instead of the never-scanned state).
     *
     * @return array{status:string,progress:int|null,finished_at:string|null,columns:int,last_status:?string,
     *               failed:list<array{service_id:int,service:string,label:string,reason:string}>,unknown:bool}
     */
    public static function scanStatus(): array
    {
        if (class_exists(self::SCAN_LAUNCHER)) {
            try {
                $s = (array)call_user_func([self::SCAN_LAUNCHER, 'status']);
                $outcome = array_key_exists('last_status', $s) ? $s : ScanHistory::lastOutcome();

                return [
                    'status' => ($s['status'] ?? 'idle') === 'running' ? 'running' : 'idle',
                    'progress' => isset($s['progress']) ? max(0, min(100, (int)$s['progress'])) : null,
                    'finished_at' => isset($s['finished_at']) ? Time::iso($s['finished_at']) : null,
                    'columns' => (int)($s['columns'] ?? self::columnCount()),
                    'last_status' => $outcome['last_status'] ?? null,
                    'failed' => array_values((array)($outcome['failed'] ?? [])),
                    'unknown' => !empty($s['unknown']) || !empty($outcome['unknown']),
                ];
            } catch (\Throwable $e) {
                // fall through to the table-based status
            }
        }

        $running = null;
        $finished = null;
        $unknown = false;
        try {
            $staleMinutes = max(1, (int)config('df-masking.scan.stale_minutes', 5));
            $running = DB::table(Tables::SCAN)
                ->where('status', 'running')
                ->where('updated_at', '>=', now()->subMinutes($staleMinutes))
                ->orderByDesc('id')
                ->first(['progress']);
            $finished = DB::table(Tables::SCAN)->where('status', 'done')->max('finished_at');
        } catch (\Throwable $e) {
            $unknown = true;
        }
        $outcome = ScanHistory::lastOutcome();

        return [
            'status' => $running ? 'running' : 'idle',
            'progress' => $running ? max(0, min(100, (int)$running->progress)) : null,
            'finished_at' => Time::iso($finished),
            'columns' => self::columnCount(),
            'last_status' => $outcome['last_status'],
            'failed' => $outcome['failed'],
            'unknown' => $unknown || $outcome['unknown'],
        ];
    }

    /** @return array{masked:int,review:int,clear:int} for columns of existing covered services */
    public static function counts(): array
    {
        $out = ['masked' => 0, 'review' => 0, 'clear' => 0];
        $ids = Coverage::coveredIds();
        if ($ids === []) {
            return $out;
        }
        try {
            $rows = DB::table(Tables::COLUMN)
                ->whereIn('service_id', $ids)
                ->groupBy('verdict')
                ->select('verdict', DB::raw('COUNT(*) AS n'))
                ->get();
            foreach ($rows as $row) {
                if (isset($out[$row->verdict])) {
                    $out[$row->verdict] = (int)$row->n;
                }
            }
        } catch (\Throwable $e) {
        }

        return $out;
    }

    private static function columnCount(): int
    {
        $ids = Coverage::coveredIds();
        if ($ids === []) {
            return 0;
        }
        try {
            return (int)DB::table(Tables::COLUMN)->whereIn('service_id', $ids)->count();
        } catch (\Throwable $e) {
            return 0;
        }
    }

    /** A scan completed and found at least one column (a scan of empty databases is not a first scan). */
    private static function anyScanFoundColumns(): bool
    {
        try {
            return DB::table(Tables::SCAN)->where('status', 'done')->where('columns_done', '>', 0)->exists();
        } catch (\Throwable $e) {
            return false;
        }
    }
}

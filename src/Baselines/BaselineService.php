<?php

namespace DreamFactory\Core\Masking\Baselines;

use DreamFactory\Core\Exceptions\BadRequestException;
use DreamFactory\Core\Exceptions\ConflictResourceException;
use DreamFactory\Core\Exceptions\NotFoundException;
use DreamFactory\Core\Exceptions\ServiceUnavailableException;
use DreamFactory\Core\Masking\Scanner\ScanLauncher;
use DreamFactory\Core\Masking\Scanner\ScanRunner;
use DreamFactory\Core\Masking\Scanner\ScanState;
use DreamFactory\Core\Masking\Support\Activity;
use DreamFactory\Core\Masking\Support\Caller;
use DreamFactory\Core\Masking\Support\Coverage;
use DreamFactory\Core\Masking\Support\PolicyVersion;
use DreamFactory\Core\Masking\Support\ScanHistory;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * Compliance baselines: the entry point used by the system/security_baseline resource and by
 * `php artisan df:masking baseline ...`.
 *
 * Authorization (sys admin / RBAC, AI sessions blocked) is the caller's job: the HTTP resource
 * checks it, the CLI is the operator. Every method returns wire-shaped (snake_case) arrays.
 */
final class BaselineService
{
    /** Same wording as PATCH system/data_masking and the CLI (no mode On before the first scan). */
    public const SCAN_FIRST_MESSAGE = 'Scan your databases before turning masking on.';

    /**
     * Starts the first scan after an Apply on a never-scanned instance: fn(string $actor): void.
     * Null = Scanner\ScanLauncher::start() for every covered service. Tests replace it.
     *
     * @internal
     */
    public static ?\Closure $scanStarter = null;

    private function __construct()
    {
    }

    /**
     * Every baseline with its live score.
     *
     * @return list<array{id:string,name:string,vertical:string,frameworks:string[],summary:string,adopted:bool,adopted_at:?string,score:array}>
     */
    public static function list(): array
    {
        $state = State::capture();
        $out = [];
        foreach (BaselineRegistry::all() as $baseline) {
            $controls = Evaluator::controls($baseline, $state);
            $out[] = [
                'id' => $baseline['id'],
                'name' => $baseline['name'],
                'vertical' => $baseline['vertical'],
                'frameworks' => $baseline['frameworks'],
                'summary' => $baseline['summary'],
                'adopted' => $state->isAdopted($baseline['id']),
                'adopted_at' => Time::iso($state->adopted[$baseline['id']]['adopted_at'] ?? null),
                'score' => Evaluator::score($controls),
            ];
        }

        return $out;
    }

    /**
     * One baseline: controls with live status, and `changes` = exactly what Apply would change
     * now (with $modeOn: what Apply with mode 'on' would change).
     *
     * @throws NotFoundException
     */
    public static function detail(string $id, bool $modeOn = false, ?State $state = null): array
    {
        $baseline = self::definition($id);
        $state ??= State::capture();
        $controls = Evaluator::controls($baseline, $state);
        $adoption = $state->adopted[$id] ?? null;

        return [
            'id' => $baseline['id'],
            'name' => $baseline['name'],
            'vertical' => $baseline['vertical'],
            'frameworks' => $baseline['frameworks'],
            'summary' => $baseline['summary'],
            'adopted' => $adoption !== null,
            'adopted_at' => Time::iso($adoption['adopted_at'] ?? null),
            'adopted_by' => $adoption['adopted_by'] ?? null,
            'applied_at' => Time::iso($adoption['applied_at'] ?? null),
            'score' => Evaluator::score($controls),
            'controls' => $controls,
            'changes' => Planner::wire(Planner::plan($baseline, $state, $modeOn)),
        ];
    }

    /**
     * Adopts the baseline and applies the DreamFactory settings it requires, in one transaction.
     * Returns the detail after Apply plus `applied` (the changes that were made) and
     * `scan_started`: true when the instance had never been scanned and the first scan is now
     * running (Apply started it, or it was already running), so masking can classify columns.
     *
     * @param string|null $mode  null, or 'on' to also turn masking on
     * @param string|null $actor activity label override (the CLI passes Activity::CONSOLE)
     *
     * @throws NotFoundException|BadRequestException
     * @throws ConflictResourceException when mode 'on' is asked before the first completed scan
     * @throws ServiceUnavailableException when dm_baseline is missing (migrations not run)
     * @throws \Throwable on a database failure (everything is rolled back)
     */
    public static function apply(string $id, ?string $mode = null, ?string $actor = null): array
    {
        $baseline = self::definition($id);
        if ($mode !== null && $mode !== '' && $mode !== 'on') {
            throw new BadRequestException("mode must be 'on' or left out; Apply never lowers masking.");
        }
        $modeOn = $mode === 'on';
        $scanned = self::firstScanDone();
        if ($modeOn && !$scanned && Settings::mode() !== 'on') {
            // Nothing is classified yet: mode On would serve every real value unmasked.
            throw new ConflictResourceException(self::SCAN_FIRST_MESSAGE);
        }
        $actorLabel = $actor ?? Caller::current()->label();

        // Read outside the transaction (PostgreSQL aborts a transaction on any failed read).
        $state = State::capture();
        if ($state->adopted === null) {
            // Same status and wording as system/data_masking when its tables are missing.
            throw new ServiceUnavailableException(
                'Compliance baselines are not set up yet. Run: php artisan df:masking setup (or php artisan migrate)'
            );
        }
        $changes = Planner::plan($baseline, $state, $modeOn);

        try {
            DB::transaction(function () use ($baseline, $changes, $actorLabel, $state) {
                Applier::write($changes, $actorLabel, $state->now);
                Applier::adopt($baseline['id'], $actorLabel, $state->now);
            });
        } finally {
            // Settings::set() bumped the version mid-transaction; a concurrent reader may have
            // cached pre-commit values under it. Bump again now that the writes are visible.
            Settings::flush();
            PolicyVersion::bump();
        }

        $ruleAdded = false;
        $modeChange = null;
        foreach ($changes as $change) {
            $ruleAdded = $ruleAdded || $change['op']['type'] === 'rule';
            if ($change['op']['type'] === 'mode') {
                $modeChange = $change['op']['to'];
            }
        }
        if ($ruleAdded) {
            self::reevaluateRules();
        }

        $activityActor = $actor; // null => Activity resolves the HTTP caller
        $count = count($changes);
        Activity::log(
            'baseline',
            sprintf(
                'Applied the %s baseline (%s)',
                $baseline['name'],
                $count === 0 ? 'nothing to change' : ($count === 1 ? '1 change' : "$count changes")
            ),
            $baseline['id'],
            ['changes' => array_column($changes, 'id')],
            $activityActor
        );
        if ($modeChange !== null) {
            Activity::log(
                'mode',
                sprintf('Masking set to %s by the %s baseline', $modeChange === 'on' ? 'On' : 'Preview', $baseline['name']),
                null,
                ['baseline' => $baseline['id']],
                $activityActor
            );
        }

        $scanStarted = $scanned ? false : self::startFirstScan($baseline, $actorLabel, $activityActor);

        $detail = self::detail($id);
        self::recordStatus($id, $detail, array_column($changes, 'id'));
        $detail['applied'] = Planner::wire($changes);
        $detail['scan_started'] = $scanStarted;

        return $detail;
    }

    /**
     * True once a scan has completed (Support\ScanHistory::firstScanDone(), the rule PATCH mode
     * uses). Falls back to the first-scan marker and the scan history when ScanHistory is absent.
     */
    public static function firstScanDone(): bool
    {
        if (class_exists(ScanHistory::class) && method_exists(ScanHistory::class, 'firstScanDone')) {
            return ScanHistory::firstScanDone();
        }
        if (Settings::has(Settings::FIRST_SCAN_AT)) {
            return true;
        }
        try {
            return DB::table(Tables::SCAN)->where('status', 'done')->exists();
        } catch (\Throwable $e) {
            return true;
        }
    }

    /**
     * Apply on a never-scanned instance starts the first scan of every covered service, so the
     * baseline ends with columns classified instead of Preview on an empty inventory. Returns
     * true when that scan is running now (started here or already running). Never fails Apply:
     * the settings are committed by then; a scan that cannot start is logged and reported false.
     */
    private static function startFirstScan(array $baseline, string $actorLabel, ?string $activityActor): bool
    {
        try {
            if (Coverage::covered(true) === []) {
                return false; // nothing to scan
            }
            $running = ScanState::running() !== null;
            if (self::$scanStarter !== null) {
                (self::$scanStarter)($actorLabel);
            } else {
                ScanLauncher::start(null, $actorLabel);
            }
            if (!$running) {
                Activity::log(
                    'scan',
                    sprintf('Scan started by the %s baseline', $baseline['name']),
                    null,
                    ['baseline' => $baseline['id']],
                    $activityActor
                );
            }

            return true;
        } catch (\Throwable $e) {
            try {
                Log::warning('df-masking baselines: could not start the first scan after Apply: ' . $e->getMessage());
            } catch (\Throwable $ignored) {
            }

            return false;
        }
    }

    /**
     * Stops tracking a baseline. The settings it applied stay as they are.
     *
     * @throws NotFoundException
     */
    public static function forget(string $id, ?string $actor = null): array
    {
        $baseline = self::definition($id);
        $deleted = DB::table(Tables::BASELINE)->where('baseline_id', $id)->delete();
        if ($deleted > 0) {
            Activity::log(
                'baseline',
                sprintf('Stopped tracking the %s baseline (settings unchanged)', $baseline['name']),
                $id,
                [],
                $actor
            );
        }

        return self::detail($id);
    }

    /** @throws NotFoundException */
    public static function report(string $id): array
    {
        $baseline = self::definition($id);
        $state = State::capture();
        $detail = self::detail($id, false, $state);

        return Report::build($baseline, $state, $detail);
    }

    /** @throws NotFoundException */
    public static function reportCsv(string $id): string
    {
        return Report::csv(self::report($id));
    }

    /** @return string[] ids of adopted baselines */
    public static function adoptedIds(): array
    {
        try {
            return DB::table(Tables::BASELINE)->orderBy('baseline_id')->pluck('baseline_id')->map(fn ($v) => (string)$v)->all();
        } catch (\Throwable $e) {
            return [];
        }
    }

    /**
     * The strictest admin grant limit among adopted baselines, in hours (null when none is
     * adopted). For callers that want to offer only grant durations the baselines allow.
     */
    public static function effectiveGrantMaxHours(): ?int
    {
        $max = null;
        foreach (self::adoptedIds() as $id) {
            $hours = (int)(BaselineRegistry::get($id)['apply']['grant_max_hours'] ?? 0);
            if ($hours > 0) {
                $max = $max === null ? $hours : min($max, $hours);
            }
        }

        return $max;
    }

    /** @throws NotFoundException */
    private static function definition(string $id): array
    {
        $baseline = BaselineRegistry::get($id);
        if ($baseline === null) {
            throw new NotFoundException("Compliance baseline '$id' not found.");
        }

        return $baseline;
    }

    /** Re-applies name rules to stored columns so new detection rules take effect immediately. */
    private static function reevaluateRules(): void
    {
        try {
            (new ScanRunner())->reevaluateRules();
        } catch (\Throwable $e) {
            // The rules are stored; they apply at the next scan.
            try {
                Log::warning('df-masking baselines: rules were added but could not be re-evaluated now: ' . $e->getMessage());
            } catch (\Throwable $ignored) {
            }
        }
    }

    private static function recordStatus(string $id, array $detail, array $changeIds): void
    {
        try {
            DB::table(Tables::BASELINE)->where('baseline_id', $id)->update([
                'last_status' => json_encode([
                    'score' => $detail['score'],
                    'changes' => $changeIds,
                    'evaluated_at' => gmdate('Y-m-d\TH:i:s\Z'),
                ], JSON_UNESCAPED_SLASHES),
            ]);
        } catch (\Throwable $e) {
            try {
                Log::warning('df-masking baselines: could not record the last status of ' . $id . ': ' . $e->getMessage());
            } catch (\Throwable $ignored) {
            }
        }
    }
}

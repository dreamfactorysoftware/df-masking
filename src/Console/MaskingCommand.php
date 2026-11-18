<?php

namespace DreamFactory\Core\Masking\Console;

use DreamFactory\Core\Masking\Resources\Handlers\OverviewHandler;
use DreamFactory\Core\Masking\Support\Access;
use DreamFactory\Core\Masking\Support\Activity;
use DreamFactory\Core\Masking\Support\Coverage;
use DreamFactory\Core\Masking\Support\License;
use DreamFactory\Core\Masking\Support\PolicyVersion;
use DreamFactory\Core\Masking\Support\ScanHistory;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use DreamFactory\Core\Masking\Support\Time;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * php artisan df:masking ...
 *
 * The operator's tool and the recovery path when nobody can reach the admin UI: shell access is
 * the operator, so every subcommand may tighten AND loosen. Changes are recorded in the masking
 * activity log as "Command line".
 */
class MaskingCommand extends Command
{
    protected $signature = 'df:masking
        {action? : status | scan | mode | grant | revoke | baseline | setup}
        {args?* : mode: off|preview|on; grant/revoke: admin email; baseline: list | apply <id>}
        {--service= : scan: only this service}
        {--sample : scan: also sample services that bill per query (Snowflake)}
        {--scan-id= : scan: run the scan recorded as this dm_scan id (used by the detached scanner)}
        {--for=8h : grant: 1h, 8h, 24h, 7d or forever}
        {--all : revoke: remove every admin grant}
        {--mode= : baseline apply: on; setup: preview or on (only ever raises the mode)}
        {--baseline= : setup: also apply this Compliance baseline (hipaa, pci_dss, glba, cjis, gdpr, soc2, iso27001)}
        {--json : status/baseline list: machine-readable output}';

    protected $description = 'Data Masking: status, scans, mode, real-value access, Compliance baselines and one-command setup.';

    private const SCAN_RUNNER = 'DreamFactory\\Core\\Masking\\Scanner\\ScanRunner';
    private const BASELINES = 'DreamFactory\\Core\\Masking\\Baselines\\BaselineService';
    private const REGISTRY = 'DreamFactory\\Core\\Masking\\Baselines\\BaselineRegistry';
    private const MODE_LABELS = ['off' => 'Off', 'preview' => 'Preview', 'on' => 'On'];
    private const MODE_RANK = ['off' => 0, 'preview' => 1, 'on' => 2];
    private const ADD_DATABASE = 'Next: add a SQL database service, then run php artisan df:masking scan.';
    private const SPANS = ['1h' => 'for 1 hour', '8h' => 'for 8 hours', '24h' => 'for 24 hours', '7d' => 'for 7 days', 'forever' => 'until turned off'];

    public function handle(): int
    {
        $action = (string)($this->argument('action') ?? 'status');
        $args = (array)$this->argument('args');
        $started = time();

        try {
            if (!self::availableWithoutGold($action, $args) && !License::isGold()) {
                $this->error(License::MESSAGE);

                return self::FAILURE;
            }
            if (!in_array($action, ['setup', 'help'], true) && !$this->migrated()) {
                $this->error('Data Masking tables are missing. Run: php artisan df:masking setup (or php artisan migrate --force).');

                return self::FAILURE;
            }

            return match ($action) {
                'status' => $this->status(),
                'scan' => $this->scan(),
                'mode' => $this->mode($args[0] ?? null),
                'grant' => $this->grant($args[0] ?? null),
                'revoke' => $this->revoke($args[0] ?? null),
                'baseline' => $this->baseline($args),
                'setup' => $this->setup(),
                'help' => $this->help(),
                default => $this->unknown($action),
            };
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        } finally {
            self::handBackStorage($started);
        }
    }

    /**
     * Actions that stay available when the license level is not Gold (Support\License): reading
     * the status, help, and the ways to reduce masking (revoke, mode off).
     */
    private static function availableWithoutGold(string $action, array $args): bool
    {
        return in_array($action, ['status', 'help', 'revoke'], true)
            || ($action === 'mode' && ($args[0] ?? null) === 'off');
    }

    /**
     * `php artisan` is often run as root (docker exec, sudo). Anything this command created in
     * the cache, log or SQLite storage (file cache entries, a new daily log, ...) would then be
     * root-owned, and the web server could no longer write it: Data Masking settings changes
     * would fail with HTTP 500. Give such files back to the owner of storage/, as DreamFactory's
     * Docker entrypoint does for the whole tree at start-up. Only files created during this run
     * are touched; nothing happens unless the command runs as root and storage/ is not root's.
     */
    private static function handBackStorage(int $since): void
    {
        if (!function_exists('posix_geteuid') || posix_geteuid() !== 0) {
            return;
        }
        try {
            $owner = @fileowner(storage_path());
            $group = @filegroup(storage_path());
            if ($owner === false || $owner === 0 || $group === false) {
                return;
            }
            $budget = 20000;
            $dirs = [storage_path('framework/cache'), storage_path('logs'), storage_path('databases'), base_path('bootstrap/cache')];
            foreach ($dirs as $dir) {
                if (!is_dir($dir) || is_link($dir)) {
                    continue;
                }
                $items = new \RecursiveIteratorIterator(
                    new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
                    \RecursiveIteratorIterator::SELF_FIRST
                );
                foreach ($items as $path => $info) {
                    if (--$budget < 0) {
                        return;
                    }
                    /** @var \SplFileInfo $info */
                    if ($info->isLink() || $info->getOwner() !== 0 || $info->getCTime() < $since - 1) {
                        continue;
                    }
                    @chown($path, $owner);
                    @chgrp($path, $group);
                }
            }
        } catch (\Throwable $e) {
            // Best effort only: never fail the command over file ownership.
        }
    }

    // ------------------------------------------------------------------------------------------

    private function status(): int
    {
        $scan = OverviewHandler::scanStatus();
        $counts = OverviewHandler::counts();
        $grants = [];
        foreach (DB::table(Tables::ADMIN_GRANT)->orderBy('id')->get(['admin_id', 'expires_at']) as $g) {
            $expires = Time::ts($g->expires_at);
            if ($expires !== null && $expires <= time()) {
                continue;
            }
            $email = DB::table('user')->where('id', $g->admin_id)->value('email');
            $grants[] = ['admin_id' => (int)$g->admin_id, 'email' => $email, 'expires_at' => Time::iso($expires)];
        }
        $roles = DB::table(Tables::ROLE_ACCESS)->join('role', 'role.id', '=', Tables::ROLE_ACCESS . '.role_id')
            ->where(Tables::ROLE_ACCESS . '.enabled', true)
            ->orderBy('role.name')
            ->get(['role.name', Tables::ROLE_ACCESS . '.scope']);
        $status = [
            'mode' => Settings::mode(),
            'ai' => Settings::ai(),
            'admins' => Settings::adminsMode(),
            'grants' => $grants,
            'roles' => array_map(fn ($r) => ['role' => $r->name, 'scope' => $r->scope], $roles->all()),
            'scan' => $scan,
            'counts' => $counts,
            'covered' => array_map(fn ($s) => $s['name'], Coverage::covered()),
            'uncovered' => array_map(fn ($s) => $s['name'], Coverage::uncovered()),
        ];
        if ($this->option('json')) {
            $this->line(json_encode($status, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return self::SUCCESS;
        }

        $this->line('Data Masking');
        $this->line('  Mode:               ' . self::MODE_LABELS[$status['mode']]);
        $this->line('  AI and MCP:         ' . ($status['ai'] === 'masked' ? 'always masked' : 'same as admins'));
        $this->line('  Admins:             ' . ($status['admins'] === 'none' ? 'masked (no one sees real values)' : $status['admins']));
        foreach ($grants as $g) {
            $this->line('    grant ' . $g['email'] . ' ' . ($g['expires_at'] ? 'until ' . $g['expires_at'] : 'until turned off'));
        }
        foreach ($status['roles'] as $r) {
            $this->line('  Role ' . $r['role'] . ': real values (' . ($r['scope'] === 'all' ? 'all classes' : 'all except restricted') . ')');
        }
        $this->line('  Scan:               ' . ($scan['status'] === 'running'
                ? 'running ' . ($scan['progress'] ?? 0) . '%'
                : ($scan['finished_at'] ? 'last finished ' . $scan['finished_at'] : 'never scanned')));
        if (in_array($scan['last_status'] ?? null, ['partial', 'failed'], true)) {
            $this->line('  Last scan:          ' . ($scan['last_status'] === 'failed' ? 'failed' : 'partly failed'));
            foreach ((array)($scan['failed'] ?? []) as $f) {
                $this->line('    could not read ' . $f['service'] . ': ' . $f['reason']);
            }
        }
        $this->line(sprintf('  Columns:            %d masked, %d to review, %d not sensitive', $counts['masked'], $counts['review'], $counts['clear']));
        $this->line('  Covered services:   ' . ($status['covered'] ? implode(', ', $status['covered']) : 'none'));
        if ($status['uncovered']) {
            $this->line('  Not covered:        ' . implode(', ', $status['uncovered']) . ' (AI sessions are blocked from these when mode is On)');
        }

        return self::SUCCESS;
    }

    private function scan(): int
    {
        if (!class_exists(self::SCAN_RUNNER)) {
            $this->error('Scanning is not available in this build of df-masking.');

            return self::FAILURE;
        }
        $service = $this->option('service');
        if ($service !== null && $service !== '') {
            $info = Coverage::byName((string)$service);
            if ($info === null || !$info['covered']) {
                $this->error("'$service' is not a database service Data Masking covers.");

                return self::FAILURE;
            }
            $service = $info['name'];
        } else {
            $service = null;
        }
        $scanId = $this->option('scan-id');
        if ($scanId !== null && filter_var($scanId, FILTER_VALIDATE_INT) === false) {
            $this->error('--scan-id must be an integer.');

            return self::FAILURE;
        }
        $scanId = $scanId === null ? null : (int)$scanId;
        if ($scanId === null && OverviewHandler::scanStatus()['status'] === 'running') {
            $this->error('A scan is already running. Check progress with: php artisan df:masking status');

            return self::FAILURE;
        }

        $quiet = $scanId !== null || !$this->output->isDecorated();
        $last = -1;
        $progress = function (...$info) use (&$last, $quiet): void {
            if ($quiet) {
                return;
            }
            $pct = is_numeric($info[0] ?? null) ? (int)$info[0] : null;
            if ($pct !== null && $pct !== $last && $pct % 10 === 0) {
                $last = $pct;
                $this->line("  $pct%");
            }
        };
        if ($scanId === null) {
            Activity::log('scan', $service === null ? 'Scan started' : 'Scan started for ' . self::serviceLabel($service), $service, ['via' => 'cli'], Activity::CONSOLE);
        }
        $runner = app(self::SCAN_RUNNER);
        $summary = (array)$runner->run($service, $scanId, $progress, (bool)$this->option('sample'));
        $failed = ($summary['status'] ?? 'done') === 'failed';
        if (!$failed && (int)($summary['columns'] ?? 0) > 0) {
            Settings::afterScanCompleted(); // the scanner does this too; idempotent
        }

        if ($scanId === null) {
            if ($failed) {
                $this->error((string)($summary['error'] ?? 'The scan failed.'));
                foreach ((array)($summary['failed'] ?? []) as $f) {
                    $this->warn('  Could not read ' . $f['service'] . ': ' . $f['reason']);
                }

                return self::FAILURE;
            }
            $columns = (int)($summary['columns'] ?? 0);
            $services = (int)($summary['services'] ?? 0);
            $this->info(sprintf(
                'Scan finished: %d %s in %d %s (%d masked, %d to review, %d not sensitive).',
                $columns,
                $columns === 1 ? 'column' : 'columns',
                $services,
                $services === 1 ? 'database' : 'databases',
                (int)($summary['masked'] ?? 0),
                (int)($summary['review'] ?? 0),
                (int)($summary['clear'] ?? 0)
            ));
            foreach ((array)($summary['failed'] ?? []) as $f) {
                $this->warn('  Could not read ' . $f['service'] . ': ' . $f['reason']);
            }
            foreach ((array)($summary['errors'] ?? []) as $error) {
                if (is_string($error) && str_starts_with($error, "Could not read service '")) {
                    continue; // shown above with its reason
                }
                $this->warn('  ' . (is_string($error) ? $error : json_encode($error)));
            }
            $this->line('Mode: ' . self::MODE_LABELS[Settings::mode()]);
        }

        return $failed ? self::FAILURE : self::SUCCESS;
    }

    private function mode(?string $mode): int
    {
        if (!in_array($mode, Settings::MODES, true)) {
            $this->error('Usage: php artisan df:masking mode off|preview|on');

            return self::FAILURE;
        }
        if ($mode === 'on' && Settings::mode() !== 'on' && !ScanHistory::firstScanDone()) {
            return $this->scanFirst();
        }
        $changed = $mode !== Settings::mode();
        Settings::set(Settings::MODE, $mode);
        if ($changed) {
            Activity::log('mode', 'Masking set to ' . self::MODE_LABELS[$mode], null, ['via' => 'cli'], Activity::CONSOLE);
        }
        $this->info('Masking mode: ' . self::MODE_LABELS[$mode] . ($changed ? '' : ' (unchanged)'));

        return self::SUCCESS;
    }

    private function grant(?string $email): int
    {
        $admin = $this->admin($email);
        if ($admin === null) {
            return self::FAILURE;
        }
        $duration = (string)$this->option('for');
        if (!array_key_exists($duration, Access::DURATIONS)) {
            $this->error('--for must be 1h, 8h, 24h, 7d or forever.');

            return self::FAILURE;
        }
        $expires = Access::expiryFor($duration);
        $values = ['expires_at' => Time::fromTs($expires), 'granted_by_id' => null, 'updated_at' => now()];
        if (!DB::table(Tables::ADMIN_GRANT)->where('admin_id', $admin->id)->update($values)) {
            if (!DB::table(Tables::ADMIN_GRANT)->where('admin_id', $admin->id)->exists()) {
                DB::table(Tables::ADMIN_GRANT)->insert($values + ['admin_id' => $admin->id, 'created_at' => now()]);
            }
        }
        $name = $this->adminName($admin);
        Activity::log('access', "$name was given real values " . self::SPANS[$duration], null, ['via' => 'cli'], Activity::CONSOLE);
        if (Settings::adminsMode() === 'none') {
            Settings::set(Settings::ADMINS_MODE, 'selected');
            Activity::log('access', 'Admin access set to selected', null, ['via' => 'cli'], Activity::CONSOLE);
        }
        PolicyVersion::bump();
        $this->info("$admin->email sees real values " . self::SPANS[$duration] . ($expires ? ' (until ' . Time::iso($expires) . ')' : '') . '.');
        if (Settings::ai() === 'masked') {
            $this->line('AI and MCP sessions stay masked for this admin.');
        }

        return self::SUCCESS;
    }

    private function revoke(?string $email): int
    {
        if ($this->option('all')) {
            $n = DB::table(Tables::ADMIN_GRANT)->delete();
            if (Settings::adminsMode() === 'all') {
                Settings::set(Settings::ADMINS_MODE, 'none');
                Activity::log('access', 'Admin access set to no one', null, ['via' => 'cli'], Activity::CONSOLE);
            }
            Activity::log('access', 'Real values removed for every admin', null, ['via' => 'cli', 'grants' => $n], Activity::CONSOLE);
            PolicyVersion::bump();
            $this->info("Removed $n grant(s). Admins are masked.");

            return self::SUCCESS;
        }
        $admin = $this->admin($email);
        if ($admin === null) {
            return self::FAILURE;
        }
        $n = DB::table(Tables::ADMIN_GRANT)->where('admin_id', $admin->id)->delete();
        PolicyVersion::bump();
        if ($n > 0) {
            Activity::log('access', 'Real values removed for ' . $this->adminName($admin), null, ['via' => 'cli'], Activity::CONSOLE);
        }
        $this->info($n > 0 ? "Removed the grant for $admin->email." : "$admin->email had no grant.");
        if (Settings::adminsMode() === 'all') {
            $this->warn('Admin access is set to "all admins": every admin still sees real values. Use --all to reset it.');
        }

        return self::SUCCESS;
    }

    private function baseline(array $args): int
    {
        if (!class_exists(self::BASELINES)) {
            $this->error('Compliance baselines are not available in this build of df-masking.');

            return self::FAILURE;
        }
        $sub = $args[0] ?? 'list';
        if ($sub === 'list') {
            $list = call_user_func([self::BASELINES, 'list']);
            if ($this->option('json')) {
                $this->line(json_encode($list, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

                return self::SUCCESS;
            }
            $rows = [];
            foreach ($list as $b) {
                $s = $b['score'] ?? [];
                $rows[] = [
                    $b['id'],
                    $b['name'],
                    $b['vertical'],
                    !empty($b['adopted']) ? 'yes' : 'no',
                    sprintf('%d pass, %d fail, %d manual', $s['pass'] ?? 0, $s['fail'] ?? 0, $s['manual'] ?? 0),
                ];
            }
            $this->table(['id', 'baseline', 'vertical', 'adopted', 'checks'], $rows);

            return self::SUCCESS;
        }
        if ($sub === 'apply') {
            $id = $args[1] ?? null;
            if (!is_string($id) || $id === '') {
                $this->error('Usage: php artisan df:masking baseline apply <id> [--mode=on]');

                return self::FAILURE;
            }
            $mode = $this->option('mode');
            if ($mode !== null && $mode !== 'on') {
                $this->error('baseline apply only takes --mode=on (Apply never lowers masking).');

                return self::FAILURE;
            }
            if ($mode === 'on' && Settings::mode() !== 'on' && !ScanHistory::firstScanDone()) {
                return $this->scanFirst();
            }

            return $this->applyBaseline($id, $mode);
        }
        $this->error('Usage: php artisan df:masking baseline list | apply <id> [--mode=on]');

        return self::FAILURE;
    }

    private function applyBaseline(string $id, ?string $mode): int
    {
        if (class_exists(self::REGISTRY) && call_user_func([self::REGISTRY, 'get'], $id) === null) {
            // Checked here so the operator gets one clean line instead of DreamFactory's REST exception log.
            $ids = array_map(fn ($b) => (string)($b['id'] ?? ''), (array)call_user_func([self::REGISTRY, 'all']));
            $this->error("Unknown baseline '$id'. Choose one of: " . implode(', ', $ids) . '.');

            return self::FAILURE;
        }
        $detail = (array)call_user_func([self::BASELINES, 'apply'], $id, $mode, Activity::CONSOLE);
        foreach (self::applyReport($id, $detail) as [$style, $text]) {
            $style === 'info' ? $this->info($text) : $this->line($text);
        }

        return self::SUCCESS;
    }

    /**
     * What `baseline apply` prints for an Apply result (BaselineService::apply()).
     *
     * @return list<array{0:string,1:string}> [style ('info'|'line'), text]
     */
    public static function applyReport(string $id, array $detail): array
    {
        $out = [['info', ($detail['name'] ?? $id) . ' baseline adopted.']];
        $applied = (array)($detail['applied'] ?? []);
        if ($applied === []) {
            $out[] = ['line', '  Nothing needed changing.'];
        }
        foreach ($applied as $change) {
            $out[] = ['line', '  - ' . (is_array($change) ? ($change['text'] ?? json_encode($change)) : (string)$change)];
        }
        $score = (array)($detail['score'] ?? []);
        if ($score) {
            $out[] = ['line', sprintf('  Checks: %d pass, %d fail, %d manual', $score['pass'] ?? 0, $score['fail'] ?? 0, $score['manual'] ?? 0)];
        }
        if (!empty($detail['scan_started'])) {
            // Apply on a never-scanned instance starts the first scan in the background.
            $out[] = ['line', 'First scan started: php artisan df:masking status'];
        }

        return $out;
    }

    /**
     * One command for new and existing installs: tables, a full scan, an optional baseline,
     * and the mode (default: whatever the first scan chose, i.e. Preview). Safe to re-run:
     * --mode only raises the mode, never lowers it.
     */
    private function setup(): int
    {
        $mode = $this->option('mode');
        if ($mode !== null && !in_array($mode, ['preview', 'on'], true)) {
            $this->error('setup --mode must be preview or on.');

            return self::FAILURE;
        }
        $baseline = $this->option('baseline');
        if ($baseline !== null && $baseline !== '' && !class_exists(self::BASELINES)) {
            $this->error('Compliance baselines are not available in this build of df-masking.');

            return self::FAILURE;
        }
        if ($baseline !== null && $baseline !== '' && class_exists(self::REGISTRY)
            && call_user_func([self::REGISTRY, 'get'], (string)$baseline) === null) {
            $ids = array_map(fn ($b) => (string)($b['id'] ?? ''), (array)call_user_func([self::REGISTRY, 'all']));
            $this->error("Unknown baseline '$baseline'. Choose one of: " . implode(', ', $ids) . '.');

            return self::FAILURE;
        }

        // 1. tables (also upgrades: any of this package's migrations not run yet)
        if (!$this->migrated() || !$this->baselineMigrated() || $this->pendingMigrations()) {
            $this->line($this->migrated() ? 'Updating Data Masking tables...' : 'Creating Data Masking tables...');
            // Only this package's migrations: setup never runs unrelated pending migrations.
            $this->call('migrate', [
                '--force' => true,
                '--path' => realpath(dirname(__DIR__, 2) . '/database/migrations'),
                '--realpath' => true,
            ]);
            if (!$this->migrated()) {
                $this->error('Migration did not create the Data Masking tables.');

                return self::FAILURE;
            }
        }
        $this->info('1/4 Tables ready.');

        // 2. scan
        $covered = Coverage::covered(true);
        if ($covered === []) {
            $this->warn('2/4 No active SQL database services yet: nothing to scan. Add a service, then run php artisan df:masking scan.');
        } elseif (!class_exists(self::SCAN_RUNNER)) {
            $this->warn('2/4 Scanning is not available in this build of df-masking.');
        } else {
            $this->line('2/4 Scanning ' . count($covered) . ' database service(s): ' . implode(', ', array_map(fn ($s) => $s['name'], $covered)) . '...');
            if ($this->scan() !== self::SUCCESS) {
                return self::FAILURE;
            }
        }

        // 3. baseline
        $raiseToOn = $mode === 'on' && Settings::mode() !== 'on';
        if ($raiseToOn && !ScanHistory::firstScanDone()) {
            return $this->scanFirst();
        }
        if ($baseline !== null && $baseline !== '') {
            $this->line("3/4 Applying the $baseline baseline...");
            if ($this->applyBaseline((string)$baseline, $raiseToOn ? 'on' : null) !== self::SUCCESS) {
                return self::FAILURE;
            }
        } else {
            $this->line('3/4 No baseline requested (see: php artisan df:masking baseline list).');
        }

        // 4. mode: --mode only ever raises it (setup is safe to re-run on a live instance)
        if ($mode !== null) {
            $current = Settings::mode();
            if (self::MODE_RANK[$mode] > self::MODE_RANK[$current]) {
                if ($this->mode($mode) !== self::SUCCESS) {
                    return self::FAILURE;
                }
            } elseif (self::MODE_RANK[$mode] < self::MODE_RANK[$current]) {
                $label = self::MODE_LABELS[$current];
                $this->line("Masking is already $label; leaving it $label (use df:masking mode $mode to lower it).");
            }
        }
        $this->info('4/4 Masking mode: ' . self::MODE_LABELS[Settings::mode()] . '.');
        $next = $this->nextStep();
        if ($next !== null) {
            $this->newLine();
            $this->line($next);
        }

        return self::SUCCESS;
    }

    /** The one useful next step after setup, from the review queue and the mode (null: nothing to do). */
    private function nextStep(): ?string
    {
        if (!ScanHistory::firstScanDone()) {
            // No scan found a column yet (only empty databases): On would be refused.
            return self::ADD_DATABASE;
        }
        $review = OverviewHandler::counts()['review'];
        $queue = $review === 1 ? 'the 1 column to review' : "the $review columns to review";

        return match (Settings::mode()) {
            'on' => $review > 0 ? "Next: open the admin app > Data Masking and decide $queue." : null,
            'preview' => $review > 0
                ? "Next: open the admin app > Data Masking, decide $queue, then switch the mode to On."
                : 'Next: switch the mode to On (admin app > Data Masking, or php artisan df:masking mode on).',
            default => 'Next: turn masking on (admin app > Data Masking, or php artisan df:masking mode on).',
        };
    }

    private function scanFirst(): int
    {
        $this->error(OverviewHandler::SCAN_FIRST_MESSAGE);
        // A scan that found no column (only empty databases) does not count: adding data does.
        $this->line(ScanHistory::anyScanFinished() ? self::ADD_DATABASE : 'Run: php artisan df:masking scan');

        return self::FAILURE;
    }

    private function help(): int
    {
        $this->line('php artisan df:masking status [--json]');
        $this->line('php artisan df:masking scan [--service=NAME] [--sample]');
        $this->line('php artisan df:masking mode off|preview|on');
        $this->line('php artisan df:masking grant ADMIN_EMAIL [--for=1h|8h|24h|7d|forever]');
        $this->line('php artisan df:masking revoke ADMIN_EMAIL | --all');
        $this->line('php artisan df:masking baseline list | apply ID [--mode=on]');
        $this->line('php artisan df:masking setup [--baseline=ID] [--mode=preview|on]');

        return self::SUCCESS;
    }

    private function unknown(string $action): int
    {
        $this->error("Unknown action '$action'.");
        $this->help();

        return self::FAILURE;
    }

    private function admin(?string $email): ?object
    {
        if ($email === null || trim($email) === '') {
            $this->error('Give the admin\'s email address.');

            return null;
        }
        $admin = DB::table('user')
            ->whereRaw('LOWER(email) = ?', [mb_strtolower(trim($email))])
            ->first(['id', 'email', 'name', 'first_name', 'last_name', 'is_sys_admin', 'is_active']);
        if (!$admin || !$admin->is_sys_admin) {
            $this->error("No system administrator with email $email.");

            return null;
        }
        if (!$admin->is_active) {
            $this->warn("$admin->email is not active.");
        }

        return $admin;
    }

    private function adminName(object $admin): string
    {
        $name = trim((string)$admin->name);
        if ($name === '') {
            $name = trim((string)$admin->first_name . ' ' . (string)$admin->last_name);
        }

        return $name !== '' ? $name : (string)$admin->email;
    }

    private function migrated(): bool
    {
        try {
            foreach (Tables::MAIN as $table) {
                if (!Schema::hasTable($table)) {
                    return false;
                }
            }

            return true;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /** True when one of this package's migrations has not run yet (an upgraded package). */
    private function pendingMigrations(): bool
    {
        try {
            $files = glob(dirname(__DIR__, 2) . '/database/migrations/*.php') ?: [];
            $ran = app('migrator')->getRepository()->getRan();
            foreach ($files as $file) {
                if (!in_array(basename($file, '.php'), $ran, true)) {
                    return true;
                }
            }

            return false;
        } catch (\Throwable $e) {
            return true; // let migrate decide (it only runs what is pending)
        }
    }

    private function baselineMigrated(): bool
    {
        try {
            return !class_exists(self::BASELINES) || Schema::hasTable(Tables::BASELINE);
        } catch (\Throwable $e) {
            return false;
        }
    }

    /** A service's label for activity texts (the admin UI names services by label), else its name. */
    private static function serviceLabel(string $service): string
    {
        try {
            $info = Coverage::byName($service);
        } catch (\Throwable $e) {
            $info = null;
        }
        $label = trim((string)($info['label'] ?? ''));

        return $label !== '' ? $label : $service;
    }
}

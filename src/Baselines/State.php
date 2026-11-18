<?php

namespace DreamFactory\Core\Masking\Baselines;

use DreamFactory\Core\Masking\Enforcement\Policy;
use DreamFactory\Core\Masking\Support\Caller;
use DreamFactory\Core\Masking\Support\Catalog;
use DreamFactory\Core\Masking\Support\Coverage;
use DreamFactory\Core\Masking\Support\ScanHistory;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;

/**
 * A read-only snapshot of every setting the baseline checks and Apply planner look at.
 *
 * capture() reads it from the live instance; tests build one directly with named arguments.
 * Each part is captured independently: a part that cannot be read (table missing, package not
 * installed, query error) is left null and the checks that need it report "could not be
 * checked" instead of failing the whole evaluation. Nothing here ever holds a data value: only
 * settings, counts, names of services/roles/admins and column metadata.
 */
final class State
{
    /**
     * @param int                     $now          unix seconds
     * @param array<string,string>|null $formats    class id => effective mask format (defaults included)
     * @param list<array{admin_id:int,name:string,email:?string,expires_at:?int}>|null $grants
     *        admin grants that have not expired yet (expires_at null = until turned off)
     * @param list<array{role_id:int,name:string,enabled:bool,scope:string}>|null $roles dm_role_access rows
     * @param list<array{id:int,match:string,pattern:string,class:string,source:string}>|null $rules
     * @param array{masked:int,review:int,clear:int}|null $verdicts column counts
     * @param array<string,int>|null  $adminCleared detected class => columns an admin marked "not sensitive"
     *        (only confident detections: score at or above the mask threshold, see ADMIN_CLEARED_MIN_SCORE)
     * @param list<array{id:int,name:string,label:string,type:string,created_at:?int,last_scan_at:?int,scan_error?:?string,scan_unknown?:bool}>|null $covered
     *        services Data Masking covers, with the finish time of the last successful scan that read each
     *        (a scan that could not read a service does not count), when a later scan could not
     *        read it, why (scan_error), and scan_unknown = true when the scan history could not be
     *        read (last_scan_at/scan_error are then unknown, not "never")
     * @param array<string,mixed>     $platform     see capturePlatform(); a null value = could not be read
     * @param array<string,array{adopted_at:?int,adopted_by:?string,applied_at:?int,last_status:?array}>|null $adopted
     * @param array<string,string>    $errors       part => short reason (for the log and diagnostics)
     * @param list<array{id:int,name:string,label:string,type:string}>|null $uncovered
     *        active database services Data Masking cannot scan (MongoDB, Cassandra, DynamoDB, ...)
     * @param list<array{id:int,name:string,last_login_at:?int,created_at:?int}>|null $admins active sys admins
     */
    public function __construct(
        public readonly int $now,
        public readonly string $mode = 'off',
        public readonly string $ai = 'masked',
        public readonly string $adminsMode = 'none',
        public readonly ?array $formats = [],
        public readonly ?array $grants = [],
        public readonly ?array $roles = [],
        public readonly ?array $rules = [],
        public readonly ?array $verdicts = ['masked' => 0, 'review' => 0, 'clear' => 0],
        public readonly ?array $adminCleared = [],
        public readonly ?array $covered = [],
        public readonly array $platform = [],
        public readonly ?array $adopted = [],
        public readonly array $errors = [],
        public readonly ?array $uncovered = [],
        public readonly ?array $admins = [],
    ) {
    }

    /**
     * An admin "not sensitive" decision counts against masking.classes only when the column was
     * detected with at least this score: the rule pack's mask threshold (bands.enforce and
     * name_only.enforce in resources/rules/pack.json). Rejecting a lower-scored suggestion that
     * was only waiting for review is the review working as intended.
     */
    public const ADMIN_CLEARED_MIN_SCORE = 70;

    /** True when $id is adopted (tracked). */
    public function isAdopted(string $id): bool
    {
        return isset($this->adopted[$id]);
    }

    /** Effective format of a class: the stored choice, else the catalog default. */
    public function formatOf(string $classId): ?string
    {
        return $this->formats[$classId] ?? Catalog::defaultFormat($classId);
    }

    public function platformValue(string $key): mixed
    {
        return $this->platform[$key] ?? null;
    }

    // ------------------------------------------------------------------------------------------
    // Capture
    // ------------------------------------------------------------------------------------------

    public static function capture(): self
    {
        $errors = [];
        $now = time();

        $mode = Settings::mode();
        $ai = Settings::ai();
        $adminsMode = Settings::adminsMode();

        $formats = self::part('formats', $errors, fn () => self::captureFormats());
        $grants = self::part('grants', $errors, fn () => self::captureGrants($now));
        $roles = self::part('roles', $errors, fn () => self::captureRoles());
        $rules = self::part('rules', $errors, fn () => self::captureRules());
        $verdicts = self::part('verdicts', $errors, fn () => self::captureVerdicts());
        $adminCleared = self::part('admin_cleared', $errors, fn () => self::captureAdminCleared());
        $covered = self::part('coverage', $errors, fn () => self::captureCovered());
        $uncovered = self::part('uncovered', $errors, fn () => self::captureUncovered());
        $adopted = self::part('adoption', $errors, fn () => self::captureAdopted());
        $admins = self::part('admins', $errors, fn () => self::captureAdmins());
        $platform = self::capturePlatform($errors, $covered);

        return new self(
            now: $now,
            mode: $mode,
            ai: $ai,
            adminsMode: $adminsMode,
            formats: $formats,
            grants: $grants,
            roles: $roles,
            rules: $rules,
            verdicts: $verdicts,
            adminCleared: $adminCleared,
            covered: $covered,
            platform: $platform,
            adopted: $adopted,
            errors: $errors,
            uncovered: $uncovered,
            admins: $admins,
        );
    }

    /**
     * Runs one capture step; on failure records the reason, logs it once and returns null.
     *
     * @template T
     * @param callable():T $fn
     * @return T|null
     */
    private static function part(string $name, array &$errors, callable $fn): mixed
    {
        try {
            return $fn();
        } catch (\Throwable $e) {
            $errors[$name] = self::reason($e);
            try {
                Log::warning('df-masking baselines: could not read ' . $name . ': ' . $e->getMessage());
            } catch (\Throwable $ignored) {
            }

            return null;
        }
    }

    private static function reason(\Throwable $e): string
    {
        $message = preg_replace('/\s+/', ' ', $e->getMessage()) ?? '';

        return mb_substr($message, 0, 200);
    }

    /** @return array<string,string> */
    private static function captureFormats(): array
    {
        $formats = [];
        foreach (Catalog::classes() as $class) {
            $formats[$class['id']] = $class['format'];
        }
        foreach (DB::table(Tables::MASK_FORMAT)->get(['class', 'format']) as $row) {
            $class = (string)$row->class;
            if (isset($formats[$class]) && is_string($row->format) && $row->format !== '') {
                $formats[$class] = $row->format;
            }
        }

        return $formats;
    }

    private static function captureGrants(int $now): array
    {
        $rows = DB::table(Tables::ADMIN_GRANT . ' as g')
            ->leftJoin('user as u', 'u.id', '=', 'g.admin_id')
            ->orderBy('g.admin_id')
            ->get(['g.admin_id', 'g.expires_at', 'u.first_name', 'u.last_name', 'u.name', 'u.email']);

        $grants = [];
        foreach ($rows as $row) {
            $expires = Time::ts($row->expires_at);
            if ($expires !== null && $expires <= $now) {
                continue; // expired: no longer in effect
            }
            $grants[] = [
                'admin_id' => (int)$row->admin_id,
                'name' => self::personName($row),
                'email' => is_string($row->email) && $row->email !== '' ? $row->email : null,
                'expires_at' => $expires,
            ];
        }

        return $grants;
    }

    private static function captureRoles(): array
    {
        $rows = DB::table(Tables::ROLE_ACCESS . ' as ra')
            ->leftJoin('role as r', 'r.id', '=', 'ra.role_id')
            ->orderBy('ra.role_id')
            ->get(['ra.role_id', 'ra.enabled', 'ra.scope', 'r.name']);

        $roles = [];
        foreach ($rows as $row) {
            $roles[] = [
                'role_id' => (int)$row->role_id,
                'name' => is_string($row->name) && $row->name !== '' ? $row->name : ('role ' . $row->role_id),
                'enabled' => (bool)$row->enabled,
                'scope' => (string)$row->scope,
            ];
        }

        return $roles;
    }

    private static function captureRules(): array
    {
        $rules = [];
        foreach (DB::table(Tables::RULE)->orderBy('id')->get(['id', 'match', 'pattern', 'class', 'source']) as $row) {
            $rules[] = [
                'id' => (int)$row->id,
                'match' => (string)$row->match,
                'pattern' => (string)$row->pattern,
                'class' => (string)$row->class,
                'source' => (string)$row->source,
            ];
        }

        return $rules;
    }

    private static function captureVerdicts(): array
    {
        $counts = ['masked' => 0, 'review' => 0, 'clear' => 0];
        $rows = DB::table(Tables::COLUMN . ' as c')
            ->join('service as s', 's.id', '=', 'c.service_id')
            ->groupBy('c.verdict')
            ->get(['c.verdict', DB::raw('COUNT(*) as n')]);
        foreach ($rows as $row) {
            $verdict = (string)$row->verdict;
            if (isset($counts[$verdict])) {
                $counts[$verdict] = (int)$row->n;
            }
        }

        return $counts;
    }

    private static function captureAdminCleared(): array
    {
        $out = [];
        $rows = DB::table(Tables::COLUMN . ' as c')
            ->join('service as s', 's.id', '=', 'c.service_id')
            ->where('c.source', 'admin')
            ->where('c.verdict', 'clear')
            ->whereNotNull('c.detected_class')
            ->where('c.detected_score', '>=', self::ADMIN_CLEARED_MIN_SCORE)
            ->groupBy('c.detected_class')
            ->get(['c.detected_class', DB::raw('COUNT(*) as n')]);
        foreach ($rows as $row) {
            $out[(string)$row->detected_class] = (int)$row->n;
        }

        return $out;
    }

    /**
     * Active covered services with the time each was last scanned successfully and, when a later
     * scan could not read it, why. Support\ScanHistory decides both (the same answer as the
     * overview and /table): a scan that could not read a service never counts as scanning it.
     *
     * Without ScanHistory (older platform code) the rule is computed here and failures are not
     * known: the latest successful scan of that service (dm_scan.service_id), or the latest
     * scanned_at of its stored columns (a full scan stamps every column it samples; inline
     * name-only classification leaves scanned_at empty, so it never counts); a covered service
     * with no stored columns (an empty database) also counts as scanned by a successful full
     * scan that finished after the service was created.
     */
    private static function captureCovered(): array
    {
        $services = self::coveredServices();
        if (empty($services)) {
            return [];
        }
        $ids = array_column($services, 'id');

        $created = [];
        try {
            foreach (DB::table('service')->whereIn('id', $ids)->get(['id', 'created_date']) as $row) {
                $created[(int)$row->id] = Time::ts($row->created_date ?? null);
            }
        } catch (\Throwable $e) {
            // no created_date column: creation times stay unknown
        }

        if (class_exists(ScanHistory::class) && method_exists(ScanHistory::class, 'services')) {
            [$history, $unreadable] = self::scanHistory($ids);
            $covered = [];
            foreach ($services as $service) {
                $id = $service['id'];
                $entry = is_array($history[$id] ?? null) ? $history[$id] : [];
                $unknown = $unreadable || self::entryUnknown($entry);
                $covered[] = $service + [
                    'created_at' => $created[$id] ?? null,
                    'last_scan_at' => $unknown ? null : (isset($entry['scanned_at']) ? (int)$entry['scanned_at'] : null),
                    'scan_error' => $unknown ? null : (isset($entry['scan_error']) ? (string)$entry['scan_error'] : null),
                    'scan_unknown' => $unknown,
                ];
            }

            return $covered;
        }

        $perService = [];
        foreach (DB::table(Tables::SCAN)
                     ->where('status', 'done')
                     ->whereIn('service_id', $ids)
                     ->groupBy('service_id')
                     ->get(['service_id', DB::raw('MAX(finished_at) as finished')]) as $row) {
            $perService[(int)$row->service_id] = Time::ts($row->finished);
        }

        $columns = [];
        foreach (DB::table(Tables::COLUMN)
                     ->whereIn('service_id', $ids)
                     ->groupBy('service_id')
                     ->get(['service_id', DB::raw('MAX(scanned_at) as scanned'), DB::raw('COUNT(*) as n')]) as $row) {
            $columns[(int)$row->service_id] = ['scanned' => Time::ts($row->scanned), 'n' => (int)$row->n];
        }

        $lastFull = Time::ts(DB::table(Tables::SCAN)
            ->where('status', 'done')
            ->whereNull('service_id')
            ->max('finished_at'));

        $covered = [];
        foreach ($services as $service) {
            $id = $service['id'];
            $createdAt = $created[$id] ?? null;
            $covered[] = $service + [
                'created_at' => $createdAt,
                'last_scan_at' => self::lastScan(
                    $perService[$id] ?? null,
                    $columns[$id]['scanned'] ?? null,
                    $columns[$id]['n'] ?? 0,
                    $lastFull,
                    $createdAt
                ),
                'scan_error' => null,
            ];
        }

        return $covered;
    }

    /**
     * Support\ScanHistory::services() plus whether the scan history could be read at all:
     * services() marks each entry unknown = true on a database error (scanned_at and scan_error
     * are then null because nothing could be checked, not because it was never scanned); a call
     * that throws or returns no array counts the same. Entries without the flag (older
     * ScanHistory) are read as known. An unreadable history makes the masking checks say
     * "Could not be checked" rather than "never scanned".
     *
     * @param list<int> $ids
     * @return array{0:array<int,mixed>,1:bool} [entries by service id, whole history unreadable]
     */
    private static function scanHistory(array $ids): array
    {
        try {
            $history = ScanHistory::services($ids);
            $why = is_array($history) ? null : 'no result';
        } catch (\Throwable $e) {
            $why = $e->getMessage();
        }
        if ($why !== null) {
            try {
                Log::warning('df-masking baselines: could not read the scan history: ' . $why);
            } catch (\Throwable $ignored) {
            }

            return [[], true];
        }

        return [$history, false];
    }

    /** A ScanHistory::services() entry whose history could not be read. */
    private static function entryUnknown(array $entry): bool
    {
        return ($entry['unknown'] ?? false) === true;
    }

    /**
     * When a covered service was last scanned (see captureCovered()).
     *
     * @param int|null $serviceScan  finish of the latest successful scan of this service
     * @param int|null $columnScan   latest scanned_at among its stored columns
     * @param int      $columns      how many columns are stored for it
     * @param int|null $lastFullScan finish of the latest successful scan of all services
     * @param int|null $createdAt    when the service was created
     */
    public static function lastScan(?int $serviceScan, ?int $columnScan, int $columns, ?int $lastFullScan, ?int $createdAt): ?int
    {
        $last = max($serviceScan ?? 0, $columnScan ?? 0) ?: null;
        if ($last === null && $columns === 0 && $lastFullScan !== null
            && ($createdAt === null || $lastFullScan >= $createdAt)) {
            $last = $lastFullScan;
        }

        return $last;
    }

    /**
     * Active services Data Masking covers (SqlDb subclasses), from Support\Coverage; falls back
     * to Enforcement\Policy::coveredServiceIds() if that helper is unavailable.
     *
     * @return list<array{id:int,name:string,label:string,type:string}>
     */
    private static function coveredServices(): array
    {
        $out = [];
        if (class_exists(Coverage::class)) {
            foreach (Coverage::covered(true) as $service) {
                $out[] = [
                    'id' => (int)$service['id'],
                    'name' => (string)$service['name'],
                    'label' => (string)($service['label'] ?: $service['name']),
                    'type' => (string)$service['type'],
                ];
            }

            return $out;
        }

        $ids = array_values(array_unique(array_map('intval', Policy::coveredServiceIds())));
        if (empty($ids)) {
            return [];
        }
        foreach (DB::table('service')->whereIn('id', $ids)->where('is_active', true)->orderBy('name')
                     ->get(['id', 'name', 'label', 'type']) as $row) {
            $out[] = [
                'id' => (int)$row->id,
                'name' => (string)$row->name,
                'label' => is_string($row->label) && $row->label !== '' ? $row->label : (string)$row->name,
                'type' => (string)$row->type,
            ];
        }

        return $out;
    }

    /** @return list<array{id:int,name:string,label:string,type:string}> */
    private static function captureUncovered(): array
    {
        if (!class_exists(Coverage::class)) {
            return [];
        }
        $out = [];
        foreach (Coverage::uncovered(true) as $service) {
            $out[] = [
                'id' => (int)$service['id'],
                'name' => (string)$service['name'],
                'label' => (string)($service['label'] ?: $service['name']),
                'type' => (string)$service['type'],
            ];
        }

        return $out;
    }

    /**
     * Active sys admins with their last sign-in. DreamFactory stamps user.last_login_date on
     * every interactive sign-in (password, OAuth, SAML, LDAP, Active Directory); token renewals
     * do not, but they stop DF_JWT_REFRESH_TTL after the sign-in.
     *
     * @return list<array{id:int,name:string,last_login_at:?int,created_at:?int}>
     */
    private static function captureAdmins(): array
    {
        $out = [];
        $rows = DB::table('user')
            ->where('is_sys_admin', true)
            ->where('is_active', true)
            ->orderBy('id')
            ->get(['id', 'first_name', 'last_name', 'name', 'email', 'last_login_date', 'created_date']);
        foreach ($rows as $row) {
            $out[] = [
                'id' => (int)$row->id,
                'name' => self::personName((object)(['admin_id' => $row->id] + (array)$row)),
                'last_login_at' => Time::ts($row->last_login_date ?? null),
                'created_at' => Time::ts($row->created_date ?? null),
            ];
        }

        return $out;
    }

    private static function captureAdopted(): array
    {
        $adopted = [];
        foreach (DB::table(Tables::BASELINE)->get() as $row) {
            $status = null;
            if (is_string($row->last_status) && $row->last_status !== '') {
                $decoded = json_decode($row->last_status, true);
                $status = is_array($decoded) ? $decoded : null;
            }
            $adopted[(string)$row->baseline_id] = [
                'adopted_at' => Time::ts($row->adopted_at),
                'adopted_by' => $row->adopted_by !== null ? (string)$row->adopted_by : null,
                'applied_at' => Time::ts($row->applied_at),
                'last_status' => $status,
            ];
        }

        return $adopted;
    }

    // ------------------------------------------------------------------------------------------
    // Platform settings (DreamFactory config, df-core tables, optional commercial packages)
    // ------------------------------------------------------------------------------------------

    public const PROVIDER_LIMITS = 'DreamFactory\\Core\\Limit\\ServiceProvider';
    public const PROVIDER_LOGGER = 'DreamFactory\\Core\\Logger\\ServiceProvider';
    public const PROVIDER_COMPLIANCE = 'DreamFactory\\Core\\Compliance\\ServiceProvider';
    public const PROVIDER_MONGO_LOGS = 'DreamFactory\\Core\\MongoLogs\\ServiceProvider';

    /**
     * Keys:
     *   app_url_https (bool), request_secure (?bool), debug (bool),
     *   jwt_ttl (?int minutes; null = tokens never expire),
     *   jwt_refresh_ttl (?int minutes after sign-in during which an expired token can be renewed
     *     without credentials; null = forever), forever_sessions (bool),
     *   cors_wildcard (?int enabled rules allowing origin *),
     *   limits_installed (bool), limits_active (?int),
     *   logger_installed (bool), logstash_events (?int events mapped to active Logstash services),
     *   logged_reads (?array<string,bool> covered service name => its data reads reach a Logstash
     *     service; see loggedReads()),
     *   mongo_logs (bool: every API request goes to the MongoDB request log),
     *   compliance_installed (bool), service_reports (bool), root_admin (?bool),
     *   open_registration (?list<string> active user services that allow open registration),
     *   activity_retention_days (int; 0 = masking activity is kept forever)
     *
     * @param list<array{name:string}>|null $covered covered services (captureCovered())
     */
    private static function capturePlatform(array &$errors, ?array $covered = []): array
    {
        $p = [];

        $url = (string)self::config('app.url', '');
        $p['app_url_https'] = strtolower((string)parse_url($url, PHP_URL_SCHEME)) === 'https';
        $p['request_secure'] = self::requestSecure();
        $p['debug'] = self::bool(self::config('app.debug', false));

        $ttl = self::config('jwt.ttl', 1440);
        $p['jwt_ttl'] = ($ttl === null || $ttl === '' || !is_numeric($ttl)) ? null : (int)$ttl;
        $refresh = self::config('jwt.refresh_ttl', 20160);
        $p['jwt_refresh_ttl'] = ($refresh === null || $refresh === '' || !is_numeric($refresh)) ? null : (int)$refresh;
        $p['forever_sessions'] = self::bool(self::config('df.allow_forever_sessions', false));

        $p['cors_wildcard'] = self::part('platform.cors', $errors, function () {
            $count = 0;
            foreach (DB::table('cors_config')->where('enabled', true)->get(['origin']) as $row) {
                $origins = array_map('trim', explode(',', (string)$row->origin));
                if (in_array('*', $origins, true)) {
                    $count++;
                }
            }

            return $count;
        });

        $p['limits_installed'] = self::installed(self::PROVIDER_LIMITS);
        $p['limits_active'] = $p['limits_installed']
            ? self::part('platform.limits', $errors, fn () => Schema::hasTable('limits')
                ? DB::table('limits')->where('is_active', 1)->count()
                : 0)
            : null;

        $p['logger_installed'] = self::installed(self::PROVIDER_LOGGER);
        $p['logstash_events'] = $p['logger_installed']
            ? self::part('platform.logstash', $errors, function () {
                $ids = DB::table('service')->where('type', 'logstash')->where('is_active', true)->pluck('id')->all();

                return empty($ids) ? 0 : DB::table('service_event_map')->whereIn('service_id', $ids)->count();
            })
            : null;
        $p['logged_reads'] = $covered === null
            ? null
            : self::part('platform.logged_reads', $errors, fn () => $p['logger_installed']
                ? self::loggedReads(array_column($covered, 'name'))
                : array_fill_keys(array_column($covered, 'name'), false));

        $p['mongo_logs'] = self::installed(self::PROVIDER_MONGO_LOGS)
            && strtolower(trim((string)env('LOGSDB_ENABLED', ''))) === 'true';

        $p['compliance_installed'] = self::installed(self::PROVIDER_COMPLIANCE);
        $p['service_reports'] = $p['compliance_installed']
            && (bool)self::part('platform.service_reports', $errors, fn () => Schema::hasTable('service_report'));
        $p['root_admin'] = $p['compliance_installed'] ? Caller::rootAdminDesignated() : null;

        $p['open_registration'] = self::part('platform.open_registration', $errors, function () {
            if (!Schema::hasTable('user_config')) {
                return []; // df-user not installed: no self-registration
            }

            return DB::table('user_config as uc')
                ->join('service as s', 's.id', '=', 'uc.service_id')
                ->where('s.is_active', true)
                ->where('uc.allow_open_registration', true)
                ->orderBy('s.name')
                ->pluck('s.name')
                ->map(fn ($v) => (string)$v)
                ->all();
        });
        $p['activity_retention_days'] = max(0, (int)self::config('df-masking.activity_retention_days', 400));

        return $p;
    }

    /**
     * Which covered services have their data reads logged by an active Logstash service.
     *
     * df-logger writes a record only for the API events mapped to it in service_event_map, and
     * DreamFactory consults that map with the final event of each request only (pre_process and
     * post_process names never reach it). A table read fires "<service>._table.{table_name}.get"
     * (lists) or "<service>._table.{table_name}.{id}.get" (one record). An event is logged when
     * a Logstash service is mapped to that exact name, or when no service at all is mapped to it
     * and a Logstash service is mapped to the wildcard "<service>.*" (DreamFactory only looks at
     * the wildcard when the exact name has no mapping). A service counts as logged when both
     * read events are.
     *
     * @param list<string> $services covered service names
     * @return array<string,bool>
     */
    public static function loggedReads(array $services): array
    {
        $out = array_fill_keys($services, false);
        if ($services === []) {
            return $out;
        }
        $logstash = array_map('intval', DB::table('service')
            ->where('type', 'logstash')
            ->where('is_active', true)
            ->pluck('id')
            ->all());
        if ($logstash === []) {
            return $out;
        }
        $wanted = [];
        foreach ($services as $name) {
            foreach (self::readEvents($name) as $event) {
                $wanted[] = $event;
            }
        }
        $mapped = [];
        foreach (array_chunk(array_values(array_unique($wanted)), 500) as $chunk) {
            foreach (DB::table('service_event_map')->whereIn('event', $chunk)->get(['service_id', 'event']) as $row) {
                $mapped[strtolower((string)$row->event)][] = (int)$row->service_id;
            }
        }
        $toLogstash = fn (string $event) => array_intersect($mapped[strtolower($event)] ?? [], $logstash) !== [];
        foreach ($services as $name) {
            [$list, $one, $wildcard] = self::readEvents($name);
            $logged = true;
            foreach ([$list, $one] as $event) {
                $hit = $toLogstash($event) || (empty($mapped[strtolower($event)]) && $toLogstash($wildcard));
                $logged = $logged && $hit;
            }
            $out[$name] = $logged;
        }

        return $out;
    }

    /** @return array{0:string,1:string,2:string} list-read event, record-read event, service wildcard */
    public static function readEvents(string $service): array
    {
        return [$service . '._table.{table_name}.get', $service . '._table.{table_name}.{id}.get', $service . '.*'];
    }

    private static function installed(string $provider): bool
    {
        if (!class_exists($provider)) {
            return false;
        }
        try {
            $app = app();

            return !method_exists($app, 'providerIsLoaded') || $app->providerIsLoaded($provider);
        } catch (\Throwable $e) {
            return true;
        }
    }

    private static function requestSecure(): ?bool
    {
        try {
            if (app()->runningInConsole() || !app()->bound('request')) {
                return null;
            }

            return (bool)app('request')->isSecure();
        } catch (\Throwable $e) {
            return null;
        }
    }

    private static function config(string $key, mixed $default): mixed
    {
        try {
            return config($key, $default);
        } catch (\Throwable $e) {
            return $default;
        }
    }

    private static function bool(mixed $value): bool
    {
        if (is_bool($value)) {
            return $value;
        }

        return filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE) ?? false;
    }

    private static function personName(object $row): string
    {
        $full = trim((string)($row->first_name ?? '') . ' ' . (string)($row->last_name ?? ''));
        if ($full !== '') {
            return $full;
        }
        foreach (['name', 'email'] as $field) {
            $value = $row->{$field} ?? null;
            if (is_string($value) && trim($value) !== '') {
                return trim($value);
            }
        }

        return 'admin ' . ($row->admin_id ?? '?');
    }
}

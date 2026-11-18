<?php

namespace DreamFactory\Core\Masking\Baselines;

use DreamFactory\Core\Masking\Support\Catalog;
use Illuminate\Support\Facades\Log;

/**
 * Evaluates a baseline's controls against a State snapshot. Pure: no database access, so the
 * same snapshot can score all seven baselines in one request.
 *
 * Every control yields {id, title, refs, status, detail, fix}:
 *   status 'pass' | 'fail' | 'manual' (checked by people, outside DreamFactory) | 'na'
 *   detail one short sentence, never a data value (counts, class labels, service/role names)
 *   fix    {kind: 'apply'|'link'|'none', route} while failing; {kind:'none', route:null} otherwise
 *
 * A check passes only when its title is true. In particular the masking checks never pass on
 * an instance where nothing has been scanned yet (nothing is classified, so nothing is masked),
 * and a database a scan could not read does not count as scanned. When the scan history itself
 * cannot be read (State marks those services scan_unknown), the checks that depend on it say
 * "Could not be checked" instead of "never scanned".
 *
 * Details name services by their label, as the rest of the admin UI does.
 */
final class Evaluator
{
    private const MODE_RANK = ['off' => 0, 'preview' => 1, 'on' => 2];

    /** Grants are compared with a minute of slack so a cap applied a moment ago never fails. */
    private const GRANT_SLACK_SECONDS = 60;

    /** At most this many names in a detail sentence ("a, b, c +2 more"). */
    private const NAMES_IN_DETAIL = 3;

    private const UNKNOWN = 'Could not be checked: see the DreamFactory log.';

    private function __construct()
    {
    }

    /**
     * @return list<array{id:string,title:string,refs:string[],status:string,detail:?string,fix:array{kind:string,route:?string}}>
     */
    public static function controls(array $baseline, State $state): array
    {
        $out = [];
        foreach ($baseline['controls'] as $control) {
            $out[] = self::control($control, $baseline, $state);
        }

        return $out;
    }

    /** @return array{pass:int,fail:int,manual:int,total:int} total excludes 'na' */
    public static function score(array $controls): array
    {
        $score = ['pass' => 0, 'fail' => 0, 'manual' => 0, 'total' => 0];
        foreach ($controls as $control) {
            if (isset($score[$control['status']])) {
                $score[$control['status']]++;
                $score['total']++;
            }
        }

        return $score;
    }

    public static function control(array $control, array $baseline, State $state): array
    {
        $id = $control['id'];
        $result = [
            'id' => $id,
            'title' => $control['title'],
            'refs' => array_values($control['refs']),
            'status' => 'manual',
            'detail' => $control['detail'] ?? null,
            'fix' => ['kind' => 'none', 'route' => null],
        ];
        if (Checks::isManual($id)) {
            return $result;
        }

        try {
            [$status, $detail] = self::evaluate($id, $control['params'] ?? [], $baseline, $state);
        } catch (\Throwable $e) {
            try {
                Log::warning('df-masking baselines: check ' . $id . ' failed: ' . $e->getMessage());
            } catch (\Throwable $ignored) {
            }
            [$status, $detail] = self::unknown();
        }

        $result['status'] = $status;
        $result['detail'] = $detail;
        if ($status === 'fail') {
            $result['fix'] = self::fixFor($id, $control['params'] ?? [], $baseline, $state, $detail);
        }

        return $result;
    }

    /** @return array{0:string,1:?string} [status, detail] */
    private static function evaluate(string $id, array $params, array $baseline, State $s): array
    {
        return match ($id) {
            Checks::MASKING_MODE => self::maskingMode($params, $s),
            Checks::MASKING_SCANNED => self::maskingScanned($params, $s),
            Checks::MASKING_REVIEW => self::maskingReview($s),
            Checks::MASKING_CLASSES => self::maskingClasses($baseline, $s),
            Checks::MASKING_FORMAT => self::maskingFormat($baseline, $s),
            Checks::ACCESS_AI => self::accessAi($s),
            Checks::ACCESS_GRANT_EXPIRY => self::accessGrantExpiry($baseline, $s),
            Checks::ACCESS_ADMINS_ALL => self::accessAdminsAll($s),
            Checks::ACCESS_ROLES_RESTRICTED => self::accessRolesRestricted($s),
            Checks::ACCESS_INACTIVE_ADMINS => self::accessInactiveAdmins($params, $s),
            Checks::PLATFORM_HTTPS => self::platformHttps($s),
            Checks::PLATFORM_DEBUG => self::platformDebug($s),
            Checks::PLATFORM_SESSION_TTL => self::platformSessionTtl($params, $s),
            Checks::PLATFORM_CORS => self::platformCors($s),
            Checks::PLATFORM_RATE_LIMIT => self::platformRateLimit($s),
            Checks::PLATFORM_AUDIT => self::platformAudit($s),
            Checks::PLATFORM_ROOT_ADMIN => self::platformRootAdmin($s),
            Checks::PLATFORM_OPEN_REGISTRATION => self::platformOpenRegistration($s),
            Checks::PLATFORM_LOG_RETENTION => self::platformLogRetention($params, $s),
            default => throw new \LogicException("Unknown check '$id'."),
        };
    }

    /** @return array{kind:string,route:?string} */
    private static function fixFor(string $id, array $params, array $baseline, State $s, ?string $detail): array
    {
        $fix = Checks::fix($id);
        // Masking checks that fail only because databases were never scanned are fixed by a
        // scan, not by Apply or the review filters. When the scan history could not be read and
        // the check could not be decided, they go to Data Masking too (its scan status).
        $known = !self::historyUnknown($s);
        $scanFirst = match ($id) {
            Checks::MASKING_MODE => self::modeReached($params, $s) && (!$known || self::neverScanned($s) !== []),
            Checks::MASKING_REVIEW, Checks::MASKING_CLASSES => $known ? self::nothingScanned($s) : $detail === self::UNKNOWN,
            default => false,
        };
        if ($scanFirst) {
            return ['kind' => 'link', 'route' => Checks::ROUTE_DATA_MASKING];
        }
        // The grant check under admins mode "all" is fixed by the admins rule; a baseline that has
        // no admins rule sends people to the Access tab instead.
        if ($id === Checks::ACCESS_GRANT_EXPIRY && $s->adminsMode === 'all'
            && empty($baseline['apply']['admins_mode_max'])) {
            return ['kind' => 'link', 'route' => Checks::ROUTE_DATA_MASKING_ACCESS];
        }

        return $fix;
    }

    private static function unknown(): array
    {
        return ['fail', self::UNKNOWN];
    }

    // ------------------------------------------------------------------------------------------
    // masking.*
    // ------------------------------------------------------------------------------------------

    private static function modeReached(array $params, State $s): bool
    {
        return (self::MODE_RANK[$s->mode] ?? 0) >= (self::MODE_RANK[$params['min'] ?? 'on'] ?? 2);
    }

    private static function maskingMode(array $params, State $s): array
    {
        $detail = match ($s->mode) {
            'on' => 'Masking is on.',
            'preview' => 'Masking is in Preview: values are not masked yet.',
            default => 'Masking is off.',
        };
        if (!self::modeReached($params, $s)) {
            return ['fail', $detail];
        }
        if ($s->covered === null || self::historyUnknown($s)) {
            return self::unknown();
        }
        // Columns of a database that was never scanned are not classified, so not masked.
        $never = self::neverScanned($s);
        if ($never !== [] && count($never) === count($s->covered)) {
            return ['fail', substr($detail, 0, -1) . ', but no database has been scanned yet.'];
        }
        if ($never !== []) {
            return ['fail', sprintf(
                '%s, but %s never been scanned: %s.',
                substr($detail, 0, -1),
                self::plural(count($never), 'database has', 'databases have'),
                self::names($never)
            )];
        }

        return ['pass', $detail];
    }

    /** @return list<string> labels of covered services that were never scanned successfully */
    private static function neverScanned(State $s): array
    {
        $out = [];
        foreach ($s->covered ?? [] as $service) {
            if ($service['last_scan_at'] === null) {
                $out[] = self::label($service);
            }
        }

        return $out;
    }

    /**
     * True when the scan history could not be read for some covered service: whether it was
     * scanned is then unknown (never "never scanned", never "scanned").
     */
    private static function historyUnknown(State $s): bool
    {
        foreach ($s->covered ?? [] as $service) {
            if (!empty($service['scan_unknown'])) {
                return true;
            }
        }

        return false;
    }

    /** True when there are covered services and none of them was ever scanned successfully. */
    private static function nothingScanned(State $s): bool
    {
        return !empty($s->covered) && count(self::neverScanned($s)) === count($s->covered);
    }

    private static function notScannedYet(): array
    {
        return ['fail', 'No database has been scanned yet, so no column is classified.'];
    }

    /**
     * Every covered SQL service scanned successfully in the last N days, and its latest scan
     * read it. Database services Data Masking cannot scan (MongoDB, DynamoDB, ...) make the
     * check a hand check ('manual'): "all databases scanned" is then not something DreamFactory
     * can confirm.
     */
    private static function maskingScanned(array $params, State $s): array
    {
        if ($s->covered === null || $s->uncovered === null || self::historyUnknown($s)) {
            return self::unknown();
        }
        $total = count($s->covered);
        $uncovered = array_map([self::class, 'label'], $s->uncovered);
        $handCheck = $uncovered === [] ? null : sprintf(
            "Data Masking can't scan %s: check %s by hand.",
            self::names($uncovered),
            count($uncovered) === 1 ? 'it' : 'them'
        );
        if ($total === 0) {
            return $handCheck === null ? ['na', 'No database services to scan.'] : ['manual', $handCheck];
        }
        $days = (int)($params['days'] ?? 30);
        $since = $s->now - $days * 86400;
        $stale = [];
        $failed = [];
        foreach ($s->covered as $service) {
            if (($service['scan_error'] ?? null) !== null) {
                $failed[] = self::label($service);
            } elseif ($service['last_scan_at'] === null || $service['last_scan_at'] < $since) {
                $stale[] = self::label($service);
            }
        }
        if ($failed !== [] || $stale !== []) {
            $parts = [];
            if ($failed !== []) {
                $parts[] = sprintf("The last scan couldn't read %s.", self::names($failed));
            }
            if ($stale !== []) {
                $parts[] = sprintf(
                    '%d of %d SQL services not scanned in the last %d days: %s.',
                    count($stale),
                    $total,
                    $days,
                    self::names($stale)
                );
            }

            return ['fail', implode(' ', $parts)];
        }
        $scanned = $total === 1
            ? "The SQL service was scanned in the last $days days."
            : "All $total SQL services were scanned in the last $days days.";

        return $handCheck === null ? ['pass', $scanned] : ['manual', $scanned . ' ' . $handCheck];
    }

    /**
     * With an unreadable scan history a count above zero still fails with its count; zero
     * cannot pass (maybe nothing was scanned), so it could not be checked.
     */
    private static function maskingReview(State $s): array
    {
        if ($s->verdicts === null || $s->covered === null) {
            return self::unknown();
        }
        $known = !self::historyUnknown($s);
        if ($known && self::nothingScanned($s)) {
            return self::notScannedYet();
        }
        $review = (int)($s->verdicts['review'] ?? 0);
        if ($review === 0) {
            return $known ? ['pass', 'No columns waiting for review.'] : self::unknown();
        }

        return ['fail', self::plural($review, 'column waits', 'columns wait') . ' for review (masked until decided).'];
    }

    private static function maskingClasses(array $baseline, State $s): array
    {
        if ($s->adminCleared === null || $s->covered === null) {
            return self::unknown();
        }
        $known = !self::historyUnknown($s);
        if ($known && self::nothingScanned($s)) {
            return self::notScannedYet();
        }
        $count = 0;
        $labels = [];
        foreach ($baseline['protected_classes'] ?? [] as $class) {
            $n = (int)($s->adminCleared[$class] ?? 0);
            if ($n > 0) {
                $count += $n;
                $labels[] = Catalog::label($class);
            }
        }
        if ($count === 0) {
            return $known ? ['pass', sprintf(
                'No column detected as protected data (score %d or more) is marked not sensitive.',
                State::ADMIN_CLEARED_MIN_SCORE
            )] : self::unknown();
        }

        return ['fail', sprintf(
            '%s detected as %s (score %d or more) %s marked not sensitive.',
            self::plural($count, 'column', 'columns'),
            self::names($labels),
            State::ADMIN_CLEARED_MIN_SCORE,
            $count === 1 ? 'is' : 'are'
        )];
    }

    private static function maskingFormat(array $baseline, State $s): array
    {
        $rules = $baseline['apply']['formats'] ?? [];
        if (empty($rules)) {
            return ['na', 'No format requirements.'];
        }
        if ($s->formats === null) {
            return self::unknown();
        }
        $bad = [];
        $good = [];
        foreach ($rules as $rule) {
            $current = $s->formatOf($rule['class']);
            $label = Catalog::label($rule['class']);
            if ($current === null || !in_array($current, $rule['allowed'], true)) {
                $bad[] = sprintf(
                    '%s uses %s (allowed: %s)',
                    $label,
                    $current === null ? 'no format' : Catalog::formatLabel($current),
                    implode(', ', array_map([Catalog::class, 'formatLabel'], $rule['allowed']))
                );
            } else {
                $good[] = $label . ': ' . Catalog::formatLabel($current);
            }
        }
        if (empty($bad)) {
            return ['pass', implode('; ', $good) . '.'];
        }

        return ['fail', implode('; ', $bad) . '.'];
    }

    // ------------------------------------------------------------------------------------------
    // access.*
    // ------------------------------------------------------------------------------------------

    private static function accessAi(State $s): array
    {
        return $s->ai === 'masked'
            ? ['pass', 'AI and MCP sessions get masked values.']
            : ['fail', 'AI and MCP sessions see the same values as admins.'];
    }

    private static function accessAdminsAll(State $s): array
    {
        return match ($s->adminsMode) {
            'all' => ['fail', 'All admins see real values.'],
            'selected' => ['pass', 'Admins see real values only with a grant.'],
            default => ['pass', 'Admins see masked values.'],
        };
    }

    private static function accessGrantExpiry(array $baseline, State $s): array
    {
        $maxHours = (int)($baseline['apply']['grant_max_hours'] ?? 0);
        if ($maxHours <= 0) {
            return ['na', 'No grant limit.'];
        }
        if ($s->adminsMode === 'none') {
            return ['pass', 'No admin sees real values.'];
        }
        if ($s->adminsMode === 'all') {
            return ['fail', 'All admins see real values with no time limit.'];
        }
        if ($s->grants === null) {
            return self::unknown();
        }
        $limit = $s->now + $maxHours * 3600 + self::GRANT_SLACK_SECONDS;
        $over = 0;
        $forever = 0;
        foreach ($s->grants as $grant) {
            if ($grant['expires_at'] === null) {
                $over++;
                $forever++;
            } elseif ($grant['expires_at'] > $limit) {
                $over++;
            }
        }
        $max = Time::hours($maxHours);
        if ($over === 0) {
            $active = count($s->grants);

            return ['pass', $active === 0
                ? 'No active admin grants.'
                : self::plural($active, 'active grant', 'active grants') . ", all within $max."];
        }
        $detail = self::plural($over, 'grant lasts', 'grants last') . " longer than $max";
        if ($forever > 0) {
            $detail .= $forever === $over ? ' (no end date)' : sprintf(' (%d with no end date)', $forever);
        }

        return ['fail', $detail . '.'];
    }

    private static function accessRolesRestricted(State $s): array
    {
        if ($s->roles === null) {
            return self::unknown();
        }
        $open = [];
        foreach ($s->roles as $role) {
            if ($role['enabled'] && $role['scope'] === 'all') {
                $open[] = $role['name'];
            }
        }
        if (empty($open)) {
            return ['pass', 'No role sees restricted real values.'];
        }

        return ['fail', sprintf(
            '%s %s restricted real values: %s.',
            self::plural(count($open), 'role', 'roles'),
            count($open) === 1 ? 'sees' : 'see',
            self::names($open)
        )];
    }

    private static function accessInactiveAdmins(array $params, State $s): array
    {
        if ($s->admins === null) {
            return self::unknown();
        }
        $days = (int)($params['days'] ?? 90);
        $since = $s->now - $days * 86400;
        $stale = [];
        foreach ($s->admins as $admin) {
            // Never signed in: counted from when the account was created.
            $last = $admin['last_login_at'] ?? $admin['created_at'] ?? null;
            if ($last === null || $last < $since) {
                $stale[] = $admin['name'];
            }
        }
        if ($stale === []) {
            return ['pass', count($s->admins) === 0
                ? 'No active admin accounts.'
                : "Every active admin signed in within the last $days days."];
        }

        return ['fail', sprintf(
            "%s not signed in for %d days: %s. Deactivate %s or remove admin rights.",
            self::plural(count($stale), 'admin has', 'admins have'),
            $days,
            self::names($stale),
            count($stale) === 1 ? 'the account' : 'the accounts'
        )];
    }

    // ------------------------------------------------------------------------------------------
    // platform.*
    // ------------------------------------------------------------------------------------------

    private static function platformHttps(State $s): array
    {
        if ($s->platformValue('app_url_https') === true) {
            return ['pass', 'APP_URL uses https (certificates and TLS versions are not checked).'];
        }
        if ($s->platformValue('request_secure') === true) {
            return ['pass', 'Requests arrive over https; APP_URL still says http (certificates and TLS versions are not checked).'];
        }

        return ['fail', 'APP_URL does not use https. Serve DreamFactory over TLS and set APP_URL to the https address.'];
    }

    private static function platformDebug(State $s): array
    {
        return $s->platformValue('debug') === true
            ? ['fail', 'APP_DEBUG is on: error responses include stack traces. Set APP_DEBUG=false.']
            : ['pass', 'APP_DEBUG is off.'];
    }

    /**
     * An idle session must not come back without signing in after max_minutes: the token must
     * expire by then (DF_JWT_TTL) and an expired token must no longer be renewable
     * (DF_JWT_REFRESH_TTL, counted from the sign-in: DreamFactory renews expired tokens without
     * credentials until then).
     */
    private static function platformSessionTtl(array $params, State $s): array
    {
        $max = (int)($params['max_minutes'] ?? 60);
        if ($s->platformValue('forever_sessions') === true) {
            return ['fail', 'Sessions that never expire are allowed. Set DF_ALLOW_FOREVER_SESSIONS=false.'];
        }
        $ttl = $s->platformValue('jwt_ttl');
        $refresh = $s->platformValue('jwt_refresh_ttl');
        $problems = [];
        $settings = [];
        if ($ttl === null || $ttl > $max) {
            $problems[] = $ttl === null ? 'session tokens never expire' : "session tokens last $ttl minutes";
            $settings[] = 'DF_JWT_TTL';
        }
        if ($refresh === null || $refresh > $max) {
            $problems[] = $refresh === null
                ? 'expired tokens can be renewed without signing in, with no time limit'
                : "expired tokens can be renewed without signing in for $refresh minutes";
            $settings[] = 'DF_JWT_REFRESH_TTL';
        }
        if ($problems !== []) {
            return ['fail', sprintf(
                '%s. Set %s to %d or less.',
                ucfirst(implode(', and ', $problems)),
                implode(' and ', $settings),
                $max
            )];
        }

        return ['pass', "Tokens last $ttl minutes and can't be renewed later than $refresh minutes after signing in."];
    }

    private static function platformCors(State $s): array
    {
        $count = $s->platformValue('cors_wildcard');
        if ($count === null) {
            return self::unknown();
        }
        if ($count === 0) {
            return ['pass', 'No enabled CORS rule allows every origin.'];
        }

        return ['fail', self::plural($count, 'enabled CORS rule allows', 'enabled CORS rules allow') . ' every origin (*).'];
    }

    private static function platformRateLimit(State $s): array
    {
        if ($s->platformValue('limits_installed') !== true) {
            return ['fail', 'API limits are not installed on this instance.'];
        }
        $active = $s->platformValue('limits_active');
        if ($active === null) {
            return self::unknown();
        }
        if ($active === 0) {
            return ['fail', 'No active API limits.'];
        }

        return ['pass', self::plural($active, 'active API limit', 'active API limits') . '.'];
    }

    /**
     * Reads from every covered SQL database are logged: the MongoDB request log (every API
     * request), or Logstash mapped to the read events of each covered service (State::loggedReads).
     * A Logstash service subscribed to other events does not count.
     */
    private static function platformAudit(State $s): array
    {
        if ($s->platformValue('mongo_logs') === true) {
            return ['pass', 'Every API request is logged to the MongoDB request log.'];
        }
        $reads = $s->platformValue('logged_reads');
        if (!is_array($reads)) {
            return self::unknown();
        }
        $total = count($reads);
        if ($total === 0) {
            return ['na', 'No SQL database services.'];
        }
        $missing = array_keys(array_filter($reads, fn ($logged) => $logged !== true));
        if ($missing === []) {
            return ['pass', $total === 1
                ? 'Logstash logs reads from the SQL service.'
                : "Logstash logs reads from all $total SQL services."];
        }
        $example = State::readEvents((string)$missing[0])[2];
        if (count($missing) < $total) {
            return ['fail', sprintf(
                'Logstash logs reads from %d of %d SQL services. Not logged: %s. Subscribe Logstash to %s.',
                $total - count($missing),
                $total,
                self::names($missing),
                $example
            )];
        }
        $events = $s->platformValue('logstash_events');
        if (is_int($events) && $events > 0) {
            return ['fail', "Logstash logs no database reads. Subscribe it to each database's events, e.g. $example."];
        }
        if ($s->platformValue('service_reports') === true) {
            return ['fail', "Only service changes are recorded (Service Reports). Add a Logstash service and subscribe it to each database's events, e.g. $example."];
        }

        return ['fail', "Reads are not logged. Add a Logstash service and subscribe it to each database's events, e.g. $example."];
    }

    /**
     * The super admin rule: with a super admin designated (df-compliance's df:root_admin), only
     * that admin can give access to real values or lower the masking mode (On to Preview or Off).
     * Without one, every full admin can do both. The command keeps its df-compliance name.
     */
    private static function platformRootAdmin(State $s): array
    {
        if ($s->platformValue('compliance_installed') !== true) {
            return ['fail', 'Every admin can give access to real values and lower the masking mode. '
                . 'Install df-compliance and designate a super admin (php artisan df:root_admin --admin_id=<id>).'];
        }
        $root = $s->platformValue('root_admin');
        if ($root === null) {
            return self::unknown();
        }

        return $root
            ? ['pass', 'A super admin is designated: only they can give access to real values or lower the masking mode.']
            : ['fail', 'No super admin: every admin can give access to real values and lower the masking mode. '
                . 'Run php artisan df:root_admin --admin_id=<id>.'];
    }

    private static function platformOpenRegistration(State $s): array
    {
        $open = $s->platformValue('open_registration');
        if (!is_array($open)) {
            return self::unknown();
        }
        if ($open === []) {
            return ['pass', 'Open registration is off.'];
        }

        return ['fail', sprintf(
            'Open registration is on for %s: anyone can create an account. Turn it off in the service settings.',
            self::names($open)
        )];
    }

    private static function platformLogRetention(array $params, State $s): array
    {
        $min = (int)($params['min_days'] ?? 365);
        $days = $s->platformValue('activity_retention_days');
        if (!is_int($days)) {
            return self::unknown();
        }
        if ($days === 0) {
            return ['pass', 'Masking activity is kept forever.'];
        }
        if ($days >= $min) {
            return ['pass', "Masking activity is kept for $days days."];
        }

        return ['fail', "Masking activity is deleted after $days days. Set DF_MASKING_ACTIVITY_RETENTION_DAYS to $min or more (0 keeps it forever)."];
    }

    // ------------------------------------------------------------------------------------------
    // Text helpers
    // ------------------------------------------------------------------------------------------

    /** A service's label as the admin UI shows it (its name when it has none). */
    private static function label(array $service): string
    {
        $label = trim((string)($service['label'] ?? ''));

        return $label !== '' ? $label : (string)($service['name'] ?? '');
    }

    private static function plural(int $n, string $one, string $many): string
    {
        return $n . ' ' . ($n === 1 ? $one : $many);
    }

    /** "a, b, c" or "a, b, c +2 more". */
    private static function names(array $names): string
    {
        $names = array_values(array_unique($names));
        $shown = array_slice($names, 0, self::NAMES_IN_DETAIL);
        $more = count($names) - count($shown);

        return implode(', ', $shown) . ($more > 0 ? " +$more more" : '');
    }
}

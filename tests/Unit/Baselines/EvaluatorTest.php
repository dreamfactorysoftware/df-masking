<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Baselines;

use DreamFactory\Core\Masking\Baselines\BaselineRegistry;
use DreamFactory\Core\Masking\Baselines\Checks;
use DreamFactory\Core\Masking\Baselines\Evaluator;
use DreamFactory\Core\Masking\Baselines\State;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Check logic on hand-built snapshots (no database). */
final class EvaluatorTest extends TestCase
{
    private const NOW = 1_800_000_000;

    /** A well-run instance: every DreamFactory-owned control passes. */
    public static function good(array $override = []): State
    {
        $args = array_replace([
            'now' => self::NOW,
            'mode' => 'on',
            'ai' => 'masked',
            'adminsMode' => 'selected',
            'formats' => ['date_of_birth' => 'year', 'card_number' => 'last4'],
            'grants' => [['admin_id' => 2, 'name' => 'Priya Shah', 'email' => 'priya@example.test', 'expires_at' => self::NOW + 3600]],
            'roles' => [['role_id' => 3, 'name' => 'support', 'enabled' => true, 'scope' => 'except_restricted']],
            'rules' => [],
            'verdicts' => ['masked' => 40, 'review' => 0, 'clear' => 200],
            'adminCleared' => ['gender' => 1],
            'covered' => [
                ['id' => 1, 'name' => 'crm', 'label' => 'CRM', 'type' => 'pgsql', 'created_at' => self::NOW - 90 * 86400, 'last_scan_at' => self::NOW - 86400],
            ],
            'platform' => [
                'app_url_https' => true,
                'request_secure' => null,
                'debug' => false,
                'jwt_ttl' => 15,
                'jwt_refresh_ttl' => 15,
                'forever_sessions' => false,
                'cors_wildcard' => 0,
                'limits_installed' => true,
                'limits_active' => 2,
                'logger_installed' => true,
                'logstash_events' => 2,
                'logged_reads' => ['crm' => true],
                'mongo_logs' => false,
                'compliance_installed' => true,
                'service_reports' => true,
                'root_admin' => true,
                'open_registration' => [],
                'activity_retention_days' => 400,
            ],
            'adopted' => [],
            'uncovered' => [],
            'admins' => [
                ['id' => 1, 'name' => 'Alex Admin', 'last_login_at' => self::NOW - 86400, 'created_at' => self::NOW - 400 * 86400],
                ['id' => 2, 'name' => 'Priya Shah', 'last_login_at' => null, 'created_at' => self::NOW - 10 * 86400],
            ],
        ], $override);

        return new State(...$args);
    }

    public static function fresh(array $override = []): State
    {
        return new State(...array_replace([
            'now' => self::NOW,
            'covered' => [['id' => 1, 'name' => 'crm', 'label' => 'CRM', 'type' => 'pgsql', 'created_at' => self::NOW - 86400, 'last_scan_at' => null]],
            'platform' => [
                'app_url_https' => false, 'request_secure' => null, 'debug' => false, 'jwt_ttl' => 1440,
                'jwt_refresh_ttl' => 20160,
                'forever_sessions' => false, 'cors_wildcard' => 1, 'limits_installed' => true, 'limits_active' => 0,
                'logger_installed' => true, 'logstash_events' => 0, 'logged_reads' => ['crm' => false], 'mongo_logs' => false,
                'compliance_installed' => true, 'service_reports' => true, 'root_admin' => false,
                'open_registration' => [], 'activity_retention_days' => 400,
            ],
        ], $override));
    }

    private static function control(string $baselineId, string $check, State $state): array
    {
        foreach (Evaluator::controls(BaselineRegistry::get($baselineId), $state) as $control) {
            if ($control['id'] === $check) {
                return $control;
            }
        }
        throw new \RuntimeException("$baselineId has no $check");
    }

    public static function baselineIds(): array
    {
        return array_combine(BaselineRegistry::ids(), array_map(fn ($id) => [$id], BaselineRegistry::ids()));
    }

    #[DataProvider('baselineIds')]
    public function testWellRunInstancePassesEveryCheck(string $id): void
    {
        $controls = Evaluator::controls(BaselineRegistry::get($id), self::good());
        foreach ($controls as $control) {
            $expected = Checks::isManual($control['id']) ? 'manual' : 'pass';
            $this->assertSame($expected, $control['status'], "$id {$control['id']}: {$control['detail']}");
            $this->assertSame(['kind' => 'none', 'route' => null], $control['fix']);
            $this->assertIsString($control['detail']);
        }
        $score = Evaluator::score($controls);
        $this->assertSame(0, $score['fail']);
        $this->assertSame($score['pass'] + $score['manual'], $score['total']);
    }

    #[DataProvider('baselineIds')]
    public function testFreshInstanceFailsWithFixes(string $id): void
    {
        $controls = Evaluator::controls(BaselineRegistry::get($id), self::fresh());
        $byId = array_column($controls, null, 'id');
        $this->assertSame('fail', $byId[Checks::MASKING_MODE]['status']);
        $this->assertSame('apply', $byId[Checks::MASKING_MODE]['fix']['kind']);
        $this->assertSame('pass', $byId[Checks::ACCESS_AI]['status']);
        $this->assertSame('pass', $byId[Checks::ACCESS_ADMINS_ALL]['status']);
        $this->assertSame('fail', $byId[Checks::PLATFORM_HTTPS]['status']);
        $this->assertSame('none', $byId[Checks::PLATFORM_HTTPS]['fix']['kind']);
        if (isset($byId[Checks::MASKING_SCANNED])) {
            $this->assertSame('fail', $byId[Checks::MASKING_SCANNED]['status']);
            $this->assertSame(['kind' => 'link', 'route' => '/api-security/data-masking'], $byId[Checks::MASKING_SCANNED]['fix']);
        }
        if (isset($byId[Checks::PLATFORM_ROOT_ADMIN])) {
            $this->assertSame('fail', $byId[Checks::PLATFORM_ROOT_ADMIN]['status']);
        }
        foreach ($controls as $control) {
            $this->assertContains($control['status'], ['pass', 'fail', 'manual', 'na']);
            if ($control['status'] === 'fail') {
                $this->assertContains($control['fix']['kind'], ['apply', 'link', 'none']);
            }
        }
    }

    public function testMaskingMode(): void
    {
        $this->assertSame('fail', self::control('hipaa', Checks::MASKING_MODE, self::good(['mode' => 'preview']))['status']);
        $this->assertStringContainsString('Preview', self::control('hipaa', Checks::MASKING_MODE, self::good(['mode' => 'preview']))['detail']);
        $this->assertSame('fail', self::control('hipaa', Checks::MASKING_MODE, self::good(['mode' => 'off']))['status']);
        $this->assertSame('pass', self::control('hipaa', Checks::MASKING_MODE, self::good(['mode' => 'on']))['status']);
    }

    public function testScanned(): void
    {
        $stale = self::good(['covered' => [
            ['id' => 1, 'name' => 'crm', 'label' => 'CRM', 'type' => 'pgsql', 'created_at' => null, 'last_scan_at' => self::NOW - 31 * 86400],
            ['id' => 2, 'name' => 'hr', 'label' => 'HR', 'type' => 'sqlsrv', 'created_at' => null, 'last_scan_at' => self::NOW - 29 * 86400],
            ['id' => 3, 'name' => 'legacy', 'label' => 'Legacy', 'type' => 'sqlite', 'created_at' => null, 'last_scan_at' => null],
        ]]);
        $c = self::control('soc2', Checks::MASKING_SCANNED, $stale);
        $this->assertSame('fail', $c['status']);
        $this->assertSame('2 of 3 SQL services not scanned in the last 30 days: CRM, Legacy.', $c['detail']);

        $this->assertSame('na', self::control('soc2', Checks::MASKING_SCANNED, self::good(['covered' => []]))['status']);
        $unknown = self::control('soc2', Checks::MASKING_SCANNED, self::good(['covered' => null]));
        $this->assertSame('fail', $unknown['status']);
        $this->assertStringContainsString('Could not be checked', $unknown['detail']);
    }

    public function testReviewQueue(): void
    {
        $c = self::control('gdpr', Checks::MASKING_REVIEW, self::good(['verdicts' => ['masked' => 1, 'review' => 12, 'clear' => 0]]));
        $this->assertSame('fail', $c['status']);
        $this->assertSame('12 columns wait for review (masked until decided).', $c['detail']);
        $this->assertSame(['kind' => 'link', 'route' => '/api-security/data-masking?filter=review'],
            self::control('gdpr', Checks::MASKING_REVIEW, self::good(['verdicts' => ['masked' => 1, 'review' => 12, 'clear' => 0]]))['fix']);
        $this->assertSame('1 column waits for review (masked until decided).',
            self::control('gdpr', Checks::MASKING_REVIEW, self::good(['verdicts' => ['masked' => 1, 'review' => 1, 'clear' => 0]]))['detail']);
    }

    public function testProtectedClassesDependOnTheBaseline(): void
    {
        $state = self::good(['adminCleared' => ['special_category' => 2, 'email' => 5]]);
        $hipaa = self::control('hipaa', Checks::MASKING_CLASSES, $state);
        $this->assertSame('fail', $hipaa['status']);
        $this->assertSame('7 columns detected as Email, Health & special category (score 70 or more) are marked not sensitive.', $hipaa['detail']);
        $this->assertSame('/api-security/data-masking?filter=clear', $hipaa['fix']['route']);
        $this->assertSame('pass', self::control('pci_dss', Checks::MASKING_CLASSES, $state)['status']);
        $soc2 = self::control('soc2', Checks::MASKING_CLASSES, $state);
        $this->assertSame('2 columns detected as Health & special category (score 70 or more) are marked not sensitive.', $soc2['detail']);
    }

    public function testFormats(): void
    {
        $c = self::control('hipaa', Checks::MASKING_FORMAT, self::good(['formats' => ['date_of_birth' => 'token']]));
        $this->assertSame('fail', $c['status']);
        $this->assertSame('Date of birth uses Token (allowed: Year only, Redact, Null).', $c['detail']);
        $this->assertSame('apply', $c['fix']['kind']);
        // Missing row = catalog default (year).
        $this->assertSame('pass', self::control('hipaa', Checks::MASKING_FORMAT, self::good(['formats' => []]))['status']);
        $this->assertSame('pass', self::control('pci_dss', Checks::MASKING_FORMAT, self::good(['formats' => ['card_number' => 'redact']]))['status']);
    }

    public function testGrantExpiry(): void
    {
        $grant = fn (?int $expires) => ['admin_id' => 2, 'name' => 'Priya', 'email' => null, 'expires_at' => $expires];

        $this->assertSame('pass', self::control('hipaa', Checks::ACCESS_GRANT_EXPIRY, self::good(['grants' => [$grant(self::NOW + 8 * 3600)]]))['status']);
        $over = self::control('hipaa', Checks::ACCESS_GRANT_EXPIRY, self::good(['grants' => [$grant(self::NOW + 9 * 3600), $grant(null)]]));
        $this->assertSame('fail', $over['status']);
        $this->assertSame('2 grants last longer than 8 hours (1 with no end date).', $over['detail']);
        $this->assertSame('1 grant lasts longer than 8 hours (no end date).',
            self::control('hipaa', Checks::ACCESS_GRANT_EXPIRY, self::good(['grants' => [$grant(null)]]))['detail']);
        // 9 hours is fine for a 24 hour baseline.
        $this->assertSame('pass', self::control('soc2', Checks::ACCESS_GRANT_EXPIRY, self::good(['grants' => [$grant(self::NOW + 9 * 3600)]]))['status']);
        // Grants only matter in "selected" mode.
        $this->assertSame('pass', self::control('hipaa', Checks::ACCESS_GRANT_EXPIRY, self::good(['adminsMode' => 'none', 'grants' => [$grant(null)]]))['status']);
        $all = self::control('hipaa', Checks::ACCESS_GRANT_EXPIRY, self::good(['adminsMode' => 'all']));
        $this->assertSame('fail', $all['status']);
        $this->assertSame('apply', $all['fix']['kind']);
        $this->assertSame('pass', self::control('hipaa', Checks::ACCESS_GRANT_EXPIRY, self::good(['grants' => []]))['status']);
    }

    public function testAdminsAndAi(): void
    {
        $this->assertSame('fail', self::control('cjis', Checks::ACCESS_ADMINS_ALL, self::good(['adminsMode' => 'all']))['status']);
        $this->assertSame('pass', self::control('cjis', Checks::ACCESS_ADMINS_ALL, self::good(['adminsMode' => 'none']))['status']);
        $ai = self::control('cjis', Checks::ACCESS_AI, self::good(['ai' => 'same_as_admins']));
        $this->assertSame('fail', $ai['status']);
        $this->assertSame('apply', $ai['fix']['kind']);
    }

    public function testRoles(): void
    {
        $roles = [
            ['role_id' => 3, 'name' => 'support', 'enabled' => true, 'scope' => 'all'],
            ['role_id' => 4, 'name' => 'billing', 'enabled' => false, 'scope' => 'all'],
            ['role_id' => 5, 'name' => 'analytics', 'enabled' => true, 'scope' => 'except_restricted'],
        ];
        $c = self::control('pci_dss', Checks::ACCESS_ROLES_RESTRICTED, self::good(['roles' => $roles]));
        $this->assertSame('fail', $c['status']);
        $this->assertSame('1 role sees restricted real values: support.', $c['detail']);
    }

    public function testPlatformChecks(): void
    {
        $p = self::good()->platform;
        $with = fn (array $changes) => self::good(['platform' => array_replace($p, $changes)]);

        $this->assertSame('fail', self::control('pci_dss', Checks::PLATFORM_HTTPS, $with(['app_url_https' => false]))['status']);
        $this->assertSame('pass', self::control('pci_dss', Checks::PLATFORM_HTTPS, $with(['app_url_https' => false, 'request_secure' => true]))['status']);
        $this->assertSame('fail', self::control('pci_dss', Checks::PLATFORM_DEBUG, $with(['debug' => true]))['status']);

        $ttl = self::control('pci_dss', Checks::PLATFORM_SESSION_TTL, $with(['jwt_ttl' => 1440]));
        $this->assertSame('fail', $ttl['status']);
        $this->assertSame('Session tokens last 1440 minutes. Set DF_JWT_TTL to 15 or less.', $ttl['detail']);
        $this->assertSame('fail', self::control('pci_dss', Checks::PLATFORM_SESSION_TTL, $with(['jwt_ttl' => null]))['status']);
        $this->assertSame('fail', self::control('pci_dss', Checks::PLATFORM_SESSION_TTL, $with(['forever_sessions' => true]))['status']);
        $this->assertSame('pass', self::control('hipaa', Checks::PLATFORM_SESSION_TTL, $with(['jwt_ttl' => 60, 'jwt_refresh_ttl' => 60]))['status']);

        $this->assertSame('fail', self::control('soc2', Checks::PLATFORM_CORS, $with(['cors_wildcard' => 2]))['status']);
        $this->assertSame('/system-settings/config/cors', self::control('soc2', Checks::PLATFORM_CORS, $with(['cors_wildcard' => 2]))['fix']['route']);
        $this->assertSame('fail', self::control('soc2', Checks::PLATFORM_CORS, $with(['cors_wildcard' => null]))['status']);

        $this->assertSame('fail', self::control('soc2', Checks::PLATFORM_RATE_LIMIT, $with(['limits_active' => 0]))['status']);
        $this->assertSame('fail', self::control('soc2', Checks::PLATFORM_RATE_LIMIT, $with(['limits_installed' => false, 'limits_active' => null]))['status']);

        $audit = self::control('hipaa', Checks::PLATFORM_AUDIT, $with(['logstash_events' => 0, 'logged_reads' => ['crm' => false]]));
        $this->assertSame('fail', $audit['status']);
        $this->assertStringContainsString('Only service changes', $audit['detail']);
        $this->assertSame('pass', self::control('hipaa', Checks::PLATFORM_AUDIT, $with(['logged_reads' => ['crm' => false], 'mongo_logs' => true]))['status']);
        $this->assertSame('fail', self::control('hipaa', Checks::PLATFORM_AUDIT, $with(['logstash_events' => null, 'logger_installed' => false, 'logged_reads' => ['crm' => false], 'service_reports' => false]))['status']);
        $this->assertSame('fail', self::control('hipaa', Checks::PLATFORM_AUDIT, $with(['logged_reads' => null]))['status'], 'unknown');

        $this->assertSame('fail', self::control('soc2', Checks::PLATFORM_ROOT_ADMIN, $with(['root_admin' => false]))['status']);
    }

    public function testLastScanRule(): void
    {
        $t = self::NOW;
        // A scan of the service, or its columns' scanned_at, whichever is later.
        $this->assertSame($t, State::lastScan($t, $t - 10, 5, null, null));
        $this->assertSame($t, State::lastScan(null, $t, 5, $t + 99, null));
        // Full scans only count for services with no stored columns, and only after creation.
        $this->assertNull(State::lastScan(null, null, 3, $t, $t - 50), 'columns stored but never sampled');
        $this->assertSame($t, State::lastScan(null, null, 0, $t, $t - 50));
        $this->assertNull(State::lastScan(null, null, 0, $t, $t + 50), 'service created after the full scan');
        $this->assertNull(State::lastScan(null, null, 0, null, null));
    }

    public function testScoreExcludesNotApplicable(): void
    {
        $controls = [
            ['status' => 'pass'], ['status' => 'fail'], ['status' => 'manual'], ['status' => 'na'], ['status' => 'pass'],
        ];
        $this->assertSame(['pass' => 2, 'fail' => 1, 'manual' => 1, 'total' => 4], Evaluator::score($controls));
    }

    public function testManualItems(): void
    {
        $c = self::control('pci_dss', 'manual.no_sad', self::fresh());
        $this->assertSame('manual', $c['status']);
        $this->assertSame(['PCI DSS 3.3.1'], $c['refs']);
        $this->assertNotEmpty($c['detail']);
        $this->assertSame(['kind' => 'none', 'route' => null], $c['fix']);
    }

    public function testDetailsNameAtMostThreeThings(): void
    {
        $roles = [];
        foreach (['a', 'b', 'c', 'd', 'e'] as $i => $name) {
            $roles[] = ['role_id' => $i, 'name' => $name, 'enabled' => true, 'scope' => 'all'];
        }
        $c = self::control('hipaa', Checks::ACCESS_ROLES_RESTRICTED, self::good(['roles' => $roles]));
        $this->assertSame('5 roles see restricted real values: a, b, c +2 more.', $c['detail']);
    }

    // ------------------------------------------------------------------------------------------
    // Evaluator edge cases
    // ------------------------------------------------------------------------------------------

    /**
     * With nothing scanned, nothing is classified and nothing is masked, so masking.mode,
     * masking.review and masking.classes must not pass (before: 8/13 HIPAA checks passed with an
     * empty inventory, including "PHI is masked in API responses").
     */
    #[DataProvider('baselineIds')]
    public function testMaskingChecksNeverPassBeforeTheFirstScan(string $id): void
    {
        $never = self::good([
            'verdicts' => ['masked' => 0, 'review' => 0, 'clear' => 0],
            'adminCleared' => [],
            'covered' => [
                ['id' => 1, 'name' => 'crm', 'label' => 'CRM', 'type' => 'pgsql', 'created_at' => self::NOW - 86400, 'last_scan_at' => null],
                ['id' => 2, 'name' => 'hr', 'label' => 'HR', 'type' => 'mysql', 'created_at' => self::NOW - 86400, 'last_scan_at' => null],
            ],
        ]);
        $byId = array_column(Evaluator::controls(BaselineRegistry::get($id), $never), null, 'id');
        foreach ([Checks::MASKING_MODE, Checks::MASKING_REVIEW, Checks::MASKING_CLASSES, Checks::MASKING_SCANNED] as $check) {
            if (!isset($byId[$check])) {
                continue;
            }
            $this->assertSame('fail', $byId[$check]['status'], "$id $check");
            $this->assertSame(['kind' => 'link', 'route' => '/api-security/data-masking'], $byId[$check]['fix'], "$id $check is fixed by a scan");
        }
        $this->assertSame('Masking is on, but no database has been scanned yet.', $byId[Checks::MASKING_MODE]['detail']);
        if (isset($byId[Checks::MASKING_REVIEW])) {
            $this->assertSame('No database has been scanned yet, so no column is classified.', $byId[Checks::MASKING_REVIEW]['detail']);
        }
    }

    public function testModeOnFailsWhileADatabaseWasNeverScanned(): void
    {
        $state = self::good(['covered' => [
            ['id' => 1, 'name' => 'crm', 'label' => 'CRM', 'type' => 'pgsql', 'created_at' => null, 'last_scan_at' => self::NOW - 86400],
            ['id' => 2, 'name' => 'warehouse', 'label' => 'Warehouse', 'type' => 'mysql', 'created_at' => null, 'last_scan_at' => null],
        ]]);
        $mode = self::control('hipaa', Checks::MASKING_MODE, $state);
        $this->assertSame('fail', $mode['status']);
        $this->assertSame('Masking is on, but 1 database has never been scanned: Warehouse.', $mode['detail']);
        $this->assertSame('link', $mode['fix']['kind']);
        // Review and class checks still judge what was scanned.
        $this->assertSame('pass', self::control('hipaa', Checks::MASKING_REVIEW, $state)['status']);
        // Preview stays an Apply fix.
        $this->assertSame('apply', self::control('hipaa', Checks::MASKING_MODE, self::good(['mode' => 'preview']))['fix']['kind']);
    }

    /**
     * A database the last scan could not read is not scanned (before: an unreadable,
     * empty service passed "All databases scanned" after any successful full scan).
     */
    public function testAServiceTheLastScanCouldNotReadFailsTheScanCheck(): void
    {
        $state = self::good(['covered' => [
            ['id' => 1, 'name' => 'crm', 'label' => 'CRM', 'type' => 'pgsql', 'created_at' => null, 'last_scan_at' => self::NOW - 3600, 'scan_error' => null],
            ['id' => 2, 'name' => 'warehouse', 'label' => 'Warehouse', 'type' => 'mysql', 'created_at' => null, 'last_scan_at' => null, 'scan_error' => 'Could not connect (SQLSTATE HY000)'],
            ['id' => 3, 'name' => 'legacy', 'label' => 'Legacy', 'type' => 'sqlite', 'created_at' => null, 'last_scan_at' => self::NOW - 40 * 86400, 'scan_error' => null],
        ]]);
        $c = self::control('hipaa', Checks::MASKING_SCANNED, $state);
        $this->assertSame('fail', $c['status']);
        $this->assertSame("The last scan couldn't read Warehouse. 1 of 3 SQL services not scanned in the last 30 days: Legacy.", $c['detail']);

        // Scanned successfully before, but the latest attempt failed: still a failure.
        $state = self::good(['covered' => [
            ['id' => 2, 'name' => 'warehouse', 'label' => 'Warehouse', 'type' => 'mysql', 'created_at' => null, 'last_scan_at' => self::NOW - 86400, 'scan_error' => 'Login failed (SQLSTATE 28000)'],
        ]]);
        $this->assertSame("The last scan couldn't read Warehouse.", self::control('pci_dss', Checks::MASKING_SCANNED, $state)['detail']);
    }

    /** Databases Data Masking cannot scan make "All databases scanned" a hand check. */
    public function testUncoveredDatabasesAreAHandCheck(): void
    {
        $mongo = [['id' => 9, 'name' => 'mongo', 'label' => 'Mongo', 'type' => 'mongodb']];
        $c = self::control('pci_dss', Checks::MASKING_SCANNED, self::good(['uncovered' => $mongo]));
        $this->assertSame('manual', $c['status']);
        $this->assertSame("The SQL service was scanned in the last 30 days. Data Masking can't scan Mongo: check it by hand.", $c['detail']);
        $this->assertSame(['kind' => 'none', 'route' => null], $c['fix']);

        $only = self::control('gdpr', Checks::MASKING_SCANNED, self::good(['covered' => [], 'uncovered' => $mongo]));
        $this->assertSame('manual', $only['status']);
        $this->assertSame('na', self::control('gdpr', Checks::MASKING_SCANNED, self::good(['covered' => [], 'uncovered' => []]))['status']);
        $this->assertSame('fail', self::control('gdpr', Checks::MASKING_SCANNED, self::good(['uncovered' => null]))['status'], 'unknown');
    }

    /**
     * DreamFactory renews expired tokens without credentials until DF_JWT_REFRESH_TTL
     * after sign-in (default 20160 minutes), so DF_JWT_TTL alone does not end idle sessions
     * (before: jwt_ttl=15 passed PCI DSS 8.2.8).
     */
    public function testSessionCheckBoundsTokenRenewal(): void
    {
        $p = self::good()->platform;
        $with = fn (array $changes) => self::good(['platform' => array_replace($p, $changes)]);

        $c = self::control('pci_dss', Checks::PLATFORM_SESSION_TTL, $with(['jwt_ttl' => 15, 'jwt_refresh_ttl' => 20160]));
        $this->assertSame('fail', $c['status']);
        $this->assertSame('Expired tokens can be renewed without signing in for 20160 minutes. Set DF_JWT_REFRESH_TTL to 15 or less.', $c['detail']);
        $this->assertSame('fail', self::control('cjis', Checks::PLATFORM_SESSION_TTL, $with(['jwt_ttl' => 30, 'jwt_refresh_ttl' => null]))['status']);
        $this->assertSame(
            'Session tokens last 1440 minutes, and expired tokens can be renewed without signing in for 20160 minutes. Set DF_JWT_TTL and DF_JWT_REFRESH_TTL to 30 or less.',
            self::control('cjis', Checks::PLATFORM_SESSION_TTL, $with(['jwt_ttl' => 1440, 'jwt_refresh_ttl' => 20160]))['detail']
        );
        $ok = self::control('cjis', Checks::PLATFORM_SESSION_TTL, $with(['jwt_ttl' => 30, 'jwt_refresh_ttl' => 30]));
        $this->assertSame('pass', $ok['status']);
        $this->assertSame("Tokens last 30 minutes and can't be renewed later than 30 minutes after signing in.", $ok['detail']);
    }

    /**
     * "Access to card data is logged" passes on every baseline only when every covered SQL
     * service's read events are logged; a Logstash service subscribed to one event is not enough.
     */
    #[DataProvider('baselineIds')]
    public function testAuditNeedsReadsOfEveryDatabaseLogged(string $id): void
    {
        $p = self::good()->platform;
        $loginOnly = self::good(['platform' => array_replace($p, ['logstash_events' => 1, 'logged_reads' => ['crm' => false]])]);
        $c = self::control($id, Checks::PLATFORM_AUDIT, $loginOnly);
        $this->assertSame('fail', $c['status']);
        $this->assertSame("Logstash logs no database reads. Subscribe it to each database's events, e.g. crm.*.", $c['detail']);

        $partial = self::good(['platform' => array_replace($p, ['logged_reads' => ['crm' => true, 'hr' => false, 'sports' => false]])]);
        $this->assertSame(
            'Logstash logs reads from 1 of 3 SQL services. Not logged: hr, sports. Subscribe Logstash to hr.*.',
            self::control($id, Checks::PLATFORM_AUDIT, $partial)['detail']
        );
        $this->assertSame('pass', self::control($id, Checks::PLATFORM_AUDIT, self::good())['status']);
    }

    /**
     * The root-admin control states what a missing super admin allows
     * (giving access and lowering the mode), and without df-compliance it fails instead of
     * dropping out of the score.
     */
    public function testRootAdminControl(): void
    {
        $p = self::good()->platform;
        $with = fn (array $changes) => self::good(['platform' => array_replace($p, $changes)]);

        $pass = self::control('hipaa', Checks::PLATFORM_ROOT_ADMIN, self::good());
        $this->assertSame('A super admin is designated: only they can give access to real values or lower the masking mode.', $pass['detail']);
        $none = self::control('hipaa', Checks::PLATFORM_ROOT_ADMIN, $with(['root_admin' => false]));
        $this->assertSame('fail', $none['status']);
        $this->assertStringContainsString('every admin can give access to real values and lower the masking mode', $none['detail']);
        $missing = self::control('iso27001', Checks::PLATFORM_ROOT_ADMIN, $with(['compliance_installed' => false, 'root_admin' => null]));
        $this->assertSame('fail', $missing['status']);
        $this->assertStringContainsString('Install df-compliance', $missing['detail']);
        $this->assertSame('none', $missing['fix']['kind']);
    }

    // ------------------------------------------------------------------------------------------
    // Unreadable state, thresholds and account checks
    // ------------------------------------------------------------------------------------------

    /**
     * UI-V1: server copy says "super admin" and "real values" like the rest of the UI (before:
     * "root admin" and "restricted data in clear").
     */
    #[DataProvider('baselineIds')]
    public function testServerCopySaysSuperAdminAndRealValues(string $id): void
    {
        $p = self::good()->platform;
        $open = [['role_id' => 3, 'name' => 'support', 'enabled' => true, 'scope' => 'all']];
        $states = [
            self::good(),
            self::fresh(),
            self::good(['roles' => $open]),
            self::good(['platform' => array_replace($p, ['root_admin' => false])]),
            self::good(['platform' => array_replace($p, ['compliance_installed' => false, 'root_admin' => null])]),
        ];
        $baseline = BaselineRegistry::get($id);
        foreach ($states as $i => $state) {
            foreach (Evaluator::controls($baseline, $state) as $c) {
                foreach (['title', 'detail'] as $field) {
                    $this->assertDoesNotMatchRegularExpression('/root admin|in (the )?clear/i', (string)$c[$field], "$id state $i {$c['id']} $field");
                }
            }
        }
        $byId = array_column($baseline['controls'], null, 'id');
        if (isset($byId[Checks::ACCESS_ROLES_RESTRICTED]) && $id !== 'pci_dss') {
            $this->assertSame('Roles never see restricted real values', $byId[Checks::ACCESS_ROLES_RESTRICTED]['title']);
        }
        if (isset($byId[Checks::ACCESS_ROLES_RESTRICTED])) {
            $this->assertSame('No role sees restricted real values.', self::control($id, Checks::ACCESS_ROLES_RESTRICTED, self::good())['detail']);
        }
        if (isset($byId[Checks::PLATFORM_ROOT_ADMIN])) {
            $this->assertSame(
                'No super admin: every admin can give access to real values and lower the masking mode. Run php artisan df:root_admin --admin_id=<id>.',
                self::control($id, Checks::PLATFORM_ROOT_ADMIN, $states[3])['detail']
            );
            $this->assertSame(
                'Every admin can give access to real values and lower the masking mode. Install df-compliance and designate a super admin (php artisan df:root_admin --admin_id=<id>).',
                self::control($id, Checks::PLATFORM_ROOT_ADMIN, $states[4])['detail']
            );
        }
    }

    /**
     * UI-V2: masking details name databases by label, as Data Masking does (before: "The last
     * scan couldn't read warehouse." on Compliance, "Couldn't read Warehouse." on Data Masking).
     */
    public function testMaskingDetailsNameDatabasesByLabel(): void
    {
        $state = self::good(['covered' => [
            ['id' => 1, 'name' => 'crm', 'label' => 'CRM', 'type' => 'pgsql', 'created_at' => null, 'last_scan_at' => self::NOW - 3600, 'scan_error' => null],
            ['id' => 2, 'name' => 'wh_prod_02', 'label' => 'Warehouse', 'type' => 'mysql', 'created_at' => null, 'last_scan_at' => null, 'scan_error' => 'Could not connect (SQLSTATE HY000)'],
            ['id' => 3, 'name' => 'legacy_db', 'label' => '', 'type' => 'sqlite', 'created_at' => null, 'last_scan_at' => null, 'scan_error' => null],
        ], 'uncovered' => [['id' => 9, 'name' => 'mongo_events', 'label' => 'Event store', 'type' => 'mongodb']]]);
        $this->assertSame(
            "The last scan couldn't read Warehouse. 1 of 3 SQL services not scanned in the last 30 days: legacy_db.",
            self::control('hipaa', Checks::MASKING_SCANNED, $state)['detail'],
            'a service without a label goes by its name'
        );
        $this->assertSame(
            'Masking is on, but 2 databases have never been scanned: Warehouse, legacy_db.',
            self::control('hipaa', Checks::MASKING_MODE, $state)['detail']
        );
        $handCheck = self::control('pci_dss', Checks::MASKING_SCANNED, self::good(['uncovered' => [['id' => 9, 'name' => 'mongo_events', 'label' => 'Event store', 'type' => 'mongodb']]]));
        $this->assertSame("The SQL service was scanned in the last 30 days. Data Masking can't scan Event store: check it by hand.", $handCheck['detail']);
    }

    /**
     * An unreadable scan history (State marks the services scan_unknown) is "Could not be
     * checked", never "never scanned" and never a pass; checks that do not depend on it are
     * unaffected, and Preview still reports Preview.
     */
    #[DataProvider('baselineIds')]
    public function testUnknownScanHistoryIsCouldNotBeChecked(string $id): void
    {
        $unknown = self::good(['covered' => [
            ['id' => 1, 'name' => 'crm', 'label' => 'CRM', 'type' => 'pgsql', 'created_at' => null, 'last_scan_at' => null, 'scan_error' => null, 'scan_unknown' => true],
        ]]);
        $byId = array_column(Evaluator::controls(BaselineRegistry::get($id), $unknown), null, 'id');
        foreach ([Checks::MASKING_MODE, Checks::MASKING_SCANNED, Checks::MASKING_REVIEW, Checks::MASKING_CLASSES] as $check) {
            if (!isset($byId[$check])) {
                continue;
            }
            $this->assertSame('fail', $byId[$check]['status'], "$id $check");
            $this->assertSame('Could not be checked: see the DreamFactory log.', $byId[$check]['detail'], "$id $check");
            $this->assertSame(['kind' => 'link', 'route' => '/api-security/data-masking'], $byId[$check]['fix'], "$id $check");
        }
        $this->assertSame('pass', $byId[Checks::ACCESS_AI]['status']);
        // A known problem still fails with its own detail and fix.
        if (isset($byId[Checks::MASKING_REVIEW])) {
            $waiting = self::control($id, Checks::MASKING_REVIEW, self::good(['covered' => $unknown->covered, 'verdicts' => ['masked' => 1, 'review' => 5, 'clear' => 0]]));
            $this->assertSame('5 columns wait for review (masked until decided).', $waiting['detail']);
            $this->assertSame(['kind' => 'link', 'route' => '/api-security/data-masking?filter=review'], $waiting['fix']);
        }
        $preview = self::control($id, Checks::MASKING_MODE, self::good(['mode' => 'preview', 'covered' => $unknown->covered]));
        $this->assertSame('Masking is in Preview: values are not masked yet.', $preview['detail']);
        $this->assertSame('apply', $preview['fix']['kind']);
    }

    /** The score threshold is applied in State capture; the detail says which columns count. */
    public function testClassesDetailNamesTheThreshold(): void
    {
        $this->assertSame(
            'No column detected as protected data (score 70 or more) is marked not sensitive.',
            self::control('hipaa', Checks::MASKING_CLASSES, self::good())['detail']
        );
    }

    /** Admins who have not signed in for 90 days. */
    public function testInactiveAdmins(): void
    {
        $this->assertSame('pass', self::control('pci_dss', Checks::ACCESS_INACTIVE_ADMINS, self::good())['status']);
        $admins = [
            ['id' => 1, 'name' => 'Alex Admin', 'last_login_at' => self::NOW - 91 * 86400, 'created_at' => self::NOW - 400 * 86400],
            ['id' => 2, 'name' => 'Priya Shah', 'last_login_at' => null, 'created_at' => self::NOW - 120 * 86400],
            ['id' => 3, 'name' => 'Lee Chen', 'last_login_at' => self::NOW - 89 * 86400, 'created_at' => null],
        ];
        $c = self::control('pci_dss', Checks::ACCESS_INACTIVE_ADMINS, self::good(['admins' => $admins]));
        $this->assertSame('fail', $c['status']);
        $this->assertSame('2 admins have not signed in for 90 days: Alex Admin, Priya Shah. Deactivate the accounts or remove admin rights.', $c['detail']);
        $this->assertSame(['kind' => 'link', 'route' => '/admin-settings/admins'], $c['fix']);
        $this->assertSame('fail', self::control('soc2', Checks::ACCESS_INACTIVE_ADMINS, self::good(['admins' => null]))['status'], 'unknown');
    }

    /** Open registration. */
    public function testOpenRegistration(): void
    {
        $p = self::good()->platform;
        $this->assertSame('pass', self::control('hipaa', Checks::PLATFORM_OPEN_REGISTRATION, self::good())['status']);
        $c = self::control('hipaa', Checks::PLATFORM_OPEN_REGISTRATION, self::good(['platform' => array_replace($p, ['open_registration' => ['user']])]));
        $this->assertSame('fail', $c['status']);
        $this->assertSame('Open registration is on for user: anyone can create an account. Turn it off in the service settings.', $c['detail']);
    }

    /** Masking activity retention. */
    public function testLogRetention(): void
    {
        $p = self::good()->platform;
        $with = fn (int $days) => self::good(['platform' => array_replace($p, ['activity_retention_days' => $days])]);
        $this->assertSame('pass', self::control('pci_dss', Checks::PLATFORM_LOG_RETENTION, $with(400))['status']);
        $this->assertSame('Masking activity is kept forever.', self::control('cjis', Checks::PLATFORM_LOG_RETENTION, $with(0))['detail']);
        $short = self::control('pci_dss', Checks::PLATFORM_LOG_RETENTION, $with(90));
        $this->assertSame('fail', $short['status']);
        $this->assertSame('Masking activity is deleted after 90 days. Set DF_MASKING_ACTIVITY_RETENTION_DAYS to 365 or more (0 keeps it forever).', $short['detail']);
    }

    public function testHttpsPassSaysWhatIsNotChecked(): void
    {
        $this->assertSame(
            'APP_URL uses https (certificates and TLS versions are not checked).',
            self::control('pci_dss', Checks::PLATFORM_HTTPS, self::good())['detail']
        );
    }
}

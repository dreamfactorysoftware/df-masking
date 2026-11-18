<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Baselines;

use DreamFactory\Core\Masking\Baselines\BaselineRegistry;
use DreamFactory\Core\Masking\Baselines\Checks;
use DreamFactory\Core\Masking\Support\Catalog;
use DreamFactory\Core\Masking\Support\RulePattern;
use DreamFactory\Core\Masking\Support\Settings;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The baseline catalog is data: these tests keep it internally consistent and consistent with
 * the class catalog, the check catalog and the framework reference formats.
 */
final class CatalogIntegrityTest extends TestCase
{
    private const EXPECTED = [
        'hipaa' => 'healthcare',
        'pci_dss' => 'payments',
        'glba' => 'banking',
        'cjis' => 'government',
        'gdpr' => 'privacy',
        'soc2' => 'general',
        'iso27001' => 'general',
    ];

    /** Every reference of a baseline must look like a reference of its framework. */
    private const REF_PATTERNS = [
        'hipaa' => '/^45 CFR 164\.(3\d\d|5\d\d)(\([A-Za-z0-9]+\))+$/',
        'pci_dss' => '/^PCI DSS \d{1,2}(\.\d{1,2}){1,3}$/',
        // FTC Safeguards Rule, and the banking agencies' Interagency Guidelines (section III.C).
        'glba' => '/^(16 CFR 314\.4(\([a-z0-9]+\))+|Interagency Guidelines III\.C\.[1-4](\.[a-h])?)$/',
        // CJISSECPOL v6.1 control identifiers (NIST SP 800-53 style); the v5.9 section numbers are gone.
        'cjis' => '/^CJIS (AC|AU|IA|SC|SI|CM)-\d{1,2}(\(\d{1,2}\))?$/',
        'gdpr' => '/^GDPR Art\. \d{1,2}(\(\d\))?(\([a-z]\))?$/',
        'soc2' => '/^SOC 2 (CC[1-9]\.[1-9]|C1\.[12]|A1\.[1-3]|PI1\.[1-5]|P[1-8]\.[1-9])$/',
        'iso27001' => '/^ISO 27001 A\.(5\.([1-9]|[1-3][0-9])|6\.[1-8]|7\.([1-9]|1[0-4])|8\.([1-9]|[12][0-9]|3[0-4]))$/',
    ];

    public function testExactlyTheContractBaselinesInDisplayOrder(): void
    {
        $this->assertSame(array_keys(self::EXPECTED), BaselineRegistry::ids());
        foreach (self::EXPECTED as $id => $vertical) {
            $this->assertSame($vertical, BaselineRegistry::get($id)['vertical'], $id);
        }
        $this->assertNull(BaselineRegistry::get('nope'));
        $this->assertCount(7, BaselineRegistry::all());
    }

    public static function baselines(): array
    {
        $out = [];
        foreach (BaselineRegistry::all() as $baseline) {
            $out[$baseline['id']] = [$baseline];
        }

        return $out;
    }

    #[DataProvider('baselines')]
    public function testShape(array $b): void
    {
        foreach (['id', 'name', 'vertical', 'summary'] as $key) {
            $this->assertIsString($b[$key]);
            $this->assertNotSame('', trim($b[$key]), "$key of {$b['id']}");
        }
        $this->assertNotEmpty($b['frameworks']);
        foreach ($b['frameworks'] as $framework) {
            $this->assertIsString($framework);
            $this->assertNotSame('', $framework);
        }
        $this->assertLessThanOrEqual(40, strlen($b['id']), 'dm_baseline.baseline_id is varchar(40)');
        $this->assertDoesNotMatchRegularExpression('/certif|compliant/i', $b['summary'], 'never claim certification');
    }

    #[DataProvider('baselines')]
    public function testControls(array $b): void
    {
        $ids = array_column($b['controls'], 'id');
        $this->assertSame(array_unique($ids), $ids, "duplicate control ids in {$b['id']}");
        $manual = 0;
        foreach ($b['controls'] as $control) {
            $id = $control['id'];
            $this->assertIsString($control['title']);
            $this->assertNotSame('', trim($control['title']), "$id title");
            $this->assertLessThanOrEqual(72, mb_strlen($control['title']), "$id title is short");
            $this->assertDoesNotMatchRegularExpression('/\bcompliant\b|certif/i', $control['title']);
            $this->assertNotEmpty($control['refs'], "{$b['id']} $id has refs");
            $this->assertSame(array_unique($control['refs']), $control['refs'], "{$b['id']} $id refs unique");
            foreach ($control['refs'] as $ref) {
                $this->assertMatchesRegularExpression(self::REF_PATTERNS[$b['id']], $ref, "{$b['id']} $id ref '$ref'");
            }
            if (Checks::isManual($id)) {
                $manual++;
                $this->assertMatchesRegularExpression('/^manual\.[a-z_]+$/', $id);
                $this->assertArrayNotHasKey('params', $control);
                continue;
            }
            $this->assertTrue(Checks::exists($id), "{$b['id']} uses unknown check '$id'");
            foreach (Checks::requiredParams($id) as $param) {
                $this->assertArrayHasKey($param, $control['params'] ?? [], "{$b['id']} $id needs param $param");
            }
        }
        $this->assertGreaterThanOrEqual(1, $manual, "{$b['id']} has manual items");
        $this->assertLessThanOrEqual(4, $manual, "{$b['id']} has at most 4 manual items");
    }

    #[DataProvider('baselines')]
    public function testParamsAreValid(array $b): void
    {
        foreach ($b['controls'] as $control) {
            $params = $control['params'] ?? [];
            switch ($control['id']) {
                case Checks::MASKING_MODE:
                    $this->assertContains($params['min'], ['preview', 'on']);
                    break;
                case Checks::MASKING_SCANNED:
                    $this->assertIsInt($params['days']);
                    $this->assertGreaterThan(0, $params['days']);
                    $this->assertStringContainsString((string)$params['days'] . ' days', $control['title']);
                    break;
                case Checks::PLATFORM_SESSION_TTL:
                    $this->assertIsInt($params['max_minutes']);
                    $this->assertGreaterThan(0, $params['max_minutes']);
                    // The check also bounds token renewal: the title is about idle sessions, not token lifetime.
                    $this->assertSame('Idle sessions require signing in again after ' . $params['max_minutes'] . ' minutes', $control['title']);
                    break;
                case Checks::ACCESS_INACTIVE_ADMINS:
                    $this->assertIsInt($params['days']);
                    $this->assertGreaterThan(0, $params['days']);
                    $this->assertStringContainsString($params['days'] . ' days', $control['title']);
                    break;
                case Checks::PLATFORM_LOG_RETENTION:
                    $this->assertIsInt($params['min_days']);
                    $this->assertGreaterThanOrEqual(365, $params['min_days'], 'the title says at least a year');
                    $this->assertStringContainsString('at least a year', $control['title']);
                    break;
            }
        }
    }

    #[DataProvider('baselines')]
    public function testApplySettingsMatchControls(array $b): void
    {
        $apply = $b['apply'];
        $checks = array_column($b['controls'], 'id');

        $this->assertSame('masked', $apply['ai'], 'every baseline masks AI sessions');
        $this->assertContains(Checks::ACCESS_AI, $checks);

        $this->assertContains($apply['admins_mode_max'], Settings::ADMINS_MODES);
        $this->assertNotSame('all', $apply['admins_mode_max']);
        $this->assertContains(Checks::ACCESS_ADMINS_ALL, $checks);

        $this->assertIsInt($apply['grant_max_hours']);
        $this->assertContains($apply['grant_max_hours'], [1, 8, 24], 'a duration the Access tab offers');
        $this->assertContains(Checks::ACCESS_GRANT_EXPIRY, $checks);
        foreach ($b['controls'] as $control) {
            if ($control['id'] === Checks::ACCESS_GRANT_EXPIRY) {
                $this->assertStringContainsString($apply['grant_max_hours'] . ' hour', $control['title']);
            }
        }

        $this->assertContains($apply['role_scope'], [null, 'except_restricted']);
        $this->assertSame(
            $apply['role_scope'] === 'except_restricted',
            in_array(Checks::ACCESS_ROLES_RESTRICTED, $checks, true),
            'roles control present exactly when Apply narrows role scopes'
        );

        $this->assertSame(
            !empty($apply['formats']),
            in_array(Checks::MASKING_FORMAT, $checks, true),
            'format control present exactly when there are format requirements'
        );

        if (in_array(Checks::MASKING_CLASSES, $checks, true)) {
            $this->assertNotEmpty($b['protected_classes']);
        }
        foreach ($b['protected_classes'] as $class) {
            $this->assertTrue(Catalog::has($class), "{$b['id']} protects unknown class '$class'");
        }
        $this->assertSame(array_unique($b['protected_classes']), $b['protected_classes']);
    }

    #[DataProvider('baselines')]
    public function testFormatRequirements(array $b): void
    {
        $this->assertIsArray($b['apply']['formats']);
        foreach ($b['apply']['formats'] as $rule) {
            $this->assertTrue(Catalog::has($rule['class']), "unknown class {$rule['class']}");
            $this->assertNotEmpty($rule['allowed']);
            foreach ($rule['allowed'] as $format) {
                $this->assertContains($format, Catalog::formatsAllowed($rule['class']), "{$rule['class']} cannot use $format");
            }
            $this->assertContains($rule['target'], $rule['allowed']);
            if (Catalog::tierOf($rule['class']) === 'restricted') {
                $this->assertNotContains('token', $rule['allowed'], 'restricted classes never use token');
            }
        }
    }

    #[DataProvider('baselines')]
    public function testDetectionRules(array $b): void
    {
        $patterns = [];
        foreach ($b['apply']['rules'] as $rule) {
            $this->assertSame('name', $rule['match']);
            $this->assertTrue(Catalog::has($rule['class']), "unknown class {$rule['class']}");
            $this->assertNotSame('', trim($rule['title']));
            $this->assertLessThanOrEqual(500, strlen($rule['pattern']), 'dm_rule.pattern is varchar(500)');
            foreach (['/', '~', '#', '%', '@', '!', '{', '}'] as $delimiter) {
                $this->assertStringNotContainsString($delimiter, $rule['pattern'], 'pattern works with any delimiter');
            }
            $this->assertNotFalse(@preg_match('/' . $rule['pattern'] . '/i', ''), "pattern compiles: {$rule['pattern']}");
            if (class_exists(RulePattern::class)) {
                $this->assertNull(RulePattern::validate($rule['pattern']), "the rule API accepts {$rule['pattern']}");
            }
            $this->assertStringStartsWith('^', $rule['pattern'], 'anchored');
            $this->assertStringEndsWith('$', $rule['pattern'], 'anchored');
            $patterns[] = $rule['pattern'];
        }
        $this->assertSame(array_unique($patterns), $patterns);
    }

    /** Positive and negative column names for every vertical detection rule. */
    public static function ruleExamples(): array
    {
        return [
            'hipaa medical record numbers' => ['hipaa', 0, ['mrn', 'MRN', 'medical_record_number', 'medicalRecordNo', 'med_rec_num', 'patient_number', 'PatientNo', 'chart_number'], ['patient_id', 'patient_name', 'mrn_type', 'record_number', 'chart_type']],
            'hipaa health plan numbers' => ['hipaa', 1, ['health_plan_id', 'health_plan_beneficiary_number', 'beneficiary_number', 'insurance_member_id', 'medicare_number', 'medicaidId', 'mbi', 'HICN'], ['plan_id', 'beneficiary_id', 'insurance_id', 'member_id', 'medicare']],
            'pci card numbers' => ['pci_dss', 0, ['pan', 'cc_num', 'ccnum', 'card_no', 'cardnum', 'primary_acct_number'], ['company', 'card_type', 'pan_size', 'panel']],
            'pci security data' => ['pci_dss', 1, ['cvv2', 'card_cvc', 'track1', 'track_2_data', 'track_data', 'magstripe', 'pin_block'], ['track_id', 'pin', 'tracking_number', 'cvv_result']],
            'pci expiry' => ['pci_dss', 2, ['card_exp', 'cc_expiry', 'card_expiration_date', 'exp_mm', 'exp_yyyy', 'card_exp_month'], ['expiry_date', 'expiration_date', 'exp', 'export_date']],
            'pci cardholder' => ['pci_dss', 3, ['cardholder', 'card_holder_name', 'name_on_card', 'cc_name'], ['holder', 'card_name', 'name']],
            'glba accounts' => ['glba', 0, ['account_number', 'acct_no', 'accountNumber', 'checking_account_number', 'loan_number', 'dda_acct_num'], ['account_id', 'account_type', 'routing_number', 'swift_code', 'acct']],
            'glba financial' => ['glba', 1, ['balance', 'account_balance', 'available_balance', 'credit_score', 'fico', 'loan_amount', 'annual_income', 'net_worth', 'debt_to_income_ratio'], ['balance_date', 'leave_balance', 'credit_card_type', 'income_source', 'amount']],
            'cjis identifiers' => ['cjis', 0, ['fbi_number', 'state_id_number', 'booking_no', 'arrest_number', 'inmate_num', 'warrant_number', 'ucn'], ['booking_id', 'state_id', 'sid', 'inmate_id', 'offender_id', 'fbi_field_office']],
            'cjis case numbers' => ['cjis', 1, ['case_number', 'incident_no', 'citation_num', 'offense_number'], ['case_id', 'case_type', 'incident_date', 'report_number']],
            'cjis history' => ['cjis', 2, ['rap_sheet', 'criminal_charges', 'offenses', 'offence', 'prior_arrests', 'arrest_history'], ['charges', 'charge_amount', 'disposition', 'offense_code']],
            'cjis biometrics' => ['cjis', 3, ['fingerprints', 'fingerprint_image', 'palm_print', 'mugshot', 'dna_profile'], ['fingerprint', 'device_fingerprint', 'key_fingerprint', 'mug']],
        ];
    }

    #[DataProvider('ruleExamples')]
    public function testRuleExamples(string $baselineId, int $index, array $positive, array $negative): void
    {
        $pattern = BaselineRegistry::get($baselineId)['apply']['rules'][$index]['pattern'];
        foreach ($positive as $name) {
            $this->assertSame(1, preg_match('/' . $pattern . '/i', $name), "$baselineId rule $index should match '$name'");
        }
        foreach ($negative as $name) {
            $this->assertSame(0, preg_match('/' . $pattern . '/i', $name), "$baselineId rule $index should not match '$name'");
        }
    }

    public function testEveryRuleHasExamples(): void
    {
        $covered = [];
        foreach (self::ruleExamples() as [$id, $index]) {
            $covered[$id . ':' . $index] = true;
        }
        foreach (BaselineRegistry::all() as $b) {
            foreach (array_keys($b['apply']['rules']) as $i) {
                $this->assertArrayHasKey($b['id'] . ':' . $i, $covered, "add examples for {$b['id']} rule $i");
            }
        }
    }

    public function testEveryCheckIsUsed(): void
    {
        $used = [];
        foreach (BaselineRegistry::all() as $b) {
            foreach ($b['controls'] as $control) {
                $used[$control['id']] = true;
            }
        }
        foreach (Checks::ids() as $check) {
            $this->assertArrayHasKey($check, $used, "check $check is used by at least one baseline");
        }
    }

    /** Strictest-wins only works if adopted baselines can always agree on a format. */
    public function testFormatRequirementsNeverConflict(): void
    {
        $byClass = [];
        foreach (BaselineRegistry::all() as $b) {
            foreach ($b['apply']['formats'] as $rule) {
                $byClass[$rule['class']][] = $rule['allowed'];
            }
        }
        foreach ($byClass as $class => $lists) {
            $common = array_shift($lists);
            foreach ($lists as $list) {
                $common = array_intersect($common, $list);
            }
            $this->assertNotEmpty($common, "baselines disagree on every format for $class");
        }
    }

    /**
     * Titles must be exactly as true as the pass condition: the audit check looks at
     * reads of covered SQL services, and "all databases" is only claimed by a check that turns
     * into a hand check when there are databases Data Masking cannot scan.
     */
    #[DataProvider('baselines')]
    public function testTitlesMatchWhatTheChecksVerify(array $b): void
    {
        foreach ($b['controls'] as $control) {
            switch ($control['id']) {
                case Checks::PLATFORM_AUDIT:
                    $this->assertSame('Reads from every SQL database are logged', $control['title']);
                    break;
                case Checks::MASKING_SCANNED:
                    $this->assertSame('All databases scanned in the last ' . $control['params']['days'] . ' days', $control['title']);
                    break;
                case Checks::PLATFORM_OPEN_REGISTRATION:
                    $this->assertSame('Open user registration is off', $control['title']);
                    break;
            }
        }
    }

    /** One CJIS policy version, named, with its real control identifiers. */
    public function testCjisCitesTheCurrentPolicyVersion(): void
    {
        $cjis = BaselineRegistry::get('cjis');
        $this->assertSame(['FBI CJIS Security Policy v6.1'], $cjis['frameworks']);
        $refs = array_merge(...array_column($cjis['controls'], 'refs'));
        foreach (['CJIS AC-3', 'CJIS AC-6', 'CJIS AC-11', 'CJIS AU-11', 'CJIS SC-8', 'CJIS SC-28', 'CJIS IA-2(1)'] as $ref) {
            $this->assertContains($ref, $refs);
        }
        foreach ($refs as $ref) {
            $this->assertDoesNotMatchRegularExpression('/^CJIS 5\./', $ref, 'v5.9 section numbers no longer exist');
        }
        $ids = array_column($cjis['controls'], 'id');
        $this->assertContains('manual.mfa', $ids);
        $this->assertNotContains('manual.advanced_auth', $ids);
    }

    /** The banking baseline cites the rules that govern banks, not only the FTC rule. */
    public function testGlbaCitesTheBankingAgenciesGuidelines(): void
    {
        $glba = BaselineRegistry::get('glba');
        $this->assertCount(2, $glba['frameworks']);
        $this->assertStringContainsString('16 CFR 314', $glba['frameworks'][0]);
        $this->assertStringContainsString('Interagency Guidelines Establishing Information Security Standards', $glba['frameworks'][1]);
        foreach (['12 CFR 30 App. B', '12 CFR 208 App. D-2', '12 CFR 364 App. B', '12 CFR 748 App. A'] as $rule) {
            $this->assertStringContainsString($rule, $glba['frameworks'][1]);
        }
        $byId = array_column($glba['controls'], null, 'id');
        $this->assertContains('Interagency Guidelines III.C.1.a', $byId[Checks::MASKING_MODE]['refs']);
        $this->assertContains('Interagency Guidelines III.C.1.c', $byId[Checks::PLATFORM_HTTPS]['refs']);
        $this->assertContains('Interagency Guidelines III.C.1.f', $byId[Checks::PLATFORM_AUDIT]['refs']);
        $this->assertContains('Interagency Guidelines III.C.1.e', $byId[Checks::PLATFORM_ROOT_ADMIN]['refs']);
        $this->assertArrayHasKey('manual.access_review', $byId);
    }

    /** The HIPAA identifier checks cover every catalog class the Safe Harbor list covers. */
    public function testHipaaGuardsEverySafeHarborClass(): void
    {
        $hipaa = BaselineRegistry::get('hipaa');
        foreach (['age', 'tax_id', 'free_text_pii', 'username', 'date_of_birth', 'national_id'] as $class) {
            $this->assertContains($class, $hipaa['protected_classes']);
        }
        $formats = array_column($hipaa['apply']['formats'], null, 'class');
        $this->assertSame(['redact', 'null'], $formats['age']['allowed']);
        $byId = array_column($hipaa['controls'], null, 'id');
        $this->assertSame('Dates of birth show the year at most, and ages are hidden', $byId[Checks::MASKING_FORMAT]['title']);
        $this->assertSame(['45 CFR 164.514(b)(2)(i)(C)'], $byId['manual.safe_harbor_dates']['refs']);
        $this->assertSame(['45 CFR 164.312(b)'], $byId[Checks::PLATFORM_AUDIT]['refs']);
    }

    /** GDPR guards direct identifiers too, and cites Art. 87 (not Art. 9) for ID numbers. */
    public function testGdprGuardsIdentifiers(): void
    {
        $gdpr = BaselineRegistry::get('gdpr');
        foreach (['email', 'phone', 'person_name', 'street_address', 'date_of_birth', 'ip_address', 'geo_precise', 'username', 'national_id'] as $class) {
            $this->assertContains($class, $gdpr['protected_classes']);
        }
        $byId = array_column($gdpr['controls'], null, 'id');
        $this->assertContains('GDPR Art. 87', $byId[Checks::MASKING_CLASSES]['refs']);
        $this->assertSame(['GDPR Art. 30(1)(c)'], $byId[Checks::MASKING_SCANNED]['refs']);
        $this->assertStringContainsString('purposes', $byId['manual.ropa']['detail']);
    }

    public function testCheckCatalogFixes(): void
    {
        foreach (Checks::ids() as $id) {
            $fix = Checks::fix($id);
            $this->assertContains($fix['kind'], ['apply', 'link', 'none']);
            if ($fix['kind'] === 'link') {
                $this->assertIsString($fix['route']);
                $this->assertStringStartsWith('/', $fix['route']);
            } else {
                $this->assertNull($fix['route']);
            }
        }
    }
}

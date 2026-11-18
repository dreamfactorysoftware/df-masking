<?php

namespace DreamFactory\Core\Masking\Baselines\Definitions;

use DreamFactory\Core\Masking\Baselines\Checks;

/**
 * HIPAA baseline (US healthcare): Security Rule technical safeguards (45 CFR 164.312), the
 * administrative safeguards DreamFactory settings support (164.308), and the Privacy Rule's
 * minimum necessary standard (164.502(b), 164.514(d)) and Safe Harbor identifiers (164.514(b)).
 */
final class Hipaa
{
    public static function definition(): array
    {
        return [
            'id' => 'hipaa',
            'name' => 'HIPAA',
            'vertical' => 'healthcare',
            'frameworks' => ['HIPAA Security Rule', 'HIPAA Privacy Rule'],
            'summary' => 'US healthcare: keep protected health information (PHI) to the minimum necessary in API responses.',
            // Catalog classes the Safe Harbor identifier list (164.514(b)(2)(i)(A)-(R)) covers.
            'protected_classes' => [
                'person_name', 'street_address', 'postal_code', 'geo_precise', 'date_of_birth', 'age', 'phone', 'email',
                'national_id', 'tax_id', 'special_category', 'bank_account', 'card_number', 'drivers_license',
                'passport_number', 'ip_address', 'username', 'free_text_pii',
            ],
            'controls' => [
                [
                    'id' => Checks::MASKING_MODE,
                    'title' => 'PHI is masked in API responses',
                    'refs' => ['45 CFR 164.502(b)', '45 CFR 164.514(d)'],
                    'params' => ['min' => 'on'],
                ],
                [
                    'id' => Checks::MASKING_SCANNED,
                    'title' => 'All databases scanned in the last 30 days',
                    'refs' => ['45 CFR 164.308(a)(1)(ii)(A)'],
                    'params' => ['days' => 30],
                ],
                [
                    'id' => Checks::MASKING_REVIEW,
                    'title' => 'No columns waiting for review',
                    'refs' => ['45 CFR 164.308(a)(1)(ii)(B)'],
                ],
                [
                    'id' => Checks::MASKING_CLASSES,
                    'title' => 'No PHI identifiers marked not sensitive',
                    'refs' => ['45 CFR 164.514(b)(2)(i)'],
                ],
                [
                    'id' => Checks::MASKING_FORMAT,
                    'title' => 'Dates of birth show the year at most, and ages are hidden',
                    'refs' => ['45 CFR 164.514(b)(2)(i)(C)'],
                ],
                [
                    'id' => Checks::ACCESS_AI,
                    'title' => 'AI and MCP sessions get masked values',
                    'refs' => ['45 CFR 164.502(b)', '45 CFR 164.312(a)(1)'],
                ],
                [
                    'id' => Checks::ACCESS_ADMINS_ALL,
                    'title' => 'Admins need a grant to see real values',
                    'refs' => ['45 CFR 164.502(b)', '45 CFR 164.312(a)(1)'],
                ],
                [
                    'id' => Checks::ACCESS_GRANT_EXPIRY,
                    'title' => 'Admin grants expire within 8 hours',
                    'refs' => ['45 CFR 164.308(a)(4)(ii)(B)', '45 CFR 164.312(a)(1)'],
                ],
                [
                    'id' => Checks::ACCESS_ROLES_RESTRICTED,
                    'title' => 'Roles never see restricted real values',
                    'refs' => ['45 CFR 164.502(b)', '45 CFR 164.514(d)'],
                ],
                [
                    'id' => Checks::PLATFORM_HTTPS,
                    'title' => 'API served over HTTPS',
                    'refs' => ['45 CFR 164.312(e)(1)', '45 CFR 164.312(e)(2)(ii)'],
                ],
                [
                    'id' => Checks::PLATFORM_SESSION_TTL,
                    'title' => 'Idle sessions require signing in again after 60 minutes',
                    'refs' => ['45 CFR 164.312(a)(2)(iii)'],
                    'params' => ['max_minutes' => 60],
                ],
                [
                    'id' => Checks::PLATFORM_AUDIT,
                    'title' => 'Reads from every SQL database are logged',
                    'refs' => ['45 CFR 164.312(b)'],
                ],
                [
                    'id' => Checks::PLATFORM_ROOT_ADMIN,
                    'title' => 'A super admin approves real-value access',
                    'refs' => ['45 CFR 164.308(a)(4)(ii)(B)'],
                ],
                [
                    'id' => Checks::PLATFORM_OPEN_REGISTRATION,
                    'title' => 'Open user registration is off',
                    'refs' => ['45 CFR 164.308(a)(4)(ii)(B)', '45 CFR 164.312(a)(1)'],
                ],
                [
                    'id' => 'manual.encryption_at_rest',
                    'title' => 'Encryption at rest on your databases',
                    'refs' => ['45 CFR 164.312(a)(2)(iv)'],
                    'detail' => 'Check outside DreamFactory: database or disk encryption on every database that holds PHI.',
                ],
                [
                    'id' => 'manual.baa',
                    'title' => 'Business associate agreements in place',
                    'refs' => ['45 CFR 164.308(b)(1)', '45 CFR 164.308(b)(3)'],
                    'detail' => 'Signed agreements with every vendor that creates, receives, maintains or transmits PHI for you.',
                ],
                [
                    'id' => 'manual.emergency_access',
                    'title' => 'Emergency access procedure documented',
                    'refs' => ['45 CFR 164.312(a)(2)(ii)'],
                    'detail' => 'Who may grant real-value access in an emergency, and how it is recorded.',
                ],
                [
                    'id' => 'manual.safe_harbor_dates',
                    'title' => 'Ages over 89 and admission, discharge and death dates',
                    'refs' => ['45 CFR 164.514(b)(2)(i)(C)'],
                    'detail' => 'Safe Harbor also removes the birth year for people over 89, and every date tied to a patient.',
                ],
            ],
            'apply' => [
                'ai' => 'masked',
                'admins_mode_max' => 'selected',
                'grant_max_hours' => 8,
                'role_scope' => 'except_restricted',
                'formats' => [
                    ['class' => 'date_of_birth', 'allowed' => ['year', 'redact', 'null'], 'target' => 'year'],
                    ['class' => 'age', 'allowed' => ['redact', 'null'], 'target' => 'redact'],
                ],
                'rules' => [
                    [
                        'match' => 'name',
                        'pattern' => '^(?:mrn|medical_?rec(?:ord)?_?(?:id|no|num|nbr|number)|med_?rec_?(?:no|num|nbr|number)|patient_?(?:no|num|nbr|number|mrn)|chart_?(?:no|num|nbr|number))$',
                        'class' => 'special_category',
                        'title' => 'Medical record, patient and chart numbers',
                    ],
                    [
                        'match' => 'name',
                        'pattern' => '^(?:health_?plan_?(?:beneficiary_?)?(?:id|no|num|nbr|number)|beneficiary_?(?:no|num|nbr|number)|insurance_?member_?(?:id|no|num|nbr|number)|(?:medicare|medicaid)_?(?:id|no|num|nbr|number)|mbi|hicn)$',
                        'class' => 'special_category',
                        'title' => 'Health plan beneficiary and Medicare/Medicaid numbers',
                    ],
                ],
            ],
        ];
    }
}

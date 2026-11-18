<?php

namespace DreamFactory\Core\Masking\Baselines\Definitions;

use DreamFactory\Core\Masking\Baselines\Checks;

/**
 * GDPR baseline (privacy): data minimisation and data protection by design and by default
 * (Art. 5, 25), special categories (Art. 9), national identification numbers (Art. 87),
 * security of processing (Art. 32) and accountability (Art. 5(2), 30).
 */
final class Gdpr
{
    public static function definition(): array
    {
        return [
            'id' => 'gdpr',
            'name' => 'GDPR',
            'vertical' => 'privacy',
            'frameworks' => ['EU GDPR (Regulation (EU) 2016/679)'],
            'summary' => 'Privacy: personal data minimised and protected by default in API responses.',
            // Direct identifiers (the identity tier), ID numbers, financial account numbers and
            // special-category data.
            'protected_classes' => [
                'person_name', 'email', 'phone', 'street_address', 'date_of_birth', 'ip_address', 'username',
                'geo_precise', 'special_category', 'national_id', 'passport_number', 'drivers_license', 'tax_id',
                'bank_account', 'card_number',
            ],
            'controls' => [
                [
                    'id' => Checks::MASKING_MODE,
                    'title' => 'Personal data is masked in API responses',
                    'refs' => ['GDPR Art. 5(1)(c)', 'GDPR Art. 25(1)'],
                    'params' => ['min' => 'on'],
                ],
                [
                    'id' => Checks::MASKING_SCANNED,
                    'title' => 'All databases scanned in the last 30 days',
                    'refs' => ['GDPR Art. 30(1)(c)'],
                    'params' => ['days' => 30],
                ],
                [
                    'id' => Checks::MASKING_REVIEW,
                    'title' => 'No columns waiting for review',
                    'refs' => ['GDPR Art. 25(1)'],
                ],
                [
                    'id' => Checks::MASKING_CLASSES,
                    'title' => 'No identifiers or special-category data marked not sensitive',
                    'refs' => ['GDPR Art. 25(1)', 'GDPR Art. 9(1)', 'GDPR Art. 87'],
                ],
                [
                    'id' => Checks::ACCESS_AI,
                    'title' => 'AI and MCP sessions get masked values',
                    'refs' => ['GDPR Art. 25(2)'],
                ],
                [
                    'id' => Checks::ACCESS_ADMINS_ALL,
                    'title' => 'Admins need a grant to see real values',
                    'refs' => ['GDPR Art. 25(2)'],
                ],
                [
                    'id' => Checks::ACCESS_GRANT_EXPIRY,
                    'title' => 'Admin grants expire within 24 hours',
                    'refs' => ['GDPR Art. 25(2)'],
                ],
                [
                    'id' => Checks::ACCESS_ROLES_RESTRICTED,
                    'title' => 'Roles never see restricted real values',
                    'refs' => ['GDPR Art. 25(2)', 'GDPR Art. 32(1)(b)'],
                ],
                [
                    'id' => Checks::PLATFORM_HTTPS,
                    'title' => 'API served over HTTPS',
                    'refs' => ['GDPR Art. 32(1)(a)'],
                ],
                [
                    'id' => Checks::PLATFORM_AUDIT,
                    'title' => 'Reads from every SQL database are logged',
                    'refs' => ['GDPR Art. 5(2)'],
                ],
                [
                    'id' => Checks::PLATFORM_OPEN_REGISTRATION,
                    'title' => 'Open user registration is off',
                    'refs' => ['GDPR Art. 25(2)'],
                ],
                [
                    'id' => 'manual.encryption_at_rest',
                    'title' => 'Encryption at rest on your databases',
                    'refs' => ['GDPR Art. 32(1)(a)'],
                    'detail' => 'Check outside DreamFactory: database or disk encryption on every database with personal data.',
                ],
                [
                    'id' => 'manual.ropa',
                    'title' => 'Records of processing activities kept',
                    'refs' => ['GDPR Art. 30(1)'],
                    'detail' => 'The masking inventory can feed the categories of personal data (Art. 30(1)(c)); the record also '
                        . 'needs purposes, data subjects, recipients, transfers, erasure time limits and security measures.',
                ],
                [
                    'id' => 'manual.dpia',
                    'title' => 'Impact assessment for high-risk processing',
                    'refs' => ['GDPR Art. 35(1)'],
                    'detail' => 'Needed before processing that is likely to result in a high risk to people, e.g. large-scale special-category data.',
                ],
            ],
            'apply' => [
                'ai' => 'masked',
                'admins_mode_max' => 'selected',
                'grant_max_hours' => 24,
                'role_scope' => 'except_restricted',
                'formats' => [],
                'rules' => [],
            ],
        ];
    }
}

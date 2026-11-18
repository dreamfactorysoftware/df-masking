<?php

namespace DreamFactory\Core\Masking\Baselines\Definitions;

use DreamFactory\Core\Masking\Baselines\Checks;

/**
 * SOC 2 baseline (general), mapped to the AICPA 2017 Trust Services Criteria (With Revised Points
 * of Focus, 2022): logical access (CC6), system operations (CC7) and confidentiality (C1). C1.1
 * applies when Confidentiality is in the report's scope, so the data checks also cite CC6.1.
 */
final class Soc2
{
    public static function definition(): array
    {
        return [
            'id' => 'soc2',
            'name' => 'SOC 2',
            'vertical' => 'general',
            'frameworks' => ['AICPA 2017 Trust Services Criteria (With Revised Points of Focus, 2022)'],
            'summary' => 'Any industry: confidential data identified, masked and accessed on a least-privilege basis.',
            'protected_classes' => [
                'national_id', 'tax_id', 'passport_number', 'drivers_license', 'card_number', 'card_security',
                'bank_account', 'credential', 'special_category',
            ],
            'controls' => [
                [
                    'id' => Checks::MASKING_MODE,
                    'title' => 'Confidential data is masked in API responses',
                    'refs' => ['SOC 2 C1.1', 'SOC 2 CC6.1'],
                    'params' => ['min' => 'on'],
                ],
                [
                    'id' => Checks::MASKING_SCANNED,
                    'title' => 'All databases scanned in the last 30 days',
                    'refs' => ['SOC 2 C1.1', 'SOC 2 CC6.1'],
                    'params' => ['days' => 30],
                ],
                [
                    'id' => Checks::MASKING_REVIEW,
                    'title' => 'No columns waiting for review',
                    'refs' => ['SOC 2 C1.1'],
                ],
                [
                    'id' => Checks::MASKING_CLASSES,
                    'title' => 'No restricted columns marked not sensitive',
                    'refs' => ['SOC 2 C1.1', 'SOC 2 CC6.1'],
                ],
                [
                    'id' => Checks::ACCESS_AI,
                    'title' => 'AI and MCP sessions get masked values',
                    'refs' => ['SOC 2 CC6.3'],
                ],
                [
                    'id' => Checks::ACCESS_ADMINS_ALL,
                    'title' => 'Admins need a grant to see real values',
                    'refs' => ['SOC 2 CC6.3'],
                ],
                [
                    'id' => Checks::ACCESS_GRANT_EXPIRY,
                    'title' => 'Admin grants expire within 24 hours',
                    'refs' => ['SOC 2 CC6.3'],
                ],
                [
                    'id' => Checks::ACCESS_INACTIVE_ADMINS,
                    'title' => 'Admins unused for 90 days are disabled',
                    'refs' => ['SOC 2 CC6.2'],
                    'params' => ['days' => 90],
                ],
                [
                    'id' => Checks::PLATFORM_HTTPS,
                    'title' => 'API served over HTTPS',
                    'refs' => ['SOC 2 CC6.7'],
                ],
                [
                    'id' => Checks::PLATFORM_CORS,
                    'title' => 'No CORS rule allows every origin',
                    'refs' => ['SOC 2 CC6.6'],
                ],
                [
                    'id' => Checks::PLATFORM_DEBUG,
                    'title' => 'Debug mode is off',
                    'refs' => ['SOC 2 CC7.1'],
                ],
                [
                    'id' => Checks::PLATFORM_RATE_LIMIT,
                    'title' => 'API rate limits are active',
                    'refs' => ['SOC 2 CC6.6'],
                ],
                [
                    'id' => Checks::PLATFORM_AUDIT,
                    'title' => 'Reads from every SQL database are logged',
                    'refs' => ['SOC 2 CC7.2'],
                ],
                [
                    'id' => Checks::PLATFORM_ROOT_ADMIN,
                    'title' => 'A super admin approves real-value access',
                    'refs' => ['SOC 2 CC6.3'],
                ],
                [
                    'id' => Checks::PLATFORM_OPEN_REGISTRATION,
                    'title' => 'Open user registration is off',
                    'refs' => ['SOC 2 CC6.2'],
                ],
                [
                    'id' => 'manual.encryption_at_rest',
                    'title' => 'Encryption at rest on your databases',
                    'refs' => ['SOC 2 CC6.1'],
                    'detail' => 'Check outside DreamFactory: database or disk encryption on every database with confidential data.',
                ],
                [
                    'id' => 'manual.access_review',
                    'title' => 'User access reviewed periodically',
                    'refs' => ['SOC 2 CC6.2'],
                    'detail' => 'Review admins, roles with real-value access and API keys on a schedule, and remove what is no longer needed.',
                ],
                [
                    'id' => 'manual.incident_response',
                    'title' => 'Incident response plan in place',
                    'refs' => ['SOC 2 CC7.4'],
                    'detail' => 'Include how to revoke real-value access quickly: php artisan df:masking revoke --all.',
                ],
            ],
            'apply' => [
                'ai' => 'masked',
                'admins_mode_max' => 'selected',
                'grant_max_hours' => 24,
                'role_scope' => null,
                'formats' => [],
                'rules' => [],
            ],
        ];
    }
}

<?php

namespace DreamFactory\Core\Masking\Baselines\Definitions;

use DreamFactory\Core\Masking\Baselines\Checks;

/**
 * ISO/IEC 27001 baseline (general), mapped to the 2022 edition's Annex A controls (A.8.11 is the
 * data masking control introduced in that edition).
 */
final class Iso27001
{
    public static function definition(): array
    {
        return [
            'id' => 'iso27001',
            'name' => 'ISO 27001',
            'vertical' => 'general',
            'frameworks' => ['ISO/IEC 27001:2022'],
            'summary' => 'Any industry: information classified, masked and limited to the people who need it.',
            'protected_classes' => [
                'national_id', 'tax_id', 'passport_number', 'drivers_license', 'card_number', 'card_security',
                'bank_account', 'credential', 'special_category',
            ],
            'controls' => [
                [
                    'id' => Checks::MASKING_MODE,
                    'title' => 'Sensitive data is masked in API responses',
                    'refs' => ['ISO 27001 A.8.11'],
                    'params' => ['min' => 'on'],
                ],
                [
                    'id' => Checks::MASKING_SCANNED,
                    'title' => 'All databases scanned in the last 30 days',
                    'refs' => ['ISO 27001 A.5.9', 'ISO 27001 A.5.12'],
                    'params' => ['days' => 30],
                ],
                [
                    'id' => Checks::MASKING_REVIEW,
                    'title' => 'No columns waiting for review',
                    'refs' => ['ISO 27001 A.5.12'],
                ],
                [
                    'id' => Checks::MASKING_CLASSES,
                    'title' => 'No restricted columns marked not sensitive',
                    'refs' => ['ISO 27001 A.5.12', 'ISO 27001 A.5.34'],
                ],
                [
                    'id' => Checks::ACCESS_AI,
                    'title' => 'AI and MCP sessions get masked values',
                    'refs' => ['ISO 27001 A.8.3', 'ISO 27001 A.8.11', 'ISO 27001 A.8.12'],
                ],
                [
                    'id' => Checks::ACCESS_ADMINS_ALL,
                    'title' => 'Admins need a grant to see real values',
                    'refs' => ['ISO 27001 A.8.2'],
                ],
                [
                    'id' => Checks::ACCESS_GRANT_EXPIRY,
                    'title' => 'Admin grants expire within 24 hours',
                    'refs' => ['ISO 27001 A.5.18', 'ISO 27001 A.8.2'],
                ],
                [
                    'id' => Checks::ACCESS_INACTIVE_ADMINS,
                    'title' => 'Admins unused for 90 days are disabled',
                    'refs' => ['ISO 27001 A.5.16', 'ISO 27001 A.5.18'],
                    'params' => ['days' => 90],
                ],
                [
                    'id' => Checks::PLATFORM_HTTPS,
                    'title' => 'API served over HTTPS',
                    'refs' => ['ISO 27001 A.8.24'],
                ],
                [
                    'id' => Checks::PLATFORM_SESSION_TTL,
                    'title' => 'Idle sessions require signing in again after 60 minutes',
                    'refs' => ['ISO 27001 A.8.5'],
                    'params' => ['max_minutes' => 60],
                ],
                [
                    'id' => Checks::PLATFORM_DEBUG,
                    'title' => 'Debug mode is off',
                    'refs' => ['ISO 27001 A.8.9'],
                ],
                [
                    'id' => Checks::PLATFORM_CORS,
                    'title' => 'No CORS rule allows every origin',
                    'refs' => ['ISO 27001 A.8.9'],
                ],
                [
                    'id' => Checks::PLATFORM_AUDIT,
                    'title' => 'Reads from every SQL database are logged',
                    'refs' => ['ISO 27001 A.8.15'],
                ],
                [
                    'id' => Checks::PLATFORM_ROOT_ADMIN,
                    'title' => 'A super admin approves real-value access',
                    'refs' => ['ISO 27001 A.5.15', 'ISO 27001 A.5.18', 'ISO 27001 A.8.2'],
                ],
                [
                    'id' => Checks::PLATFORM_OPEN_REGISTRATION,
                    'title' => 'Open user registration is off',
                    'refs' => ['ISO 27001 A.5.16', 'ISO 27001 A.5.18'],
                ],
                [
                    'id' => 'manual.encryption_at_rest',
                    'title' => 'Encryption at rest on your databases',
                    'refs' => ['ISO 27001 A.8.24'],
                    'detail' => 'Check outside DreamFactory: database or disk encryption on every database with sensitive data.',
                ],
                [
                    'id' => 'manual.access_review',
                    'title' => 'Access rights reviewed at planned intervals',
                    'refs' => ['ISO 27001 A.5.18'],
                    'detail' => 'Review admins, roles with real-value access and API keys on a schedule.',
                ],
                [
                    'id' => 'manual.backups',
                    'title' => 'Backups taken and restores tested',
                    'refs' => ['ISO 27001 A.8.13'],
                    'detail' => 'Include the DreamFactory system database: it holds masking decisions and settings.',
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

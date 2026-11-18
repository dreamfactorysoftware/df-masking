<?php

namespace DreamFactory\Core\Masking\Baselines\Definitions;

use DreamFactory\Core\Masking\Baselines\Checks;

/**
 * CJIS baseline (US government and law enforcement), mapped to the FBI CJIS Security Policy
 * (CJISSECPOL) v6.1 of 06/25/2026. Since v5.9.2 the policy's requirements are NIST SP 800-53
 * controls (AC-6, AU-11, SC-28, ...); every control cited here has the same identifier in
 * v5.9.5, the version many state CJIS Systems Agencies still audit against until 2027.
 * The old v5.9 section numbers (5.5.2.1, 5.10.1.2, ...) no longer exist.
 */
final class Cjis
{
    public static function definition(): array
    {
        return [
            'id' => 'cjis',
            'name' => 'CJIS',
            'vertical' => 'government',
            'frameworks' => ['FBI CJIS Security Policy v6.1'],
            'summary' => 'Government and law enforcement: criminal justice information on a least-privilege basis.',
            'protected_classes' => ['special_category', 'national_id', 'drivers_license', 'passport_number', 'date_of_birth'],
            'controls' => [
                [
                    'id' => Checks::MASKING_MODE,
                    'title' => 'Criminal justice information is masked in API responses',
                    'refs' => ['CJIS AC-3', 'CJIS AC-6'],
                    'params' => ['min' => 'on'],
                ],
                [
                    'id' => Checks::MASKING_CLASSES,
                    'title' => 'No identifiers or criminal history marked not sensitive',
                    'refs' => ['CJIS AC-3'],
                ],
                [
                    'id' => Checks::ACCESS_AI,
                    'title' => 'AI and MCP sessions get masked values',
                    'refs' => ['CJIS AC-6'],
                ],
                [
                    'id' => Checks::ACCESS_ADMINS_ALL,
                    'title' => 'Admins need a grant to see real values',
                    'refs' => ['CJIS AC-6', 'CJIS AC-6(5)'],
                ],
                [
                    'id' => Checks::ACCESS_GRANT_EXPIRY,
                    'title' => 'Admin grants expire within 8 hours',
                    'refs' => ['CJIS AC-6'],
                ],
                [
                    'id' => Checks::ACCESS_ROLES_RESTRICTED,
                    'title' => 'Roles never see restricted real values',
                    'refs' => ['CJIS AC-6'],
                ],
                [
                    'id' => Checks::ACCESS_INACTIVE_ADMINS,
                    'title' => 'Admins unused for 90 days are disabled',
                    'refs' => ['CJIS AC-2(3)'],
                    'params' => ['days' => 90],
                ],
                [
                    'id' => Checks::PLATFORM_HTTPS,
                    'title' => 'API served over HTTPS',
                    'refs' => ['CJIS SC-8', 'CJIS SC-8(1)'],
                ],
                [
                    'id' => Checks::PLATFORM_SESSION_TTL,
                    'title' => 'Idle sessions require signing in again after 30 minutes',
                    'refs' => ['CJIS AC-11'],
                    'params' => ['max_minutes' => 30],
                ],
                [
                    'id' => Checks::PLATFORM_DEBUG,
                    'title' => 'Debug mode is off',
                    'refs' => ['CJIS SI-11'],
                ],
                [
                    'id' => Checks::PLATFORM_AUDIT,
                    'title' => 'Reads from every SQL database are logged',
                    'refs' => ['CJIS AU-2', 'CJIS AU-3', 'CJIS AU-12'],
                ],
                [
                    'id' => Checks::PLATFORM_LOG_RETENTION,
                    'title' => 'Masking activity kept for at least a year',
                    'refs' => ['CJIS AU-11'],
                    'params' => ['min_days' => 365],
                ],
                [
                    'id' => Checks::PLATFORM_ROOT_ADMIN,
                    'title' => 'A super admin approves real-value access',
                    'refs' => ['CJIS AC-6(1)'],
                ],
                [
                    'id' => Checks::PLATFORM_OPEN_REGISTRATION,
                    'title' => 'Open user registration is off',
                    'refs' => ['CJIS AC-2'],
                ],
                [
                    'id' => 'manual.encryption_at_rest',
                    'title' => 'CJI encrypted at rest (FIPS 140-3, 256-bit keys)',
                    'refs' => ['CJIS SC-28', 'CJIS SC-28(1)', 'CJIS SC-13'],
                    'detail' => 'Check outside DreamFactory: wherever CJI is stored outside a physically secure location.',
                ],
                [
                    'id' => 'manual.mfa',
                    'title' => 'Multi-factor authentication for every user who reaches CJI',
                    'refs' => ['CJIS IA-2(1)', 'CJIS IA-2(2)'],
                    'detail' => 'Use an identity provider with multi-factor authentication (SAML, OpenID Connect, Azure AD).',
                ],
                [
                    'id' => 'manual.audit_retention',
                    'title' => 'API logs kept for at least one year',
                    'refs' => ['CJIS AU-11'],
                    'detail' => 'Keep the Logstash or MongoDB request logs (and exported evidence reports) for a year or more.',
                ],
            ],
            'apply' => [
                'ai' => 'masked',
                'admins_mode_max' => 'selected',
                'grant_max_hours' => 8,
                'role_scope' => 'except_restricted',
                'formats' => [],
                'rules' => [
                    [
                        'match' => 'name',
                        'pattern' => '^(?:fbi|state_?id|booking|arrest|inmate|offender|warrant)_?(?:no|num|nbr|number)$|^ucn$',
                        'class' => 'special_category',
                        'title' => 'FBI, state ID, booking, arrest and warrant numbers',
                    ],
                    [
                        'match' => 'name',
                        'pattern' => '^(?:case|incident|offense|offence|citation)_?(?:no|num|nbr|number)$',
                        'class' => 'special_category',
                        'title' => 'Case, incident and citation numbers',
                    ],
                    [
                        'match' => 'name',
                        'pattern' => '^(?:rap_?sheet|criminal_?charges?|offen[cs]es?|prior_?arrests?|arrest_?history)$',
                        'class' => 'special_category',
                        'title' => 'Criminal history fields',
                    ],
                    [
                        'match' => 'name',
                        'pattern' => '^(?:fingerprints|finger_?print_?(?:image|template|data)|palm_?prints?|mug_?shot|dna_?profile)$',
                        'class' => 'special_category',
                        'title' => 'Biometric fields',
                    ],
                ],
            ],
        ];
    }
}

<?php

namespace DreamFactory\Core\Masking\Baselines\Definitions;

use DreamFactory\Core\Masking\Baselines\Checks;

/**
 * GLBA baseline (US banks and other financial institutions). Two rules implement GLBA section
 * 501(b): the FTC Safeguards Rule (16 CFR 314.4, as amended in 2021) for financial
 * institutions under FTC jurisdiction (non-bank lenders, finance companies, ...), and the
 * Interagency Guidelines Establishing Information Security Standards for banks (OCC 12 CFR 30
 * App. B, Federal Reserve 12 CFR 208 App. D-2, FDIC 12 CFR 364 App. B). Federally insured credit
 * unions follow NCUA 12 CFR 748 App. A, which uses the same section numbering. Controls cite both.
 */
final class Glba
{
    public static function definition(): array
    {
        return [
            'id' => 'glba',
            'name' => 'GLBA',
            'vertical' => 'banking',
            'frameworks' => [
                'FTC Safeguards Rule, 16 CFR 314 (non-bank financial institutions)',
                'Interagency Guidelines Establishing Information Security Standards (banks: 12 CFR 30 App. B, '
                    . '12 CFR 208 App. D-2, 12 CFR 364 App. B; credit unions: 12 CFR 748 App. A)',
            ],
            'summary' => 'Banks and other financial institutions: customer information only for people who need it.',
            'protected_classes' => ['bank_account', 'card_number', 'card_security', 'national_id', 'tax_id', 'financial_personal'],
            'controls' => [
                [
                    'id' => Checks::MASKING_MODE,
                    'title' => 'Customer information is masked in API responses',
                    'refs' => ['16 CFR 314.4(c)(1)', 'Interagency Guidelines III.C.1.a'],
                    'params' => ['min' => 'on'],
                ],
                [
                    'id' => Checks::MASKING_SCANNED,
                    'title' => 'All databases scanned in the last 30 days',
                    'refs' => ['16 CFR 314.4(c)(2)'],
                    'params' => ['days' => 30],
                ],
                [
                    'id' => Checks::MASKING_REVIEW,
                    'title' => 'No columns waiting for review',
                    'refs' => ['16 CFR 314.4(c)(2)'],
                ],
                [
                    'id' => Checks::MASKING_CLASSES,
                    'title' => 'No account, card or tax numbers marked not sensitive',
                    'refs' => ['16 CFR 314.4(c)(1)', 'Interagency Guidelines III.C.1.a'],
                ],
                [
                    'id' => Checks::ACCESS_AI,
                    'title' => 'AI and MCP sessions get masked values',
                    'refs' => ['16 CFR 314.4(c)(1)', 'Interagency Guidelines III.C.1.a'],
                ],
                [
                    'id' => Checks::ACCESS_ADMINS_ALL,
                    'title' => 'Admins need a grant to see real values',
                    'refs' => ['16 CFR 314.4(c)(1)', 'Interagency Guidelines III.C.1.a'],
                ],
                [
                    'id' => Checks::ACCESS_GRANT_EXPIRY,
                    'title' => 'Admin grants expire within 24 hours',
                    'refs' => ['16 CFR 314.4(c)(1)', 'Interagency Guidelines III.C.1.a'],
                ],
                [
                    'id' => Checks::ACCESS_ROLES_RESTRICTED,
                    'title' => 'Roles never see restricted real values',
                    'refs' => ['16 CFR 314.4(c)(1)', 'Interagency Guidelines III.C.1.a'],
                ],
                [
                    'id' => Checks::PLATFORM_HTTPS,
                    'title' => 'API served over HTTPS',
                    'refs' => ['16 CFR 314.4(c)(3)', 'Interagency Guidelines III.C.1.c'],
                ],
                [
                    'id' => Checks::PLATFORM_SESSION_TTL,
                    'title' => 'Idle sessions require signing in again after 60 minutes',
                    'refs' => ['16 CFR 314.4(c)(1)', 'Interagency Guidelines III.C.1.a'],
                    'params' => ['max_minutes' => 60],
                ],
                [
                    'id' => Checks::PLATFORM_AUDIT,
                    'title' => 'Reads from every SQL database are logged',
                    'refs' => ['16 CFR 314.4(c)(8)', 'Interagency Guidelines III.C.1.f'],
                ],
                [
                    'id' => Checks::PLATFORM_ROOT_ADMIN,
                    'title' => 'A super admin approves real-value access',
                    'refs' => ['16 CFR 314.4(c)(1)', 'Interagency Guidelines III.C.1.e'],
                ],
                [
                    'id' => Checks::PLATFORM_OPEN_REGISTRATION,
                    'title' => 'Open user registration is off',
                    'refs' => ['16 CFR 314.4(c)(1)(i)', 'Interagency Guidelines III.C.1.a'],
                ],
                [
                    'id' => 'manual.mfa',
                    'title' => 'Multi-factor authentication for everyone with access',
                    'refs' => ['16 CFR 314.4(c)(5)'],
                    'detail' => 'Use an MFA-capable identity provider (SAML, OpenID Connect, Azure AD) for admins and users.',
                ],
                [
                    'id' => 'manual.encryption_at_rest',
                    'title' => 'Customer information encrypted at rest',
                    'refs' => ['16 CFR 314.4(c)(3)', 'Interagency Guidelines III.C.1.c'],
                    'detail' => 'Check outside DreamFactory: database or disk encryption on every database with customer information.',
                ],
                [
                    'id' => 'manual.testing',
                    'title' => 'Yearly penetration test and twice-yearly vulnerability scans',
                    'refs' => ['16 CFR 314.4(d)(2)', 'Interagency Guidelines III.C.3'],
                    'detail' => 'Unless your systems are monitored continuously. Banks: test key controls as often as the risk assessment says.',
                ],
                [
                    'id' => 'manual.access_review',
                    'title' => 'Access controls reviewed periodically',
                    'refs' => ['16 CFR 314.4(c)(1)'],
                    'detail' => 'Review admins, roles with real-value access and API keys on a schedule, and remove what is no longer needed.',
                ],
            ],
            'apply' => [
                'ai' => 'masked',
                'admins_mode_max' => 'selected',
                'grant_max_hours' => 24,
                'role_scope' => 'except_restricted',
                'formats' => [],
                'rules' => [
                    [
                        'match' => 'name',
                        'pattern' => '^(?:(?:customer|deposit|checking|savings|loan|ach|dda)_?acc(?:oun)?t_?(?:no|num|nbr|number)|acc(?:oun)?t_?(?:no|num|nbr|number)|loan_?(?:no|num|nbr|number))$',
                        'class' => 'bank_account',
                        'title' => 'Account and loan numbers',
                    ],
                    [
                        'match' => 'name',
                        'pattern' => '^(?:(?:account|available|current|ledger|outstanding|loan|principal|statement)_?)?balance$|^(?:credit_?(?:score|rating|limit)|fico(?:_?score)?|loan_?amount|annual_?income|net_?worth|debt_?to_?income(?:_?ratio)?)$',
                        'class' => 'financial_personal',
                        'title' => 'Balances, credit scores and income',
                    ],
                ],
            ],
        ];
    }
}

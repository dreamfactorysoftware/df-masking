<?php

namespace DreamFactory\Core\Masking\Baselines\Definitions;

use DreamFactory\Core\Masking\Baselines\Checks;

/**
 * PCI DSS baseline (payments), mapped to PCI DSS v4.0.1 requirement numbers (unchanged from
 * v4.0 for every requirement cited here).
 */
final class PciDss
{
    public static function definition(): array
    {
        return [
            'id' => 'pci_dss',
            'name' => 'PCI DSS',
            'vertical' => 'payments',
            'frameworks' => ['PCI DSS v4.0.1'],
            'summary' => 'Payments: card numbers show at most the last four digits, and only people with a business need see more.',
            'protected_classes' => ['card_number', 'card_security'],
            'controls' => [
                [
                    'id' => Checks::MASKING_MODE,
                    'title' => 'Card data is masked in API responses',
                    'refs' => ['PCI DSS 3.4.1', 'PCI DSS 7.2.6'],
                    'params' => ['min' => 'on'],
                ],
                [
                    'id' => Checks::MASKING_SCANNED,
                    'title' => 'All databases scanned in the last 30 days',
                    'refs' => ['PCI DSS 12.5.2'],
                    'params' => ['days' => 30],
                ],
                [
                    'id' => Checks::MASKING_REVIEW,
                    'title' => 'No columns waiting for review',
                    'refs' => ['PCI DSS 12.5.2'],
                ],
                [
                    'id' => Checks::MASKING_CLASSES,
                    'title' => 'No card data marked not sensitive',
                    'refs' => ['PCI DSS 3.4.1'],
                ],
                [
                    'id' => Checks::MASKING_FORMAT,
                    'title' => 'Card numbers show at most the last 4 digits',
                    'refs' => ['PCI DSS 3.4.1'],
                ],
                [
                    'id' => Checks::ACCESS_AI,
                    'title' => 'AI and MCP sessions get masked values',
                    'refs' => ['PCI DSS 7.2.1', 'PCI DSS 7.2.5'],
                ],
                [
                    'id' => Checks::ACCESS_ADMINS_ALL,
                    'title' => 'Admins need a grant to see real values',
                    'refs' => ['PCI DSS 3.4.1', 'PCI DSS 7.2.2'],
                ],
                [
                    'id' => Checks::ACCESS_GRANT_EXPIRY,
                    'title' => 'Admin grants expire within 8 hours',
                    'refs' => ['PCI DSS 3.4.1', 'PCI DSS 7.2.2'],
                ],
                [
                    'id' => Checks::ACCESS_ROLES_RESTRICTED,
                    'title' => 'Roles never see full card data',
                    'refs' => ['PCI DSS 3.4.1', 'PCI DSS 7.2.1', 'PCI DSS 7.2.6'],
                ],
                [
                    'id' => Checks::ACCESS_INACTIVE_ADMINS,
                    'title' => 'Admins unused for 90 days are disabled',
                    'refs' => ['PCI DSS 8.2.6'],
                    'params' => ['days' => 90],
                ],
                [
                    'id' => Checks::PLATFORM_HTTPS,
                    'title' => 'API served over HTTPS',
                    'refs' => ['PCI DSS 4.2.1'],
                ],
                [
                    'id' => Checks::PLATFORM_SESSION_TTL,
                    'title' => 'Idle sessions require signing in again after 15 minutes',
                    'refs' => ['PCI DSS 8.2.8'],
                    'params' => ['max_minutes' => 15],
                ],
                [
                    'id' => Checks::PLATFORM_DEBUG,
                    'title' => 'Debug mode is off',
                    'refs' => ['PCI DSS 2.2.4'],
                ],
                [
                    'id' => Checks::PLATFORM_AUDIT,
                    'title' => 'Reads from every SQL database are logged',
                    'refs' => ['PCI DSS 10.2.1', 'PCI DSS 10.2.1.1'],
                ],
                [
                    'id' => Checks::PLATFORM_LOG_RETENTION,
                    'title' => 'Masking activity kept for at least a year',
                    'refs' => ['PCI DSS 10.5.1'],
                    'params' => ['min_days' => 365],
                ],
                [
                    'id' => Checks::PLATFORM_ROOT_ADMIN,
                    'title' => 'A super admin approves real-value access',
                    'refs' => ['PCI DSS 7.2.3'],
                ],
                [
                    'id' => Checks::PLATFORM_OPEN_REGISTRATION,
                    'title' => 'Open user registration is off',
                    'refs' => ['PCI DSS 8.2.4'],
                ],
                [
                    'id' => 'manual.pan_unreadable',
                    'title' => 'Stored card numbers are unreadable',
                    'refs' => ['PCI DSS 3.5.1'],
                    'detail' => 'Check outside DreamFactory: card numbers encrypted, truncated, tokenized or hashed wherever they are stored.',
                ],
                [
                    'id' => 'manual.no_sad',
                    'title' => 'No security codes or track data kept after authorization',
                    'refs' => ['PCI DSS 3.3.1'],
                    'detail' => 'Masking hides these values; it does not remove them. Delete them from your databases.',
                ],
                [
                    'id' => 'manual.access_review',
                    'title' => 'User access reviewed every six months',
                    'refs' => ['PCI DSS 7.2.4'],
                    'detail' => 'Review admins, roles with real-value access and API keys at least every six months.',
                ],
            ],
            'apply' => [
                'ai' => 'masked',
                'admins_mode_max' => 'selected',
                'grant_max_hours' => 8,
                'role_scope' => 'except_restricted',
                'formats' => [
                    ['class' => 'card_number', 'allowed' => ['last4', 'redact', 'null'], 'target' => 'last4'],
                ],
                'rules' => [
                    [
                        'match' => 'name',
                        'pattern' => '^(?:pan|cc_?(?:no|num|nbr)|card_?(?:no|num|nbr)|cardnum|acct_?pan|primary_?acct_?(?:no|num|nbr|number))$',
                        'class' => 'card_number',
                        'title' => 'Card number abbreviations (pan, cc_num, card_no)',
                    ],
                    [
                        'match' => 'name',
                        'pattern' => '^(?:cvv2|cvc2|cav2|card_?(?:cvv|cvc|cvv2|cvc2|cid)|track_?[12](?:_?data)?|track_?data|mag_?stripe(?:_?data)?|pin_?block)$',
                        'class' => 'card_security',
                        'title' => 'Card codes, track data and PIN blocks',
                    ],
                    [
                        'match' => 'name',
                        'pattern' => '^(?:(?:cc|card)_?exp(?:iry|iration)?(?:_?(?:date|month|year|mm|yy|yyyy|mmyy))?|exp_?(?:mm|yy|yyyy|mmyy))$',
                        'class' => 'card_expiry',
                        'title' => 'Card expiry fields',
                    ],
                    [
                        'match' => 'name',
                        'pattern' => '^(?:card_?holder(?:_?name)?|name_?on_?card|cc_?name)$',
                        'class' => 'person_name',
                        'title' => 'Cardholder names',
                    ],
                ],
            ],
        ];
    }
}

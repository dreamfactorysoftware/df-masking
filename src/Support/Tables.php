<?php

namespace DreamFactory\Core\Masking\Support;

/**
 * System database table names owned by df-masking. Every dm_* table is created by
 * database/migrations/2026_10_29_000001_create_dm_tables.php, except dm_baseline
 * (database/migrations/2026_10_29_000100_create_dm_baseline_table.php);
 * 2026_10_29_000003_dm_exact_names_and_scan_failures.php makes dm_column names compare exactly
 * and adds dm_scan.failed_services.
 *
 * No table ever holds a raw data value: only column metadata, verdicts, evidence
 * text, already-masked examples and settings.
 */
final class Tables
{
    public const SETTING = 'dm_setting';
    public const COLUMN = 'dm_column';
    public const MASK_FORMAT = 'dm_mask_format';
    public const RULE = 'dm_rule';
    public const ADMIN_GRANT = 'dm_admin_grant';
    public const ROLE_ACCESS = 'dm_role_access';
    public const ACTIVITY = 'dm_activity';
    public const SCAN = 'dm_scan';
    public const BASELINE = 'dm_baseline';

    /** Every table created by the main migration, in creation order. */
    public const MAIN = [
        self::SETTING,
        self::COLUMN,
        self::MASK_FORMAT,
        self::RULE,
        self::ADMIN_GRANT,
        self::ROLE_ACCESS,
        self::ACTIVITY,
        self::SCAN,
    ];

    private function __construct()
    {
    }
}

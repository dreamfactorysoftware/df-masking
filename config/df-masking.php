<?php

/*
 * df-masking configuration. Every value is env-backed, so the file is `config:cache` safe.
 * Masking policy itself (mode, access, formats, rules) lives in the system database and is
 * managed from the admin UI (Data Masking), the API (system/data_masking) or
 * `php artisan df:masking`.
 */
return [
    /*
     * HMAC key for `token` masks: base64 of exactly 32 bytes. Optional. When unset, a key is
     * generated on first use and stored encrypted (APP_KEY) in the system database. Set it to
     * keep tokens identical across instances that share data (or across an APP_KEY rotation).
     */
    'token_key' => env('DF_MASKING_TOKEN_KEY'),

    /* Masking activity older than this many days is pruned (0 = keep forever). */
    'activity_retention_days' => (int)env('DF_MASKING_ACTIVITY_RETENTION_DAYS', 400),

    'rules' => [
        /* Wall-clock budget for POST system/data_masking/rule/test on value rules. */
        'test_budget_ms' => (int)env('DF_MASKING_RULE_TEST_BUDGET_MS', 3000),
        /* pcre.backtrack_limit while evaluating admin patterns (guards catastrophic patterns). */
        'backtrack_limit' => (int)env('DF_MASKING_RULE_BACKTRACK_LIMIT', 100000),
    ],

    'scan' => [
        /* A running scan with no heartbeat for this long is reported as failed. */
        'stale_minutes' => (int)env('DF_MASKING_SCAN_STALE_MINUTES', 5),
        /* PHP binary for the detached scan process (defaults to PHP_BINARY, then "php"). */
        'php_binary' => env('DF_MASKING_PHP_BINARY'),
        /*
         * Sampling budget per table. PostgreSQL and MySQL also get a per-statement timeout; on
         * other databases the table budget is checked between statements.
         */
        'table_budget_ms' => (int)env('DF_MASKING_SCAN_TABLE_BUDGET_MS', 20000),
        'statement_timeout_ms' => (int)env('DF_MASKING_SCAN_STATEMENT_TIMEOUT_MS', 10000),
    ],

    'access' => [
        /* How long a resolved admin grant / role access decision may be cached. */
        'cache_seconds' => (int)env('DF_MASKING_ACCESS_CACHE_SECONDS', 30),
    ],
];

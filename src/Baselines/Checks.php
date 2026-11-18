<?php

namespace DreamFactory\Core\Masking\Baselines;

/**
 * The shared check catalog every baseline's controls are built from.
 *
 * Each check evaluates one DreamFactory-owned control against live settings (Evaluator). Some
 * can be fixed by a baseline's Apply (Planner); others link to the admin UI page that fixes
 * them, or need a server setting / command the UI cannot change.
 */
final class Checks
{
    public const MASKING_MODE = 'masking.mode';
    public const MASKING_SCANNED = 'masking.scanned';
    public const MASKING_REVIEW = 'masking.review';
    public const MASKING_CLASSES = 'masking.classes';
    public const MASKING_FORMAT = 'masking.format';
    public const ACCESS_AI = 'access.ai';
    public const ACCESS_GRANT_EXPIRY = 'access.grant_expiry';
    public const ACCESS_ADMINS_ALL = 'access.admins_all';
    public const ACCESS_ROLES_RESTRICTED = 'access.roles_restricted';
    public const ACCESS_INACTIVE_ADMINS = 'access.inactive_admins';
    public const PLATFORM_HTTPS = 'platform.https';
    public const PLATFORM_DEBUG = 'platform.debug';
    public const PLATFORM_SESSION_TTL = 'platform.session_ttl';
    public const PLATFORM_CORS = 'platform.cors';
    public const PLATFORM_RATE_LIMIT = 'platform.rate_limit';
    public const PLATFORM_AUDIT = 'platform.audit';
    public const PLATFORM_ROOT_ADMIN = 'platform.root_admin';
    public const PLATFORM_OPEN_REGISTRATION = 'platform.open_registration';
    public const PLATFORM_LOG_RETENTION = 'platform.log_retention';

    /** Control ids of hand-checked items start with this prefix ("manual.encryption_at_rest"). */
    public const MANUAL_PREFIX = 'manual.';

    /** Admin UI routes the `link` fixes point at. */
    public const ROUTE_DATA_MASKING = '/api-security/data-masking';
    /** The Data Masking page opens its Columns tab on a filter given as ?filter=review|clear|... */
    public const ROUTE_DATA_MASKING_REVIEW = '/api-security/data-masking?filter=review';
    public const ROUTE_DATA_MASKING_CLEAR = '/api-security/data-masking?filter=clear';
    public const ROUTE_DATA_MASKING_ACCESS = '/api-security/data-masking?tab=access';
    public const ROUTE_CORS = '/system-settings/config/cors';
    public const ROUTE_RATE_LIMITS = '/api-security/rate-limiting';
    public const ROUTE_LOGS = '/system-settings/logs';
    public const ROUTE_ADMINS = '/admin-settings/admins';

    /**
     * check id => [fix kind when failing, route|null, params it requires].
     * kind 'apply': the baseline's Apply fixes it; 'link': a UI page fixes it; 'none': a server
     * setting or command (the detail says which).
     */
    private const CATALOG = [
        self::MASKING_MODE => ['apply', null, ['min']],
        self::MASKING_SCANNED => ['link', self::ROUTE_DATA_MASKING, ['days']],
        self::MASKING_REVIEW => ['link', self::ROUTE_DATA_MASKING_REVIEW, []],
        self::MASKING_CLASSES => ['link', self::ROUTE_DATA_MASKING_CLEAR, []],
        self::MASKING_FORMAT => ['apply', null, []],
        self::ACCESS_AI => ['apply', null, []],
        self::ACCESS_GRANT_EXPIRY => ['apply', null, []],
        self::ACCESS_ADMINS_ALL => ['apply', null, []],
        self::ACCESS_ROLES_RESTRICTED => ['apply', null, []],
        self::ACCESS_INACTIVE_ADMINS => ['link', self::ROUTE_ADMINS, ['days']],
        self::PLATFORM_HTTPS => ['none', null, []],
        self::PLATFORM_DEBUG => ['none', null, []],
        self::PLATFORM_SESSION_TTL => ['none', null, ['max_minutes']],
        self::PLATFORM_CORS => ['link', self::ROUTE_CORS, []],
        self::PLATFORM_RATE_LIMIT => ['link', self::ROUTE_RATE_LIMITS, []],
        self::PLATFORM_AUDIT => ['link', self::ROUTE_LOGS, []],
        self::PLATFORM_ROOT_ADMIN => ['none', null, []],
        self::PLATFORM_OPEN_REGISTRATION => ['none', null, []],
        self::PLATFORM_LOG_RETENTION => ['none', null, ['min_days']],
    ];

    private function __construct()
    {
    }

    /** @return string[] every check id */
    public static function ids(): array
    {
        return array_keys(self::CATALOG);
    }

    public static function exists(string $id): bool
    {
        return isset(self::CATALOG[$id]);
    }

    public static function isManual(string $controlId): bool
    {
        return str_starts_with($controlId, self::MANUAL_PREFIX);
    }

    /** @return array{kind:string,route:?string} the fix offered while the check fails */
    public static function fix(string $id): array
    {
        [$kind, $route] = self::CATALOG[$id] ?? ['none', null];

        return ['kind' => $kind, 'route' => $route];
    }

    /** @return string[] params a control using this check must define */
    public static function requiredParams(string $id): array
    {
        return self::CATALOG[$id][2] ?? [];
    }

    /** True when Apply can change the setting this check verifies. */
    public static function applyFixes(string $id): bool
    {
        return (self::CATALOG[$id][0] ?? null) === 'apply';
    }
}

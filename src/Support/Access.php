<?php

namespace DreamFactory\Core\Masking\Support;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

/**
 * Real-value access lookups, shared by the HTTP API and enforcement.
 *
 * - Admin grants (dm_admin_grant) and role access (dm_role_access) are each read as one small
 *   table snapshot, cached for df-masking.access.cache_seconds (default 30 s) under
 *   PolicyVersion::current(); every write through the API/CLI bumps the version, so changes
 *   apply immediately. Grant expiry is compared with the clock on every call.
 * - Missing rows mean "no access" (fail closed).
 */
final class Access
{
    /** Grant durations offered by the UI, in seconds (null = until turned off). */
    public const DURATIONS = [
        '1h' => 3600,
        '8h' => 8 * 3600,
        '24h' => 24 * 3600,
        '7d' => 7 * 24 * 3600,
        'forever' => null,
    ];

    public const SCOPES = ['all', 'except_restricted'];

    /** @var array<int,int|null>|null admin_id => expires_at unix ts (null = no expiry) */
    private static ?array $grants = null;
    private static ?int $grantsVersion = null;
    /** @var array<int,array{enabled:bool,scope:string}>|null */
    private static ?array $roles = null;
    private static ?int $rolesVersion = null;

    private function __construct()
    {
    }

    /**
     * The admin's unexpired grant: ['expires_at' => unix ts|null], or null when none.
     */
    public static function activeGrant(int $adminId, ?int $now = null): ?array
    {
        $grants = self::grants();
        if (!array_key_exists($adminId, $grants)) {
            return null;
        }
        $expires = $grants[$adminId];
        if ($expires !== null && $expires <= ($now ?? time())) {
            return null;
        }

        return ['expires_at' => $expires];
    }

    /**
     * Would this admin see real values when masking is on (ignoring AI, which the caller
     * checks)? adminsMode all, or selected with an unexpired grant.
     */
    public static function adminSeesRealValues(int $adminId, ?int $now = null): bool
    {
        return match (Settings::adminsMode()) {
            'all' => true,
            'selected' => self::activeGrant($adminId, $now) !== null,
            default => false,
        };
    }

    /** ['enabled' => bool, 'scope' => 'all'|'except_restricted']; missing rows are disabled. */
    public static function roleAccess(int $roleId): array
    {
        return self::roles()[$roleId] ?? ['enabled' => false, 'scope' => 'except_restricted'];
    }

    /** Does a role see real values for a column of this tier (ignoring AI)? */
    public static function roleSeesTier(int $roleId, ?string $tier): bool
    {
        $access = self::roleAccess($roleId);
        if (!$access['enabled']) {
            return false;
        }

        return $access['scope'] === 'all' || $tier !== Catalog::TIER_RESTRICTED;
    }

    /**
     * Full real-value decision for a caller and a column tier: does the caller see the real value?
     * (Mode is not considered here: callers short-circuit on mode first.)
     *
     * A console process without a session (scheduler, queue worker, MQTT/AMQP listeners calling
     * the API internally) has neither an admin grant nor a role, so it is masked like any other
     * anonymous caller. The scanner never needs real values through the API: it reads the
     * databases directly.
     */
    public static function callerSeesRealValues(Caller $caller, ?string $tier): bool
    {
        if ($caller->isAi() && Settings::ai() !== 'same_as_admins') {
            return false;
        }
        if ($caller->isSysAdmin()) {
            if ($caller->userId() === null) {
                return false;
            }

            return self::adminSeesRealValues($caller->userId());
        }
        $roleId = $caller->roleId();

        return $roleId !== null && self::roleSeesTier($roleId, $tier);
    }

    /** Parses '1h'|'8h'|'24h'|'7d'|'forever' into an expiry timestamp (null = forever). */
    public static function expiryFor(string $duration, ?int $now = null): ?int
    {
        if (!array_key_exists($duration, self::DURATIONS)) {
            throw new \InvalidArgumentException("Unknown duration '$duration'. Use 1h, 8h, 24h, 7d or forever.");
        }
        $seconds = self::DURATIONS[$duration];

        return $seconds === null ? null : ($now ?? time()) + $seconds;
    }

    /** Drops the per-process snapshots (tests, after writes in the same process). */
    public static function forget(): void
    {
        self::$grants = self::$roles = null;
        self::$grantsVersion = self::$rolesVersion = null;
    }

    /** @return array<int,int|null> */
    private static function grants(): array
    {
        $version = PolicyVersion::current();
        if (self::$grants !== null && self::$grantsVersion === $version) {
            return self::$grants;
        }
        self::$grants = self::remember('grants', $version, function (): array {
            $out = [];
            foreach (DB::table(Tables::ADMIN_GRANT)->get(['admin_id', 'expires_at']) as $row) {
                // An unparsable expiry counts as already expired (fail closed).
                $out[(int)$row->admin_id] = $row->expires_at === null ? null : (Time::ts($row->expires_at) ?? 0);
            }

            return $out;
        });
        self::$grantsVersion = $version;

        return self::$grants;
    }

    /** @return array<int,array{enabled:bool,scope:string}> */
    private static function roles(): array
    {
        $version = PolicyVersion::current();
        if (self::$roles !== null && self::$rolesVersion === $version) {
            return self::$roles;
        }
        self::$roles = self::remember('roles', $version, function (): array {
            $out = [];
            foreach (DB::table(Tables::ROLE_ACCESS)->get(['role_id', 'enabled', 'scope']) as $row) {
                $out[(int)$row->role_id] = [
                    'enabled' => (bool)$row->enabled,
                    'scope' => $row->scope === 'all' ? 'all' : 'except_restricted',
                ];
            }

            return $out;
        });
        self::$rolesVersion = $version;

        return self::$roles;
    }

    private static function remember(string $what, int $version, \Closure $load): array
    {
        $ttl = max(1, (int)config('df-masking.access.cache_seconds', 30));
        $key = 'df-masking:' . $what . ':v' . $version;
        try {
            $cached = $version > 0 ? Cache::get($key) : null;
            if (is_array($cached)) {
                return $cached;
            }
        } catch (\Throwable $e) {
        }
        try {
            $value = $load();
        } catch (\Throwable $e) {
            return []; // not migrated yet: nobody has access (fail closed)
        }
        try {
            if ($version > 0) {
                Cache::put($key, $value, $ttl);
            }
        } catch (\Throwable $e) {
        }

        return $value;
    }
}

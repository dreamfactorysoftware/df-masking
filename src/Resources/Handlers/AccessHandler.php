<?php

namespace DreamFactory\Core\Masking\Resources\Handlers;

use DreamFactory\Core\Exceptions\BadRequestException;
use DreamFactory\Core\Exceptions\ConflictResourceException;
use DreamFactory\Core\Masking\Support\Access;
use DreamFactory\Core\Masking\Support\Activity;
use DreamFactory\Core\Masking\Support\Caller;
use DreamFactory\Core\Masking\Support\PolicyVersion;
use DreamFactory\Core\Masking\Support\Retry;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use DreamFactory\Core\Masking\Support\Time;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

/**
 * GET/PATCH system/data_masking/access: who sees real values.
 *
 * Loosening (more admins, a new or longer grant, AI = same as admins, enabling a role or
 * widening its scope) needs the super admin; tightening is always allowed. A PATCH that
 * contains any loosening change is rejected as a whole when the caller is not the super admin.
 *
 * Concurrency: GET returns `version`, an opaque digest of the effective access state (mode, AI,
 * live grants with their expiry, role access). A PATCH that sends `version` is refused with 409
 * when the state changed since (another admin, `df:masking revoke`, a grant that expired), so a
 * stale screen can never restore what someone else removed. A grant listed without a duration
 * keeps its expiry; listed without a duration for an admin who has no live grant (it expired or
 * was revoked meanwhile) is refused with 409 instead of silently becoming a new grant.
 */
final class AccessHandler
{
    public const STALE_MESSAGE = 'Access settings changed since you loaded them. Reload and try again.';

    private const WRITE_LOCK = 'df-masking:access:write';

    private const ADMIN_RANK = ['none' => 0, 'selected' => 1, 'all' => 2];

    private const SPANS = [
        '1h' => 'for 1 hour',
        '8h' => 'for 8 hours',
        '24h' => 'for 24 hours',
        '7d' => 'for 7 days',
        'forever' => 'until turned off',
    ];

    public function get(): array
    {
        $now = time();
        $admins = self::admins();
        $byId = [];
        foreach ($admins as $a) {
            $byId[$a['admin_id']] = $a;
        }

        $grants = [];
        foreach (self::grantRows() as $row) {
            $adminId = (int)$row->admin_id;
            $expires = $row->expires_at === null ? null : (Time::ts($row->expires_at) ?? 0);
            if ($expires !== null && $expires <= $now) {
                continue; // expired: no longer a grant
            }
            if (!isset($byId[$adminId])) {
                continue; // no longer an active admin
            }
            $grants[] = [
                'admin_id' => $adminId,
                'name' => $byId[$adminId]['name'],
                'email' => $byId[$adminId]['email'],
                'expires_at' => Time::iso($expires),
            ];
        }

        $me = Caller::current()->userId();
        $available = array_map(fn (array $a) => $a + ['you' => $a['admin_id'] === $me], $admins);

        $access = self::roleAccessRows();
        $roles = [];
        foreach (self::roleRows() as $role) {
            $id = (int)$role->id;
            $roles[] = [
                'role_id' => $id,
                'name' => (string)$role->name,
                'enabled' => (bool)($access[$id]['enabled'] ?? false),
                'scope' => ($access[$id]['scope'] ?? 'except_restricted') === 'all' ? 'all' : 'except_restricted',
            ];
        }

        return [
            'admins' => [
                'mode' => Settings::adminsMode(),
                'grants' => $grants,
                'available' => $available,
            ],
            'ai' => Settings::ai(),
            'roles' => $roles,
            'version' => self::version($now),
        ];
    }

    /**
     * Opaque digest of the effective access state. Live grants only, so a grant that expires
     * changes it too.
     */
    public static function version(?int $now = null): string
    {
        $now ??= time();
        $grants = [];
        foreach (self::grantRows() as $row) {
            $expires = $row->expires_at === null ? null : (Time::ts($row->expires_at) ?? 0);
            if ($expires === null || $expires > $now) {
                $grants[] = [(int)$row->admin_id, $expires];
            }
        }
        sort($grants);
        $roles = [];
        foreach (self::roleAccessRows() as $id => $r) {
            if ($r['enabled']) {
                $roles[] = [$id, $r['scope']];
            }
        }
        sort($roles);
        $state = [Settings::adminsMode(), Settings::ai(), $grants, $roles];

        return substr(hash('sha256', json_encode($state)), 0, 20);
    }

    /**
     * @throws BadRequestException|\DreamFactory\Core\Exceptions\ForbiddenException
     */
    public function patch(array $payload): array
    {
        $blocked = 'Blocked an attempt to change access';
        Guard::denyAi($blocked);

        $version = $payload['version'] ?? null;
        if ($version !== null && !is_string($version)) {
            throw new BadRequestException('version must be the string GET access returned.');
        }

        // One access write at a time, so the version check and the write see the same state.
        return self::locked(function () use ($payload, $version, $blocked): array {
            $now = time();
            if ($version !== null && !hash_equals(self::version($now), $version)) {
                throw new ConflictResourceException(self::STALE_MESSAGE);
            }
            $plan = $this->plan($payload, $now);
            if ($plan['loosens'] && !Caller::current()->isSuperAdmin()) {
                Guard::requireSuperAdmin($blocked);
            }
            if ($plan['changes'] === [] && $plan['grant_deletes'] === [] && $plan['grant_upserts'] === [] && $plan['role_upserts'] === []) {
                return $this->get();
            }
            $this->write($plan);

            return $this->get();
        });
    }

    /** Applies a validated plan. */
    private function write(array $plan): void
    {
        $caller = Caller::current();
        $label = mb_substr($caller->label(), 0, 255);
        Retry::transaction(function () use ($plan, $caller, $label) {
            foreach ($plan['grant_deletes'] as $adminId) {
                DB::table(Tables::ADMIN_GRANT)->where('admin_id', $adminId)->delete();
            }
            foreach ($plan['grant_upserts'] as $adminId => $expires) {
                $values = [
                    'expires_at' => Time::fromTs($expires),
                    'granted_by_id' => $caller->userId(),
                    'updated_at' => now(),
                ];
                $updated = DB::table(Tables::ADMIN_GRANT)->where('admin_id', $adminId)->update($values);
                if ($updated === 0 && !DB::table(Tables::ADMIN_GRANT)->where('admin_id', $adminId)->exists()) {
                    DB::table(Tables::ADMIN_GRANT)->insert($values + ['admin_id' => $adminId, 'created_at' => now()]);
                }
            }
            foreach ($plan['role_upserts'] as $roleId => $r) {
                $values = ['enabled' => $r['enabled'], 'scope' => $r['scope'], 'updated_by' => $label, 'updated_at' => now()];
                $updated = DB::table(Tables::ROLE_ACCESS)->where('role_id', $roleId)->update($values);
                if ($updated === 0 && !DB::table(Tables::ROLE_ACCESS)->where('role_id', $roleId)->exists()) {
                    DB::table(Tables::ROLE_ACCESS)->insert($values + ['role_id' => $roleId]);
                }
            }
        });
        // Settings::set() bumps the policy version itself; table writes need an explicit bump.
        if ($plan['admins_mode'] !== null) {
            Settings::set(Settings::ADMINS_MODE, $plan['admins_mode']);
        }
        if ($plan['ai'] !== null) {
            Settings::set(Settings::AI, $plan['ai']);
        }
        PolicyVersion::bump();
        Access::forget();

        foreach ($plan['changes'] as $text) {
            Activity::log('access', $text);
        }
    }

    /** Runs $fn under a short cache lock when the store supports locks. */
    private static function locked(\Closure $fn): array
    {
        try {
            if (Cache::getStore() instanceof \Illuminate\Contracts\Cache\LockProvider) {
                return Cache::lock(self::WRITE_LOCK, 10)->block(5, $fn);
            }
        } catch (\Illuminate\Contracts\Cache\LockTimeoutException $e) {
            throw new ConflictResourceException(self::STALE_MESSAGE);
        }

        return $fn();
    }

    /**
     * Validates a PATCH body and works out exactly what it changes. Pure apart from reads.
     *
     * @return array{loosens:bool,changes:string[],admins_mode:?string,ai:?string,grant_upserts:array<int,?int>,grant_deletes:int[],role_upserts:array<int,array{enabled:bool,scope:string}>}
     * @throws BadRequestException
     */
    public function plan(array $payload, int $now): array
    {
        $plan = [
            'loosens' => false,
            'changes' => [],
            'admins_mode' => null,
            'ai' => null,
            'grant_upserts' => [],
            'grant_deletes' => [],
            'role_upserts' => [],
        ];
        $known = array_intersect_key($payload, array_flip(['admins', 'ai', 'roles']));
        if ($known === []) {
            throw new BadRequestException('Nothing to change. Send admins, ai and/or roles.');
        }

        // ---- admins
        if (array_key_exists('admins', $payload)) {
            $admins = $payload['admins'];
            if (!is_array($admins)) {
                throw new BadRequestException('admins must be an object.');
            }
            if (array_key_exists('mode', $admins)) {
                $mode = $admins['mode'];
                if (!is_string($mode) || !isset(self::ADMIN_RANK[$mode])) {
                    throw new BadRequestException("Invalid admins.mode. Use 'none', 'selected' or 'all'.");
                }
                $current = Settings::adminsMode();
                if ($mode !== $current) {
                    $plan['admins_mode'] = $mode;
                    $plan['loosens'] = $plan['loosens'] || self::ADMIN_RANK[$mode] > self::ADMIN_RANK[$current];
                    $plan['changes'][] = 'Admin access set to ' . ($mode === 'none' ? 'no one' : $mode);
                }
            }
            if (array_key_exists('grants', $admins)) {
                $this->planGrants($admins['grants'], $now, $plan);
            }
        }

        // ---- ai
        if (array_key_exists('ai', $payload)) {
            $ai = $payload['ai'];
            if (!is_string($ai) || !in_array($ai, Settings::AI_MODES, true)) {
                throw new BadRequestException("Invalid ai. Use 'masked' or 'same_as_admins'.");
            }
            if ($ai !== Settings::ai()) {
                $plan['ai'] = $ai;
                $plan['loosens'] = $plan['loosens'] || $ai === 'same_as_admins';
                $plan['changes'][] = $ai === 'masked'
                    ? 'AI and MCP sessions set to always masked'
                    : 'AI and MCP sessions now match admins';
            }
        }

        // ---- roles
        if (array_key_exists('roles', $payload)) {
            $this->planRoles($payload['roles'], $plan);
        }

        return $plan;
    }

    /** @throws BadRequestException */
    private function planGrants(mixed $grants, int $now, array &$plan): void
    {
        if (!is_array($grants) || !array_is_list($grants)) {
            throw new BadRequestException('admins.grants must be a list of {admin_id, duration?}.');
        }
        $admins = [];
        foreach (self::admins() as $a) {
            $admins[$a['admin_id']] = $a;
        }
        $current = [];
        foreach (self::grantRows() as $row) {
            $expires = $row->expires_at === null ? null : (Time::ts($row->expires_at) ?? 0);
            $current[(int)$row->admin_id] = ['expires' => $expires, 'live' => $expires === null || $expires > $now];
        }

        $desired = [];
        foreach ($grants as $g) {
            if (!is_array($g) || !isset($g['admin_id']) || filter_var($g['admin_id'], FILTER_VALIDATE_INT) === false) {
                throw new BadRequestException('Each grant needs a numeric admin_id.');
            }
            $adminId = (int)$g['admin_id'];
            if (!isset($admins[$adminId])) {
                throw new BadRequestException("Admin $adminId is not an active system administrator.");
            }
            if (array_key_exists($adminId, $desired)) {
                throw new BadRequestException("Admin $adminId appears twice in grants.");
            }
            $duration = $g['duration'] ?? null;
            if ($duration !== null && (!is_string($duration) || !array_key_exists($duration, Access::DURATIONS))) {
                throw new BadRequestException("Invalid duration for admin $adminId. Use 1h, 8h, 24h, 7d or forever.");
            }
            $desired[$adminId] = $duration;
        }

        foreach ($desired as $adminId => $duration) {
            $existing = $current[$adminId] ?? null;
            $live = $existing !== null && $existing['live'];
            $name = $admins[$adminId]['name'];
            if ($duration === null) {
                if ($live) {
                    continue; // keeps its expiry
                }
                // The client believes a grant exists that does not (expired or revoked since it
                // loaded the list): never turn that into a new grant.
                throw new ConflictResourceException("$name has no current grant to keep. Reload and try again, or send a duration to give a new grant.");
            }
            $expires = Access::expiryFor($duration, $now);
            $plan['grant_upserts'][$adminId] = $expires;
            $plan['changes'][] = $name . ' was given real values ' . self::SPANS[$duration];
            // New grant, or a re-timed one that ends later than the current one: loosening.
            if (!$live || ($existing['expires'] !== null && ($expires === null || $expires > $existing['expires']))) {
                $plan['loosens'] = true;
            }
        }
        foreach ($current as $adminId => $c) {
            if (array_key_exists($adminId, $desired)) {
                continue;
            }
            $plan['grant_deletes'][] = $adminId;
            if ($c['live'] && isset($admins[$adminId])) {
                $plan['changes'][] = 'Real values removed for ' . $admins[$adminId]['name'];
            }
        }
    }

    /** @throws BadRequestException */
    private function planRoles(mixed $roles, array &$plan): void
    {
        if (!is_array($roles) || !array_is_list($roles)) {
            throw new BadRequestException('roles must be a list of {role_id, enabled, scope}.');
        }
        $names = [];
        foreach (self::roleRows() as $r) {
            $names[(int)$r->id] = (string)$r->name;
        }
        $access = self::roleAccessRows();
        $seen = [];
        foreach ($roles as $r) {
            if (!is_array($r) || !isset($r['role_id']) || filter_var($r['role_id'], FILTER_VALIDATE_INT) === false) {
                throw new BadRequestException('Each role needs a numeric role_id.');
            }
            $roleId = (int)$r['role_id'];
            if (!isset($names[$roleId])) {
                throw new BadRequestException("Role $roleId does not exist.");
            }
            if (isset($seen[$roleId])) {
                throw new BadRequestException("Role $roleId appears twice.");
            }
            $seen[$roleId] = true;
            $old = $access[$roleId] ?? ['enabled' => false, 'scope' => 'except_restricted'];
            $enabled = array_key_exists('enabled', $r) ? filter_var($r['enabled'], FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE) : $old['enabled'];
            if ($enabled === null) {
                throw new BadRequestException("Invalid enabled flag for role $roleId.");
            }
            $scope = $r['scope'] ?? $old['scope'];
            if (!is_string($scope) || !in_array($scope, Access::SCOPES, true)) {
                throw new BadRequestException("Invalid scope for role $roleId. Use 'all' or 'except_restricted'.");
            }
            if ($enabled === $old['enabled'] && $scope === $old['scope']) {
                continue;
            }
            $plan['role_upserts'][$roleId] = ['enabled' => $enabled, 'scope' => $scope];
            $name = $names[$roleId];
            $scopeText = $scope === 'all' ? 'all classes' : 'all except restricted';
            if ($enabled && !$old['enabled']) {
                $plan['loosens'] = true;
                $plan['changes'][] = "$name now sees real values ($scopeText)";
            } elseif (!$enabled && $old['enabled']) {
                $plan['changes'][] = "$name is masked again";
            } elseif ($enabled) {
                // enabled both before and after: scope changed
                if ($scope === 'all') {
                    $plan['loosens'] = true;
                }
                $plan['changes'][] = "$name now sees real values for $scopeText";
            }
            // disabled before and after with a new scope: stored without an activity row
            // (patch() writes role_upserts even when there is no change text)
        }
    }

    /**
     * Active, full system administrators (df-compliance restricted admins, i.e. admins with a
     * role, are excluded: DreamFactory treats them as role users).
     *
     * @return list<array{admin_id:int,name:string,email:string}>
     */
    private static function admins(): array
    {
        $rows = DB::table('user')
            ->where('is_sys_admin', true)
            ->where('is_active', true)
            ->whereNotExists(function ($q) {
                $q->select(DB::raw(1))->from('user_to_app_to_role')->whereColumn('user_to_app_to_role.user_id', 'user.id');
            })
            ->orderBy('id')
            ->get(['id', 'name', 'first_name', 'last_name', 'email']);
        $out = [];
        foreach ($rows as $row) {
            $name = trim((string)$row->name);
            if ($name === '') {
                $name = trim((string)$row->first_name . ' ' . (string)$row->last_name);
            }
            $out[] = [
                'admin_id' => (int)$row->id,
                'name' => $name !== '' ? $name : (string)$row->email,
                'email' => (string)$row->email,
            ];
        }

        return $out;
    }

    private static function grantRows(): iterable
    {
        return DB::table(Tables::ADMIN_GRANT)->orderBy('id')->get(['admin_id', 'expires_at']);
    }

    private static function roleRows(): iterable
    {
        return DB::table('role')->orderBy('name')->get(['id', 'name']);
    }

    /** @return array<int,array{enabled:bool,scope:string}> */
    private static function roleAccessRows(): array
    {
        $out = [];
        foreach (DB::table(Tables::ROLE_ACCESS)->get(['role_id', 'enabled', 'scope']) as $row) {
            $out[(int)$row->role_id] = [
                'enabled' => (bool)$row->enabled,
                'scope' => $row->scope === 'all' ? 'all' : 'except_restricted',
            ];
        }

        return $out;
    }
}

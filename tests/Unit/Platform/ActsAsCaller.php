<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Platform;

use DreamFactory\Core\Masking\Support\Caller;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Facades\Schema;

/**
 * Gives a harness test a DreamFactory session (the keys df-core's Session helper reads), so
 * Support\Caller resolves the caller the way it does on a live request.
 *
 * Use in a DreamFactory\Core\Masking\Tests\TestCase subclass after bootHarness().
 */
trait ActsAsCaller
{
    /**
     * @param int|null $userId  null = no user (an API key app, or nobody)
     * @param bool     $sysAdmin user.is_sys_admin
     * @param int|null $roleId  role of the session (a role user, or a restricted admin)
     */
    protected function actAs(?int $userId, bool $sysAdmin = true, ?int $roleId = null, ?int $appId = null): void
    {
        if (!class_exists('Session', false)) {
            class_alias(\Illuminate\Support\Facades\Session::class, 'Session'); // df-core's Session helper uses the global alias
        }
        $store = new Store('df-test', new ArraySessionHandler(60));
        if ($userId !== null) {
            $store->put('user', ['id' => $userId, 'is_sys_admin' => $sysAdmin, 'name' => 'User ' . $userId]);
        }
        $store->put('has_role', $roleId !== null);
        if ($roleId !== null) {
            $store->put('role', ['id' => $roleId]);
        }
        if ($appId !== null) {
            $store->put('app', ['id' => $appId]);
        }
        $this->app->instance('session', $store);
        Facade::clearResolvedInstance('session');
        Caller::forget();
    }

    /** Makes $rootId the df-compliance root admin (adds user.is_root_admin like df-compliance does). */
    protected function designateRootAdmin(int $rootId): void
    {
        if (!Schema::hasColumn('user', 'is_root_admin')) {
            Schema::table('user', function ($t) {
                $t->boolean('is_root_admin')->default(false);
            });
        }
        $this->db()->table('user')->update(['is_root_admin' => false]);
        $this->db()->table('user')->where('id', $rootId)->update(['is_root_admin' => true]);
        Caller::forget();
    }
}

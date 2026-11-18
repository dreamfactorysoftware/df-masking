<?php

namespace DreamFactory\Core\Masking;

use DreamFactory\Core\Enums\LicenseLevel;
use DreamFactory\Core\Masking\Console\MaskingCommand;
use DreamFactory\Core\Masking\Resources\DataMasking;
use DreamFactory\Core\Masking\Support\PolicyVersion;
use DreamFactory\Core\Masking\Support\Tables;
use DreamFactory\Core\System\Components\SystemResourceManager;
use DreamFactory\Core\System\Components\SystemResourceType;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\ServiceProvider as BaseServiceProvider;

/**
 * Laravel auto-discovered provider (composer extra.laravel.providers).
 *
 * register():
 *  - merges config/df-masking.php
 *  - adds the Gold system resources `data_masking` (Data Masking) and `security_baseline`
 *    (Compliance baselines, when that class is present)
 *  - lets Enforcement\Registrar attach its API event listeners. That happens in register() on
 *    purpose: df-core subscribes its ServiceEventHandler (and df-script its scriptable handler)
 *    in boot(), so listeners registered here run first and event scripts see masked data.
 *
 * boot(): migrations, the df:masking console command, cleanup listeners for deleted
 * services, roles and users, Scanner\Hooks (background re-scan of a covered service after
 * it is created or changed), and a terminating callback that starts deferred background scans.
 */
class ServiceProvider extends BaseServiceProvider
{
    public const VERSION = '0.1.0';

    private const SECURITY_BASELINE = 'DreamFactory\\Core\\Masking\\Resources\\SecurityBaseline';
    private const REGISTRAR = 'DreamFactory\\Core\\Masking\\Enforcement\\Registrar';
    private const SCAN_HOOKS = 'DreamFactory\\Core\\Masking\\Scanner\\Hooks';
    private const SCAN_LAUNCHER = 'DreamFactory\\Core\\Masking\\Scanner\\ScanLauncher';

    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/df-masking.php', 'df-masking');

        $addTypes = function (SystemResourceManager $df): void {
            static::addSystemResourceTypes($df);
        };
        if ($this->app->resolved('df.system.resource')) {
            $addTypes($this->app->make('df.system.resource'));
        } else {
            $this->app->resolving('df.system.resource', $addTypes);
        }

        if (class_exists(self::REGISTRAR)) {
            try {
                call_user_func([self::REGISTRAR, 'register'], $this->app);
            } catch (\Throwable $e) {
                Log::error('df-masking: enforcement could not be registered: ' . $e->getMessage());
            }
        }
    }

    public function boot(): void
    {
        $configPath = __DIR__ . '/../config/df-masking.php';
        $this->publishes([$configPath => $this->app->configPath('df-masking.php')], 'config');
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');

        if ($this->app->runningInConsole()) {
            $this->commands([MaskingCommand::class]);
        }

        $this->registerCleanupListeners();

        // Background re-scan of a covered service when it is created or changed. Registered in
        // boot() (after df-core's ServiceEventHandler, which purges the stale service config
        // first), unlike the enforcement listeners, which must run first and use register().
        if (class_exists(self::SCAN_HOOKS)) {
            try {
                call_user_func([self::SCAN_HOOKS, 'register'], $this->app);
            } catch (\Throwable $e) {
                Log::error('df-masking: scan hooks could not be registered: ' . $e->getMessage());
            }
        }

        // Background re-scans deferred by the throttle (ScanLauncher::startThrottled) start after
        // the response of the first request that finds one due: one cache read per request, and
        // nothing at all happens in the response itself.
        if (!$this->app->runningInConsole() && class_exists(self::SCAN_LAUNCHER) && method_exists($this->app, 'terminating')) {
            $this->app->terminating(static function (): void {
                try {
                    call_user_func([self::SCAN_LAUNCHER, 'tick']);
                } catch (\Throwable $e) {
                    // never let a deferred scan affect a request
                }
            });
        }
    }

    public static function addSystemResourceTypes(SystemResourceManager $df): void
    {
        if ($df->getResourceType('data_masking') === null) {
            $df->addType(new SystemResourceType([
                'name' => 'data_masking',
                'label' => 'Data Masking',
                'description' => 'Classifies database columns and masks sensitive values for apps, roles and AI tools.',
                'class_name' => DataMasking::class,
                'subscription_required' => LicenseLevel::GOLD,
                'singleton' => false,
                'read_only' => false,
            ]));
        }
        if (class_exists(self::SECURITY_BASELINE) && $df->getResourceType('security_baseline') === null) {
            $df->addType(new SystemResourceType([
                'name' => 'security_baseline',
                'label' => 'Compliance baselines',
                'description' => 'One-click presets, live checklists and evidence for HIPAA, PCI DSS, GLBA, CJIS, GDPR, SOC 2 and ISO 27001.',
                'class_name' => self::SECURITY_BASELINE,
                'subscription_required' => LicenseLevel::GOLD,
                'singleton' => false,
                'read_only' => false,
            ]));
        }
    }

    /**
     * Deleted services/roles/users: drop their df-masking rows (foreign keys cascade too, but
     * SQLite system databases may run without foreign key enforcement) and invalidate caches.
     * Modified services (renamed, re-pointed): invalidate caches so coverage and policy reload.
     */
    private function registerCleanupListeners(): void
    {
        $events = $this->app['events'];

        $events->listen('DreamFactory\\Core\\Events\\ServiceDeletedEvent', function ($event): void {
            $id = isset($event->service) ? (int)$event->service->getKey() : 0;
            self::cleanup(function () use ($id): void {
                if ($id > 0) {
                    DB::table(Tables::COLUMN)->where('service_id', $id)->delete();
                    DB::table(Tables::SCAN)->where('service_id', $id)->update(['service_id' => null]);
                }
            });
        });
        $events->listen('DreamFactory\\Core\\Events\\ServiceModifiedEvent', function (): void {
            self::cleanup(null);
        });
        $events->listen('DreamFactory\\Core\\Events\\RoleDeletedEvent', function ($event): void {
            $id = isset($event->role) ? (int)$event->role->getKey() : 0;
            self::cleanup(function () use ($id): void {
                if ($id > 0) {
                    DB::table(Tables::ROLE_ACCESS)->where('role_id', $id)->delete();
                }
            });
        });
        $events->listen('DreamFactory\\Core\\Events\\UserDeletedEvent', function ($event): void {
            $id = isset($event->user) ? (int)$event->user->getKey() : 0;
            self::cleanup(function () use ($id): void {
                if ($id > 0) {
                    DB::table(Tables::ADMIN_GRANT)->where('admin_id', $id)->delete();
                }
            });
        });
    }

    private static function cleanup(?\Closure $work): void
    {
        try {
            if ($work !== null) {
                $work();
            }
        } catch (\Throwable $e) {
            // Tables not migrated yet, or the row is already gone: nothing to clean.
            Log::debug('df-masking: cleanup skipped: ' . $e->getMessage());
        }
        PolicyVersion::bump();
    }
}

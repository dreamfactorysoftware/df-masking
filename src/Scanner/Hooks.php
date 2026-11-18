<?php

namespace DreamFactory\Core\Masking\Scanner;

use DreamFactory\Core\Masking\Support\Activity;
use DreamFactory\Core\Masking\Support\License;
use Illuminate\Support\Facades\Log;

/**
 * Keeps classifications current without anyone pressing Scan: when a covered SQL service is
 * created or its configuration changes (DreamFactory's ServiceModifiedEvent, dispatched after the
 * save commits), a background scan of that service is requested right away
 * (ScanLauncher::startThrottled with no throttle: once any scan has run or the mode is not Off,
 * even after a scan of empty databases; one scan at a time, never sampling warehouses). Nothing
 * is requested when the instance's license level is not Gold (Support\License).
 *
 * Call Hooks::register($app) from the package ServiceProvider's boot(), so the listener runs after
 * df-core's ServiceEventHandler has purged the stale service configuration.
 */
final class Hooks
{
    public const SERVICE_MODIFIED = 'DreamFactory\\Core\\Events\\ServiceModifiedEvent';

    private function __construct()
    {
    }

    /** @param \Illuminate\Contracts\Foundation\Application|\Illuminate\Contracts\Container\Container $app */
    public static function register($app): void
    {
        // A closure, not [class, method]: Laravel resolves array listeners through the container,
        // and this class cannot be instantiated (that would make every service save throw).
        $app['events']->listen(self::SERVICE_MODIFIED, static function (object $event): void {
            self::onServiceModified($event);
        });
    }

    public static function onServiceModified(object $event): void
    {
        try {
            if (!License::isGold()) {
                return;
            }
            $service = $event->service ?? null;
            if (!is_object($service) || !(bool) ($service->is_active ?? false)) {
                return;
            }
            $name = (string) ($service->name ?? '');
            $type = (string) ($service->type ?? '');
            if ($name === '' || $type === '' || !Services::isCoveredType($type, $name)) {
                return;
            }
            // No throttle: a configuration change can rename every table (schema, database), and
            // until the re-scan the new names carry name-only verdicts. One scan at a time still:
            // with a scan running, this one runs at its end.
            ScanLauncher::startThrottled($name, Activity::SYSTEM, 0);
        } catch (\Throwable $e) {
            // Never let a background-scan hook fail a service save.
            Log::debug('df-masking: service change hook skipped: ' . $e->getMessage());
        }
    }
}

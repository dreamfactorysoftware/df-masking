<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Enforcement;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Log;

/**
 * Wires Data Masking enforcement into DreamFactory without changing df-core.
 *
 * Called from the package ServiceProvider::register(). Laravel calls listeners in registration
 * order, and df-core subscribes its ServiceEventHandler (df-script its ScriptableEventHandler,
 * df-logger and others theirs) in boot(), which always runs after every register(). So the
 * listeners added here are the first to see each PreProcessApiEvent, PostProcessApiEvent and
 * ApiEvent: event scripts, the request log and notifications get masked data (same technique as
 * df-trial's ServiceProvider).
 *
 * The _spec middleware is pushed onto DreamFactory's df.api route group once the application
 * has booted (the group is defined in df-core's boot()), so it runs after authentication.
 *
 * The listener closures always return null: a listener returning false would stop event
 * propagation and silence every listener after it.
 */
final class Registrar
{
    public const PRE_PROCESS = 'DreamFactory\\Core\\Events\\PreProcessApiEvent';
    public const POST_PROCESS = 'DreamFactory\\Core\\Events\\PostProcessApiEvent';
    public const FINAL = 'DreamFactory\\Core\\Events\\ApiEvent';

    public const MIDDLEWARE_ALIAS = 'df.masking';

    private function __construct()
    {
    }

    public static function register(Application $app): void
    {
        if (!class_exists(self::PRE_PROCESS) || !class_exists(self::POST_PROCESS) || !class_exists(self::FINAL)) {
            Log::warning('df-masking: DreamFactory API events not found (df-core too old?): masking is not enforced.');

            return;
        }

        $app->singleton(Listener::class, fn () => new Listener());

        $events = $app['events'];
        $events->listen(self::PRE_PROCESS, function ($event) use ($app): void {
            $app->make(Listener::class)->onPreProcess($event);
        });
        $events->listen(self::POST_PROCESS, function ($event) use ($app): void {
            $app->make(Listener::class)->onPostProcess($event);
        });
        $events->listen(self::FINAL, function ($event) use ($app): void {
            $app->make(Listener::class)->onFinal($event);
        });

        $app->booted(function () use ($app): void {
            try {
                $router = $app['router'];
                $router->aliasMiddleware(self::MIDDLEWARE_ALIAS, SpecMiddleware::class);
                if (method_exists($router, 'hasMiddlewareGroup') && !$router->hasMiddlewareGroup('df.api')) {
                    Log::warning('df-masking: the df.api middleware group is missing: _spec models are not masked.');

                    return;
                }
                $router->pushMiddlewareToGroup('df.api', self::MIDDLEWARE_ALIAS);
            } catch (\Throwable $e) {
                Log::error('df-masking: could not register the _spec middleware: ' . $e->getMessage());
            }
        });
    }
}

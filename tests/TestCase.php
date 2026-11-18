<?php

namespace DreamFactory\Core\Masking\Tests;

use DreamFactory\Core\Masking\Support\Access;
use DreamFactory\Core\Masking\Support\Caller;
use DreamFactory\Core\Masking\Support\Coverage;
use DreamFactory\Core\Masking\Support\Formats;
use DreamFactory\Core\Masking\Support\PolicyVersion;
use DreamFactory\Core\Masking\Support\Settings;
use Illuminate\Cache\CacheManager;
use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Database\Capsule\Manager as Capsule;
use Illuminate\Encryption\Encrypter;
use Illuminate\Events\Dispatcher;
use Illuminate\Support\DateFactory;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\TestCase as BaseTestCase;
use Psr\Log\NullLogger;

/**
 * Base class for df-masking unit tests that need Laravel services.
 *
 * bootHarness() builds a fresh container per test: config (df-masking defaults), an array
 * cache, an in-memory SQLite "system database" with stub DreamFactory tables (service, user,
 * role, user_to_app_to_role) plus every df-masking migration, an encrypter, events and a null
 * logger. Facades and helpers (config(), now(), app()) resolve against it. Nothing touches a
 * live instance.
 */
abstract class TestCase extends BaseTestCase
{
    protected Container $app;
    protected Capsule $capsule;

    protected function bootHarness(array $config = []): void
    {
        $app = new Container();
        Container::setInstance($app);

        $packageConfig = require dirname(__DIR__) . '/config/df-masking.php';
        $app->instance('config', new Repository(array_replace_recursive([
            'app' => ['timezone' => 'UTC', 'cipher' => 'AES-256-CBC'],
            'cache' => ['default' => 'array', 'stores' => ['array' => ['driver' => 'array', 'serialize' => true]], 'prefix' => 'test'],
            'df-masking' => $packageConfig,
        ], $config)));

        $app->instance('events', new Dispatcher($app));
        $app->instance('log', new NullLogger());
        $app->instance('date', new DateFactory());
        $app->instance('encrypter', new Encrypter(random_bytes(32), 'AES-256-CBC'));
        $app->singleton('cache', fn ($app) => new CacheManager($app));
        $app->singleton('cache.store', fn ($app) => $app['cache']->driver());

        $capsule = new Capsule($app);
        $capsule->addConnection(['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '', 'foreign_key_constraints' => true]);
        $capsule->setEventDispatcher($app['events']);
        $capsule->setAsGlobal();
        $capsule->bootEloquent();
        $app->instance('db', $capsule->getDatabaseManager());
        $app->bind('db.connection', fn ($app) => $app['db']->connection());
        $app->bind('db.schema', fn ($app) => $app['db']->connection()->getSchemaBuilder());
        $this->capsule = $capsule;

        Facade::clearResolvedInstances();
        Facade::setFacadeApplication($app);
        $this->app = $app;
        self::registerFacadeAliases();

        $this->createDreamFactoryStubTables();
        $this->runPackageMigrations();
        $this->forgetMemos();
    }

    protected function tearDown(): void
    {
        $this->forgetMemos();
        if (isset($this->app)) {
            Facade::clearResolvedInstances();
            Facade::setFacadeApplication(null);
            Container::setInstance(null);
        }
        parent::tearDown();
    }

    /** The global facade aliases DreamFactory code uses (config/app.php aliases in an install). */
    private static function registerFacadeAliases(): void
    {
        foreach ([
            'Event' => \Illuminate\Support\Facades\Event::class,
            'Log' => \Illuminate\Support\Facades\Log::class,
            'Cache' => \Illuminate\Support\Facades\Cache::class,
            'DB' => \Illuminate\Support\Facades\DB::class,
            'Config' => \Illuminate\Support\Facades\Config::class,
            'Schema' => \Illuminate\Support\Facades\Schema::class,
            'Crypt' => \Illuminate\Support\Facades\Crypt::class,
        ] as $alias => $class) {
            if (!class_exists($alias, false)) {
                class_alias($class, $alias);
            }
        }
    }

    /** Drops every per-process memo the Support classes keep. */
    protected function forgetMemos(): void
    {
        PolicyVersion::forget();
        Settings::flush();
        Access::forget();
        Formats::forget();
        Coverage::forget();
        Caller::forget();
    }

    protected function db(): \Illuminate\Database\Connection
    {
        return $this->capsule->getConnection();
    }

    /** Minimal shapes of the DreamFactory core tables df-masking references. */
    private function createDreamFactoryStubTables(): void
    {
        $schema = Schema::getFacadeRoot();
        $schema->create('service', function ($t) {
            $t->increments('id');
            $t->string('name', 40)->unique();
            $t->string('label', 80)->nullable();
            $t->string('type', 40);
            $t->boolean('is_active')->default(true);
        });
        $schema->create('user', function ($t) {
            $t->increments('id');
            $t->string('name')->nullable();
            $t->string('first_name')->nullable();
            $t->string('last_name')->nullable();
            $t->string('email')->unique();
            $t->boolean('is_sys_admin')->default(false);
            $t->boolean('is_active')->default(true);
        });
        $schema->create('role', function ($t) {
            $t->increments('id');
            $t->string('name', 64)->unique();
        });
        $schema->create('user_to_app_to_role', function ($t) {
            $t->increments('id');
            $t->unsignedInteger('user_id');
            $t->unsignedInteger('app_id')->nullable();
            $t->unsignedInteger('role_id');
        });
    }

    private function runPackageMigrations(): void
    {
        $files = glob(dirname(__DIR__) . '/database/migrations/*.php') ?: [];
        sort($files);
        foreach ($files as $file) {
            $migration = require $file;
            if (is_object($migration) && method_exists($migration, 'up')) {
                $migration->up();
            }
        }
    }
}

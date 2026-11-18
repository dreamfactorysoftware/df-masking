<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Scanner;

use DreamFactory\Core\Database\Schema\ColumnSchema;
use DreamFactory\Core\Database\Schema\TableSchema;
use DreamFactory\Core\Masking\Classifier\NameOnly;
use DreamFactory\Core\Masking\Scanner\Services;
use DreamFactory\Core\Masking\Support\Caller;
use DreamFactory\Core\Masking\Support\Coverage;
use DreamFactory\Core\Masking\Support\Formats;
use DreamFactory\Core\Masking\Support\PolicyVersion;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\SqlDb\Services\SqlDb;
use Illuminate\Cache\CacheManager;
use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Database\Capsule\Manager as Capsule;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\SQLiteConnection;
use Illuminate\Support\DateFactory;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Facades\Schema;
use Psr\Log\NullLogger;

/**
 * Scanner test environment: a minimal Laravel container on an in-memory SQLite system database
 * (config, db, cache, date, log), the package migrations, DreamFactory's `service` table, and a
 * fake service manager whose services are real DreamFactory\Core\SqlDb\Services\SqlDb subclasses
 * backed by SQLite databases, exposing DreamFactory TableSchema/ColumnSchema objects the way
 * df-sqldb's SQLite schema does.
 */
final class Harness
{
    /** @var array<string,object> */
    public static array $services = [];

    public static function boot(): Container
    {
        $app = new Container();
        Container::setInstance($app);
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication($app);
        $app->instance('config', new Repository([
            'app' => ['timezone' => 'UTC'],
            'cache' => ['default' => 'array', 'stores' => ['array' => ['driver' => 'array', 'serialize' => false]]],
            'database' => ['default' => 'sqlite'],
            'df-masking' => ['token_key' => base64_encode(str_repeat("\x2a", 32)), 'scan' => ['stale_minutes' => 5]],
        ]));
        $capsule = new Capsule($app);
        $capsule->addConnection(['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        $capsule->setAsGlobal();
        $capsule->bootEloquent();
        $app->instance('db', $capsule->getDatabaseManager());
        $app->bind('db.schema', fn () => $capsule->getConnection()->getSchemaBuilder());
        $app->singleton('cache', fn ($app) => new CacheManager($app));
        $app->singleton('cache.store', fn ($app) => $app['cache']->driver());
        $app->singleton('date', fn () => new DateFactory());
        $app->instance('log', new NullLogger());
        self::$services = [];
        $app->instance('df.service', new class {
            public function getService(string $name): object
            {
                return Harness::$services[$name] ?? throw new \RuntimeException("no service $name");
            }

            public function getServiceType(string $type): ?object
            {
                return new class ($type) {
                    public function __construct(private string $type)
                    {
                    }

                    public function getGroup(): string
                    {
                        return in_array($this->type, ['sqlite', 'pgsql', 'snowflake'], true) ? 'Database' : 'File';
                    }
                };
            }
        });
        Settings::flush();
        PolicyVersion::forget();
        Caller::forget();
        Coverage::forget();
        Formats::forget();
        Services::forget();
        NameOnly::forget();

        Schema::create('service', function (Blueprint $t) {
            $t->increments('id');
            $t->string('name');
            $t->string('label')->nullable();
            $t->string('type');
            $t->boolean('is_active')->default(true);
            $t->text('config')->nullable();
        });
        foreach (['user', 'role'] as $table) {
            Schema::create($table, function (Blueprint $t) {
                $t->increments('id');
                $t->string('name')->nullable();
            });
        }
        $files = glob(dirname(__DIR__, 3) . '/database/migrations/*.php') ?: [];
        sort($files);
        foreach ($files as $file) {
            $migration = require $file;
            if (is_object($migration) && method_exists($migration, 'up')) {
                $migration->up();
            }
        }
        return $app;
    }

    /** Registers a fake covered service over $pdo and its `service` row. */
    public static function addService(string $name, \PDO $pdo, string $type = 'sqlite', bool $active = true): int
    {
        $id = (int) Capsule::table('service')->insertGetId(['name' => $name, 'label' => ucfirst($name), 'type' => $type, 'is_active' => $active]);
        self::$services[$name] = new FakeSqliteService($name, new SQLiteConnection($pdo), $type === 'snowflake' ? 'snowflake' : 'sqlite');
        return $id;
    }

    /** A SQLite database file with the given DDL and rows. */
    public static function sqlite(array $ddl, array $rows = []): \PDO
    {
        $pdo = new \PDO('sqlite::memory:', null, null, [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]);
        foreach ($ddl as $sql) {
            $pdo->exec($sql);
        }
        foreach ($rows as $table => $list) {
            if ($list === []) {
                continue;
            }
            $cols = array_keys($list[0]);
            $st = $pdo->prepare('INSERT INTO "' . $table . '" (' . implode(',', array_map(fn ($c) => '"' . $c . '"', $cols)) . ') VALUES (' . implode(',', array_fill(0, count($cols), '?')) . ')');
            $pdo->beginTransaction();
            foreach ($list as $r) {
                $st->execute(array_values($r));
            }
            $pdo->commit();
        }
        return $pdo;
    }
}

/**
 * A df-sqldb service whose schema comes from SQLite catalog pragmas, shaped like df-sqldb's
 * SqliteSchema output (lower-cased dbType, DreamFactory simple types, quoted names, PK/FK flags).
 */
final class FakeSqliteService extends SqlDb
{
    public array $removed = [];
    public bool $failSchema = false;
    /** Columns whose values cannot be read (selecting them fails, like SQL Server rowversion as text). */
    public array $unreadable = [];

    public function __construct(string $name, private readonly SQLiteConnection $conn, private readonly string $driverName = 'sqlite')
    {
        $this->name = $name;
    }

    public function __destruct()
    {
    }

    public function getConnection()
    {
        if ($this->driverName === 'sqlite' && $this->unreadable === []) {
            return $this->conn;
        }
        // Selecting an unreadable column fails the statement, as SQL Server does for a rowversion
        // cast to text (the scanner quotes names itself, so the failure is simulated here).
        $unreadable = array_map(static fn ($c) => '"' . str_replace('"', '""', $c) . '"', $this->unreadable);
        return new class ($this->conn, $this->driverName, $unreadable) extends SQLiteConnection {
            public function __construct(SQLiteConnection $c, private string $driver, private array $unreadable)
            {
                parent::__construct($c->getPdo());
            }

            public function getDriverName()
            {
                return $this->driver;
            }

            protected function run($query, $bindings, \Closure $callback)
            {
                foreach ($this->unreadable as $quoted) {
                    if (str_contains((string) $query, $quoted)) {
                        $e = new \PDOException('SQLSTATE[HY000]: General error: 1 cannot render the value as text');
                        $e->errorInfo = ['HY000', 1, 'cannot render the value as text'];
                        throw $e;
                    }
                }
                return parent::run($query, $bindings, $callback);
            }
        };
    }

    public function removeFromCache($key)
    {
        $this->removed[] = $key;
        return true;
    }

    public function getTableNames($schema = null, $refresh = false)
    {
        if ($this->failSchema) {
            throw new \PDOException('SQLSTATE[HY000]: unable to open database file');
        }
        $out = [];
        foreach ($this->conn->select("SELECT name, type FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY name") as $r) {
            $out[strtolower($r->name)] = new TableSchema(['name' => $r->name, 'resourceName' => $r->name, 'internalName' => $r->name,
                'quotedName' => '"' . $r->name . '"', 'isView' => $r->type === 'view']);
        }
        return $out;
    }

    public function getTableSchema($name, $refresh = false)
    {
        $names = $this->getTableNames();
        $ts = $names[strtolower($name)] ?? null;
        if ($ts === null) {
            return null;
        }
        $q = '"' . str_replace('"', '""', $ts->name) . '"';
        $fks = [];
        foreach ($this->conn->select("PRAGMA foreign_key_list($q)") as $fk) {
            $fks[$fk->from] = $fk->table;
        }
        foreach ($this->conn->select("PRAGMA table_info($q)") as $c) {
            $db = strtolower((string) $c->type);
            $col = new ColumnSchema(['name' => $c->name]);
            $col->dbType = $db;
            // Exactly like df-database: quote + name + quote, unescaped (the scanner must not use it).
            $col->quotedName = '"' . $c->name . '"';
            $col->isPrimaryKey = (int) $c->pk > 0;
            $col->isForeignKey = isset($fks[$c->name]);
            $col->refTable = $fks[$c->name] ?? null;
            $col->type = match (true) {
                str_contains($db, 'int') => $col->isPrimaryKey ? 'id' : ($col->isForeignKey ? 'reference' : 'integer'),
                str_contains($db, 'char') => 'string',
                str_contains($db, 'date') => 'date',
                str_contains($db, 'blob') => 'binary',
                str_contains($db, 'real'), str_contains($db, 'doub') => 'double',
                str_contains($db, 'bool') => 'boolean',
                default => 'text',
            };
            $ts->addColumn($col);
            if ($col->isPrimaryKey) {
                $ts->addPrimaryKey($c->name);
            }
        }
        return $ts;
    }
}

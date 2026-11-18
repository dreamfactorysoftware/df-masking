<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Scanner;

use DreamFactory\Core\Masking\Enforcement\Policy;
use DreamFactory\Core\Masking\Scanner\ColumnWriter;
use DreamFactory\Core\Masking\Scanner\Examples;
use DreamFactory\Core\Masking\Support\Caller;
use DreamFactory\Core\Masking\Support\Catalog;
use DreamFactory\Core\Masking\Support\Coverage;
use DreamFactory\Core\Masking\Support\Formats;
use DreamFactory\Core\Masking\Support\PolicyVersion;
use DreamFactory\Core\Masking\Support\Retry;
use DreamFactory\Core\Masking\Support\ScanHistory;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use Illuminate\Cache\CacheManager;
use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Events\Dispatcher;
use Illuminate\Database\Capsule\Manager as Capsule;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\DateFactory;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

/**
 * Opt-in, on real system databases: set DM_SYSDB_URLS to a ';'-separated list
 * of throwaway databases, e.g.
 *   pgsql://postgres:pw@pg:5432/dm_port;mysql://root:pw@mysql:3306/dm_port;sqlsrv://sa:pw@mssql:1433/dm_port
 * Each database must be empty and is left empty. Runs the package migrations there (with the
 * MySQL utf8mb4_unicode_ci / SQL Server *_CI_AS defaults DreamFactory installs use), then checks
 * that accent and case variants are separate dm_column rows, that a lost insert race does not
 * abort the scan transaction (PostgreSQL 25P02), and that the upgrade migration rolls back and
 * re-applies.
 */
final class SystemDbPortabilityTest extends TestCase
{
    public static function databases(): iterable
    {
        $urls = array_values(array_filter(array_map('trim', explode(';', (string)getenv('DM_SYSDB_URLS')))));
        if ($urls === []) {
            yield 'not configured' => [null];
            return;
        }
        foreach ($urls as $url) {
            yield (string)parse_url($url, PHP_URL_SCHEME) => [$url];
        }
    }

    private static function config(string $url): array
    {
        $u = parse_url($url);
        $driver = $u['scheme'];
        $c = ['driver' => $driver, 'host' => $u['host'], 'port' => $u['port'] ?? null, 'database' => ltrim($u['path'], '/'),
            'username' => urldecode($u['user'] ?? ''), 'password' => urldecode($u['pass'] ?? ''), 'prefix' => ''];
        if ($driver === 'mysql') {
            $c += ['charset' => 'utf8mb4', 'collation' => 'utf8mb4_unicode_ci'];
        }
        if ($driver === 'sqlsrv') {
            $c += ['trust_server_certificate' => true, 'encrypt' => 'no'];
        }
        if ($driver === 'pgsql') {
            $c += ['charset' => 'utf8', 'schema' => 'public', 'search_path' => 'public'];
        }

        return $c;
    }

    private function boot(string $url): void
    {
        $app = new Container();
        Container::setInstance($app);
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication($app);
        $app->instance('config', new Repository([
            'app' => ['timezone' => 'UTC'],
            'cache' => ['default' => 'array', 'stores' => ['array' => ['driver' => 'array', 'serialize' => false]]],
            'df-masking' => ['token_key' => base64_encode(str_repeat("\x2a", 32))],
        ]));
        $capsule = new Capsule($app);
        $capsule->addConnection(self::config($url));
        $capsule->addConnection(self::config($url), 'other');
        $capsule->setEventDispatcher(new Dispatcher($app));
        $capsule->setAsGlobal();
        $app->instance('db', $capsule->getDatabaseManager());
        $app->bind('db.schema', fn () => $capsule->getConnection()->getSchemaBuilder());
        $app->singleton('cache', fn ($app) => new CacheManager($app));
        $app->singleton('cache.store', fn ($app) => $app['cache']->driver());
        $app->singleton('date', fn () => new DateFactory());
        $app->instance('log', new NullLogger());
        foreach ([Settings::class, PolicyVersion::class, Coverage::class, Formats::class, Caller::class] as $c) {
            method_exists($c, 'flush') ? $c::flush() : $c::forget();
        }
        ScanHistory::forget();
        Policy::forget();
    }

    private function migrations(): array
    {
        $files = glob(dirname(__DIR__, 3) . '/database/migrations/*.php') ?: [];
        sort($files);

        return array_map(fn ($f) => require $f, $files);
    }

    private function migration(string $name): object
    {
        return require dirname(__DIR__, 3) . '/database/migrations/' . $name . '.php';
    }

    private function cleanup(): void
    {
        foreach (array_reverse($this->migrations()) as $m) {
            $m->down();
        }
        foreach (['user_to_app_to_role', 'role', 'user', 'service'] as $t) {
            Schema::dropIfExists($t);
        }
    }

    private static function col(string $verdict, ?string $class, int $score): array
    {
        return [
            'db_type' => 'text', 'ordinal' => 1, 'fingerprint' => str_repeat('a', 64), 'raw' => null, 'df_type' => 'string', 'name_only' => false,
            'result' => ['verdict' => $verdict, 'class' => $class, 'tier' => $class ? Catalog::tierOf($class) : null, 'score' => $score, 'source' => 'detected',
                'detected_class' => $class, 'detected_score' => $score,
                'evidence' => ['total' => $score, 'threshold_mask' => 70, 'threshold_review' => 40, 'lines' => [], 'shapes' => []]],
        ];
    }

    #[DataProvider('databases')]
    public function testExactNamesRaceAndUpgradeOn(?string $url): void
    {
        if ($url === null) {
            $this->markTestSkipped('Set DM_SYSDB_URLS to throwaway system databases to run the portability checks.');
        }
        $this->boot($url);
        $this->cleanup();
        try {
            Schema::create('service', function (Blueprint $t) {
                $t->increments('id');
                $t->string('name', 40);
                $t->string('type', 40);
            });
            foreach (['user', 'role'] as $table) {
                Schema::create($table, function (Blueprint $t) {
                    $t->increments('id');
                    $t->string('name', 64)->nullable();
                });
            }
            foreach ($this->migrations() as $m) {
                $m->up();
            }
            $svc = (int)DB::table('service')->insertGetId(['name' => 'pgdata', 'type' => 'pgsql']);
            $w = new ColumnWriter(new Examples());

            // An hr2.collide table, plus an ASCII case pair
            $variants = [
                "r\u{E9}sum\u{E9}" => ['masked', 'free_text_pii', 75], 'resume' => ['clear', null, 0],
                "\u{C9}MAIL" => ['masked', 'email', 100], "\u{E9}mail" => ['clear', null, 30],
                "stra\u{DF}e" => ['masked', 'street_address', 70], 'strasse' => ['clear', null, 0],
                'Email' => ['masked', 'email', 100], 'email' => ['clear', null, 0],
            ];
            $w->write($svc, 'hr2.collide', array_map(fn ($v) => self::col(...$v), $variants), 'v');
            $stored = [];
            foreach (DB::table(Tables::COLUMN)->where('table_name', 'hr2.collide')->get(['column_name', 'verdict']) as $r) {
                $stored[(string)$r->column_name] = (string)$r->verdict;
            }
            ksort($stored, SORT_STRING);
            $want = array_map(fn ($v) => $v[0], $variants);
            ksort($want, SORT_STRING);
            $this->assertSame($want, $stored, 'one row per exact column name');

            // table names too ("Clients" vs "clients")
            $w->write($svc, 'Clients', ['notes' => self::col('masked', 'free_text_pii', 75)], 'v');
            $w->write($svc, 'clients', ['notes' => self::col('clear', null, 0)], 'v');
            PolicyVersion::bump();
            Policy::forget();
            $this->assertSame(['notes'], array_keys(Policy::forTable($svc, 'Clients')));
            $this->assertSame([], Policy::forTable($svc, 'clients'));

            // Lose the insert race to a second connection inside the scan's transaction
            $fired = false;
            DB::connection()->listen(function ($q) use (&$fired, $svc) {
                if (!$fired && str_starts_with(strtolower(ltrim($q->sql)), 'select') && in_array('hr2.race_t', $q->bindings, true)) {
                    $fired = true;
                    DB::connection('other')->table(Tables::COLUMN)->insert(['service_id' => $svc, 'table_name' => 'hr2.race_t',
                        'column_name' => 'contact_email', 'verdict' => 'clear', 'score' => 0, 'source' => 'detected']);
                }
            });
            $stats = $w->write($svc, 'hr2.race_t', ['contact_email' => self::col('masked', 'email', 100), 'z' => self::col('clear', null, 0)], 'v');
            $this->assertTrue($fired);
            $this->assertSame(2, $stats['inserted']);
            $this->assertSame('masked', DB::table(Tables::COLUMN)->where('table_name', 'hr2.race_t')->where('column_name', 'contact_email')->value('verdict'));
            $this->assertSame(1, DB::table(Tables::COLUMN)->where('table_name', 'hr2.race_t')->where('column_name', 'z')->count(),
                'the transaction went on after the conflict');

            // A lost insert race inside an outer transaction (Compliance Apply)
            $settingRace = false;
            DB::connection()->listen(function ($q) use (&$settingRace) {
                if (!$settingRace && str_contains($q->sql, 'dm_setting') && in_array('race_key', $q->bindings, true)
                    && str_starts_with(strtolower(ltrim($q->sql)), 'select')) {
                    $settingRace = true;
                    DB::connection('other')->table(Tables::SETTING)->insert(['name' => 'race_key', 'value' => '"theirs"']);
                }
            });
            DB::transaction(function () {
                Settings::set('race_key', 'ours');
                DB::table(Tables::SETTING)->insert(['name' => 'after_race', 'value' => '1']);
            });
            $this->assertTrue($settingRace);
            $this->assertSame('"ours"', DB::table(Tables::SETTING)->where('name', 'race_key')->value('value'));
            $this->assertSame(1, DB::table(Tables::SETTING)->where('name', 'after_race')->count(), 'the outer transaction survived');

            // Retry helper: retries on contention, not on other errors
            $n = 0;
            $this->assertSame('ok', Retry::transaction(function () use (&$n) {
                if (++$n < 3) {
                    throw new \PDOException('SQLSTATE[HY000]: General error: 5 database is locked');
                }
                return 'ok';
            }));
            $this->assertSame(3, $n);

            // the upgrade migration rolls back and re-applies with data in place
            $upgrade = $this->migrations()[1];
            DB::table(Tables::SCAN)->insert(['status' => 'done', 'failed_services' => '[]']);
            DB::table(Tables::COLUMN)->where('table_name', 'hr2.collide')->where('column_name', 'email')->update(['source' => 'admin']);
            $upgrade->down();
            $this->assertFalse(Schema::hasColumn(Tables::SCAN, 'failed_services'));
            $driver = DB::connection()->getDriverName();
            if (in_array($driver, ['mysql', 'sqlsrv'], true)) {
                // back to the case-insensitive default: one row per colliding name, the admin decision kept
                $left = DB::table(Tables::COLUMN)->where('table_name', 'hr2.collide')->pluck('source', 'column_name')->all();
                $this->assertSame('admin', $left['email'] ?? $left['Email'] ?? null);
                $this->assertLessThan(8, count($left));
            }
            DB::table(Tables::COLUMN)->where('table_name', 'hr2.collide')->delete();
            $upgrade->up();
            ScanHistory::forget();
            $this->assertTrue(ScanHistory::supported());
            $w->write($svc, 'hr2.collide', array_map(fn ($v) => self::col(...$v), $variants), 'v');
            $this->assertSame(8, DB::table(Tables::COLUMN)->where('table_name', 'hr2.collide')->count(), 'exact again after re-applying');

            // dm_scan.scope is additive, backfilled from service_id, and rolls back
            $scope = $this->migration('2026_10_29_000004_dm_scan_scope');
            DB::table(Tables::SCAN)->delete();
            $scope->down();
            ScanHistory::forget();
            $this->assertFalse(Schema::hasColumn(Tables::SCAN, ScanHistory::SCOPE_COLUMN));
            DB::table(Tables::SCAN)->insert(['service_id' => null, 'status' => 'done']);
            DB::table(Tables::SCAN)->insert(['service_id' => $svc, 'status' => 'done']);
            $scope->up();
            $this->assertSame(['full', 'service'], DB::table(Tables::SCAN)->orderBy('id')->pluck(ScanHistory::SCOPE_COLUMN)->all());
            $scope->up(); // idempotent
            $scope->down();
            $this->assertFalse(Schema::hasColumn(Tables::SCAN, ScanHistory::SCOPE_COLUMN));
            $scope->up();
            ScanHistory::forget();
            $this->assertTrue(ScanHistory::scoped());
        } finally {
            $this->cleanup();
        }
    }
}

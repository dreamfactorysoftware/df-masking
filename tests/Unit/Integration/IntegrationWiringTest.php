<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Integration;

use DreamFactory\Core\Masking\Enforcement\InlineClassifier;
use DreamFactory\Core\Masking\Enforcement\TableTarget;
use DreamFactory\Core\Masking\Scanner\Hooks;
use DreamFactory\Core\Masking\Scanner\ScanLauncher;
use DreamFactory\Core\Masking\Scanner\ScanRunner;
use DreamFactory\Core\Masking\Scanner\ScanState;
use DreamFactory\Core\Masking\Scanner\Services;
use DreamFactory\Core\Masking\Support\Coverage;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use DreamFactory\Core\Masking\Tests\Unit\Scanner\Harness;
use DreamFactory\Core\SqlDb\Services\SqlDb;
use Illuminate\Container\Container;
use Illuminate\Events\Dispatcher;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\TestCase;

/**
 * Regression tests for problems found while wiring the areas together on a live stack:
 *  - the service-changed scan hook made every service save throw (array listener on a class the
 *    container cannot build);
 *  - a scan opened SQLite services whose database file did not exist, which creates the file
 *    (root-owned when the scan runs from `php artisan` as root);
 *  - inline classification dropped its background re-scan while another scan was running.
 */
final class IntegrationWiringTest extends TestCase
{
    /** @var list<string> */
    private array $tempFiles = [];

    protected function tearDown(): void
    {
        foreach ($this->tempFiles as $f) {
            @unlink($f);
        }
        parent::tearDown();
    }

    public function testServiceChangedHookNeverMakesAServiceSaveThrow(): void
    {
        $app = new Container();
        $events = new Dispatcher($app);
        $app->instance('events', $events);

        Hooks::register($app);

        $this->assertTrue($events->hasListeners(Hooks::SERVICE_MODIFIED));
        // An inactive service: the hook returns early. Before the fix, building the listener
        // itself threw "Target [...Hooks] is not instantiable" on every dispatch.
        $events->dispatch(Hooks::SERVICE_MODIFIED, [(object)['service' => (object)['is_active' => false, 'name' => 'x', 'type' => 'mysql']]]);
        // No service at all, and an uncovered type: also no exception.
        $events->dispatch(Hooks::SERVICE_MODIFIED, [(object)[]]);
        $this->addToAssertionCount(1);
    }

    public function testMissingSqliteFileDetectionReadsTheServiceConfigOnly(): void
    {
        Harness::boot();
        $missing = $this->tempPath();
        $existing = $this->tempPath();
        touch($existing);

        $this->assertTrue(Services::isMissingSqliteFile($this->configOnly(['driver' => 'sqlite', 'database' => $missing])));
        $this->assertFalse(Services::isMissingSqliteFile($this->configOnly(['driver' => 'sqlite', 'database' => $existing])));
        $this->assertFalse(Services::isMissingSqliteFile($this->configOnly(['driver' => 'sqlite', 'database' => ':memory:'])));
        $this->assertFalse(Services::isMissingSqliteFile($this->configOnly(['driver' => 'mysql', 'database' => 'crm'])));
        $this->assertFalse(Services::isMissingSqliteFile($this->configOnly([])), 'no configuration: not a missing file');
        $this->assertFalse(Services::isMissingSqliteFile(new \stdClass()));

        // A bare file name lives in df.db.sqlite_storage, as in DreamFactory's SQLite connector.
        config(['df.db.sqlite_storage' => dirname($existing)]);
        $this->assertFalse(Services::isMissingSqliteFile($this->configOnly(['driver' => 'sqlite', 'database' => basename($existing)])));
        $this->assertTrue(Services::isMissingSqliteFile($this->configOnly(['driver' => 'sqlite', 'database' => basename($missing)])));
    }

    public function testScanSkipsASqliteServiceWithoutADatabaseFileAndNeverConnects(): void
    {
        Harness::boot();
        $file = $this->tempPath();
        $service = new class ($file) extends SqlDb {
            public bool $connected = false;

            public function __construct(string $file)
            {
                $this->name = 'ghost';
                $this->config = ['driver' => 'sqlite', 'database' => $file];
            }

            public function __destruct()
            {
            }

            public function getConnection()
            {
                $this->connected = true;

                throw new \RuntimeException('the scan must not open this connection');
            }
        };
        DB::table('service')->insert(['name' => 'ghost', 'label' => 'Ghost', 'type' => 'sqlite', 'is_active' => true]);
        Harness::$services['ghost'] = $service;
        Coverage::forget();

        $summary = (new ScanRunner())->run('ghost');

        $this->assertSame('done', $summary['status']);
        $this->assertSame([], $summary['services_failed']);
        $this->assertSame(0, $summary['columns']);
        $this->assertFalse($service->connected, 'no connection was opened');
        $this->assertFileDoesNotExist($file, 'no database file was created');
        $this->assertSame([], (new ScanRunner())->testRule('value', 'x', 500)['matches']);
        $this->assertFalse($service->connected, 'the value-rule test skips it too');
    }

    public function testInlineClassificationQueuesItsRescanBehindARunningScan(): void
    {
        Harness::boot();
        $crm = Harness::addService('crm', Harness::sqlite(['CREATE TABLE people (id integer primary key, email text)']));
        $other = Harness::addService('other', Harness::sqlite(['CREATE TABLE t (id integer primary key)']));
        Coverage::forget();
        Settings::set(Settings::FIRST_SCAN_AT, '2026-10-29T00:00:00Z');
        $running = ScanState::create($other, 'test');

        $target = new TableTarget('crm', $crm, 'sqlite', 'people', [
            'id' => ['name' => 'id', 'column' => 'id', 'type' => 'id', 'db_type' => 'integer'],
            'email' => ['name' => 'email', 'column' => 'email', 'type' => 'string', 'db_type' => 'text'],
        ], [], ['id']);

        $verdicts = InlineClassifier::classifyUnknown($target, []);

        $this->assertNotNull($verdicts);
        $this->assertSame('masked', $verdicts['email']['verdict']);
        $this->assertSame(2, DB::table(Tables::COLUMN)->where('service_id', $crm)->count());
        $this->assertSame(1, DB::table(Tables::SCAN)->count(), 'no second scan was started');
        $this->assertSame((int)$running->id, (int)ScanState::running()->id);
        $this->assertContains('crm', ScanLauncher::dueRequests(), 'crm is scanned when the running scan ends');
    }

    private function configOnly(array $config): object
    {
        return new class ($config) {
            public function __construct(private array $config)
            {
            }

            public function getConfig($key = null, $default = null)
            {
                if ($this->config === []) {
                    return []; // DreamFactory's BaseRestService::getConfig() on an empty config
                }

                return $key === null ? $this->config : ($this->config[$key] ?? $default);
            }
        };
    }

    private function tempPath(): string
    {
        $path = sys_get_temp_dir() . '/df-masking-test-' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tempFiles[] = $path;

        return $path;
    }
}

<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Platform;

use DreamFactory\Core\Components\InternalServiceRequest;
use DreamFactory\Core\Masking\Resources\DataMasking;
use DreamFactory\Core\Masking\Support\PolicyVersion;
use DreamFactory\Core\Masking\Support\ScanHistory;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use DreamFactory\Core\Masking\Tests\TestCase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Schema;

/**
 * `migrate:reset` of the df-masking migrations without
 * cache:clear, `migrate` again, then `mode on` was accepted on empty tables: the cached settings
 * (mode, first-scan marker) outlived the dropped tables for up to an hour. The migrations now drop
 * the cached settings and bump the policy version, and mode On needs a finished dm_scan row that
 * found columns. The overview never reports a mode read from tables
 * that are gone. Plus package housekeeping.
 */
final class ReinstallCacheTest extends TestCase
{
    use ActsAsCaller;

    protected function setUp(): void
    {
        parent::setUp();
        $this->bootHarness();
        $this->db()->table('user')->insert(['id' => 1, 'name' => 'Alex Admin', 'email' => 'k@example.com', 'is_sys_admin' => true]);
        $this->actAs(1);
    }

    /** @return list<object> the package migrations, in file order */
    private static function migrations(): array
    {
        $files = glob(dirname(__DIR__, 3) . '/database/migrations/*.php') ?: [];
        sort($files);

        return array_map(static fn ($f) => require $f, $files);
    }

    /** A new php process: per-process memos are empty, the application cache is not. */
    private function newProcess(): void
    {
        Settings::flush();
        PolicyVersion::forget();
        ScanHistory::forget();
    }

    private function scannedPreviewInstance(): void
    {
        $this->db()->table(Tables::SCAN)->insert(['status' => 'done', 'progress' => 100, 'columns_total' => 12, 'columns_done' => 12,
            'started_at' => now(), 'finished_at' => now(), 'created_at' => now(), 'updated_at' => now()]);
        Settings::set(Settings::FIRST_SCAN_AT, '2026-10-29T00:00:00Z');
        Settings::set(Settings::MODE, 'preview');
        $this->newProcess();
        $this->assertSame('preview', Settings::mode()); // cached now
        $this->assertTrue(ScanHistory::firstScanDone());
    }

    private function setMode(string $mode): array
    {
        $request = new InternalServiceRequest();
        $request->setMethod('PATCH');
        $request->setPayloadData(['mode' => $mode]);
        $response = (new DataMasking(['name' => 'data_masking']))->handleRequest($request, '');

        return [$response->getStatusCode(), $response->getContent()];
    }

    public function testReinstallWithoutCacheClearStartsFromScratch(): void
    {
        $this->scannedPreviewInstance();

        // php artisan migrate:reset --path=.../df-masking/database/migrations (no cache:clear)
        foreach (array_reverse(self::migrations()) as $migration) {
            $migration->down();
        }
        $this->newProcess();
        $this->assertFalse(Schema::hasTable(Tables::SETTING));
        $this->assertSame('off', Settings::mode(), 'no tables: nothing to enforce, whatever was cached');

        // php artisan migrate
        foreach (self::migrations() as $migration) {
            $migration->up();
        }
        $this->newProcess();
        $this->assertSame('off', Settings::mode(), 'fresh tables start at the default mode');
        $this->assertFalse(Settings::has(Settings::FIRST_SCAN_AT), 'the cached first-scan marker is gone');
        $this->assertFalse(ScanHistory::firstScanDone());

        [$status, $body] = $this->setMode('on');
        $this->assertSame(409, $status, 'mode On before any scan on the new tables');
        $this->assertSame('Scan your databases before turning masking on.', $body['error']['message'] ?? null);
        $this->newProcess();
        $this->assertSame('off', Settings::mode());
    }

    public function testEachMigrationThatCreatesOrDropsTheTablesInvalidatesTheCache(): void
    {
        [$create, , , , $baseline] = self::migrations();
        foreach (['create up' => fn () => $create->up(), 'create down' => fn () => $create->down(), 'baseline down' => fn () => $baseline->down()] as $what => $run) {
            if (!Schema::hasTable(Tables::SETTING)) {
                $create->up();
            }
            Settings::set(Settings::MODE, 'preview');
            $this->newProcess();
            $this->assertSame('preview', Settings::mode());
            $before = PolicyVersion::current();
            $this->assertSame('preview', Cache::get(Settings::LAST_MODE_KEY));

            $run();

            $this->assertGreaterThan($before, PolicyVersion::current(), "$what bumps the policy version");
            $this->assertNull(Cache::get('df-masking:settings:v' . $before), "$what drops the cached settings");
            $this->assertNull(Cache::get(Settings::LAST_MODE_KEY), "$what drops the last-mode fallback");
        }
    }

    /** A first-scan marker without a finished scan row behind it (cached, or left over) does not allow On. */
    public function testModeOnNeedsAFinishedScanRowWithColumns(): void
    {
        Settings::set(Settings::FIRST_SCAN_AT, '2026-10-29T00:00:00Z');
        $this->assertFalse(ScanHistory::firstScanDone(), 'marker only');
        [$status] = $this->setMode('on');
        $this->assertSame(409, $status);

        $this->db()->table(Tables::SCAN)->insert(['status' => 'done', 'progress' => 100, 'columns_done' => 0,
            'started_at' => now(), 'finished_at' => now(), 'created_at' => now(), 'updated_at' => now()]);
        $this->assertFalse(ScanHistory::firstScanDone(), 'a scan that found no column');
        $this->db()->table(Tables::SCAN)->insert(['status' => 'running', 'progress' => 50, 'columns_done' => 9,
            'started_at' => now(), 'created_at' => now(), 'updated_at' => now()]);
        $this->assertFalse(ScanHistory::firstScanDone(), 'a scan that has not finished');

        $this->db()->table(Tables::SCAN)->insert(['status' => 'done', 'progress' => 100, 'columns_done' => 9,
            'started_at' => now(), 'finished_at' => now(), 'created_at' => now(), 'updated_at' => now()]);
        $this->assertTrue(ScanHistory::firstScanDone());
        [$status, $body] = $this->setMode('on');
        $this->assertSame(200, $status);
        $this->assertSame('on', $body['mode']);
    }

    /** Tables dropped by hand while the settings are cached: the overview re-checks. */
    public function testOverviewDoesNotReportACachedModeOnceTheTablesAreGone(): void
    {
        $this->scannedPreviewInstance();
        foreach ([Tables::SCAN, 'dm_activity', 'dm_role_access', 'dm_admin_grant', 'dm_rule', 'dm_mask_format', Tables::COLUMN, Tables::SETTING, Tables::BASELINE] as $t) {
            Schema::dropIfExists($t); // by hand: no migration ran
        }
        $this->newProcess();
        $this->assertSame('preview', Settings::mode(), 'still served from the cache (no query per request)');

        $request = new InternalServiceRequest();
        $request->setMethod('GET');
        $response = (new DataMasking(['name' => 'data_masking']))->handleRequest($request, '');
        $body = $response->getContent();
        $this->assertNotSame('preview', $body['mode'] ?? null, 'GET system/data_masking re-checked the tables');
        $this->newProcess();
        $this->assertSame('off', Settings::mode());
    }

    public function testRevalidateKeepsTheFailClosedFallbackWhenOnlyDmSettingIsGone(): void
    {
        Settings::set(Settings::MODE, 'on');
        $this->newProcess();
        $this->assertSame('on', Settings::mode());
        Schema::rename(Tables::SETTING, 'dm_setting_hidden');
        $this->assertFalse(Settings::revalidate());
        $this->newProcess();
        $this->assertSame('on', Settings::mode(), 'dm_column still exists: unreadable settings enforce the last mode');
        Schema::rename('dm_setting_hidden', Tables::SETTING);
        $this->assertTrue(Settings::revalidate());
    }

    /** Package housekeeping: no unused config keys, Python caches ignored. */
    public function testHousekeeping(): void
    {
        $config = require dirname(__DIR__, 3) . '/config/df-masking.php';
        $this->assertArrayNotHasKey('unscanned_rescan_minutes', $config['scan'], 'dead key: unknown columns start a scan at once');
        $ignore = (string)file_get_contents(dirname(__DIR__, 3) . '/.gitignore');
        $this->assertStringContainsString("tests/Live/__pycache__/\n", $ignore);
        $this->assertStringContainsString("*.pyc\n", $ignore);
    }
}

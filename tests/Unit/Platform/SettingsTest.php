<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Platform;

use DreamFactory\Core\Masking\Support\Activity;
use DreamFactory\Core\Masking\Support\PolicyVersion;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use DreamFactory\Core\Masking\Tests\TestCase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Schema;

final class SettingsTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->bootHarness();
    }

    public function testDefaultsWhenNothingIsStored(): void
    {
        $this->assertSame('off', Settings::mode());
        $this->assertSame('masked', Settings::ai());
        $this->assertSame('none', Settings::adminsMode());
        $this->assertNull(Settings::get('missing'));
        $this->assertSame(7, Settings::get('missing', 7));
        $this->assertFalse(Settings::has(Settings::MODE));
    }

    public function testRoundTripsJsonValuesAndBumpsThePolicyVersion(): void
    {
        $v0 = PolicyVersion::current();
        Settings::set('complex', ['a' => 1, 'b' => [true, null, 'x']]);
        $this->assertGreaterThan($v0, PolicyVersion::current());
        $this->assertSame(['a' => 1, 'b' => [true, null, 'x']], Settings::get('complex'));
        $this->assertSame('{"a":1,"b":[true,null,"x"]}', $this->db()->table(Tables::SETTING)->where('name', 'complex')->value('value'));

        Settings::set(Settings::MODE, 'on');
        Settings::set(Settings::MODE, 'preview'); // update, not a duplicate insert
        $this->assertSame('preview', Settings::mode());
        $this->assertSame(1, $this->db()->table(Tables::SETTING)->where('name', Settings::MODE)->count());
        $this->assertTrue(Settings::has(Settings::MODE));

        Settings::forget(Settings::MODE);
        $this->assertSame('off', Settings::mode());
    }

    public function testInvalidStoredValuesFailClosed(): void
    {
        $this->db()->table(Tables::SETTING)->insert([
            ['name' => Settings::MODE, 'value' => '"loud"'],
            ['name' => Settings::AI, 'value' => '"whatever"'],
            ['name' => Settings::ADMINS_MODE, 'value' => 'not json'],
        ]);
        Settings::flush();
        PolicyVersion::bump();
        $this->assertSame('off', Settings::mode());
        $this->assertSame('masked', Settings::ai());
        $this->assertSame('none', Settings::adminsMode());
    }

    public function testReadsAreCachedUnderThePolicyVersion(): void
    {
        Settings::set(Settings::AI, 'same_as_admins');
        $this->assertSame('same_as_admins', Settings::ai());

        // A write that does not go through Settings (another process) is not seen until the version moves.
        $this->db()->table(Tables::SETTING)->where('name', Settings::AI)->update(['value' => '"masked"']);
        Settings::flush();
        $this->assertSame('same_as_admins', Settings::ai(), 'served from the cache');
        PolicyVersion::bump();
        $this->assertSame('masked', Settings::ai(), 'reloaded after the bump');
    }

    public function testMissingTableMeansDefaultsNotErrors(): void
    {
        // Not migrated: no df-masking tables at all (a lone missing dm_setting fails closed instead).
        Schema::drop(Tables::SETTING);
        Schema::drop(Tables::COLUMN);
        Settings::flush();
        PolicyVersion::bump();
        $this->assertSame('off', Settings::mode());
        $this->assertSame('masked', Settings::ai());
        $this->assertSame([], Settings::all());
    }

    public function testRejectsBadNames(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Settings::set(str_repeat('x', 65), 1);
    }

    public function testTokenKeyIsGeneratedOnceStoredEncryptedAndHidden(): void
    {
        $key = Settings::tokenKey();
        $this->assertSame(32, strlen($key));
        Settings::flush();
        PolicyVersion::forget();
        $this->assertSame($key, Settings::tokenKey(), 'stable across processes');

        $stored = json_decode((string)$this->db()->table(Tables::SETTING)->where('name', Settings::TOKEN_KEY)->value('value'), true);
        $this->assertIsString($stored);
        $this->assertStringNotContainsString(base64_encode($key), $stored, 'never stored in clear');
        $this->assertSame(base64_encode($key), Crypt::decryptString($stored));
        $this->assertArrayNotHasKey(Settings::TOKEN_KEY, Settings::all());
    }

    public function testTokenKeyFromEnvironmentWins(): void
    {
        $raw = random_bytes(32);
        $this->app['config']->set('df-masking.token_key', base64_encode($raw));
        $this->assertSame($raw, Settings::tokenKey());
        $this->assertSame(0, $this->db()->table(Tables::SETTING)->where('name', Settings::TOKEN_KEY)->count());

        Settings::flush();
        $this->app['config']->set('df-masking.token_key', 'base64:' . base64_encode($raw));
        $this->assertSame($raw, Settings::tokenKey(), 'Laravel-style base64: prefix accepted');

        Settings::flush();
        $this->app['config']->set('df-masking.token_key', 'too-short');
        $this->assertNotSame($raw, Settings::tokenKey(), 'an invalid env key falls back to the stored key');
    }

    public function testUndecryptableStoredKeyIsReplaced(): void
    {
        $this->db()->table(Tables::SETTING)->insert(['name' => Settings::TOKEN_KEY, 'value' => '"garbage"']);
        Settings::flush();
        PolicyVersion::bump();
        $key = Settings::tokenKey();
        $this->assertSame(32, strlen($key));
        Settings::flush();
        $this->assertSame($key, Settings::tokenKey());
        $this->assertSame(1, $this->db()->table(Tables::SETTING)->where('name', Settings::TOKEN_KEY)->count());
    }

    public function testFirstScanSwitchesToPreviewOnce(): void
    {
        $this->assertTrue(Settings::afterScanCompleted());
        $this->assertSame('preview', Settings::mode());
        $this->assertNotNull(Settings::get(Settings::FIRST_SCAN_AT));
        $rows = $this->db()->table(Tables::ACTIVITY)->get();
        $this->assertCount(1, $rows);
        $this->assertSame('System', $rows[0]->actor);
        $this->assertSame('mode', $rows[0]->kind);
        $this->assertSame('Masking set to Preview after the first scan', $rows[0]->text);

        Settings::set(Settings::MODE, 'off');
        $this->assertFalse(Settings::afterScanCompleted(), 'only the first scan ever');
        $this->assertSame('off', Settings::mode());
        $this->assertSame(1, $this->db()->table(Tables::ACTIVITY)->count());
    }

    public function testFirstScanRespectsAnExplicitlyChosenMode(): void
    {
        Settings::set(Settings::MODE, 'off'); // an admin chose Off before the first scan
        $this->assertFalse(Settings::afterScanCompleted());
        $this->assertSame('off', Settings::mode());
        $this->assertNotNull(Settings::get(Settings::FIRST_SCAN_AT));
        $this->assertSame(0, $this->db()->table(Tables::ACTIVITY)->count());
    }

    public function testPolicyVersionSeedsFromTheClockAndSurvivesAFlush(): void
    {
        PolicyVersion::forget();
        $v1 = PolicyVersion::current();
        $this->assertGreaterThan(1_600_000_000_000, $v1, 'seeded from the clock in ms');
        PolicyVersion::bump();
        $v2 = PolicyVersion::current();
        $this->assertSame($v1 + 1, $v2);

        usleep(2000);
        Cache::flush();
        PolicyVersion::forget();
        $this->assertGreaterThan($v2, PolicyVersion::current(), 'a flushed cache never reuses an older version');
    }

    public function testActivityLogsClipsAndNeverThrows(): void
    {
        Activity::log('rule', str_repeat('x', 600), str_repeat('t', 300), ['n' => 1], 'Someone');
        $row = $this->db()->table(Tables::ACTIVITY)->first();
        $this->assertSame('Someone', $row->actor);
        $this->assertSame(500, mb_strlen($row->text));
        $this->assertStringEndsWith('…', $row->text);
        $this->assertSame(255, mb_strlen($row->target));
        $this->assertSame('{"n":1}', $row->meta);

        Activity::log('not-a-kind', 'ignored');
        $this->assertSame(1, $this->db()->table(Tables::ACTIVITY)->count());

        Schema::drop(Tables::ACTIVITY);
        Activity::log('mode', 'no table: swallowed');
        $this->addToAssertionCount(1);
    }

    public function testThrottledActivityLogsOncePerWindow(): void
    {
        Activity::logThrottled('preview|key|crm.t', 3600, 'preview', 'Would mask 2 columns', 'crm.t');
        Activity::logThrottled('preview|key|crm.t', 3600, 'preview', 'Would mask 2 columns', 'crm.t');
        Activity::logThrottled('preview|key|crm.u', 3600, 'preview', 'Would mask 1 column', 'crm.u');
        $this->assertSame(2, $this->db()->table(Tables::ACTIVITY)->count());
    }
}

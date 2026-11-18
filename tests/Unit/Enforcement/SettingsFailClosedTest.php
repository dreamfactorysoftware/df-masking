<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Tests\Unit\Enforcement;

use DreamFactory\Core\Masking\Masking\Masker;
use DreamFactory\Core\Masking\Enforcement\Listener;
use DreamFactory\Core\Masking\Support\PolicyVersion;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use DreamFactory\Core\Utility\ServiceResponse;
use Illuminate\Support\Facades\Cache;

/**
 * A dm_setting read that fails on an instance that has
 * the df-masking tables never turns masking off. The last mode read successfully is used (kept
 * without expiry), and 'on' when none is known; an instance without the tables (not migrated, or
 * rolled back) keeps the defaults.
 */
final class SettingsFailClosedTest extends EnforcementHarness
{
    private function breakSettingsRead(bool $clearLastMode = false): void
    {
        Cache::forget('df-masking:settings:v' . PolicyVersion::current());
        if ($clearLastMode) {
            Cache::forget(Settings::LAST_MODE_KEY);
        }
        Settings::flush();
        $this->db()->getSchemaBuilder()->rename(Tables::SETTING, 'dm_setting_unavailable');
    }

    public function testSettingsReadFailureDoesNotTurnMaskingOff(): void
    {
        $this->assertSame('on', Settings::mode());
        $this->breakSettingsRead();
        $this->assertSame('on', Settings::mode(), 'a failed settings read silently reported mode off');
        $this->assertSame('masked', Settings::ai());
        $this->assertSame('none', Settings::adminsMode());
    }

    public function testUnknownLastModeEnforcesOn(): void
    {
        $this->breakSettingsRead(true);
        $this->assertSame('on', Settings::mode());
    }

    public function testLastKnownOffStaysOff(): void
    {
        Settings::set('mode', 'off');
        $this->breakSettingsRead();
        $this->assertSame('off', Settings::mode(), 'last known mode wins');
    }

    public function testWritesKeepTheFallbackCurrent(): void
    {
        Settings::set('mode', 'preview');
        $this->assertSame('preview', Cache::get(Settings::LAST_MODE_KEY));
        Settings::forget('mode');
        $this->assertSame('off', Cache::get(Settings::LAST_MODE_KEY));
    }

    public function testNotMigratedKeepsDefaults(): void
    {
        $this->breakSettingsRead();
        $this->db()->getSchemaBuilder()->drop(Tables::COLUMN);
        Settings::flush();
        $this->assertSame('off', Settings::mode(), 'no df-masking tables: nothing to enforce');
    }

    /**
     * The first-scan bookkeeping read dm_setting through a reader
     * that returns null on errors, so a failed read looked like "never scanned, no mode chosen"
     * and the following writes switched an On instance to Preview. Reads failing while writes
     * still work must change nothing.
     */
    public function testFirstScanBookkeepingNeverLowersTheModeWhenReadsFail(): void
    {
        Settings::set(Settings::FIRST_SCAN_AT, '2026-01-01T00:00:00Z');
        $this->assertSame('on', Settings::mode());
        $failReads = true;
        $this->db()->beforeExecuting(static function (string $sql) use (&$failReads): void {
            if ($failReads && stripos(ltrim($sql), 'select') === 0 && str_contains($sql, Tables::SETTING)) {
                throw new \RuntimeException('simulated dm_setting read failure');
            }
        });
        $this->assertFalse(Settings::afterScanCompleted());
        $failReads = false;
        $rows = $this->db()->table(Tables::SETTING)->pluck('value', 'name')->all();
        $this->assertSame('"on"', $rows['mode'] ?? null, 'a failed read let the first-scan bookkeeping lower the mode');
        $this->assertSame('"2026-01-01T00:00:00Z"', $rows[Settings::FIRST_SCAN_AT] ?? null, 'first scan time overwritten');
    }

    public function testSettingsReadFailureFailsClosedEndToEnd(): void
    {
        $warm = $this->tableFlow($this->request('GET', ['fields' => '*']), new ServiceResponse(['resource' => [$this->record()]]), 'customers');
        $this->assertSame(Masker::redacted(), $warm->getContent()['resource'][0]['ssn']);

        $this->breakSettingsRead(true);
        $this->listener = new Listener(new Masker(str_repeat("\x03", 32)));
        $response = new ServiceResponse(['resource' => [$this->record()]]);
        try {
            $this->tableFlow($this->request('GET', ['fields' => '*']), $response, 'customers');
        } catch (\Throwable $e) {
            $this->assertTrue(true, 'refusing is acceptable (fail closed)');

            return;
        }
        $this->assertNotSame(self::SSN, $response->getContent()['resource'][0]['ssn'], 'real ssn served while mode is on');
    }
}

<?php

namespace DreamFactory\Core\Masking\Support;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * dm_setting key/value store. Values are JSON-encoded in the `value` column.
 *
 * Reads are served from a per-process memo and from the application cache, both keyed by
 * PolicyVersion::current(), so a steady-state request costs zero database queries. set() bumps
 * the policy version, which invalidates every df-masking cache at once.
 *
 * Never throws on read. Before the migration has run (package installed, `migrate` not yet
 * run) every getter returns its default, so installing the package cannot break an instance.
 * A read that fails on an instance that has the df-masking tables fails closed: the mode is the
 * last one read successfully (LAST_MODE_KEY, kept in the application cache without expiry), or
 * 'on' when none is known; every other setting falls back to its (fail-closed) default.
 */
final class Settings
{
    public const MODE = 'mode';
    public const AI = 'ai';
    public const ADMINS_MODE = 'admins_mode';
    public const TOKEN_KEY = 'token_key';
    public const FIRST_SCAN_AT = 'first_scan_at';

    public const MODES = ['off', 'preview', 'on'];
    public const AI_MODES = ['masked', 'same_as_admins'];
    public const ADMINS_MODES = ['none', 'selected', 'all'];

    /** Never returned by all()/public listings. */
    private const SECRET_KEYS = [self::TOKEN_KEY];

    private const CACHE_PREFIX = 'df-masking:settings:v';
    private const CACHE_TTL = 3600;

    /** Last mode read from dm_setting (no TTL): what enforcement uses when dm_setting cannot be read. */
    public const LAST_MODE_KEY = 'df-masking:settings:last-mode';

    /** @var array<string,mixed>|null */
    private static ?array $memo = null;
    private static ?int $memoVersion = null;
    private static ?string $tokenKey = null;

    private function __construct()
    {
    }

    public static function get(string $key, mixed $default = null): mixed
    {
        $all = self::load();

        return array_key_exists($key, $all) ? $all[$key] : $default;
    }

    /** True when the setting has a stored row (as opposed to falling back to its default). */
    public static function has(string $key): bool
    {
        return array_key_exists($key, self::load());
    }

    /**
     * Upserts one setting and bumps the policy version.
     *
     * @throws \Throwable when the database write fails (callers report it; never swallowed)
     */
    public static function set(string $key, mixed $value): void
    {
        if ($key === '' || strlen($key) > 64) {
            throw new \InvalidArgumentException('Setting names are 1-64 characters.');
        }
        $encoded = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        self::write($key, $encoded);
        if ($key === self::MODE) {
            self::rememberMode($value);
        }
        self::flush();
        PolicyVersion::bump();
    }

    /** Removes a setting (it falls back to its default) and bumps the policy version. */
    public static function forget(string $key): void
    {
        DB::table(Tables::SETTING)->where('name', $key)->delete();
        if ($key === self::MODE) {
            self::rememberMode('off');
        }
        self::flush();
        PolicyVersion::bump();
    }

    /** 'off' | 'preview' | 'on'; default 'off'. */
    public static function mode(): string
    {
        $mode = self::get(self::MODE);

        return in_array($mode, self::MODES, true) ? $mode : 'off';
    }

    /** 'masked' | 'same_as_admins'; anything unexpected fails closed to 'masked'. */
    public static function ai(): string
    {
        return self::get(self::AI) === 'same_as_admins' ? 'same_as_admins' : 'masked';
    }

    /** 'none' | 'selected' | 'all'; anything unexpected fails closed to 'none'. */
    public static function adminsMode(): string
    {
        $mode = self::get(self::ADMINS_MODE);

        return in_array($mode, self::ADMINS_MODES, true) ? $mode : 'none';
    }

    /**
     * The 32-byte HMAC key for `token` masks. DF_MASKING_TOKEN_KEY (base64 of 32 bytes,
     * config df-masking.token_key) wins; otherwise a key generated on first use is stored
     * encrypted with the APP_KEY (Crypt) in dm_setting.token_key. One key per instance, so
     * tokens are joinable inside an instance and differ between instances.
     */
    public static function tokenKey(): string
    {
        if (self::$tokenKey !== null) {
            return self::$tokenKey;
        }

        $configured = self::configuredTokenKey();
        if ($configured !== null) {
            return self::$tokenKey = $configured;
        }

        $stored = self::get(self::TOKEN_KEY);
        if (is_string($stored) && ($raw = self::decryptKey($stored)) !== null) {
            return self::$tokenKey = $raw;
        }

        // Read the row directly: another process may have generated it after our cache fill.
        $row = self::readRaw(self::TOKEN_KEY);
        if (is_string($row) && ($raw = self::decryptKey($row)) !== null) {
            self::flush();

            return self::$tokenKey = $raw;
        }

        $raw = random_bytes(32);
        $encoded = json_encode(Crypt::encryptString(base64_encode($raw)), JSON_THROW_ON_ERROR);
        if ($row === null) {
            try {
                // Insert-only: if another process won the race, use its key.
                DB::table(Tables::SETTING)->insert([
                    'name' => self::TOKEN_KEY,
                    'value' => $encoded,
                    'updated_at' => now(),
                ]);
            } catch (\Throwable $e) {
                $winner = self::readRaw(self::TOKEN_KEY);
                if (is_string($winner) && ($won = self::decryptKey($winner)) !== null) {
                    self::flush();

                    return self::$tokenKey = $won;
                }
                throw $e;
            }
        } else {
            // A stored key that no longer decrypts (APP_KEY rotated): replace it. Tokens issued
            // before the rotation will not match new ones; nothing else depends on the key.
            Log::warning('df-masking: the stored token key could not be decrypted (was APP_KEY changed?); generated a new one. Masked tokens will differ from earlier ones.');
            self::write(self::TOKEN_KEY, $encoded);
        }
        self::flush();
        PolicyVersion::bump();

        return self::$tokenKey = $raw;
    }

    /**
     * Called once a scan has finished successfully (by the scanner and, defensively, by the
     * overview endpoint). The first time ever: if nobody has chosen a mode yet (mode is still
     * the default 'off'), switch to 'preview'. Preview never changes data, so this is safe on
     * existing instances and makes the next step obvious. Idempotent.
     *
     * @return bool true when this call switched the mode
     */
    public static function afterScanCompleted(): bool
    {
        $work = static function (): bool {
            // Strict reads: a failed read is not "never scanned / no mode chosen";
            // the error reaches the catch below and nothing is written.
            if (self::readRaw(self::FIRST_SCAN_AT, true) !== null) {
                return false;
            }
            $switch = self::readRaw(self::MODE, true) === null;
            self::set(self::FIRST_SCAN_AT, now()->toIso8601ZuluString());
            if ($switch) {
                self::set(self::MODE, 'preview');
                Activity::log('mode', 'Masking set to Preview after the first scan', null, [], Activity::SYSTEM);
            }

            return $switch;
        };

        try {
            // The scanner and the overview endpoint may both get here at the same moment.
            $lock = null;
            try {
                $lock = Cache::lock('df-masking:first-scan', 15);
            } catch (\Throwable $e) {
                $lock = null; // store without locks: best effort
            }
            if ($lock === null) {
                return $work();
            }
            $result = $lock->block(5, $work);

            return (bool)$result;
        } catch (\Throwable $e) {
            Log::warning('df-masking: could not record the first scan: ' . $e->getMessage());

            return false;
        }
    }

    /**
     * Every non-secret setting (for diagnostics and the evidence report).
     *
     * @return array<string,mixed>
     */
    public static function all(): array
    {
        return array_diff_key(self::load(), array_flip(self::SECRET_KEYS));
    }

    /**
     * Re-checks that dm_setting still exists before the cached settings are trusted again. Called
     * when enforcement could not read the policy store and by the overview: settings are served
     * from the application cache for up to an hour, so after the tables were dropped (a manual
     * DROP or rename, `migrate:reset` without cache:clear) the cache would keep reporting the old
     * mode. When dm_setting is gone the cached settings are dropped (policy version bumped), so
     * the next read goes to the database: no tables at all = not installed (defaults); dm_setting
     * missing beside other df-masking tables = unreadable (fails closed to the last mode read).
     * The last-mode fallback is kept on purpose.
     *
     * @return bool false when dm_setting is gone (the cache was dropped)
     */
    public static function revalidate(): bool
    {
        try {
            $exists = DB::connection()->getSchemaBuilder()->hasTable(Tables::SETTING);
        } catch (\Throwable $e) {
            return true; // cannot tell: keep what we have (reads fail closed on their own)
        }
        if (!$exists) {
            try {
                Cache::forget(self::CACHE_PREFIX . PolicyVersion::current());
            } catch (\Throwable $e) {
            }
            self::flush();
            PolicyVersion::bump();
        }

        return $exists;
    }

    /**
     * Drops every cached df-masking setting, including the last-mode fallback, and bumps the
     * policy version (which invalidates every other df-masking cache entry). The migrations call
     * it when they create or drop the tables: settings cached for an hour must never outlive the
     * tables they were read from (a reinstall within the hour would otherwise start with the old
     * mode and first-scan marker on empty tables). Never throws.
     */
    public static function invalidateCache(): void
    {
        try {
            Cache::forget(self::CACHE_PREFIX . PolicyVersion::current());
            Cache::forget(self::LAST_MODE_KEY);
        } catch (\Throwable $e) {
            // no cache store: nothing cached
        }
        self::flush();
        PolicyVersion::bump();
    }

    /** Drops the per-process memo (after a write, in tests, in long-running processes). */
    public static function flush(): void
    {
        self::$memo = null;
        self::$memoVersion = null;
        self::$tokenKey = null;
    }

    /** @return array<string,mixed> */
    private static function load(): array
    {
        $version = PolicyVersion::current();
        if (self::$memo !== null && self::$memoVersion === $version) {
            return self::$memo;
        }

        $all = null;
        $cacheKey = self::CACHE_PREFIX . $version;
        if ($version > 0) {
            try {
                $cached = Cache::get($cacheKey);
                $all = is_array($cached) ? $cached : null;
            } catch (\Throwable $e) {
                $all = null;
            }
        }

        if ($all === null) {
            $all = [];
            try {
                foreach (DB::table(Tables::SETTING)->get(['name', 'value']) as $row) {
                    $all[(string)$row->name] = self::decode($row->value);
                }
                self::rememberMode($all[self::MODE] ?? 'off');
                if ($version > 0) {
                    try {
                        Cache::put($cacheKey, $all, self::CACHE_TTL);
                    } catch (\Throwable $e) {
                        // uncached is fine
                    }
                }
            } catch (\Throwable $e) {
                // Not memoised across versions (the next request retries) and never cached.
                $all = self::unreadable($e);
            }
        }

        self::$memo = $all;
        self::$memoVersion = $version;

        return $all;
    }

    /**
     * Settings when dm_setting could not be read. Package not migrated (neither dm_setting nor
     * dm_column exists, and no mode was ever read): defaults, so installing the package changes
     * nothing. Otherwise fail closed: the last mode read successfully, or 'on' when none is known.
     *
     * @return array<string,mixed>
     */
    private static function unreadable(\Throwable $e): array
    {
        $last = null;
        try {
            $last = Cache::get(self::LAST_MODE_KEY);
        } catch (\Throwable $ignored) {
        }
        $last = in_array($last, self::MODES, true) ? $last : null;
        try {
            $schema = DB::connection()->getSchemaBuilder();
            if (!$schema->hasTable(Tables::SETTING) && !$schema->hasTable(Tables::COLUMN)) {
                return []; // not migrated yet (or rolled back): nothing to enforce
            }
        } catch (\Throwable $ignored) {
            // Cannot tell: enforce.
        }
        Log::error('df-masking: could not read dm_setting (' . get_class($e) . '); enforcing mode ' . ($last ?? 'on') . ' until it can be read.');

        return [self::MODE => $last ?? 'on'];
    }

    /** Keeps the last mode read or written, without expiry (fail-closed fallback). */
    private static function rememberMode(mixed $mode): void
    {
        if (!in_array($mode, self::MODES, true)) {
            $mode = 'off';
        }
        try {
            if (Cache::get(self::LAST_MODE_KEY) !== $mode) {
                Cache::forever(self::LAST_MODE_KEY, $mode);
            }
        } catch (\Throwable $e) {
            // no cache: the fallback is 'on'
        }
    }

    private static function write(string $key, string $encoded): void
    {
        $values = ['value' => $encoded, 'updated_at' => now()];
        try {
            // A nested transaction is a savepoint: inside an outer transaction (Compliance Apply)
            // a lost insert race would otherwise abort it on PostgreSQL (25P02) before the update.
            DB::transaction(static fn () => DB::table(Tables::SETTING)->updateOrInsert(['name' => $key], $values));
        } catch (\Throwable $e) {
            // Lost an insert race to a concurrent writer: the row exists now, update it.
            $updated = DB::table(Tables::SETTING)->where('name', $key)->update($values);
            if ($updated === 0 && self::readRaw($key) === null) {
                throw $e;
            }
        }
    }

    /** The stored (decoded) value straight from the database, skipping every cache. */
    private static function readRaw(string $key, bool $strict = false): mixed
    {
        try {
            $value = DB::table(Tables::SETTING)->where('name', $key)->value('value');
        } catch (\Throwable $e) {
            if ($strict) {
                throw $e;
            }

            return null;
        }

        return $value === null ? null : self::decode($value);
    }

    private static function decode(mixed $value): mixed
    {
        if ($value === null) {
            return null;
        }
        try {
            return json_decode((string)$value, true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            return null;
        }
    }

    private static function configuredTokenKey(): ?string
    {
        try {
            $configured = config('df-masking.token_key');
        } catch (\Throwable $e) {
            $configured = null;
        }
        if (!is_string($configured) || trim($configured) === '') {
            return null;
        }
        $configured = trim($configured);
        if (str_starts_with($configured, 'base64:')) {
            $configured = substr($configured, 7);
        }
        $raw = base64_decode($configured, true);
        if ($raw === false || strlen($raw) !== 32) {
            Log::warning('df-masking: DF_MASKING_TOKEN_KEY is set but is not base64 of 32 bytes; using the stored key instead.');

            return null;
        }

        return $raw;
    }

    private static function decryptKey(string $encrypted): ?string
    {
        try {
            $raw = base64_decode(Crypt::decryptString($encrypted), true);
        } catch (\Throwable $e) {
            return null;
        }

        return ($raw !== false && strlen($raw) === 32) ? $raw : null;
    }
}

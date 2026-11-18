<?php

namespace DreamFactory\Core\Masking\Scanner;

use DreamFactory\Core\Masking\Support\Coverage;

/**
 * The covered services a scan visits: active database services whose service class is
 * DreamFactory\Core\SqlDb\Services\SqlDb or a subclass (every df-sqldb-family connector).
 * Coverage itself is decided in one place, Support\Coverage (the same answer the API overview
 * and enforcement use); this class adds what only the scanner needs.
 */
final class Services
{
    /** Driver names of warehouses that bill per query: never sampled unless explicitly requested. */
    public const COST_BEARING_DRIVERS = ['snowflake', 'databricks', 'trino', 'dremio', 'bigquery'];

    private function __construct()
    {
    }

    /**
     * @param ?string $only service name (case-insensitive) to restrict to, or null for all
     * @return list<array{id:int, name:string, label:string, type:string}>
     * @throws \InvalidArgumentException when $only names no active covered service
     */
    public static function covered(?string $only = null): array
    {
        $out = [];
        foreach (Coverage::covered(true) as $s) {
            if ($only !== null && strcasecmp($s['name'], $only) !== 0) {
                continue;
            }
            $out[] = ['id' => $s['id'], 'name' => $s['name'], 'label' => $s['label'], 'type' => $s['type']];
        }
        if ($only !== null && $out === []) {
            throw new \InvalidArgumentException("No active SQL database service named '$only'. Data Masking covers MySQL, MariaDB, PostgreSQL, SQLite, SQL Server, Oracle, Snowflake and other SQL services.");
        }
        return $out;
    }

    /** True when services of this type are SqlDb services. */
    public static function isCoveredType(string $type, ?string $sampleServiceName = null): bool
    {
        return Coverage::classifyType($type, $sampleServiceName) === true;
    }

    /** True when sampling this service costs the customer compute (cloud warehouses). */
    public static function isCostBearing(string $driver, string $type): bool
    {
        return in_array(strtolower($driver), self::COST_BEARING_DRIVERS, true)
            || in_array(strtolower($type), self::COST_BEARING_DRIVERS, true);
    }

    /**
     * True when $service is a SQLite service whose database file does not exist yet.
     *
     * Connecting to such a service makes PDO create an empty file (DreamFactory's built-in `db`
     * service starts that way). A scan is read-only and must not create it: run from the command
     * line as root, the new file would be root-owned and the service read-only for the web server.
     * There is nothing to classify in a database that does not exist, so callers skip it.
     */
    public static function isMissingSqliteFile(object $service): bool
    {
        // Read the service configuration, never the connection: DreamFactory opens the PDO
        // connection (and so creates the file) as soon as the connection is asked for.
        if (!method_exists($service, 'getConfig')) {
            return false;
        }
        try {
            // DreamFactory's getConfig() returns [] (not the default) when a service has no config.
            $driver = $service->getConfig('driver');
            if (!is_string($driver) || strtolower($driver) !== 'sqlite') {
                return false;
            }
            $file = $service->getConfig('database');
        } catch (\Throwable $e) {
            return false;
        }
        if (!is_string($file)) {
            return false;
        }
        if ($file === '' || $file === ':memory:' || str_starts_with($file, 'file:')) {
            return false;
        }
        // Same resolution as DreamFactory's SQLite connector: a bare file name lives in df.db.sqlite_storage.
        if (!str_contains($file, DIRECTORY_SEPARATOR)) {
            $storage = config('df.db.sqlite_storage');
            if (is_string($storage) && $storage !== '') {
                $file = rtrim($storage, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $file;
            }
        }
        clearstatcache(true, $file);

        return !file_exists($file);
    }

    /** Drops memoized coverage (tests, long-running processes). */
    public static function forget(): void
    {
        Coverage::forget();
    }
}

<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Enforcement;

use DreamFactory\Core\Masking\Support\Coverage;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

/**
 * What kind of service a request targets, for enforcement:
 *
 *  - covered:   a database service whose class is DreamFactory\Core\SqlDb\Services\SqlDb or a
 *               subclass (MySQL/MariaDB, PostgreSQL/AlloyDB, SQLite, SQL Server, Oracle,
 *               Snowflake, ...): masked.
 *  - uncovered: any other database service (MongoDB, Cassandra, CouchDB, DynamoDB, Salesforce,
 *               ...): humans and apps are unaffected; AI sessions are blocked when masking is on.
 *  - other:     not a database (system, user, files, remote web services, scripts, email, ...).
 *
 * The decision per service type is Support\Coverage::classifyType() (class of a service of
 * that type: DreamFactory service types register a factory closure, not a class name), cached
 * here in the application cache for a day so a request never has to build a service just to
 * decide. Service name to type comes from DreamFactory's own cached name/type map, so deciding
 * costs no query on a warm cache.
 */
final class ServiceClass
{
    public const COVERED = 'covered';
    public const UNCOVERED = 'uncovered';
    public const OTHER = 'other';

    public const SQLDB_CLASS = 'DreamFactory\\Core\\SqlDb\\Services\\SqlDb';

    private const CACHE_PREFIX = 'df-masking:service-kind:';
    private const CACHE_TTL = 86400;

    /** @var array<string,string> service type => kind */
    private static array $typeKinds = [];

    /** @var array<string,mixed> per-request name lookups */
    private static array $lookups = [];
    private static ?int $lookupRequest = null;
    private static float $lookupAt = 0.0;

    private function __construct()
    {
    }

    public static function kindOf(string $serviceName): string
    {
        $type = self::typeOf($serviceName);

        return $type === null ? self::OTHER : self::kindOfType($type, $serviceName);
    }

    public static function typeOf(string $serviceName): ?string
    {
        return self::lookup('type', $serviceName, function () use ($serviceName) {
            $manager = app('df.service');
            $type = $manager->getServiceTypeByName($serviceName);
            if ((!is_string($type) || $type === '') && ($stored = self::storedName($serviceName)) !== null) {
                $type = $manager->getServiceTypeByName($stored);
            }

            return is_string($type) && $type !== '' ? $type : null;
        });
    }

    public static function idOf(string $serviceName): ?int
    {
        return self::lookup('id', $serviceName, function () use ($serviceName) {
            $manager = app('df.service');
            $id = $manager->getServiceIdByName($serviceName);
            if (!is_numeric($id) && ($stored = self::storedName($serviceName)) !== null) {
                $id = $manager->getServiceIdByName($stored);
            }

            return is_numeric($id) ? (int)$id : null;
        });
    }

    /**
     * The stored spelling of a service name that differs only in case (DreamFactory lower-cases
     * names taken from URLs; its name maps are exact-key), or null.
     */
    private static function storedName(string $serviceName): ?string
    {
        try {
            foreach ((array)app('df.service')->getServiceNameTypeMap() as $name => $_) {
                if (is_string($name) && $name !== $serviceName && strcasecmp($name, $serviceName) === 0) {
                    return $name;
                }
            }
        } catch (\Throwable $e) {
        }

        return null;
    }

    /**
     * Name -> type/id through DreamFactory's cached maps, memoized per HTTP request (each map
     * read unserializes the whole map; a request asks several times).
     */
    private static function lookup(string $what, string $serviceName, \Closure $resolve): mixed
    {
        $request = 0;
        try {
            $request = app()->bound('request') ? spl_object_id(app('request')) : 0;
        } catch (\Throwable $e) {
        }
        $now = microtime(true);
        if (self::$lookupRequest !== $request || ($now - self::$lookupAt) > 30.0) {
            self::$lookups = [];
            self::$lookupRequest = $request;
            self::$lookupAt = $now;
        }
        $key = $what . "\0" . $serviceName;
        if (array_key_exists($key, self::$lookups)) {
            return self::$lookups[$key];
        }
        try {
            $value = $resolve();
        } catch (\Throwable $e) {
            return null; // not memoized: the next call retries
        }

        return self::$lookups[$key] = $value;
    }

    /** @param string|null $sampleService a service of this type, built when the type is new */
    public static function kindOfType(string $type, ?string $sampleService = null): string
    {
        if (isset(self::$typeKinds[$type])) {
            return self::$typeKinds[$type];
        }
        $cacheKey = self::CACHE_PREFIX . $type;
        try {
            $cached = Cache::get($cacheKey);
            if (in_array($cached, [self::COVERED, self::UNCOVERED, self::OTHER], true)) {
                return self::$typeKinds[$type] = $cached;
            }
        } catch (\Throwable $e) {
        }

        $kind = self::detect($type, $sampleService);
        if ($kind === null) {
            // Could not build a sample service: undecided, never cached. Treated as uncovered by
            // the caller (AI blocked, humans unaffected) until a later request decides.
            return self::UNCOVERED;
        }
        self::$typeKinds[$type] = $kind;
        try {
            Cache::put($cacheKey, $kind, self::CACHE_TTL);
        } catch (\Throwable $e) {
        }

        return $kind;
    }

    /** @return int[] ids of every covered service (active or not) */
    public static function coveredServiceIds(): array
    {
        try {
            $manager = app('df.service');
            $types = (array)$manager->getServiceNameTypeMap();
            $ids = [];
            foreach ($types as $name => $type) {
                if (is_string($type) && self::kindOfType($type, (string)$name) === self::COVERED) {
                    $id = $manager->getServiceIdByName((string)$name);
                    if (is_numeric($id)) {
                        $ids[] = (int)$id;
                    }
                }
            }
            sort($ids);

            return $ids;
        } catch (\Throwable $e) {
            Log::warning('df-masking: could not list covered services: ' . $e->getMessage());

            return [];
        }
    }

    /** Drops the per-process memo (tests). */
    public static function forget(): void
    {
        self::$typeKinds = [];
        self::$lookups = [];
        self::$lookupRequest = null;
    }

    /**
     * Delegates to Support\Coverage::classifyType() (the platform's single definition, also
     * used by the API overview and the scanner): true = covered, false = uncovered database,
     * null = not a database service.
     */
    private static function detect(string $type, ?string $sampleService): ?string
    {
        try {
            if ($sampleService === null) {
                foreach ((array)app('df.service')->getServiceNameTypeMap() as $name => $t) {
                    if ($t === $type) {
                        $sampleService = (string)$name;
                        break;
                    }
                }
            }
            $covered = Coverage::classifyType($type, $sampleService);
        } catch (\Throwable $e) {
            Log::debug("df-masking: could not classify service type '$type': " . $e->getMessage());

            return null;
        }

        return match ($covered) {
            true => self::COVERED,
            false => self::UNCOVERED,
            default => self::OTHER,
        };
    }
}

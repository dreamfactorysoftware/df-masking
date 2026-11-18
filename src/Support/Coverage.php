<?php

namespace DreamFactory\Core\Masking\Support;

use DreamFactory\Core\Models\Service;
use Illuminate\Support\Facades\Cache;

/**
 * Which database services Data Masking covers.
 *
 * Covered = the service's class is DreamFactory\Core\SqlDb\Services\SqlDb or a subclass
 * (MySQL/MariaDB, PostgreSQL/AlloyDB, SQLite, SQL Server, Oracle, Snowflake and every other
 * connector built on df-sqldb). Uncovered = any other service of a database type group
 * ("Database", "Big Data": MongoDB, Cassandra, CouchDB, DynamoDB, Salesforce, ...). Everything
 * else (files, remote web services, scripts, email, system) is not a database service and is
 * out of scope.
 *
 * The service list is cached under PolicyVersion (service saves/deletes bump it).
 */
final class Coverage
{
    public const SQLDB_CLASS = 'DreamFactory\\Core\\SqlDb\\Services\\SqlDb';
    public const DB_CLASS = 'DreamFactory\\Core\\Database\\Services\\BaseDbService';
    public const SQLDB_CONFIG_CLASS = 'DreamFactory\\Core\\SqlDb\\Models\\BaseSqlDbConfig';

    /** Service type groups that hold database services. */
    public const DB_GROUPS = ['database', 'big data'];

    /** @var array<string,bool|null> service type => covered (null: not a database type) */
    private static array $typeMemo = [];

    /** @var list<array{id:int,name:string,label:string,type:string,is_active:bool,covered:bool}>|null */
    private static ?array $memo = null;
    private static ?int $memoVersion = null;

    private function __construct()
    {
    }

    /**
     * Every database service, ordered by name.
     *
     * @return list<array{id:int,name:string,label:string,type:string,is_active:bool,covered:bool}>
     */
    public static function services(): array
    {
        $version = PolicyVersion::current();
        if (self::$memo !== null && self::$memoVersion === $version) {
            return self::$memo;
        }
        $key = 'df-masking:coverage:v' . $version;
        $list = null;
        try {
            $cached = $version > 0 ? Cache::get($key) : null;
            $list = is_array($cached) ? $cached : null;
        } catch (\Throwable $e) {
        }
        if ($list === null) {
            $list = self::load();
            try {
                if ($version > 0) {
                    Cache::put($key, $list, 600);
                }
            } catch (\Throwable $e) {
            }
        }
        self::$memo = $list;
        self::$memoVersion = $version;

        return $list;
    }

    /** @return list<array{id:int,name:string,label:string,type:string,is_active:bool,covered:bool}> */
    public static function covered(bool $activeOnly = false): array
    {
        return array_values(array_filter(
            self::services(),
            fn (array $s) => $s['covered'] && (!$activeOnly || $s['is_active'])
        ));
    }

    /** @return list<array{id:int,name:string,label:string,type:string,is_active:bool,covered:bool}> */
    public static function uncovered(bool $activeOnly = false): array
    {
        return array_values(array_filter(
            self::services(),
            fn (array $s) => !$s['covered'] && (!$activeOnly || $s['is_active'])
        ));
    }

    /** @return int[] ids of covered services */
    public static function coveredIds(): array
    {
        return array_map(fn (array $s) => $s['id'], self::covered());
    }

    /** @return array{id:int,name:string,label:string,type:string,is_active:bool,covered:bool}|null */
    public static function byName(string $name): ?array
    {
        foreach (self::services() as $service) {
            if (strcasecmp($service['name'], $name) === 0) {
                return $service;
            }
        }

        return null;
    }

    /** @return array{id:int,name:string,label:string,type:string,is_active:bool,covered:bool}|null */
    public static function byId(int $id): ?array
    {
        foreach (self::services() as $service) {
            if ($service['id'] === $id) {
                return $service;
            }
        }

        return null;
    }

    /**
     * true = covered SQL service type, false = uncovered database type, null = not a database
     * service type (or unknown).
     *
     * DreamFactory service types register a factory closure, not a class, so the class is
     * learned from one service instance of the type (constructing a service never opens a
     * connection; DreamFactory does the same on every request to it). When no instance can be
     * built, the config model decides (df-sqldb family configs extend BaseSqlDbConfig).
     * Memoised per type for the life of the process.
     */
    public static function classifyType(string $type, ?string $sampleServiceName = null): ?bool
    {
        if (array_key_exists($type, self::$typeMemo)) {
            return self::$typeMemo[$type];
        }
        try {
            $info = app('df.service')->getServiceType($type);
        } catch (\Throwable $e) {
            $info = null;
        }
        if ($info === null || !in_array(strtolower((string)$info->getGroup()), self::DB_GROUPS, true)) {
            return self::$typeMemo[$type] = null;
        }

        $covered = null;
        try {
            $name = $sampleServiceName ?? Service::query()->where('type', $type)->value('name');
            if ($name !== null) {
                $covered = is_a(app('df.service')->getService((string)$name), self::SQLDB_CLASS);
            }
        } catch (\Throwable $e) {
            $covered = null;
        }
        if ($covered === null) {
            try {
                $handler = (string)$info->getConfigHandler();
                $covered = $handler !== '' && class_exists(self::SQLDB_CONFIG_CLASS)
                    && is_a($handler, self::SQLDB_CONFIG_CLASS, true);
            } catch (\Throwable $e) {
                $covered = false;
            }
        }

        return self::$typeMemo[$type] = $covered;
    }

    public static function forget(): void
    {
        self::$memo = null;
        self::$memoVersion = null;
        self::$typeMemo = [];
    }

    /** @return list<array{id:int,name:string,label:string,type:string,is_active:bool,covered:bool}> */
    private static function load(): array
    {
        $out = [];
        try {
            $rows = Service::query()->orderBy('name')->get(['id', 'name', 'label', 'type', 'is_active']);
        } catch (\Throwable $e) {
            return [];
        }
        foreach ($rows as $row) {
            $covered = self::classifyType((string)$row->type, (string)$row->name);
            if ($covered === null) {
                continue;
            }
            $out[] = [
                'id' => (int)$row->id,
                'name' => (string)$row->name,
                'label' => (string)($row->label ?: $row->name),
                'type' => (string)$row->type,
                'is_active' => (bool)$row->is_active,
                'covered' => $covered,
            ];
        }

        return $out;
    }
}

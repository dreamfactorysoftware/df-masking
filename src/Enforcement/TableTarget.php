<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Enforcement;

/**
 * A covered table addressed by a request: service, DreamFactory table name, its fields and
 * relations, read from DreamFactory's (cached) table schema.
 *
 * Field keys are lower-cased DreamFactory field names, i.e. the alias when the admin defined
 * one, otherwise the column name: that is how DreamFactory names fields in responses and how it
 * resolves field names in filters, order and fields parameters.
 */
final class TableTarget
{
    /**
     * @param array<string,array{name:string,column:string,type:?string,db_type:?string,virtual?:bool,select_fn?:?string,filter_fn?:?string}> $fields
     *        select_fn / filter_fn: the field's SELECT / FILTER db_function (DreamFactory computes
     *        the value, or the filtered expression, with it), null when it has none
     * @param array<string,array{name:string,type:string,ref_service_id:?int,ref_table:?string}> $relations
     * @param list<string> $primaryKey lower-cased field names
     */
    public function __construct(
        public readonly string $service,
        public readonly int $serviceId,
        public readonly string $serviceType,
        public readonly string $table,
        public readonly array $fields,
        public readonly array $relations,
        public readonly array $primaryKey,
    ) {
    }

    /** Long-running processes (queue workers, schedule:work) see one request object for hours. */
    private const MEMO_SECONDS = 30.0;

    /** @var array<string,self|false> */
    private static array $memo = [];
    private static ?int $memoRequest = null;
    private static float $memoAt = 0.0;

    /**
     * @param string $tableName  the table as written in the URL (any case, may be an alias)
     * @param bool   $byRealName resolve a real table name (the _spec model lists tables by their
     *                           real name) instead of the name a URL uses
     * @return self|null null when the service is not covered or the table does not exist
     *                   (DreamFactory then answers the request itself, e.g. with a 404)
     */
    public static function resolve(string $service, string $tableName, bool $byRealName = false): ?self
    {
        self::resetForRequest();
        $key = strtolower($service) . "\0" . strtolower($tableName) . ($byRealName ? "\0r" : '');
        if (array_key_exists($key, self::$memo)) {
            return self::$memo[$key] ?: null;
        }

        return (self::$memo[$key] = self::build($service, $tableName, $byRealName) ?? false) ?: null;
    }

    /** @return array<string,string> lower-cased real column name => real name (database columns, not virtual fields) */
    public function realColumns(): array
    {
        $out = [];
        foreach ($this->fields as $field) {
            if (empty($field['virtual'])) {
                $out[strtolower($field['column'])] = $field['column'];
            }
        }

        return $out;
    }

    /** The service-side handle used to read schemas (covered services only). */
    public static function serviceInstance(string $service): ?object
    {
        if (ServiceClass::kindOf($service) !== ServiceClass::COVERED) {
            return null;
        }
        $manager = app('df.service');
        $instance = self::handlingInstance($manager, $service) ?? $manager->getService($service);

        return is_a($instance, ServiceClass::SQLDB_CLASS) ? $instance : null;
    }

    /**
     * In a web request, the instance DreamFactory itself created for this service
     * (ServiceManager::getService() builds a new one on every call, about half a millisecond, and
     * keeps the latest in its list): the one handling the request, so its schema is the one
     * DreamFactory serves. Console processes live long, so they always build a fresh instance.
     * Null when unavailable (then getService() as before).
     */
    private static function handlingInstance(object $manager, string $service): ?object
    {
        try {
            $app = app();
            if (!method_exists($app, 'runningInConsole') || $app->runningInConsole()) {
                return null;
            }
            $read = \Closure::bind(function (string $name) {
                return isset($this->services) && is_array($this->services) ? ($this->services[$name] ?? null) : null;
            }, $manager, get_class($manager));
            $instance = $read($service);
        } catch (\Throwable $e) {
            return null;
        }

        return is_object($instance) ? $instance : null;
    }

    public static function forget(): void
    {
        self::$memo = [];
        self::$memoRequest = null;
        self::$memoAt = 0.0;
    }

    /** @return array<string,array{name:string,column:string,type:?string,db_type:?string}> keyed by lower-cased real column name */
    public function fieldsByColumn(): array
    {
        $out = [];
        foreach ($this->fields as $field) {
            $out[strtolower($field['column'])] = $field;
        }

        return $out;
    }

    private static function build(string $service, string $tableName, bool $byRealName): ?self
    {
        $instance = self::serviceInstance($service);
        if ($instance === null) {
            return null;
        }
        $schema = null;
        if (!$byRealName) {
            // Exactly as DreamFactory resolves a URL (BaseDbTableResource::doesTableExist): the
            // table list re-keyed by lower-cased alias (or name), the last entry winning.
            $byAlias = [];
            foreach ((array)$instance->getTableNames() as $candidate) {
                if (is_object($candidate)) {
                    $byAlias[strtolower((string)$candidate->getName(true))] = $candidate;
                }
            }
            $hit = $byAlias[strtolower($tableName)] ?? null;
            if ($hit !== null) {
                $schema = $instance->getTableSchema((string)$hit->name);
            }
        }
        if (!$schema) {
            // A real table name (internal callers, the _spec model), or a table list DreamFactory
            // did not return (masking more than DreamFactory serves is harmless).
            $schema = $instance->getTableSchema($tableName);
        }
        if (!$schema) {
            return null;
        }

        $fields = [];
        $byColumn = [];
        foreach ($schema->getColumns() as $column) {
            $name = (string)$column->getName(true);
            $real = (string)$column->name;
            $fields[strtolower($name)] = [
                'name' => $name,
                'column' => $real,
                'type' => isset($column->type) ? (string)$column->type : null,
                'db_type' => isset($column->dbType) ? (string)$column->dbType : null,
                'virtual' => (bool)($column->isVirtual ?? false),
                'select_fn' => self::dbFunction($column, 'SELECT'),
                'filter_fn' => self::dbFunction($column, 'FILTER'),
            ];
            $byColumn[strtolower($real)] = $name;
        }

        $relations = [];
        foreach ($schema->getRelations() as $relation) {
            $name = (string)$relation->getName(true);
            $relations[strtolower($name)] = [
                'name' => $name,
                'type' => (string)$relation->type,
                'ref_service_id' => isset($relation->refServiceId) ? (int)$relation->refServiceId : null,
                'ref_table' => isset($relation->refTable) ? (string)$relation->refTable : null,
            ];
        }

        $primaryKey = [];
        foreach ((array)$schema->getPrimaryKey() as $pk) {
            $primaryKey[] = strtolower($byColumn[strtolower((string)$pk)] ?? (string)$pk);
        }

        return new self(
            $service,
            (int)(ServiceClass::idOf($service) ?? 0),
            (string)(ServiceClass::typeOf($service) ?? ''),
            (string)$schema->name,
            $fields,
            $relations,
            $primaryKey,
        );
    }

    /** The column's db_function for one use (DbFunctionUses::SELECT / FILTER), or null. */
    private static function dbFunction(object $column, string $use): ?string
    {
        try {
            $fn = method_exists($column, 'getDbFunction') ? $column->getDbFunction($use) : null;
        } catch (\Throwable $e) {
            $fn = null;
        }

        return is_string($fn) && trim($fn) !== '' ? $fn : null;
    }

    /**
     * One memo per HTTP request object, and never older than MEMO_SECONDS, so a long-running
     * process notices schema changes (new columns are classified before they are served).
     */
    private static function resetForRequest(): void
    {
        $id = 0;
        try {
            $id = app()->bound('request') ? spl_object_id(app('request')) : 0;
        } catch (\Throwable $e) {
        }
        $now = microtime(true);
        if (self::$memoRequest !== $id || ($now - self::$memoAt) > self::MEMO_SECONDS) {
            self::$memo = [];
            self::$memoRequest = $id;
            self::$memoAt = $now;
        }
    }
}

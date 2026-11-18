<?php
declare(strict_types=1);

namespace DreamFactory\Core\Masking\Classifier;

/**
 * Maps a column's native database type (and DreamFactory's simple type as a fallback) to the
 * classifier's type vocabulary: string, text, integer, smallint, bigint, decimal, float, double,
 * money, date, time, timestamp, timestamptz, datetime, boolean, json, jsonb, binary, uuid.
 *
 * The native type is preferred because DreamFactory's simple types are lossy for classification
 * (PostgreSQL text and varchar are both "string", smallint is "integer", integer keys become
 * "id"/"reference"). For PostgreSQL and SQLite the mapping reproduces the classifier's reference
 * introspection exactly (format_type output, SQLite affinity rules), so a DreamFactory scan feeds
 * the engine the same facts the evaluated corpus runs did.
 *
 * Pure and deterministic; no I/O.
 */
final class TypeMap
{
    /** Types whose values are never sampled. */
    public const UNSAMPLED = ['binary'];

    private const CHAR_TYPES = ['character varying', 'varchar', 'character', 'char', 'bpchar', 'nchar', 'nvarchar', 'varchar2', 'nvarchar2', 'national character varying', 'national character', 'national char'];

    private function __construct()
    {
    }

    /**
     * @param ?string $dbType native type as DreamFactory reports it (ColumnSchema::$dbType)
     * @param ?string $dfType DreamFactory simple type (ColumnSchema::$type), used when the native type is unknown
     * @param ?string $driver Illuminate driver name (pgsql, mysql, mariadb, sqlite, sqlsrv, oracle, snowflake, ...)
     * @return array{0:string, 1:?int} [engine type, character length for bounded string columns]
     */
    public static function map(?string $dbType, ?string $dfType = null, ?string $driver = null): array
    {
        $db = strtolower(trim((string) $dbType));
        $driver = $driver !== null ? strtolower($driver) : null;
        if ($driver === 'sqlite') {
            return self::sqlite($db);
        }
        if ($db !== '') {
            $type = self::fromDbType($db, $driver);
            if ($type !== null) {
                return [$type, $type === 'string' ? self::charLength($db) : null];
            }
        }
        return [self::fromDfType($dfType), null];
    }

    /** Engine type only. */
    public static function engineType(?string $dbType, ?string $dfType = null, ?string $driver = null): string
    {
        return self::map($dbType, $dfType, $driver)[0];
    }

    /** SQLite declared type -> engine type by SQLite's affinity rules (as the reference introspection does). */
    public static function sqlite(string $decl): array
    {
        $u = strtoupper($decl);
        $size = preg_match('/\((\d+)/', $u, $m) ? (int) $m[1] : null;
        return match (true) {
            $u === '' => ['text', null],
            str_contains($u, 'BIGINT') => ['bigint', null],
            str_contains($u, 'SMALLINT') || str_contains($u, 'TINYINT') => ['smallint', null],
            str_contains($u, 'INT') => ['integer', null],
            str_contains($u, 'BOOL') => ['boolean', null],
            str_contains($u, 'UUID') => ['uuid', null],
            str_contains($u, 'JSON') => ['json', null],
            str_contains($u, 'DATETIME') || str_contains($u, 'TIMESTAMP') => ['timestamp', null],
            str_contains($u, 'DATE') => ['date', null],
            str_contains($u, 'CHAR') => ['string', $size],
            str_contains($u, 'CLOB') || str_contains($u, 'TEXT') => ['text', null],
            str_contains($u, 'BLOB') => ['binary', null],
            str_contains($u, 'REAL') || str_contains($u, 'FLOA') || str_contains($u, 'DOUB') => ['double', null],
            str_contains($u, 'NUMERIC') || str_contains($u, 'DECIMAL') => ['decimal', null],
            default => ['text', null],
        };
    }

    /** Native (lower-cased) type name -> engine type, or null when unknown. */
    private static function fromDbType(string $db, ?string $driver): ?string
    {
        // PostgreSQL arrays (format_type "text[]", internal "_int4") are text, like the reference.
        if (str_ends_with($db, '[]') || ($driver === 'pgsql' && str_starts_with($db, '_'))) {
            return 'text';
        }
        // SQL Server (n)varchar(max) / varbinary(max) are LOB columns.
        if (preg_match('/^(n?varchar|n?char)\s*\(\s*max\s*\)/', $db)) {
            return 'text';
        }
        // MySQL tinyint(1) is how booleans are declared (DreamFactory maps it the same way).
        if (preg_match('/^tinyint\s*\(\s*1\s*\)/', $db)) {
            return 'boolean';
        }
        $base = preg_replace('/\([^)]*\)/', '', $db) ?? $db;                      // drop (n), (p,s), enum(...)
        $base = preg_replace('/\b(unsigned|signed|zerofill)\b/', '', $base) ?? $base;
        $base = trim(preg_replace('/\s+/', ' ', $base) ?? $base);
        if ($base === '') {
            return null;
        }
        if (in_array($base, self::CHAR_TYPES, true)) {
            return 'string';
        }
        if ($base === 'number' || ($driver === 'snowflake' && in_array($base, ['numeric', 'decimal'], true))) {
            return self::oracleNumber($db);
        }
        // SQL Server `timestamp` is a synonym of rowversion: an 8-byte row version counter, not a
        // date. It cannot be converted to text and holds no personal data: never sampled.
        if ($base === 'rowversion' || ($driver === 'sqlsrv' && $base === 'timestamp')) {
            return 'binary';
        }
        if (str_starts_with($base, 'timestamp')) {
            if (preg_match('/with (local )?time zone|^timestamp_(tz|ltz)$|^timestamptz$/', $base) && !str_contains($base, 'without')) {
                return 'timestamptz';
            }
            return 'timestamp';
        }
        if ($base === 'timetz' || str_starts_with($base, 'time ') || $base === 'time') {
            return 'time';
        }
        if (str_starts_with($base, 'interval')) {
            return 'string';
        }
        return match ($base) {
            'text', 'tinytext', 'mediumtext', 'longtext', 'ntext', 'clob', 'nclob', 'long', 'long varchar', 'xml', 'tsvector' => 'text',
            'string' => 'string',
            'name', 'citext', 'inet', 'cidr', 'macaddr', 'macaddr8', 'point', 'line', 'lseg', 'box', 'path', 'polygon', 'circle',
            'varbit', 'bit varying', 'enum', 'set', 'rowid', 'urowid', 'sysname', 'tsquery', 'hstore', 'ltree' => 'string',
            'bit' => $driver === 'pgsql' ? 'string' : 'boolean',
            'bool', 'boolean' => 'boolean',
            'smallint', 'int2', 'tinyint', 'smallserial', 'byteint' => 'smallint',
            'integer', 'int', 'int4', 'mediumint', 'serial', 'oid', 'year' => 'integer',
            'bigint', 'int8', 'bigserial' => 'bigint',
            'decimal', 'numeric', 'dec' => 'decimal',
            'money', 'smallmoney' => 'money',
            'real', 'float4', 'binary_float' => 'float',
            'float' => in_array($driver, ['sqlsrv', 'snowflake'], true) ? 'double' : 'float',
            'double', 'double precision', 'float8', 'binary_double' => 'double',
            'date' => 'date',
            'datetime', 'datetime2', 'smalldatetime' => 'datetime',
            'datetimeoffset' => 'timestamptz',
            'json' => 'json',
            'jsonb' => 'jsonb',
            'variant', 'object', 'array' => 'json',
            'uuid', 'uniqueidentifier' => 'uuid',
            'bytea', 'blob', 'tinyblob', 'mediumblob', 'longblob', 'binary', 'varbinary', 'image', 'raw', 'long raw', 'bfile' => 'binary',
            'geometry', 'geography' => $driver === 'pgsql' ? 'string' : 'binary',
            default => self::knownSimpleType($base),
        };
    }

    /** Oracle / Snowflake NUMBER(p,s): scale > 0 -> decimal; integers by precision; bare NUMBER -> decimal. */
    private static function oracleNumber(string $db): string
    {
        if (!preg_match('/\(\s*(\d+)\s*(?:,\s*(-?\d+)\s*)?\)/', $db, $m)) {
            return 'decimal';
        }
        $p = (int) $m[1];
        $s = isset($m[2]) ? (int) $m[2] : 0;
        if ($s > 0) {
            return 'decimal';
        }
        return match (true) {
            $p <= 4 => 'smallint',
            $p <= 9 => 'integer',
            default => 'bigint',
        };
    }

    /** A DreamFactory simple type passed where a native type was expected (or an unknown native type). */
    private static function knownSimpleType(string $t): ?string
    {
        $mapped = self::fromDfType($t);
        return ($mapped === 'string' && $t !== 'string') ? null : $mapped;
    }

    /** DreamFactory simple type -> engine type. Unknown -> 'string'. */
    public static function fromDfType(?string $dfType): string
    {
        return match (strtolower((string) $dfType)) {
            'string' => 'string',
            'text', 'longtext', 'mediumtext', 'array' => 'text',
            'id', 'mediumid', 'reference', 'integer', 'mediumint', 'user_id', 'user_id_on_create', 'user_id_on_update' => 'integer',
            'bigid', 'bigint' => 'bigint',
            'smallid', 'smallint', 'tinyint' => 'smallint',
            'decimal' => 'decimal',
            'float' => 'float',
            'double' => 'double',
            'money' => 'money',
            'boolean' => 'boolean',
            'date' => 'date',
            'datetime' => 'datetime',
            'datetimetz', 'timestamptz' => 'timestamptz',
            'timestamp', 'timestamp_on_create', 'timestamp_on_update' => 'timestamp',
            'time', 'timetz' => 'time',
            'json', 'object' => 'json',
            'jsonb' => 'jsonb',
            'binary' => 'binary',
            'uuid', 'timeuuid' => 'uuid',
            default => 'string',
        };
    }

    /** Declared length of a bounded character column (varchar(20) -> 20), else null. */
    private static function charLength(string $db): ?int
    {
        if (preg_match('/^(?:character varying|varchar2?|nvarchar2?|character|n?char|bpchar|national character(?: varying)?|national char)\s*\(\s*(\d+)/', $db, $m)) {
            return (int) $m[1];
        }
        return null;
    }
}

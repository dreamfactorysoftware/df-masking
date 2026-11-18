<?php

namespace DreamFactory\Core\Masking\Scanner;

use DreamFactory\Core\Masking\Classifier\ColumnMeta;
use DreamFactory\Core\Masking\Classifier\TableMeta;
use DreamFactory\Core\Masking\Classifier\TypeMap;

/**
 * Reads a covered service's schema through DreamFactory's own schema layer (the same TableSchema /
 * ColumnSchema objects the service's _schema and _table resources use), so it works on every
 * df-sqldb driver without driver-specific catalog queries.
 *
 * The scan wants the schema as it is now: the table list is refreshed and each table's cached
 * schema is dropped before it is read again, exactly like DreamFactory's "refresh schema".
 */
final class SchemaReader
{
    public function __construct(private readonly object $service)
    {
    }

    /** Illuminate driver name of the service connection (pgsql, mysql, sqlite, sqlsrv, oracle, snowflake, ...). */
    public function driver(): string
    {
        return (string) $this->service->getConnection()->getDriverName();
    }

    /**
     * Fresh list of the service's tables and views, keyed by lower-cased DreamFactory name.
     *
     * @return array<string,object> name => TableSchema (names only; columns not yet loaded)
     */
    public function tableNames(): array
    {
        $tables = $this->service->getTableNames(null, true);
        if (method_exists($this->service, 'removeFromCache')) {
            // getTableSchema() merges relationships from this cache; drop it so it is rebuilt once.
            $this->service->removeFromCache('table_constraints');
        }
        return is_array($tables) ? $tables : [];
    }

    /** Full schema of one table, re-read from the database. Null when the table vanished. */
    public function tableSchema(string $name): ?object
    {
        if (method_exists($this->service, 'removeFromCache')) {
            $this->service->removeFromCache('table:' . strtolower($name));
        }
        $schema = $this->service->getTableSchema($name);
        return is_object($schema) ? $schema : null;
    }

    /**
     * DreamFactory TableSchema -> classifier TableMeta plus what the sampler needs.
     *
     * @return array{meta:TableMeta, plan:array}
     *   plan = [from => quoted table, kind => table|view, key => list<quoted>, key_kind => pk|unique|null,
     *           columns => list<array{name, quoted, type, df_type, sampled, virtual, select_fn}>]
     *   Every identifier is quoted here, from the raw schema/table/column names, with the dialect's
     *   quote character doubled inside the name (quote()). DreamFactory's own quotedName is never
     *   used: df-database builds it as quote + name + quote without escaping, so a name holding the
     *   quote character could not be read and the rest of the name would be parsed as SQL.
     *   select_fn: the column's SELECT db_function (DreamFactory computes the value with it: virtual
     *   fields, or a SELECT override); Enforcement\DerivedFields::applyToScan() derives its verdict
     *   from the columns the expression reads.
     */
    public static function describe(object $ts, string $driver): array
    {
        $columns = [];
        $plan = [];
        $pk = [];
        foreach (self::columnsOf($ts) as $c) {
            $name = (string) $c->name;
            [$type, $size] = TypeMap::map(is_string($c->dbType ?? null) ? $c->dbType : null, is_string($c->type ?? null) ? $c->type : null, $driver);
            if ($size === null && $type === 'string' && !in_array($driver, ['pgsql', 'sqlite'], true)
                && is_numeric($c->size ?? null) && (int) $c->size > 0 && (int) $c->size < 1000000) {
                // Some drivers (SQL Server) report "nvarchar" without its length; DreamFactory keeps
                // the length in $size. PostgreSQL/SQLite keep the reference introspection's rule.
                $size = (int) $c->size;
            }
            $virtual = (bool) ($c->isVirtual ?? false);
            $sampled = !$virtual && !in_array($type, TypeMap::UNSAMPLED, true);
            $comment = is_string($c->comment ?? null) && trim($c->comment) !== '' ? $c->comment : null;
            $columns[] = new ColumnMeta(
                name: $name,
                dbType: (string) ($c->dbType ?? ''),
                dfType: $type,
                size: $size,
                isPrimaryKey: (bool) ($c->isPrimaryKey ?? false),
                isForeignKey: (bool) ($c->isForeignKey ?? false),
                refTable: is_string($c->refTable ?? null) && $c->refTable !== '' ? $c->refTable : null,
                isUnique: (bool) ($c->isUnique ?? false),
                comment: $comment,
                sampleable: $sampled,
            );
            $plan[] = [
                'name' => $name,
                'quoted' => self::quotedColumn($c, $driver),
                'type' => $type,
                'df_type' => is_string($c->type ?? null) ? $c->type : null,
                'sampled' => $sampled,
                'virtual' => $virtual,
                'select_fn' => self::selectFunction($c),
            ];
        }
        foreach ((array) ($ts->primaryKey ?? []) as $k) {
            $pk[] = (string) $k;
        }
        $uniqueKey = $pk === [] ? self::singleUniqueColumn($ts) : null;
        $quotedByName = [];
        foreach ($plan as $p) {
            $quotedByName[$p['name']] = $p['quoted'];
        }
        $keyNames = $pk !== [] ? $pk : ($uniqueKey !== null ? [$uniqueKey] : []);
        $key = [];
        foreach ($keyNames as $k) {
            if (!isset($quotedByName[$k])) {
                $key = [];
                break;
            }
            $key[] = $quotedByName[$k];
        }
        $isView = (bool) ($ts->isView ?? false);
        $dfName = (string) $ts->name;
        $meta = new TableMeta(
            schema: (string) ($ts->schemaName ?? ''),
            name: (string) (($ts->resourceName ?? null) ?: $dfName),
            dfName: $dfName,
            kind: $isView ? 'view' : 'table',
            columns: $columns,
            primaryKey: $pk,
            uniqueKey: $uniqueKey,
        );
        return ['meta' => $meta, 'plan' => [
            'from' => self::quotedTable($ts, $driver),
            'kind' => $isView ? 'view' : 'table',
            'key' => $key,
            'key_kind' => $key === [] ? null : ($pk !== [] ? 'pk' : 'unique'),
            'columns' => $plan,
        ]];
    }

    /** The SELECT db_function of a column (DbFunctionUses::SELECT), or null. */
    private static function selectFunction(object $c): ?string
    {
        try {
            $fn = method_exists($c, 'getDbFunction') ? $c->getDbFunction('SELECT') : null;
        } catch (\Throwable $e) {
            $fn = null;
        }
        return is_string($fn) && trim($fn) !== '' ? $fn : null;
    }

    /** @return list<object> ColumnSchema objects in table order */
    private static function columnsOf(object $ts): array
    {
        if (method_exists($ts, 'getColumns')) {
            return array_values($ts->getColumns());
        }
        return array_values((array) ($ts->columns ?? []));
    }

    /** First single-column unique constraint, for tables without a primary key. */
    private static function singleUniqueColumn(object $ts): ?string
    {
        foreach ((array) ($ts->constraints ?? []) as $con) {
            $type = strtolower((string) ($con['constraint_type'] ?? ''));
            $cols = (array) ($con['column_name'] ?? []);
            if ($type !== '' && $type[0] === 'u' && count($cols) === 1) {
                return (string) reset($cols);
            }
        }
        return null;
    }

    /**
     * schema.table from the raw names: TableSchema::schemaName (empty on SQLite) and resourceName
     * (the table's own name; DreamFactory defaults it to name). Never TableSchema::quotedName
     * (unescaped), and never split on dots: a dot inside a name is part of it.
     */
    public static function quotedTable(object $ts, string $driver): string
    {
        $schema = is_string($ts->schemaName ?? null) ? $ts->schemaName : '';
        $name = $ts->resourceName ?? null;
        if (!is_string($name) || $name === '') {
            $name = (string) $ts->name;
        }
        return ($schema !== '' ? self::quote($schema, $driver) . '.' : '') . self::quote($name, $driver);
    }

    /** The column name quoted from ColumnSchema::name (never ColumnSchema::quotedName, which is unescaped). */
    public static function quotedColumn(object $c, string $driver): string
    {
        return self::quote((string) $c->name, $driver);
    }

    /**
     * One identifier, quoted for the driver with the closing quote character doubled inside it,
     * so any legal name is read as that name and nothing in it is ever parsed as SQL:
     * MySQL/MariaDB/SingleStore `a``b`, SQL Server/SQL Anywhere [a]]b], everyone else "a""b"
     * (SQL standard: PostgreSQL, SQLite, Oracle, Snowflake, Db2, Firebird). Informix: DreamFactory
     * quotes nothing there (DELIMIDENT unset), so plain names stay bare; any other name is
     * double-quoted with doubling (with DELIMIDENT unset DreamFactory cannot read such a column
     * itself, and the quoted text is a literal: nothing in it runs).
     */
    public static function quote(string $ident, string $driver): string
    {
        return match (strtolower($driver)) {
            'mysql', 'mariadb', 'memsql', 'singlestore' => '`' . str_replace('`', '``', $ident) . '`',
            'sqlsrv', 'dblib', 'sqlanywhere' => '[' . str_replace(']', ']]', $ident) . ']',
            'informix' => preg_match('/^[A-Za-z_][A-Za-z0-9_$]*$/D', $ident) ? $ident : '"' . str_replace('"', '""', $ident) . '"',
            default => '"' . str_replace('"', '""', $ident) . '"',
        };
    }
}

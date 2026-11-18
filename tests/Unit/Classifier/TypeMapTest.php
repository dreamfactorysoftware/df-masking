<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Classifier;

use DreamFactory\Core\Masking\Classifier\TypeMap;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class TypeMapTest extends TestCase
{
    public static function cases(): iterable
    {
        // PostgreSQL: DreamFactory stores LOWER(format_type(...)); must match the reference introspection.
        yield ['pgsql', 'character varying(255)', 'string', ['string', 255]];
        yield ['pgsql', 'character varying', 'string', ['string', null]];
        yield ['pgsql', 'character(1)', 'string', ['string', 1]];
        yield ['pgsql', 'text', 'string', ['text', null]];
        yield ['pgsql', 'text[]', 'string', ['text', null]];
        yield ['pgsql', 'integer', 'id', ['integer', null]];
        yield ['pgsql', 'integer', 'reference', ['integer', null]];
        yield ['pgsql', 'smallint', 'integer', ['smallint', null]];
        yield ['pgsql', 'bigint', 'bigint', ['bigint', null]];
        yield ['pgsql', 'numeric(10,2)', 'decimal', ['decimal', null]];
        yield ['pgsql', 'real', 'double', ['float', null]];
        yield ['pgsql', 'double precision', 'double', ['double', null]];
        yield ['pgsql', 'money', 'money', ['money', null]];
        yield ['pgsql', 'boolean', 'boolean', ['boolean', null]];
        yield ['pgsql', 'date', 'date', ['date', null]];
        yield ['pgsql', 'timestamp without time zone', 'timestamp', ['timestamp', null]];
        yield ['pgsql', 'timestamp(3) with time zone', 'timestamptz', ['timestamptz', null]];
        yield ['pgsql', 'time without time zone', 'time', ['time', null]];
        yield ['pgsql', 'json', 'json', ['json', null]];
        yield ['pgsql', 'jsonb', 'jsonb', ['jsonb', null]];
        yield ['pgsql', 'bytea', 'binary', ['binary', null]];
        yield ['pgsql', 'uuid', 'uuid', ['uuid', null]];
        yield ['pgsql', 'inet', 'string', ['string', null]];
        yield ['pgsql', 'citext', 'string', ['string', null]];
        yield ['pgsql', 'mood', 'string', ['string', null]]; // enum type -> DreamFactory's fallback
        // MySQL / MariaDB
        yield ['mysql', 'varchar(120)', 'string', ['string', 120]];
        yield ['mysql', 'tinyint(1)', 'boolean', ['boolean', null]];
        yield ['mysql', 'int(11) unsigned', 'integer', ['integer', null]];
        yield ['mysql', 'longtext', 'text', ['text', null]];
        yield ['mysql', 'datetime', 'datetime', ['datetime', null]];
        yield ['mysql', "enum('a','b')", 'string', ['string', null]];
        yield ['mysql', 'blob', 'binary', ['binary', null]];
        yield ['mysql', 'float', 'float', ['float', null]];
        // SQL Server
        yield ['sqlsrv', 'nvarchar(max)', 'text', ['text', null]];
        yield ['sqlsrv', 'nvarchar(50)', 'string', ['string', 50]];
        yield ['sqlsrv', 'uniqueidentifier', 'string', ['uuid', null]];
        yield ['sqlsrv', 'bit', 'boolean', ['boolean', null]];
        yield ['sqlsrv', 'datetimeoffset', 'datetimetz', ['timestamptz', null]];
        yield ['sqlsrv', 'float', 'float', ['double', null]];
        yield ['sqlsrv', 'image', 'binary', ['binary', null]];
        // Oracle / Snowflake
        yield ['oracle', 'NUMBER(10)', 'integer', ['bigint', null]];
        yield ['oracle', 'NUMBER(9,0)', 'integer', ['integer', null]];
        yield ['oracle', 'NUMBER(10,2)', 'decimal', ['decimal', null]];
        yield ['oracle', 'NUMBER', 'decimal', ['decimal', null]];
        yield ['oracle', 'VARCHAR2(100)', 'string', ['string', 100]];
        yield ['oracle', 'CLOB', 'text', ['text', null]];
        yield ['snowflake', 'NUMBER(38,0)', 'integer', ['bigint', null]];
        yield ['snowflake', 'VARIANT', 'string', ['json', null]];
        yield ['snowflake', 'TIMESTAMP_TZ', 'timestamptz', ['timestamptz', null]];
        yield ['snowflake', 'TIMESTAMP_NTZ', 'timestamp', ['timestamp', null]];
        // SQLite: affinity rules
        yield ['sqlite', 'varchar(50)', 'string', ['string', 50]];
        yield ['sqlite', '', 'string', ['text', null]];
        yield ['sqlite', 'datetime', 'datetime', ['timestamp', null]];
        yield ['sqlite', 'blob', 'binary', ['binary', null]];
        yield ['sqlite', 'integer', 'id', ['integer', null]];
    }

    #[DataProvider('cases')]
    public function testMap(string $driver, string $db, string $df, array $want): void
    {
        $this->assertSame($want, TypeMap::map($db, $df, $driver));
    }

    public function testDreamFactorySimpleTypesAsFallback(): void
    {
        $this->assertSame('integer', TypeMap::engineType(null, 'id'));
        $this->assertSame('integer', TypeMap::engineType('string-ish-unknown', 'reference'));
        $this->assertSame('bigint', TypeMap::engineType(null, 'bigid'));
        $this->assertSame('timestamp', TypeMap::engineType(null, 'timestamp_on_create'));
        $this->assertSame('string', TypeMap::engineType(null, null));
        // DreamFactory simple type passed where a native type is expected (NameOnly callers)
        $this->assertSame('string', TypeMap::engineType('string'));
        $this->assertSame('integer', TypeMap::engineType('id'));
        $this->assertSame('text', TypeMap::engineType('text'));
    }
}

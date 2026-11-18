<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Scanner;

use DreamFactory\Core\Database\Schema\ColumnSchema;
use DreamFactory\Core\Database\Schema\TableSchema;
use DreamFactory\Core\Masking\Scanner\Sampler;
use DreamFactory\Core\Masking\Scanner\ScanRunner;
use DreamFactory\Core\Masking\Scanner\SchemaReader;
use DreamFactory\Core\Masking\Support\Coverage;
use DreamFactory\Core\Masking\Support\Tables;
use Illuminate\Database\SQLiteConnection;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\TestCase;

/**
 * Every identifier in scanner SQL is quoted from the raw name with the dialect's quote
 * character doubled (never DreamFactory's unescaped quotedName), so any legal table or column name
 * is sampled and nothing in a name is ever executed; MySQL and SQL Server sample reads run in a
 * read-only / snapshot transaction that is always rolled back (PostgreSQL already did).
 */
final class IdentifierQuotingTest extends TestCase
{
    /** Column names that broke (or were executed by) the sampler, each holding distinct emails. */
    private const HOSTILE = [
        'quo"te',
        'br]acket',
        'back`tick',
        'paren)x',
        'semi;colon',
        'x" FROM t); INSERT INTO canary VALUES (1); --',
        'y` FROM t); INSERT INTO canary VALUES (2); --',
        'z] FROM t); INSERT INTO canary VALUES (3); --',
    ];

    public function testQuoteDoublesTheDialectQuoteCharacter(): void
    {
        foreach (['pgsql', 'sqlite', 'oracle', 'snowflake', 'ibm', 'firebird', 'unknown'] as $driver) {
            $this->assertSame('"quo""te"', SchemaReader::quote('quo"te', $driver), $driver);
            $this->assertSame('"x""); DROP TABLE t; --"', SchemaReader::quote('x"); DROP TABLE t; --', $driver), $driver);
            $this->assertSame('"br]acket`"', SchemaReader::quote('br]acket`', $driver), $driver);
        }
        foreach (['mysql', 'mariadb', 'memsql', 'singlestore', 'MySQL'] as $driver) {
            $this->assertSame('`back``tick`', SchemaReader::quote('back`tick', $driver), $driver);
            $this->assertSame('`quo"te]`', SchemaReader::quote('quo"te]', $driver), $driver);
        }
        foreach (['sqlsrv', 'dblib', 'sqlanywhere'] as $driver) {
            $this->assertSame('[br]]acket]', SchemaReader::quote('br]acket', $driver), $driver);
            $this->assertSame('[x]]; INSERT INTO c VALUES (1); --]', SchemaReader::quote('x]; INSERT INTO c VALUES (1); --', $driver), $driver);
            $this->assertSame('[a[b"c`]', SchemaReader::quote('a[b"c`', $driver), $driver);
        }
        $this->assertSame('plain_name$1', SchemaReader::quote('plain_name$1', 'informix'), 'DreamFactory quotes nothing on Informix');
        $this->assertSame('"semi;co""lon"', SchemaReader::quote('semi;co"lon', 'informix'));
    }

    public function testDescribeQuotesRawNamesNeverDreamFactorysQuotedName(): void
    {
        // df-database builds quotedName as quote + name + quote, unescaped: exactly this.
        $build = static function (string $name, ?string $schema, ?string $resource, array $columns): TableSchema {
            $ts = new TableSchema(array_filter(['name' => $name, 'schemaName' => $schema, 'resourceName' => $resource,
                'quotedName' => '"' . $name . '"'], static fn ($v) => $v !== null));
            foreach ($columns as $i => $c) {
                $col = new ColumnSchema(['name' => $c]);
                $col->quotedName = '"' . $c . '"';
                $col->dbType = 'text';
                $col->type = 'text';
                $col->isPrimaryKey = $i === 0;
                $ts->addColumn($col);
                if ($i === 0) {
                    $ts->addPrimaryKey($c);
                }
            }
            return $ts;
        };

        $pg = SchemaReader::describe($build('hr2.pe"ople', 'hr2', 'pe"ople', ['i"d', 'quo"te', 'paren)x']), 'pgsql');
        $this->assertSame('"hr2"."pe""ople"', $pg['plan']['from']);
        $this->assertSame(['"i""d"'], $pg['plan']['key']);
        $this->assertSame(['"i""d"', '"quo""te"', '"paren)x"'], array_column($pg['plan']['columns'], 'quoted'));
        $this->assertSame(['i"d', 'quo"te', 'paren)x'], array_column($pg['plan']['columns'], 'name'), 'names stay raw');

        $my = SchemaReader::describe($build('back`tick', 'crm', 'back`tick', ['id', 'a`b']), 'mysql');
        $this->assertSame('`crm`.`back``tick`', $my['plan']['from']);
        $this->assertSame(['`id`', '`a``b`'], array_column($my['plan']['columns'], 'quoted'));

        $ms = SchemaReader::describe($build('t]x', 'dbo', 't]x', ['id', 'br]acket']), 'sqlsrv');
        $this->assertSame('[dbo].[t]]x]', $ms['plan']['from']);
        $this->assertSame(['[id]', '[br]]acket]'], array_column($ms['plan']['columns'], 'quoted'));

        // SQLite: no schema; a dot in the name is part of the name (DreamFactory would split it).
        $lite = SchemaReader::describe($build('a.b"c', null, null, ['id', 'semi;colon']), 'sqlite');
        $this->assertSame('"a.b""c"', $lite['plan']['from']);
        $this->assertSame(['"id"', '"semi;colon"'], array_column($lite['plan']['columns'], 'quoted'));

        // PostgreSQL outside the default schema: name "sales.orders", resourceName "orders".
        $other = SchemaReader::describe($build('sales.orders', 'sales', 'orders', ['id']), 'pgsql');
        $this->assertSame('"sales"."orders"', $other['plan']['from']);
    }

    /** A full scan of a SQLite database whose table and column names carry quote characters and SQL. */
    public function testEveryHostileColumnIsSampledAndNothingInANameRuns(): void
    {
        Harness::boot();
        $cols = array_merge(['id'], self::HOSTILE);
        $q = static fn (string $n) => '"' . str_replace('"', '""', $n) . '"';
        $ddl = [
            'CREATE TABLE canary (n integer)',
            'CREATE TABLE ' . $q('odd "t"; x)') . ' (' . implode(', ', array_map(static fn ($c) => $q($c) . ($c === 'id' ? ' integer primary key' : ' text'), $cols)) . ')',
            // no key: read by rowid
            'CREATE TABLE ' . $q('heap]`"') . ' (' . $q('semi;colon') . ' text, ' . $q('quo"te') . ' text)',
        ];
        $pdo = Harness::sqlite($ddl);
        $ins = $pdo->prepare('INSERT INTO ' . $q('odd "t"; x)') . ' VALUES (' . implode(',', array_fill(0, count($cols), '?')) . ')');
        $heap = $pdo->prepare('INSERT INTO ' . $q('heap]`"') . ' VALUES (?, ?)');
        for ($i = 1; $i <= 40; $i++) {
            $ins->execute(array_merge([$i], array_map(static fn ($k) => "user{$i}.c{$k}@example.org", array_keys(self::HOSTILE))));
            $heap->execute(["h{$i}@example.net", "g{$i}@example.com"]);
        }
        $id = Harness::addService('legacy', $pdo);
        Coverage::forget();

        $summary = (new ScanRunner())->run('legacy');

        $this->assertSame('done', $summary['status']);
        $this->assertSame(0, $summary['unreadable_columns'], 'every column was read');
        $this->assertSame(0, (int) $pdo->query('SELECT COUNT(*) FROM canary')->fetchColumn(), 'nothing in a name was executed');
        $rows = DB::table(Tables::COLUMN)->where('service_id', $id)->get()->all();
        $by = [];
        foreach ($rows as $r) {
            $by[$r->table_name . '|' . $r->column_name] = $r;
        }
        foreach (self::HOSTILE as $c) {
            $row = $by['odd "t"; x)|' . $c] ?? null;
            $this->assertNotNull($row, $c);
            // The names say nothing: only the sampled values can make these columns emails.
            $this->assertSame(['masked', 'email'], [$row->verdict, $row->class], $c);
            $this->assertStringNotContainsString('could not be read', (string) $row->evidence, $c);
        }
        $this->assertSame(['masked', 'email'], [$by['heap]`"|semi;colon']->verdict, $by['heap]`"|semi;colon']->class]);
        $this->assertSame(['masked', 'email'], [$by['heap]`"|quo"te']->verdict, $by['heap]`"|quo"te']->class]);
    }

    /** MySQL: SET TRANSACTION READ ONLY + a transaction that is rolled back, backticks doubled. */
    public function testMysqlSampleReadsRunInAReadOnlyTransaction(): void
    {
        $pdo = self::pdoWithLeft();
        $pdo->exec('CREATE TABLE canary (n integer)');
        $pdo->exec('CREATE TABLE t (id integer primary key, "back`tick" text, "y` FROM t); INSERT INTO canary VALUES (2); --" text)');
        for ($i = 1; $i <= 20; $i++) {
            $pdo->exec("INSERT INTO t VALUES ($i, 'v$i', 'w$i')");
        }
        $conn = new RecordingConnection($pdo, 'mysql');
        $plan = self::plan('t', ['id', 'back`tick', 'y` FROM t); INSERT INTO canary VALUES (2); --'], 'mysql');

        $s = (new Sampler($conn, 'mysql'))->sample(self::meta('t', array_column($plan['columns'], 'name')), $plan);

        $this->assertNull($s['error']);
        $this->assertCount(20, $s['rows']);
        $row7 = array_values(array_filter($s['rows'], static fn ($r) => $r['id'] === '7'))[0];
        $this->assertSame('v7', $row7['back`tick']);
        $this->assertSame('w7', $row7['y` FROM t); INSERT INTO canary VALUES (2); --']);
        $this->assertSame(0, (int) $pdo->query('SELECT COUNT(*) FROM canary')->fetchColumn());
        $this->assertSame(['SET TRANSACTION READ ONLY', 'BEGIN', 'SELECT', 'ROLLBACK'], $conn->kinds());
        $this->assertStringContainsString('`back``tick`', $conn->selects()[0]);
        $this->assertSame(0, $conn->transactionLevel());
    }

    /** SQL Server: SNAPSHOT isolation when the database allows it, restored after the rollback. */
    public function testSqlServerSampleReadsUseASnapshotTransaction(): void
    {
        $conn = new RecordingConnection(new \PDO('sqlite::memory:'), 'sqlsrv', snapshot: true);
        $plan = self::plan('t', ['id', 'br]acket', 'z] FROM t); INSERT INTO canary VALUES (3); --'], 'sqlsrv', 'dbo');
        $sampler = new Sampler($conn, 'sqlsrv');

        $s = $sampler->sample(self::meta('t', array_column($plan['columns'], 'name')), $plan);

        $this->assertNull($s['error']);
        $this->assertSame(['SNAPSHOT?', 'SET TRANSACTION ISOLATION LEVEL SNAPSHOT', 'BEGIN', 'SELECT', 'ROLLBACK',
            'SET TRANSACTION ISOLATION LEVEL READ COMMITTED'], $conn->kinds());
        $select = $conn->selects()[0];
        $this->assertStringContainsString('from [dbo].[t]', $select);
        $this->assertStringContainsString('SUBSTRING(CAST([br]]acket] AS NVARCHAR(MAX)), 1, 1000)', $select);
        $this->assertStringContainsString('[z]] FROM t); INSERT INTO canary VALUES (3); --]', $select);

        // Without ALLOW_SNAPSHOT_ISOLATION: still one transaction, always rolled back, isolation untouched.
        $plain = new RecordingConnection(new \PDO('sqlite::memory:'), 'sqlsrv', snapshot: false);
        (new Sampler($plain, 'sqlsrv'))->sample(self::meta('t', array_column($plan['columns'], 'name')), $plan);
        $this->assertSame(['SNAPSHOT?', 'BEGIN', 'SELECT', 'ROLLBACK'], $plain->kinds());
    }

    /** PostgreSQL keeps its READ ONLY transaction with a statement timeout; identifiers are escaped. */
    public function testPostgresSampleReadsStayReadOnly(): void
    {
        $conn = new RecordingConnection(new \PDO('sqlite::memory:'), 'pgsql');
        $plan = self::plan('pe"ople', ['id', 'quo"te'], 'pgsql', 'hr2');

        (new Sampler($conn, 'pgsql'))->sample(self::meta('pe"ople', ['id', 'quo"te']), $plan);

        $this->assertSame(['BEGIN', 'SET TRANSACTION READ ONLY', 'SET LOCAL statement_timeout = 10000', 'SELECT', 'ROLLBACK'], $conn->kinds());
        $this->assertStringContainsString('LEFT(("quo""te")::text, 1000)', $conn->selects()[0]);
        $this->assertStringContainsString('from "hr2"."pe""ople"', $conn->selects()[0]);
    }

    // ------------------------------------------------------------------------------ helpers

    private static function plan(string $table, array $cols, string $driver, ?string $schema = null): array
    {
        $ts = new TableSchema(array_filter(['name' => $table, 'schemaName' => $schema, 'resourceName' => $schema !== null ? $table : null],
            static fn ($v) => $v !== null));
        foreach ($cols as $i => $c) {
            $col = new ColumnSchema(['name' => $c]);
            $col->quotedName = '"' . $c . '"'; // unescaped, like df-database
            $col->dbType = $i === 0 ? 'integer' : 'text';
            $col->type = $i === 0 ? 'id' : 'text';
            $col->isPrimaryKey = $i === 0;
            $ts->addColumn($col);
            if ($i === 0) {
                $ts->addPrimaryKey($c);
            }
        }
        return SchemaReader::describe($ts, $driver)['plan'];
    }

    private static function meta(string $table, array $cols): \DreamFactory\Core\Masking\Classifier\TableMeta
    {
        return new \DreamFactory\Core\Masking\Classifier\TableMeta('', $table, $table, 'table',
            array_map(static fn ($c) => new \DreamFactory\Core\Masking\Classifier\ColumnMeta($c, 'text', 'text'), $cols));
    }

    /** SQLite with MySQL's LEFT(), so the MySQL dialect runs for real. */
    private static function pdoWithLeft(): \PDO
    {
        $left = static fn ($s, $n) => $s === null ? null : mb_substr((string) $s, 0, (int) $n);
        if (method_exists(\PDO::class, 'connect')) {
            $pdo = \PDO::connect('sqlite::memory:');
            $pdo->createFunction('LEFT', $left, 2);
        } else {
            $pdo = new \PDO('sqlite::memory:');
            $pdo->sqliteCreateFunction('LEFT', $left, 2);
        }
        $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        return $pdo;
    }
}

/**
 * Records what the sampler sends. 'mysql' runs selects on SQLite for real (backtick quoting and
 * LEFT() work there); 'pgsql'/'sqlsrv' answer selects with no rows (their SQL is checked as text).
 */
final class RecordingConnection extends SQLiteConnection
{
    /** @var list<array{0:string,1:string}> kind, sql */
    public array $log = [];

    public function __construct(\PDO $pdo, private string $driver, private bool $snapshot = false)
    {
        parent::__construct($pdo);
    }

    public function getDriverName()
    {
        return $this->driver;
    }

    public function beginTransaction()
    {
        $this->log[] = ['BEGIN', ''];
        parent::beginTransaction();
    }

    public function rollBack($toLevel = null)
    {
        $this->log[] = ['ROLLBACK', ''];
        parent::rollBack($toLevel);
    }

    protected function run($query, $bindings, \Closure $callback)
    {
        $sql = (string) $query;
        if (str_starts_with($sql, 'SET ')) {
            $this->log[] = [$sql, $sql];
            return true;
        }
        if (str_contains($sql, 'snapshot_isolation_state')) {
            $this->log[] = ['SNAPSHOT?', $sql];
            return [(object) ['s' => $this->snapshot ? 1 : 0]];
        }
        $this->log[] = ['SELECT', $sql];
        return $this->driver === 'mysql' ? parent::run($query, $bindings, $callback) : [];
    }

    /** @return list<string> */
    public function kinds(): array
    {
        return array_column($this->log, 0);
    }

    /** @return list<string> */
    public function selects(): array
    {
        return array_values(array_map(static fn ($e) => $e[1], array_filter($this->log, static fn ($e) => $e[0] === 'SELECT')));
    }
}

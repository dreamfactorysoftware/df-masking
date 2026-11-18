<?php

namespace DreamFactory\Core\Masking\Scanner;

use DreamFactory\Core\Masking\Classifier\TableMeta;
use Illuminate\Database\ConnectionInterface;

/**
 * Deterministic, read-only value sampling through a service's own Illuminate connection.
 *
 * Two windows per table: the first and the last $perWindow rows ordered by the primary key (else a
 * single-column unique key, else the physical row id on PostgreSQL/SQLite), de-duplicated and
 * merged in key order. Tables without any usable key are read once, unordered, with LIMIT
 * 2 x $perWindow. Wide tables are read in chunks of 200 columns joined by key.
 *
 * Every statement is a SELECT built with the query builder from identifiers that came from the
 * schema, each quoted by SchemaReader::quote() with the dialect's quote character doubled, so no
 * part of a table or column name is ever parsed as SQL; no value is ever bound or interpolated.
 * Values are cast to text in SQL where the driver allows (PostgreSQL and SQLite exactly as the
 * classifier's reference sampler does) and truncated to 1000 characters.
 *
 * Each read runs in its own transaction that is always rolled back: PostgreSQL READ ONLY with
 * SET LOCAL statement_timeout; MySQL/MariaDB READ ONLY (plus the MAX_EXECUTION_TIME hint); SQL
 * Server SNAPSHOT isolation when the database allows it (no shared locks on the customer's rows),
 * else the default isolation. Other drivers read in autocommit and rely on the per-table time
 * budget between statements.
 *
 * Sampled values exist only in the returned array: never logged, cached or persisted. Errors
 * carry only the SQLSTATE (driver messages can echo data).
 */
final class Sampler
{
    public const PER_WINDOW = 128;
    public const MAX_COLUMNS_PER_QUERY = 200;
    public const MAX_VALUE_CHARS = 1000;

    private readonly string $driver;
    /** SQL Server: SNAPSHOT isolation allowed in the connected database (null = not asked yet). */
    private ?bool $snapshot = null;

    public function __construct(
        private readonly ConnectionInterface $conn,
        ?string $driver = null,
        private readonly int $perWindow = self::PER_WINDOW,
        private readonly int $tableBudgetMs = 20000,
        private readonly int $statementTimeoutMs = 10000,
    ) {
        $this->driver = strtolower($driver ?? (method_exists($conn, 'getDriverName') ? (string) $conn->getDriverName() : ''));
    }

    /**
     * @param array $plan SchemaReader::describe()['plan']
     * @return array{rows:list<array<string,?string>>, ordered:string|false, error:?string, queries:int, partial:bool,
     *               failed_columns:array<string,string>}
     *         error: SQLSTATE when nothing could be read; failed_columns: column => SQLSTATE for columns
     *         whose values could not be read while the others were (their values are absent from rows)
     */
    public function sample(TableMeta $t, array $plan): array
    {
        $cols = array_values(array_filter($plan['columns'], static fn ($c) => $c['sampled']));
        $result = ['rows' => [], 'ordered' => false, 'error' => null, 'queries' => 0, 'partial' => false, 'failed_columns' => []];
        if ($cols === []) {
            return $result;
        }
        $key = $plan['key'];
        $ordered = $plan['key_kind'] ?? false;
        if ($key === [] && $plan['kind'] === 'table' && ($pk = $this->physicalKey()) !== null) {
            $key = [$pk];
            $ordered = 'rowid';
        }
        $result['ordered'] = $key === [] ? false : $ordered;

        $started = hrtime(true);
        try {
            $result['rows'] = $this->read($plan['from'], $cols, $key, $started, $result);

            return $result;
        } catch (\Throwable $e) {
            $tableError = self::sqlState($e);
        }

        // One column the driver cannot render as text (SQL Server rowversion, a CLR type, ...)
        // fails the whole statement. Read column by column so it cannot hide the others; the
        // columns that still fail are reported, never silently treated as empty.
        $readable = [];
        $byColumn = [];
        foreach ($cols as $c) {
            if ($this->overBudget($started)) {
                $result['partial'] = true; // the rest stays unsampled (budget), not failed
                break;
            }
            try {
                $byColumn[$c['name']] = $this->read($plan['from'], [$c], $key, $started, $result, false);
                $readable[] = $c;
            } catch (\Throwable $e) {
                $result['failed_columns'][$c['name']] = self::sqlState($e);
            }
        }
        if ($readable === []) {
            $result['rows'] = [];
            $result['error'] = $result['failed_columns'] !== [] ? reset($result['failed_columns']) : $tableError;

            return $result;
        }
        try {
            if ($key !== []) {
                // Every read used the same key order and windows: align the columns by key.
                $merged = [];
                foreach ($byColumn as $rows) {
                    foreach ($rows as $k => $r) {
                        $merged[$k] = ($merged[$k] ?? []) + $r;
                    }
                }
                ksort($merged, SORT_STRING);
                $result['rows'] = array_values($merged);
            } else {
                // No key to align separate reads: read the readable columns together once more.
                $result['rows'] = $this->read($plan['from'], $readable, [], $started, $result);
            }
        } catch (\Throwable $e) {
            $result['rows'] = [];
            $result['error'] = self::sqlState($e);
        }

        return $result;
    }

    /**
     * Reads the sample windows of $cols inside its own read transaction (beginRead(); PostgreSQL:
     * READ ONLY with a statement timeout, so a failed statement never poisons the next one).
     *
     * @param bool $list true: rows as a list in key order; false: keyed by row key (for merging)
     * @return array<int|string, array<string,?string>>
     * @throws \Throwable the first failing statement
     */
    private function read(string $from, array $cols, array $key, int $started, array &$result, bool $list = true): array
    {
        $tx = $this->beginRead();
        try {
            if ($key === []) {
                return array_values($this->fetch($from, $cols, [], null, 2 * $this->perWindow, $result['queries']));
            }
            $merged = [];
            foreach (array_chunk($cols, self::MAX_COLUMNS_PER_QUERY) as $chunk) {
                $byKey = [];
                foreach (['ASC', 'DESC'] as $dir) {
                    $got = $this->fetch($from, $chunk, $key, $dir, $this->perWindow, $result['queries']);
                    foreach ($got as $k => $r) {
                        $byKey[$k] ??= $r;
                    }
                    if ($dir === 'ASC' && count($got) < $this->perWindow) {
                        break; // the head already holds the whole table
                    }
                    if ($dir === 'ASC' && $this->overBudget($started)) {
                        $result['partial'] = true;
                        break;
                    }
                }
                foreach ($byKey as $k => $r) {
                    $merged[$k] = ($merged[$k] ?? []) + $r;
                }
                if ($this->overBudget($started)) {
                    // Columns of later chunks stay unsampled; rows are still aligned by key.
                    $result['partial'] = $result['partial'] || count($cols) > self::MAX_COLUMNS_PER_QUERY;
                    break;
                }
            }
            ksort($merged, SORT_STRING);

            return $list ? array_values($merged) : $merged;
        } finally {
            $this->endRead($tx);
        }
    }

    /**
     * Opens the read transaction for this driver (see the class comment), or nothing when the
     * driver has none or the connection is already inside a transaction.
     *
     * @return ?string what to undo in endRead(): 'tx', 'tx+isolation' or null
     * @throws \Throwable PostgreSQL: the statement that failed (the transaction is rolled back)
     */
    private function beginRead(): ?string
    {
        if (!method_exists($this->conn, 'transactionLevel') || $this->conn->transactionLevel() !== 0) {
            return null;
        }
        switch ($this->driver) {
            case 'pgsql':
                $this->conn->beginTransaction();
                try {
                    $this->conn->statement('SET TRANSACTION READ ONLY');
                    $this->conn->statement('SET LOCAL statement_timeout = ' . max(1000, $this->statementTimeoutMs));
                } catch (\Throwable $e) {
                    $this->endRead('tx');
                    throw $e;
                }
                return 'tx';
            case 'mysql':
            case 'mariadb':
                // Applies to the next transaction only (MySQL 5.6.5+, MariaDB 10.0+).
                try {
                    $this->conn->statement('SET TRANSACTION READ ONLY');
                } catch (\Throwable $e) {
                    return null; // a MySQL-compatible engine without it: autocommit reads
                }
                try {
                    $this->conn->beginTransaction();
                } catch (\Throwable $e) {
                    try {
                        $this->conn->statement('SET TRANSACTION READ WRITE'); // never leave it pending
                    } catch (\Throwable $ignored) {
                    }
                    return null;
                }
                return 'tx';
            case 'sqlsrv':
                $snapshot = $this->snapshotAllowed();
                try {
                    if ($snapshot) {
                        $this->conn->statement('SET TRANSACTION ISOLATION LEVEL SNAPSHOT');
                    }
                    $this->conn->beginTransaction();
                } catch (\Throwable $e) {
                    $this->endRead($snapshot ? 'isolation' : null);
                    return null;
                }
                return $snapshot ? 'tx+isolation' : 'tx';
            default:
                return null;
        }
    }

    private function endRead(?string $tx): void
    {
        if ($tx === null) {
            return;
        }
        if ($tx === 'tx' || $tx === 'tx+isolation') {
            try {
                $this->conn->rollBack();
            } catch (\Throwable $e) {
                // the connection is unusable; the next statement reports it
            }
        }
        if ($tx === 'isolation' || $tx === 'tx+isolation') {
            try {
                $this->conn->statement('SET TRANSACTION ISOLATION LEVEL READ COMMITTED'); // the session default
            } catch (\Throwable $e) {
            }
        }
    }

    /** SQL Server: the connected database allows SNAPSHOT isolation (ALLOW_SNAPSHOT_ISOLATION ON). */
    private function snapshotAllowed(): bool
    {
        if ($this->snapshot === null) {
            try {
                $row = $this->conn->selectOne('SELECT snapshot_isolation_state AS s FROM sys.databases WHERE database_id = DB_ID()');
                $this->snapshot = (int) (((array) $row)['s'] ?? 0) === 1;
            } catch (\Throwable $e) {
                $this->snapshot = false;
            }
        }
        return $this->snapshot;
    }

    /**
     * One window (or the unordered read). Returns rows keyed by the row key string (or by
     * position when unordered), each row = column name => ?string.
     *
     * @return array<string|int, array<string,?string>>
     */
    private function fetch(string $from, array $cols, array $key, ?string $dir, int $limit, int &$queries): array
    {
        $select = [];
        foreach ($key as $i => $k) {
            $select[] = $this->keyExpr($k) . ' AS ' . $this->alias('k' . $i);
        }
        foreach ($cols as $i => $c) {
            $select[] = $this->valueExpr($c['quoted'], $c['type']) . ' AS ' . $this->alias('c' . $i);
        }
        if (in_array($this->driver, ['mysql', 'mariadb'], true)) {
            // Optimizer hint: MySQL 5.7.8+ enforces it; MariaDB treats it as a comment.
            $select[0] = '/*+ MAX_EXECUTION_TIME(' . max(1000, $this->statementTimeoutMs) . ') */ ' . $select[0];
        }
        $q = $this->conn->query()->from($this->conn->raw($from));
        $q->select(array_map(fn ($s) => $this->conn->raw($s), $select));
        if ($dir !== null) {
            $q->orderByRaw(implode(', ', array_map(static fn ($k) => "$k $dir", $key)));
        }
        $q->limit($limit);
        $queries++;
        $out = [];
        $pos = 0;
        foreach ($q->get() as $row) {
            $r = array_change_key_case((array) $row, CASE_LOWER);
            $vals = [];
            foreach ($cols as $i => $c) {
                $vals[$c['name']] = self::text($r['c' . $i] ?? null);
            }
            if ($key === []) {
                $out[$pos++] = $vals;
                continue;
            }
            $parts = [];
            foreach ($key as $i => $_) {
                $parts[] = (string) self::text($r['k' . $i] ?? null);
            }
            $out[implode("\x1f", $parts)] = $vals;
        }
        return $out;
    }

    private function overBudget(int $started): bool
    {
        return (hrtime(true) - $started) / 1e6 > $this->tableBudgetMs;
    }

    private function physicalKey(): ?string
    {
        return match ($this->driver) {
            'pgsql' => 'ctid',
            'sqlite' => 'rowid',
            default => null,
        };
    }

    private function alias(string $a): string
    {
        return $this->driver === 'sqlsrv' ? '[' . $a . ']' : ($this->driver === 'mysql' || $this->driver === 'mariadb' ? '`' . $a . '`' : '"' . $a . '"');
    }

    private function keyExpr(string $quoted): string
    {
        return match ($this->driver) {
            'pgsql' => "($quoted)::text",
            'sqlite' => "CAST($quoted AS TEXT)",
            default => $quoted,
        };
    }

    /** Text rendering of one column, truncated in SQL where the driver supports it safely. */
    private function valueExpr(string $quoted, string $type): string
    {
        $n = self::MAX_VALUE_CHARS;
        $stringLike = in_array($type, ['string', 'text'], true);
        return match ($this->driver) {
            'pgsql' => "LEFT(($quoted)::text, $n)",
            'sqlite' => "substr(CAST($quoted AS TEXT), 1, $n)",
            'mysql', 'mariadb' => "LEFT(CAST($quoted AS CHAR), $n)",
            'sqlsrv' => match (true) {
                $stringLike => "SUBSTRING(CAST($quoted AS NVARCHAR(MAX)), 1, $n)",
                in_array($type, ['date', 'datetime', 'timestamp', 'timestamptz', 'time'], true) => "CONVERT(NVARCHAR(40), $quoted, 126)",
                default => $quoted,
            },
            'oracle' => match (true) {
                $type === 'text' => "DBMS_LOB.SUBSTR($quoted, $n, 1)",
                $type === 'string' => "SUBSTR($quoted, 1, $n)",
                in_array($type, ['date', 'datetime', 'timestamp'], true) => "TO_CHAR($quoted, 'YYYY-MM-DD HH24:MI:SS')",
                default => $quoted,
            },
            'snowflake' => "LEFT(TO_VARCHAR($quoted), $n)",
            default => $quoted,
        };
    }

    /**
     * Any fetched cell -> text the classifier can read: null stays null; booleans become
     * 'true'/'false'; LOB streams are read up to the limit; invalid UTF-8 is scrubbed (so no byte
     * sequence can ever reach the engine's output paths); everything is cut to 1000 characters.
     */
    public static function text(mixed $v): ?string
    {
        if ($v === null) {
            return null;
        }
        if (is_bool($v)) {
            $s = $v ? 'true' : 'false';
        } elseif (is_int($v) || is_float($v) || is_string($v)) {
            $s = (string) $v;
        } elseif (is_resource($v)) {
            $s = (string) stream_get_contents($v, 4 * self::MAX_VALUE_CHARS);
        } elseif ($v instanceof \DateTimeInterface) {
            $s = $v->format('Y-m-d H:i:s');
        } elseif ($v instanceof \Stringable) {
            $s = (string) $v;
        } else {
            return null;
        }
        if (!mb_check_encoding($s, 'UTF-8')) {
            $s = mb_scrub($s, 'UTF-8');
        }
        if (strlen($s) > self::MAX_VALUE_CHARS) {
            $s = mb_substr($s, 0, self::MAX_VALUE_CHARS, 'UTF-8');
        }
        return $s;
    }

    /** SQLSTATE of a database error (never the message: drivers can echo data in messages). */
    public static function sqlState(\Throwable $e): string
    {
        for ($x = $e; $x !== null; $x = $x->getPrevious()) {
            if ($x instanceof \PDOException) {
                $state = $x->errorInfo[0] ?? $x->getCode();
                if (is_string($state) && $state !== '' && $state !== '0') {
                    return 'SQLSTATE ' . $state;
                }
            }
        }
        return (new \ReflectionClass($e))->getShortName();
    }
}

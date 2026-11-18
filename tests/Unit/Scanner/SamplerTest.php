<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Scanner;

use DreamFactory\Core\Masking\Classifier\ColumnMeta;
use DreamFactory\Core\Masking\Classifier\TableMeta;
use DreamFactory\Core\Masking\Scanner\Sampler;
use Illuminate\Database\SQLiteConnection;
use PHPUnit\Framework\TestCase;

final class SamplerTest extends TestCase
{
    private static function plan(string $table, array $cols, array $key, ?string $keyKind, string $kind = 'table', array $types = []): array
    {
        return [
            'from' => '"' . $table . '"',
            'kind' => $kind,
            'key' => array_map(static fn ($k) => '"' . $k . '"', $key),
            'key_kind' => $keyKind,
            'columns' => array_map(static fn ($c) => ['name' => $c, 'quoted' => '"' . $c . '"', 'type' => $types[$c] ?? 'text', 'df_type' => null, 'sampled' => ($types[$c] ?? 'text') !== 'binary'], $cols),
        ];
    }

    private static function meta(string $table, array $cols): TableMeta
    {
        return new TableMeta('main', $table, $table, 'table', array_map(static fn ($c) => new ColumnMeta($c, 'text', 'text'), $cols));
    }

    public function testHeadAndTailWindowsByPrimaryKey(): void
    {
        $pdo = new \PDO('sqlite::memory:');
        $pdo->exec('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)');
        for ($i = 1; $i <= 1000; $i++) {
            $pdo->exec("INSERT INTO t VALUES ($i, 'v$i')");
        }
        $s = (new Sampler(new SQLiteConnection($pdo), 'sqlite', 128))->sample(self::meta('t', ['id', 'v']), self::plan('t', ['id', 'v'], ['id'], 'pk'));
        $this->assertNull($s['error']);
        $this->assertSame('pk', $s['ordered']);
        $this->assertCount(256, $s['rows']);
        $ids = array_map(static fn ($r) => (int) $r['id'], $s['rows']);
        $this->assertContains(1, $ids);
        $this->assertContains(128, $ids);
        $this->assertContains(873, $ids);
        $this->assertContains(1000, $ids);
        $this->assertNotContains(500, $ids);
        $this->assertSame(2, $s['queries']);
    }

    public function testSmallTableIsReadOnce(): void
    {
        $pdo = new \PDO('sqlite::memory:');
        $pdo->exec('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)');
        for ($i = 1; $i <= 50; $i++) {
            $pdo->exec("INSERT INTO t VALUES ($i, 'v$i')");
        }
        $s = (new Sampler(new SQLiteConnection($pdo), 'sqlite'))->sample(self::meta('t', ['v']), self::plan('t', ['v'], ['id'], 'pk'));
        $this->assertCount(50, $s['rows']);
        $this->assertSame(1, $s['queries']);
    }

    public function testWideTablesAreChunkedAndJoinedByKey(): void
    {
        $pdo = new \PDO('sqlite::memory:');
        $cols = array_map(static fn ($i) => "c$i", range(1, 250));
        $pdo->exec('CREATE TABLE wide (id INTEGER PRIMARY KEY, ' . implode(', ', array_map(static fn ($c) => "$c TEXT", $cols)) . ')');
        $ins = $pdo->prepare('INSERT INTO wide VALUES (' . implode(',', array_fill(0, 251, '?')) . ')');
        $pdo->beginTransaction();
        for ($r = 1; $r <= 300; $r++) {
            $ins->execute(array_merge([$r], array_map(static fn ($i) => "r{$r}c$i", range(1, 250))));
        }
        $pdo->commit();
        $all = array_merge(['id'], $cols);
        $s = (new Sampler(new SQLiteConnection($pdo), 'sqlite'))->sample(self::meta('wide', $all), self::plan('wide', $all, ['id'], 'pk'));
        $this->assertCount(256, $s['rows']);
        $this->assertCount(251, $s['rows'][0]);
        $this->assertSame(4, $s['queries']);
        foreach ($s['rows'] as $row) {
            $r = (int) $row['id'];
            $this->assertSame("r{$r}c1", $row['c1']);
            $this->assertSame("r{$r}c250", $row['c250']);
        }
    }

    public function testTablesWithoutKeysUseRowidAndViewsAreUnordered(): void
    {
        $pdo = new \PDO('sqlite::memory:');
        $pdo->exec('CREATE TABLE heap (v TEXT)');
        for ($i = 1; $i <= 400; $i++) {
            $pdo->exec("INSERT INTO heap VALUES ('v$i')");
        }
        $pdo->exec('CREATE VIEW vw AS SELECT v FROM heap');
        $sampler = new Sampler(new SQLiteConnection($pdo), 'sqlite');
        $heap = $sampler->sample(self::meta('heap', ['v']), self::plan('heap', ['v'], [], null));
        $this->assertSame('rowid', $heap['ordered']);
        $this->assertCount(256, $heap['rows']);
        $view = $sampler->sample(self::meta('vw', ['v']), self::plan('vw', ['v'], [], null, 'view'));
        $this->assertFalse($view['ordered']);
        $this->assertCount(256, $view['rows']);
        $this->assertSame(1, $view['queries']);
    }

    public function testValuesAreTextTruncatedAndScrubbed(): void
    {
        $pdo = new \PDO('sqlite::memory:');
        $pdo->exec('CREATE TABLE t (id INTEGER PRIMARY KEY, big TEXT, bad BLOB, num REAL, bin BLOB)');
        $st = $pdo->prepare('INSERT INTO t VALUES (1, ?, CAST(? AS TEXT), 1.5, ?)');
        $st->execute([str_repeat('é', 1500), "ab\xC3\x28cd", "\x00\x01"]);
        $s = (new Sampler(new SQLiteConnection($pdo), 'sqlite'))->sample(
            self::meta('t', ['big', 'bad', 'num', 'bin']),
            self::plan('t', ['big', 'bad', 'num', 'bin'], ['id'], 'pk', 'table', ['num' => 'double', 'bin' => 'binary'])
        );
        $row = $s['rows'][0];
        $this->assertSame(1000, mb_strlen($row['big']));
        $this->assertTrue(mb_check_encoding($row['bad'], 'UTF-8'));
        $this->assertSame('1.5', $row['num']);
        $this->assertArrayNotHasKey('bin', $row, 'binary columns are never sampled');
    }

    public function testErrorsCarryOnlyTheSqlState(): void
    {
        $pdo = new \PDO('sqlite::memory:');
        $s = (new Sampler(new SQLiteConnection($pdo), 'sqlite'))->sample(self::meta('missing', ['secret_value']), self::plan('missing', ['secret_value'], ['id'], 'pk'));
        $this->assertSame([], $s['rows']);
        $this->assertMatchesRegularExpression('/^SQLSTATE [0-9A-Z]{5}$/', $s['error']);
    }

    public function testText(): void
    {
        $this->assertNull(Sampler::text(null));
        $this->assertSame('true', Sampler::text(true));
        $this->assertSame('false', Sampler::text(false));
        $this->assertSame('42', Sampler::text(42));
        $this->assertSame('2026-10-29 01:02:03', Sampler::text(new \DateTimeImmutable('2026-10-29 01:02:03')));
        $this->assertNull(Sampler::text(['array']));
        $fh = fopen('php://memory', 'r+');
        fwrite($fh, str_repeat('x', 5000));
        rewind($fh);
        $this->assertSame(1000, strlen((string) Sampler::text($fh)));
    }
}

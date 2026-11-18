<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Classifier;

use DreamFactory\Core\Masking\Classifier\CanonicalJson;
use DreamFactory\Core\Masking\Classifier\ColumnMeta;
use DreamFactory\Core\Masking\Classifier\Engine;
use DreamFactory\Core\Masking\Classifier\RulePack;
use DreamFactory\Core\Masking\Classifier\Ruleset;
use DreamFactory\Core\Masking\Classifier\TableMeta;
use DreamFactory\Core\Masking\Scanner\Sampler;
use DreamFactory\Core\Masking\Scanner\SchemaReader;
use Illuminate\Database\SQLiteConnection;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Opt-in parity with the classifier prototype (set DM_SPIKE_DIR to its directory): the prototype's
 * SQLite fixtures run through both engines with identical inputs must give byte-identical output
 * that also matches the hashes the prototype recorded; and the scanner's Sampler must read exactly
 * the rows the prototype's sampler read.
 */
final class SpikeParityTest extends TestCase
{
    private static function spike(): string
    {
        $dir = (string) getenv('DM_SPIKE_DIR');
        if ($dir === '' || !is_file($dir . '/src/autoload.php')) {
            self::markTestSkipped('Set DM_SPIKE_DIR to the classifier prototype directory to run parity tests.');
        }
        require_once $dir . '/src/autoload.php';
        return $dir;
    }

    public static function fixtures(): iterable
    {
        foreach (['adversarial', 'opaque', 'synth'] as $db) {
            foreach (['hybrid', 'name-only'] as $mode) {
                yield "$db $mode" => [$db, $mode];
            }
        }
    }

    #[DataProvider('fixtures')]
    public function testEngineMatchesPrototype(string $db, string $mode): void
    {
        $dir = self::spike();
        $pdo = new \PDO("sqlite:$dir/fixtures/$db.sqlite", null, null, [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]);
        $dialect = new \DreamFactory\Core\Classification\Sampling\SqliteDialect($pdo);
        $tables = $dialect->tables();
        $samples = [];
        foreach ($tables as $t) {
            $samples[$t->dfName] = $dialect->sample($t, 128);
        }
        $recorded = json_decode((string) file_get_contents("$dir/out/$db.$mode.json"), true);
        $now = $recorded['meta']['reference_date'];
        $sampler = static fn ($t) => $samples[$t->dfName];
        $a = (new \DreamFactory\Core\Classification\Engine\Classifier(\DreamFactory\Core\Classification\Engine\RulePack::load("$dir/rules/pack.json"), $now))
            ->classifyDatabase($tables, $mode === 'hybrid' ? $sampler : null, $mode);
        $b = (new Engine(RulePack::load(Ruleset::path()), $now))->classifyDatabase(array_map([self::class, 'port'], $tables), $mode === 'hybrid' ? $sampler : null, $mode);
        $pa = $pb = [];
        foreach ($a as $k => $v) {
            $pa["$db.$k"] = $v;
        }
        foreach ($b as $k => $v) {
            $pb["$db.$k"] = $v;
        }
        ksort($pa, SORT_STRING);
        ksort($pb, SORT_STRING);
        $this->assertSame(\DreamFactory\Core\Classification\Util\CanonicalJson::encode($pa), CanonicalJson::encode($pb));
        $this->assertSame($recorded['meta']['output_hash'], hash('sha256', CanonicalJson::encode($pb)));
    }

    #[DataProvider('fixtures')]
    public function testSamplerReadsTheSameRows(string $db, string $mode): void
    {
        if ($mode !== 'hybrid') {
            $this->assertTrue(true);
            return;
        }
        $dir = self::spike();
        $pdo = new \PDO("sqlite:$dir/fixtures/$db.sqlite", null, null, [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]);
        $dialect = new \DreamFactory\Core\Classification\Sampling\SqliteDialect($pdo);
        $sampler = new Sampler(new SQLiteConnection(new \PDO("sqlite:$dir/fixtures/$db.sqlite")), 'sqlite');
        foreach ($dialect->tables() as $t) {
            $want = $dialect->sample($t, 128);
            $plan = [
                'from' => SchemaReader::quote($t->name, 'sqlite'),
                'kind' => $t->kind,
                'key' => array_map(static fn ($k) => SchemaReader::quote($k, 'sqlite'), $t->primaryKey !== [] ? $t->primaryKey : ($t->uniqueKey !== null ? [$t->uniqueKey] : [])),
                'key_kind' => $t->primaryKey !== [] ? 'pk' : ($t->uniqueKey !== null ? 'unique' : null),
                'columns' => array_map(static fn ($c) => ['name' => $c->name, 'quoted' => SchemaReader::quote($c->name, 'sqlite'), 'type' => $c->dfType, 'df_type' => null, 'sampled' => $c->sampleable], $t->columns),
            ];
            $got = $sampler->sample(self::port($t), $plan);
            $this->assertSame($want['rows'], $got['rows'], "$db.{$t->name}");
            $this->assertSame($want['ordered'], $got['ordered'], "$db.{$t->name}");
        }
    }

    /** Prototype TableMeta -> df-masking TableMeta (same fields). */
    public static function port(object $t): TableMeta
    {
        return new TableMeta($t->schema, $t->name, $t->dfName, $t->kind, array_map(
            static fn ($c) => new ColumnMeta($c->name, $c->dbType, $c->dfType, $c->size, $c->isPrimaryKey, $c->isForeignKey, $c->refTable, $c->isUnique, $c->comment, $c->sampleable),
            $t->columns
        ), $t->primaryKey, $t->uniqueKey, $t->comment);
    }
}

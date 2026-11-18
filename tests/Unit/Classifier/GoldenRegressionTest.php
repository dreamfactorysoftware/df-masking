<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Classifier;

use DreamFactory\Core\Masking\Classifier\CanonicalJson;
use DreamFactory\Core\Masking\Classifier\ColumnMeta;
use DreamFactory\Core\Masking\Classifier\Engine;
use DreamFactory\Core\Masking\Classifier\Ruleset;
use DreamFactory\Core\Masking\Classifier\TableMeta;
use DreamFactory\Core\Masking\Tests\Unit\Classifier\Support\SyntheticData;
use PHPUnit\Framework\TestCase;

/**
 * Byte-level regression of the engine on a deterministic synthetic database. The expected hashes
 * were produced by the classifier prototype (the evaluated engine: corpus F1 0.885) on the same
 * input, so a passing test proves the shipped engine still behaves exactly like it.
 */
final class GoldenRegressionTest extends TestCase
{
    /** sha256 of the canonical JSON of every column verdict, as produced by the prototype engine. */
    private const HYBRID_SHA256 = '14cfab2a44b4eaa7b2c41b8ad4f30981fbff0cd78d6b4fcbc48cb1d41ce02f1b';
    private const NAME_ONLY_SHA256 = '3c5b647a3e33056c64d6cf4fc2167b134ec85fc60a542e88f9d8bb5472050f01';

    private static function classify(string $mode): array
    {
        $d = SyntheticData::build();
        $tables = [];
        foreach ($d['tables'] as $t) {
            $cols = [];
            foreach ($t['columns'] as [$n, $db, $df, $size, $pk, $fk, $ref, $comment]) {
                $cols[] = new ColumnMeta($n, $db, $df, $size, $pk, $fk, $ref, false, $comment, true);
            }
            $tables[] = new TableMeta('public', $t['name'], $t['name'], 'table', $cols, $t['pk']);
        }
        $sampler = static fn (TableMeta $t) => ['rows' => $d['rows'][$t->dfName], 'ordered' => $t->primaryKey === [] ? false : 'pk', 'error' => null, 'queries' => 2];
        $out = Ruleset::engine('2026-10-28')->classifyDatabase($tables, $mode === Engine::MODE_HYBRID ? $sampler : null, $mode);
        ksort($out, SORT_STRING);
        return $out;
    }

    public function testHybridOutputIsByteIdenticalToThePrototype(): void
    {
        $out = self::classify(Engine::MODE_HYBRID);
        $this->assertSame(self::HYBRID_SHA256, hash('sha256', CanonicalJson::encode($out)));
    }

    public function testNameOnlyOutputIsByteIdenticalToThePrototype(): void
    {
        $out = self::classify(Engine::MODE_NAME_ONLY);
        $this->assertSame(self::NAME_ONLY_SHA256, hash('sha256', CanonicalJson::encode($out)));
    }

    public function testExpectedVerdicts(): void
    {
        $out = self::classify(Engine::MODE_HYBRID);
        $want = [
            'customers.email' => ['enforce', 'email'], 'customers.ssn' => ['enforce', 'national_id'],
            'customers.first_name' => ['enforce', 'person_name'], 'customers.birth_date' => ['enforce', 'date_of_birth'],
            'customers.phone' => ['enforce', 'phone'], 'customers.notes' => ['enforce', 'free_text_pii'],
            'customers.fld7' => ['enforce', 'tax_id'], 'payments.pan' => ['enforce', 'card_number'],
            'payments.card_exp' => ['enforce', 'card_expiry'], 'payments.payload' => ['enforce', 'free_text_pii'],
            'audit_log.ip' => ['enforce', 'ip_address'], 'customers.created_at' => ['clear', null],
            'customers.id' => ['clear', null], 'payments.customer_id' => ['clear', null], 'products.email' => ['clear', null],
            'products.name' => ['clear', null], 'payments.amount' => ['clear', null],
        ];
        foreach ($want as $col => [$verdict, $class]) {
            $this->assertSame([$verdict, $class], [$out[$col]['verdict'], $out[$col]['class']], $col);
        }
    }

    public function testOutputNeverContainsASampledValue(): void
    {
        $d = SyntheticData::build();
        $json = CanonicalJson::encode(self::classify(Engine::MODE_HYBRID));
        $checked = 0;
        foreach ($d['rows'] as $rows) {
            foreach ($rows as $row) {
                foreach ($row as $v) {
                    $v = trim((string) $v);
                    // Every value long enough to be distinctive (plain words could collide with schema words).
                    if (strlen($v) >= 6 && preg_match('/[\d@\s]/', $v)) {
                        $checked++;
                        $this->assertStringNotContainsString($v, $json);
                    }
                }
            }
        }
        $this->assertGreaterThan(2000, $checked);
    }
}

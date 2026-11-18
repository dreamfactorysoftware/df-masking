<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Classifier;

use DreamFactory\Core\Masking\Classifier\ColumnMeta;
use DreamFactory\Core\Masking\Classifier\Engine;
use DreamFactory\Core\Masking\Classifier\Ruleset;
use DreamFactory\Core\Masking\Classifier\TableMeta;
use PHPUnit\Framework\TestCase;

/**
 * Name-pass regression over the prototype's names corpus (fixtures/names.csv, no values):
 * "class" = name score >= 70 for that class, "class?" = >= 40, "clear" = < 40.
 */
final class NamesCorpusTest extends TestCase
{
    public function testNamesCorpus(): void
    {
        $rows = [];
        foreach (file(__DIR__ . '/fixtures/names.csv') as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            $rows[] = str_getcsv($line, ',', '"', '');
        }
        $this->assertGreaterThan(200, count($rows));
        $byTable = [];
        foreach ($rows as [$t, $c, $type]) {
            $byTable[$t][] = new ColumnMeta($c, $type, $type);
        }
        $tables = [];
        foreach ($byTable as $t => $cols) {
            $tables[] = new TableMeta('public', $t, $t, 'table', $cols);
        }
        $out = Ruleset::engine('2026-10-28')->classifyDatabase($tables, null, Engine::MODE_NAME_ONLY);
        $failures = [];
        foreach ($rows as [$t, $c, $type, $want]) {
            $v = $out["$t.$c"];
            $soft = str_ends_with($want, '?');
            $cls = rtrim($want, '?');
            $ok = $cls === 'clear' ? $v['confidence'] < 40 : ($v['class'] === $cls && $v['confidence'] >= ($soft ? 40 : 70));
            if (!$ok) {
                $failures[] = sprintf('%s.%s (%s): want %s, got %s %s %d', $t, $c, $type, $want, $v['verdict'], $v['class'] ?? '-', $v['confidence']);
            }
        }
        $this->assertSame([], $failures);
    }
}

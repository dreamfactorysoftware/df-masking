<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Tests\Unit\Enforcement;

use DreamFactory\Core\Masking\Enforcement\DerivedFields;
use DreamFactory\Core\Masking\Scanner\ColumnWriter;
use DreamFactory\Core\Masking\Scanner\Examples;
use PHPUnit\Framework\TestCase;

/**
 * A column masked because its SELECT db_function read ssn keeps that masking after the
 * expression is removed (automatic rescans never remove masking). Its evidence then says what it
 * was built from, so a plain "city" column masked as National ID is explained.
 */
final class DerivedEvidenceTest extends TestCase
{
    private static function evidence(string ...$texts): array
    {
        return ['total' => 90, 'lines' => array_map(fn ($t) => ['points' => 0, 'kind' => 'context', 'text' => $t], $texts)];
    }

    public function testWasBuiltFrom(): void
    {
        $this->assertSame('Was built from: ssn', DerivedFields::wasBuiltFrom(self::evidence('Column name "city"', 'Built from: ssn')));
        $this->assertSame('Was built from: email, ssn (and parts that could not be checked)',
            DerivedFields::wasBuiltFrom(json_encode(self::evidence(DerivedFields::evidenceText(['email', 'ssn'], true)))));
        $this->assertSame('Was built from an expression that could not be checked', DerivedFields::wasBuiltFrom(self::evidence(DerivedFields::UNCHECKED_TEXT)));
        $this->assertSame('Was built from: ssn', DerivedFields::wasBuiltFrom(self::evidence('Was built from: ssn', 'An earlier scan ...')), 'stays on later rescans');
        $this->assertNull(DerivedFields::wasBuiltFrom(self::evidence('Column name "ssn"')));
        $this->assertNull(DerivedFields::wasBuiltFrom(null));
        $this->assertNull(DerivedFields::wasBuiltFrom('not json'));
    }

    public function testStickyDerivedVerdictSaysWhatItWasBuiltFrom(): void
    {
        $writer = new ColumnWriter(new Examples());
        $old = ['verdict' => 'masked', 'class' => 'national_id', 'tier' => 'restricted', 'score' => 90, 'source' => 'detected',
            'scanned_at' => '2026-10-29 08:00:00', 'examples' => null,
            'evidence' => json_encode(self::evidence('Column name "city"', 'Built from: ssn'))];
        $rescan = ['raw' => null, 'df_type' => 'string', 'name_only' => false, 'result' => [
            'verdict' => 'clear', 'class' => null, 'tier' => null, 'score' => 0, 'source' => 'detected',
            'evidence' => self::evidence('Column name "city"')]];
        $merged = $writer->merge($old, $rescan);
        $this->assertSame(['masked', 'national_id'], [$merged['verdict'], $merged['class']], 'rescans never remove masking');
        $texts = array_column(json_decode($merged['evidence'], true)['lines'], 'text');
        $this->assertContains('Was built from: ssn', $texts);
        $this->assertStringStartsWith(ColumnWriter::KEPT_PREFIX . 'National ID', end($texts));

        // a column that was never derived gets no such line
        $plain = $writer->merge(['evidence' => json_encode(self::evidence('Column name "ssn"'))] + $old, $rescan);
        $this->assertSame([], preg_grep('/built from/i', array_column(json_decode($plain['evidence'], true)['lines'], 'text')));
    }
}

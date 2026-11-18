<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Scanner;

use DreamFactory\Core\Masking\Scanner\ColumnWriter;
use DreamFactory\Core\Masking\Scanner\Examples;
use DreamFactory\Core\Masking\Support\Catalog;
use DreamFactory\Core\Masking\Support\Tables;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\TestCase;

final class ColumnWriterTest extends TestCase
{
    private int $svc;
    private ColumnWriter $writer;

    protected function setUp(): void
    {
        Harness::boot();
        $this->svc = (int) DB::table('service')->insertGetId(['name' => 'crm', 'type' => 'sqlite', 'is_active' => true]);
        $this->writer = new ColumnWriter(new Examples());
    }

    private static function col(string $verdict, ?string $class, int $score, ?string $raw = 'jane@example.com', bool $nameOnly = false, string $source = 'detected'): array
    {
        return [
            'db_type' => 'varchar(100)', 'ordinal' => 1, 'fingerprint' => str_repeat('a', 64), 'raw' => $raw, 'df_type' => 'string', 'name_only' => $nameOnly,
            'result' => ['verdict' => $verdict, 'class' => $class, 'tier' => $class ? Catalog::tierOf($class) : null, 'score' => $score, 'source' => $source,
                'detected_class' => $class, 'detected_score' => $score,
                'evidence' => ['total' => $score, 'threshold_mask' => 70, 'threshold_review' => 40, 'lines' => [['points' => $score, 'kind' => 'name', 'text' => 'Column name "x"']], 'shapes' => []] + ($nameOnly ? ['name_only' => true] : [])],
        ];
    }

    private function row(string $column = 'email'): object
    {
        return DB::table(Tables::COLUMN)->where('service_id', $this->svc)->where('table_name', 'contacts')->where('column_name', $column)->first();
    }

    public function testInsertStoresEvidenceAndMaskedExamplesOnly(): void
    {
        $stats = $this->writer->write($this->svc, 'contacts', ['email' => self::col('masked', 'email', 100)], '2026.11.0');
        $this->assertSame(1, $stats['inserted']);
        $r = $this->row();
        $this->assertSame(['masked', 'email', 'identity', 100, 'detected', '2026.11.0'], [$r->verdict, $r->class, $r->tier, (int) $r->score, $r->source, $r->ruleset_version]);
        $this->assertNotNull($r->scanned_at);
        $this->assertStringNotContainsString('jane@example.com', $r->examples . $r->evidence);
        $examples = json_decode($r->examples, true);
        $this->assertSame(Catalog::formatsAllowed('email'), array_column($examples, 'format'));
    }

    public function testAdminDecisionsAreSticky(): void
    {
        $this->writer->write($this->svc, 'contacts', ['email' => self::col('masked', 'email', 100)], 'v1');
        DB::table(Tables::COLUMN)->where('column_name', 'email')->update(['verdict' => 'clear', 'class' => null, 'tier' => null, 'source' => 'admin', 'decided_by' => 'Alex Admin']);
        $this->writer->write($this->svc, 'contacts', ['email' => self::col('masked', 'email', 100)], 'v1');
        $r = $this->row();
        $this->assertSame(['clear', null, 'admin', 'Alex Admin', 'email'], [$r->verdict, $r->class, $r->source, $r->decided_by, $r->detected_class]);
        $this->assertNull($r->examples);
    }

    public function testAutomaticChangesNeverClear(): void
    {
        $this->writer->write($this->svc, 'contacts', ['email' => self::col('masked', 'email', 100)], 'v1');
        $stats = $this->writer->write($this->svc, 'contacts', ['email' => self::col('clear', null, 20)], 'v1');
        $r = $this->row();
        $this->assertSame(['masked', 'email', 100], [$r->verdict, $r->class, (int) $r->score]);
        $this->assertSame(0, $stats['changed']);
        $lines = json_decode($r->evidence, true)['lines'];
        $this->assertStringStartsWith(ColumnWriter::KEPT_PREFIX . 'Email (masked)', end($lines)['text']);
        // ... but a stricter result replaces a weaker one.
        $this->writer->write($this->svc, 'contacts', ['email' => self::col('masked', 'national_id', 90, '123-45-6789')], 'v1');
        $this->assertSame('national_id', $this->row()->class);
        // ... and a weaker tier never replaces a stricter one.
        $this->writer->write($this->svc, 'contacts', ['email' => self::col('masked', 'email', 100)], 'v1');
        $this->assertSame('national_id', $this->row()->class);
    }

    public function testRuleMaskingOutlivesTheRule(): void
    {
        $this->writer->write($this->svc, 'contacts', ['city' => self::col('masked', 'street_address', 70, 'Springfield', false, 'rule')], 'v1');
        $this->writer->write($this->svc, 'contacts', ['city' => self::col('clear', null, 0, 'Springfield')], 'v1');
        $r = $this->row('city');
        $this->assertSame(['masked', 'street_address', 'rule'], [$r->verdict, $r->class, $r->source]);
        $lines = json_decode($r->evidence, true)['lines'];
        $this->assertStringStartsWith(ColumnWriter::KEPT_RULE_PREFIX . 'Street address by a detection rule that no longer matches', end($lines)['text']);
    }

    public function testProvisionalRowsAreReplaced(): void
    {
        // Enforcement's inline name-only verdict (scanned_at null) is replaced, even by "clear".
        DB::table(Tables::COLUMN)->insert(['service_id' => $this->svc, 'table_name' => 'contacts', 'column_name' => 'email', 'verdict' => 'review',
            'class' => 'person_name', 'tier' => 'identity', 'score' => 15, 'source' => 'detected', 'scanned_at' => null, 'created_at' => now(), 'updated_at' => now()]);
        $this->writer->write($this->svc, 'contacts', ['email' => self::col('clear', null, 0, 'x')], 'v1');
        $this->assertSame('clear', $this->row()->verdict);
        // A name-only scan result is replaced by a sampled one.
        $this->writer->write($this->svc, 'contacts', ['name' => self::col('review', 'person_name', 15, null, true)], 'v1', false);
        $this->writer->write($this->svc, 'contacts', ['name' => self::col('clear', null, 5, 'Widget')], 'v1', false);
        $this->assertSame('clear', $this->row('name')->verdict);
    }

    public function testMissingColumnsAndTablesAreDeleted(): void
    {
        $this->writer->write($this->svc, 'contacts', ['email' => self::col('masked', 'email', 100), 'old' => self::col('clear', null, 0)], 'v1');
        $stats = $this->writer->write($this->svc, 'contacts', ['email' => self::col('masked', 'email', 100)], 'v1');
        $this->assertSame(1, $stats['deleted']);
        $this->writer->write($this->svc, 'gone', ['x' => self::col('clear', null, 0)], 'v1');
        $this->assertSame(1, ColumnWriter::deleteTablesExcept($this->svc, ['contacts']));
        $this->assertSame(1, DB::table(Tables::COLUMN)->count());
    }
}

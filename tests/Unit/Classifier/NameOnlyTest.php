<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Classifier;

use DreamFactory\Core\Masking\Classifier\NameOnly;
use DreamFactory\Core\Masking\Classifier\Ruleset;
use DreamFactory\Core\Masking\Support\Catalog;
use PHPUnit\Framework\TestCase;

final class NameOnlyTest extends TestCase
{
    protected function setUp(): void
    {
        NameOnly::forget();
    }

    public function testShape(): void
    {
        $r = NameOnly::classify('customers', 'email', 'character varying(255)');
        $this->assertSame(['class', 'score', 'verdict', 'tier', 'evidence'], array_keys($r));
        $this->assertSame(['masked', 'email', 70, 'identity'], [$r['verdict'], $r['class'], $r['score'], $r['tier']]);
        $this->assertSame(70, $r['evidence']['threshold_mask']);
        $this->assertSame(15, $r['evidence']['threshold_review']);
        $this->assertTrue($r['evidence']['name_only']);
        $this->assertNotEmpty($r['evidence']['lines']);
    }

    public function testVerdicts(): void
    {
        $this->assertSame('national_id', NameOnly::classify('employees', 'ssn', 'char(11)')['class']);
        $this->assertSame('masked', NameOnly::classify('employees', 'ssn')['verdict']);
        $this->assertSame('clear', NameOnly::classify('orders', 'quantity', 'integer')['verdict']);
        $this->assertSame('clear', NameOnly::classify('orders', 'id', 'integer')['verdict']);
        $this->assertNull(NameOnly::classify('orders', 'quantity', 'integer')['class']);
        // Type gate: an email-named boolean is not an email.
        $this->assertSame('clear', NameOnly::classify('users', 'email_opt_in', 'boolean')['verdict']);
        // DreamFactory simple types work as the type argument too.
        $this->assertSame('masked', NameOnly::classify('patients', 'date_of_birth', 'date')['verdict']);
        // Weak name signal without values: fail closed into review.
        $weak = NameOnly::classify('audit_log', 'token', 'varchar(64)');
        $this->assertSame(['review', 'credential'], [$weak['verdict'], $weak['class']]);
        // Schema-qualified table names are accepted.
        $this->assertSame('email', NameOnly::classify('sales.customers', 'contact_email', 'text')['class']);
    }

    public function testEveryClassIsInTheCatalog(): void
    {
        foreach (array_keys(Ruleset::pack()->classes()) as $class) {
            $this->assertTrue(Catalog::has($class), "pack class $class missing from the catalog");
        }
        $this->assertEqualsCanonicalizing(Catalog::ids(), array_keys(Ruleset::pack()->classes()));
    }

    public function testSiblingContextInClassifyTable(): void
    {
        $alone = NameOnly::classify('wallet', 'pan', 'varchar(19)');
        $table = NameOnly::classifyTable('wallet', ['pan' => 'varchar(19)', 'card_exp' => 'varchar(5)']);
        $this->assertSame('card_number', $table['pan']['class']);
        $this->assertSame('masked', $table['pan']['verdict']);
        $this->assertNotSame('masked', $alone['verdict']);
    }

    public function testFastAndMemoized(): void
    {
        NameOnly::classify('warmup', 'email', 'text');
        $t = hrtime(true);
        for ($i = 0; $i < 200; $i++) {
            NameOnly::classify('t' . $i, 'customer_email_' . $i, 'varchar(100)');
        }
        $perCallMs = (hrtime(true) - $t) / 1e6 / 200;
        $this->assertLessThan(2.0, $perCallMs, 'uncached name-only classification should take well under 2 ms');
        $t = hrtime(true);
        for ($i = 0; $i < 1000; $i++) {
            NameOnly::classify('t1', 'customer_email_1', 'varchar(100)');
        }
        $this->assertLessThan(0.05, (hrtime(true) - $t) / 1e6 / 1000);
    }

    /** A never-scanned free-text column is span-masked until the scan reads its values. */
    public function testUnscannedFreeTextIsSpanMaskedUntilScanned(): void
    {
        foreach ([['Notes', 'nvarchar(400)'], ['comments', 'text'], ['order_description', 'varchar(2000)'], ['bemerkung', null]] as [$col, $type]) {
            $r = NameOnly::classify('customers', $col, $type);
            $this->assertSame(['review', 'free_text_pii', 'free_text'], [$r['verdict'], $r['class'], $r['tier']], $col);
            $this->assertContains('Free text not scanned yet: personal data in it is masked until a scan reads the values',
                array_column($r['evidence']['lines'], 'text'));
        }
        $this->assertSame('clear', NameOnly::classify('customers', 'metadata', 'jsonb')['verdict'], 'JSON documents wait for the scan');
        $this->assertSame('masked', NameOnly::classify('customers', 'email', 'text')['verdict'], 'stronger verdicts are kept');
    }

    /**
     * Any never-scanned text or string column whose name says nothing is span-masked
     * until a scan reads it (an email in a column named "contact" is not served in clear); numbers,
     * dates, booleans, UUIDs and JSON are not. Before: only free-text names (notes, comments, ...)
     * of 64+ characters were, so "contact" and "status" were clear.
     */
    public function testEveryUnscannedTextColumnIsSpanMaskedUntilScanned(): void
    {
        foreach ([['contact', 'varchar(120)'], ['status', 'text'], ['note_code', 'varchar(10)'], ['ref', 'char(36)'], ['x', 'nvarchar(max)'], ['label', null]] as [$col, $type]) {
            $r = NameOnly::classify('customers', $col, $type);
            $this->assertSame(['review', 'free_text_pii', 'free_text'], [$r['verdict'], $r['class'], $r['tier']], $col);
            $this->assertContains('Not scanned yet: personal data in its values is masked until a scan reads them',
                array_column($r['evidence']['lines'], 'text'), $col);
        }
        foreach ([['quantity', 'integer'], ['created_at', 'timestamp'], ['is_active', 'boolean'], ['id', 'uuid'], ['metadata', 'jsonb'], ['price', 'numeric(10,2)']] as [$col, $type]) {
            $this->assertSame('clear', NameOnly::classify('customers', $col, $type)['verdict'], "$col $type");
        }
    }
}

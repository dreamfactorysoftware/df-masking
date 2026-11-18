<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Classifier;

use DreamFactory\Core\Masking\Classifier\ColumnMeta;
use DreamFactory\Core\Masking\Classifier\Engine;
use DreamFactory\Core\Masking\Classifier\Ruleset;
use DreamFactory\Core\Masking\Classifier\TableMeta;
use PHPUnit\Framework\TestCase;

/**
 * Identifiers embedded in short free text ("Write to x@example.org", notes that are
 * mostly "ok") are found, while columns that only hold identifiers (an email list, timestamps,
 * IP addresses) are left to the column detectors.
 */
final class ShortFreeTextTest extends TestCase
{
    /** @param array<string,list<?string>> $columns name => values (aligned rows) */
    private static function classify(array $columns, string $table = 'memo_test'): array
    {
        $metas = [new ColumnMeta('id', 'integer', 'integer', null, true, false, null, true, null, true)];
        foreach (array_keys($columns) as $name) {
            $metas[] = new ColumnMeta($name, 'text', 'text', null, false, false, null, false, null, true);
        }
        $n = max(array_map('count', $columns));
        $rows = [];
        for ($i = 0; $i < $n; $i++) {
            $r = ['id' => (string)($i + 1)];
            foreach ($columns as $name => $values) {
                $r[$name] = $values[$i] ?? null;
            }
            $rows[] = $r;
        }
        $t = new TableMeta('public', $table, $table, 'table', $metas, ['id']);
        $engine = Ruleset::engine('2026-10-28');
        $ctx = $engine->tableContexts([$t])[$table];

        return $engine->classifyTable($t, $ctx, ['rows' => $rows, 'ordered' => 'pk', 'error' => null, 'queries' => 2], Engine::MODE_HYBRID);
    }

    public function testShortNotesWithEmailsAndPhonesAreDetected(): void
    {
        $notes = $comments = [];
        for ($i = 1; $i <= 50; $i++) {
            $notes[] = "Write to cl$i@example.org";
            $comments[] = 'Call me on +1 415 555 ' . str_pad((string)(100 + $i), 4, '0', STR_PAD_LEFT);
        }
        $out = self::classify(['notes' => $notes, 'comments' => $comments]);

        $this->assertSame(['enforce', 'free_text_pii'], [$out['notes']['verdict'], $out['notes']['class']], 'notes');
        $this->assertNotSame('clear', $out['comments']['verdict'], 'comments');
        $this->assertSame('free_text_pii', $out['comments']['class']);
    }

    public function testMostlyShortNotesWithSomeCardsAndPhonesAreAtLeastReviewed(): void
    {
        $notes = [];
        for ($i = 1; $i <= 60; $i++) {
            $notes[] = $i % 5 === 0 && $i <= 55
                ? 'Called from +1 303-555-02' . str_pad((string)($i % 100), 2, '0', STR_PAD_LEFT) . ' about card 4111 1111 1111 1111'
                : 'ok';
        }
        $out = self::classify(['notes' => $notes], 'members');

        $this->assertNotSame('clear', $out['notes']['verdict'], '11 of 60 rows hold a phone and a card');
        $this->assertSame('free_text_pii', $out['notes']['class']);
    }

    public function testColumnsThatOnlyHoldIdentifiersAreNotFreeText(): void
    {
        $emails = $stamps = $ips = $ibans = $rare = [];
        for ($i = 1; $i <= 60; $i++) {
            $emails[] = "user$i@example.org";
            $stamps[] = sprintf('2026-10-%02d 10:%02d:00+00', $i % 28 + 1, $i % 60);
            $ips[] = "10.0.$i.1, 10.0.$i.2";
            $ibans[] = 'NL91 ABNA 0417 1643 00';
            $rare[] = $i === 7 ? 'Reach me at me@example.org' : 'Delivered to the front desk as agreed';
        }
        $out = self::classify(['contact_list' => $emails, 'imported_at' => $stamps, 'hops' => $ips, 'acct' => $ibans, 'remark' => $rare]);

        $this->assertNotSame('free_text_pii', $out['contact_list']['class'], 'a value that IS an email is the email detector\'s business');
        $this->assertSame('clear', $out['imported_at']['verdict'], 'timestamps are not phone numbers in text');
        $this->assertSame('clear', $out['hops']['verdict']);
        $this->assertNotSame('free_text_pii', $out['acct']['class']);
        $this->assertSame('clear', $out['remark']['verdict'], 'one incidental email in 60 rows does not flag the column');
    }
}

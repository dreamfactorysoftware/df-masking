<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Tests\Unit\Enforcement;

use DreamFactory\Core\Masking\Enforcement\Listener;
use DreamFactory\Core\Masking\Masking\Masker;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use DreamFactory\Core\Utility\ServiceResponse;

/**
 * In mode On, a column dm_column does not know yet (added after the last scan)
 * whose name says nothing and whose type is text is span-masked on the very first request: an
 * email or phone in it is hidden, while UUIDs, codes, numbers and prose pass unchanged (keys and
 * joins keep working). Before, such a column was served in clear until the scan reached it.
 */
final class UnscannedColumnsTest extends EnforcementHarness
{
    private const UUID = '550e8400-e29b-41d4-a716-446655440000';

    public function testFirstRequestToANeverScannedTextColumnIsSpanMasked(): void
    {
        $this->defineTable('contacts', [
            ['id', 'id', 'clear', null, null],
            ['contact', 'string', null, null, null],   // added by a DBA: emails under an innocuous name
            ['ref', 'string', null, null, null],       // UUID keys
            ['code', 'string', null, null, null],      // order codes
            ['remark', 'string', null, null, null],    // prose with a phone number in it
            ['qty', 'integer', null, null, null],      // a number (DreamFactory type integer)
        ]);
        $rows = [
            ['id' => 1, 'contact' => 'jane.doe@example.com', 'ref' => self::UUID, 'code' => 'ORD-2024-0042', 'remark' => 'Call 415-555-0132 after 5', 'qty' => 3],
            ['id' => 2, 'contact' => 'bob@example.org', 'ref' => '6fa459ea-ee8a-3ca4-894e-db77e160355e', 'code' => 'SKU 1182', 'remark' => 'Leave at the door', 'qty' => 12],
        ];

        $out = $this->tableFlow($this->request('GET'), new ServiceResponse($rows), 'contacts')->getContent();

        $this->assertStringNotContainsString('@', (string)$out[0]['contact'], 'the email is not served in clear');
        $this->assertStringContainsString(self::G, (string)$out[0]['contact']);
        $this->assertStringNotContainsString('bob@example.org', (string)$out[1]['contact']);
        $this->assertSame(self::UUID, $out[0]['ref'], 'keys pass unchanged');
        $this->assertSame('ORD-2024-0042', $out[0]['code']);
        $this->assertSame('SKU 1182', $out[1]['code']);
        $this->assertStringNotContainsString('415-555-0132', (string)$out[0]['remark']);
        $this->assertStringStartsWith('Call ', (string)$out[0]['remark'], 'only the span is hidden');
        $this->assertSame('Leave at the door', $out[1]['remark']);
        $this->assertSame(3, $out[0]['qty']);

        $stored = $this->db()->table(Tables::COLUMN)->where('table_name', 'contacts')->where('column_name', 'contact')->first();
        $this->assertSame(['review', 'free_text_pii', null], [$stored->verdict, $stored->class, $stored->scanned_at]);
        $this->assertSame('clear', $this->db()->table(Tables::COLUMN)->where('table_name', 'contacts')->where('column_name', 'qty')->value('verdict'));
        $this->assertSame('varchar', $this->db()->table(Tables::COLUMN)->where('table_name', 'contacts')->where('column_name', 'qty')->value('db_type'),
            'the stored native type is unchanged');
    }

    /** Preview never changes bodies: the same column is only reported. */
    public function testPreviewOnlyReportsIt(): void
    {
        Settings::set('mode', 'preview');
        $this->listener = new Listener(new Masker(str_repeat("\x03", 32)));
        $this->defineTable('contacts', [
            ['id', 'id', 'clear', null, null],
            ['contact', 'string', null, null, null],
        ]);

        $response = $this->tableFlow($this->request('GET'), new ServiceResponse([['id' => 1, 'contact' => 'jane.doe@example.com']]), 'contacts');

        $this->assertSame('jane.doe@example.com', $response->getContent()[0]['contact']);
        $this->assertSame([], $response->getHeaders(), 'Preview adds no headers');
        $row = $this->db()->table(Tables::ACTIVITY)->where('kind', 'preview')->first();
        $this->assertContains('contact', json_decode((string)$row->meta, true)['columns']);
    }
}

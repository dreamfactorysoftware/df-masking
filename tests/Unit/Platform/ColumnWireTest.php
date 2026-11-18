<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Platform;

use DreamFactory\Core\Masking\Resources\Handlers\ColumnHandler;
use DreamFactory\Core\Masking\Resources\Handlers\MaskHandler;
use DreamFactory\Core\Masking\Support\Formats;
use DreamFactory\Core\Masking\Support\PolicyVersion;
use DreamFactory\Core\Masking\Support\Tables;
use DreamFactory\Core\Masking\Tests\TestCase;

/**
 * The Column wire shape and mask-format selection.
 */
final class ColumnWireTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->bootHarness();
    }

    private function row(array $overrides = []): object
    {
        return (object)array_merge([
            'id' => 1,
            'service_id' => 10,
            'table_name' => 'customers',
            'column_name' => 'email',
            'db_type' => 'varchar(120)',
            'verdict' => 'masked',
            'class' => 'email',
            'tier' => 'identity',
            'score' => 100,
            'source' => 'detected',
            'evidence' => json_encode([
                'total' => 145,
                'threshold_mask' => 70,
                'threshold_review' => 40,
                'lines' => [['points' => 70, 'kind' => 'name', 'text' => 'Column name "email"']],
                'shapes' => [['a+@a+.a+', 60]],
            ]),
            'examples' => json_encode([
                ['format' => 'token', 'value' => 'EMAIL_1a2b3c4d'],
                ['format' => 'initial', 'value' => 'j•••@•••••.com'],
                ['format' => 'null', 'value' => null],
            ]),
            'decided_by' => 'Alex Admin',
            'decided_at' => '2026-10-29 10:00:00',
            'ordinal' => 3,
        ], $overrides);
    }

    public function testMaskedDetectedColumn(): void
    {
        $wire = (new ColumnHandler())->wire($this->row(), 'crm');
        $this->assertSame([
            'id' => 'crm.customers.email',
            'service' => 'crm',
            'table' => 'customers',
            'column' => 'email',
            'type' => 'varchar(120)',
            'verdict' => 'masked',
            'class' => 'email',
            'tier' => 'identity',
            'source' => 'detected',
            'decided_by' => null,
            'decided_at' => null,
            'confidence' => 100,
            'example' => 'EMAIL_1a2b3c4d',
            'format' => 'token',
            'evidence' => [
                'total' => 145,
                'threshold_mask' => 70,
                'threshold_review' => 40,
                'lines' => [['points' => 70, 'kind' => 'name', 'text' => 'Column name "email"']],
                'shapes' => [['a+@a+.a+', 60]],
            ],
        ], $wire);
    }

    public function testExampleFollowsTheCurrentFormat(): void
    {
        (new MaskHandler())->patch(['resource' => [['class' => 'email', 'format' => 'initial']]]);
        $this->assertSame('initial', Formats::current('email'));
        $wire = (new ColumnHandler())->wire($this->row(), 'crm');
        $this->assertSame('initial', $wire['format']);
        $this->assertSame('j•••@•••••.com', $wire['example']);

        (new MaskHandler())->patch(['resource' => [['class' => 'email', 'format' => 'null']]]);
        $wire = (new ColumnHandler())->wire($this->row(), 'crm');
        $this->assertSame('null', $wire['format']);
        $this->assertNull($wire['example']);

        $log = $this->db()->table(Tables::ACTIVITY)->orderBy('id')->pluck('text')->all();
        $this->assertSame(['Email now masked as first letter', 'Email now masked as null'], $log);
    }

    public function testAdminDecisionsAndClearColumns(): void
    {
        $wire = (new ColumnHandler())->wire($this->row([
            'verdict' => 'clear', 'class' => null, 'tier' => null, 'source' => 'admin',
        ]), 'crm');
        $this->assertSame('clear', $wire['verdict']);
        $this->assertNull($wire['class']);
        $this->assertNull($wire['tier']);
        $this->assertNull($wire['format']);
        $this->assertNull($wire['example']);
        $this->assertSame('admin', $wire['source']);
        $this->assertSame('Alex Admin', $wire['decided_by']);
        $this->assertSame('2026-10-29T10:00:00Z', $wire['decided_at']);

        // rule / baseline origins are 'detected' on the wire
        foreach (['rule', 'baseline'] as $source) {
            $this->assertSame('detected', (new ColumnHandler())->wire($this->row(['source' => $source]), 'crm')['source']);
        }
    }

    public function testDefensiveDefaults(): void
    {
        $wire = (new ColumnHandler())->wire($this->row([
            'verdict' => 'weird', 'evidence' => null, 'examples' => 'not json', 'score' => 250, 'db_type' => null,
        ]), 'crm');
        $this->assertSame('review', $wire['verdict'], 'unknown verdicts fail closed');
        $this->assertSame(100, $wire['confidence']);
        $this->assertSame(['total' => 100, 'threshold_mask' => 70, 'threshold_review' => 40, 'lines' => [], 'shapes' => []], $wire['evidence']);
        $this->assertSame('', $wire['type']);
        // no stored example for the format: the synthetic class sample through the Masker
        $this->assertMatchesRegularExpression('/^EMAIL_[0-9a-f]{8}$/', (string)$wire['example']);

        $wire = (new ColumnHandler())->wire($this->row(['class' => 'card_number', 'tier' => 'restricted', 'examples' => null]), 'crm');
        $this->assertSame('last4', $wire['format']);
        $this->assertStringEndsWith('1234', (string)$wire['example']);
        $this->assertStringNotContainsString('4111', (string)$wire['example']);
    }

    public function testStoredFormatThatIsNotAllowedFallsBackToTheDefault(): void
    {
        $this->db()->table(Tables::MASK_FORMAT)->insert(['class' => 'national_id', 'format' => 'token']);
        PolicyVersion::bump();
        $this->assertSame('redact', Formats::current('national_id'));
        $this->assertNull(Formats::current('nope'));
        $this->assertCount(23, Formats::all());
    }

    public function testMaskPatchValidation(): void
    {
        foreach ([
            [[], 'resource list'],
            [['resource' => [['class' => 'nope', 'format' => 'redact']]], 'Unknown class'],
            [['resource' => [['class' => 'national_id', 'format' => 'token']]], 'National ID can be masked as: redact, last4, null.'],
            [['resource' => 'x'], 'resource list'],
        ] as [$payload, $message]) {
            try {
                (new MaskHandler())->patch($payload);
                $this->fail('expected 400 for ' . json_encode($payload));
            } catch (\DreamFactory\Core\Exceptions\BadRequestException $e) {
                $this->assertStringContainsString($message, $e->getMessage());
            }
        }
        $this->assertSame(0, $this->db()->table(Tables::MASK_FORMAT)->count());
    }
}

<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Scanner;

use DreamFactory\Core\Masking\Scanner\Examples;
use DreamFactory\Core\Masking\Support\Catalog;
use PHPUnit\Framework\TestCase;

final class ExamplesTest extends TestCase
{
    protected function setUp(): void
    {
        Harness::boot();
    }

    private static function byFormat(array $examples): array
    {
        $out = [];
        foreach ($examples as $e) {
            $out[$e['format']] = $e['value'];
        }
        return $out;
    }

    public function testOneExamplePerAllowedFormatNeverRaw(): void
    {
        $ex = new Examples();
        $raw = 'user.one@example.com';
        $e = self::byFormat($ex->build('email', $raw, 'string'));
        $this->assertSame(Catalog::formatsAllowed('email'), array_keys($e));
        $this->assertMatchesRegularExpression('/^EMAIL_[0-9a-f]{8}$/', $e['token']);
        $this->assertNull($e['null']);
        $this->assertStringContainsString(Examples::GLYPH, $e['initial']);
        $this->assertStringContainsString(Examples::GLYPH, $e['redact']);
        foreach ($e as $v) {
            $this->assertNotSame($raw, $v);
            $this->assertStringNotContainsString('one@example', (string) $v);
        }
    }

    public function testLast4AndYear(): void
    {
        $ex = new Examples();
        $this->assertSame("\u{2022}\u{2022}\u{2022}-\u{2022}\u{2022}-6789", self::byFormat($ex->build('national_id', '123-45-6789', 'string'))['last4']);
        $this->assertSame("1984-\u{2022}\u{2022}-\u{2022}\u{2022}", self::byFormat($ex->build('date_of_birth', '1984-03-12', 'date'))['year']);
    }

    public function testIntegerColumnsAreMaskedLikeTheApiReturnsThem(): void
    {
        // A bigint card number is a JSON number in responses; the Masker nulls non-strings.
        $e = self::byFormat((new Examples())->build('card_number', '4539578763621486', 'bigint'));
        $this->assertNull($e['last4']);
        $this->assertNull($e['redact']);
    }

    public function testFreeTextAndMissingValuesUseTheSyntheticSample(): void
    {
        $ex = new Examples();
        $span = self::byFormat($ex->build('free_text_pii', 'Patient John Realname called from 555-0100', 'text'))['span'];
        $this->assertStringNotContainsString('Realname', $span);
        $this->assertStringStartsWith('Call Jane at', $span);
        $this->assertSame(Catalog::formatsAllowed('phone'), array_column($ex->build('phone', null, null), 'format'));
        $this->assertSame([], $ex->build('no_such_class', 'x', null));
    }

    public function testSamplesCoverTheCatalog(): void
    {
        $this->assertEqualsCanonicalizing(Catalog::ids(), array_keys(Examples::SAMPLES));
        $ui = getenv('DM_UI_CATALOG') ?: dirname(__DIR__, 3) . '/../df-admin-interface/src/app/adf-data-masking/data-masking.catalog.ts';
        if (is_file($ui)) {
            preg_match_all("/id: '([a-z_]+)',.*?sample: '((?:[^'\\\\]|\\\\.)*)'/s", (string) file_get_contents($ui), $m, PREG_SET_ORDER);
            $this->assertCount(count(Catalog::ids()), $m);
            foreach ($m as [, $id, $sample]) {
                $this->assertSame(stripslashes($sample), Examples::SAMPLES[$id], "sample of $id differs from the admin UI catalog");
            }
        }
    }

    public function testReuseKeepsValueFormatsAndReplacesTokens(): void
    {
        $ex = new Examples();
        $previous = $ex->build('national_id', '123-45-6789', 'string');
        $reused = self::byFormat($ex->reuse('phone', $previous));
        $this->assertSame(Catalog::formatsAllowed('phone'), array_keys($reused));
        $this->assertSame("\u{2022}\u{2022}\u{2022}-\u{2022}\u{2022}-6789", $reused['last4']);
        $this->assertMatchesRegularExpression('/^PHONE_[0-9a-f]{8}$/', $reused['token']);
    }
}

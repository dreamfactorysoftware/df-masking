<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Tests\Unit\Masking;

use DreamFactory\Core\Masking\Masking\Masker;
use DreamFactory\Core\Masking\Support\Catalog;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class MaskerTest extends TestCase
{
    private const G = "\u{2022}";

    private Masker $m;

    protected function setUp(): void
    {
        $this->m = new Masker(str_repeat("\x01", 32));
    }

    private static function g(int $n): string
    {
        return str_repeat(self::G, $n);
    }

    // ------------------------------------------------------------------ redact / null

    public function testRedactHidesLengthAndContent(): void
    {
        $this->assertSame(self::g(8), $this->m->mask('a much longer secret value', 'credential', 'redact'));
        $this->assertSame(self::g(8), $this->m->mask('x', 'credential', 'redact'));
        $this->assertSame(self::g(8), $this->m->mask('42', 'age', 'redact'));
    }

    public function testEmptyStringStaysEmptyAndNullStaysNull(): void
    {
        foreach (['redact', 'last4', 'initial', 'year', 'span'] as $format) {
            $this->assertSame('', $this->m->mask('', 'national_id', $format), $format);
            $this->assertNull($this->m->mask(null, 'national_id', $format), $format);
        }
        $this->assertNull($this->m->mask(null, 'email', 'token'));
    }

    public function testNullFormat(): void
    {
        $this->assertNull($this->m->mask('jane@example.com', 'email', 'null'));
        $this->assertNull($this->m->mask(42, 'age', 'null'));
    }

    public static function nonStrings(): array
    {
        return [[42], [3.14], [true], [false], [0], [['a' => 'b']]];
    }

    #[DataProvider('nonStrings')]
    public function testNonStringValuesBecomeNullExceptToken(mixed $value): void
    {
        foreach (['redact', 'last4', 'initial', 'year'] as $format) {
            $this->assertNull($this->m->mask($value, 'financial_personal', $format), $format);
        }
        $this->assertMatchesRegularExpression('/^EMAIL_[0-9a-f]{8}$/', $this->m->mask($value, 'email', 'token'));
    }

    public function testIntTokenEqualsStringToken(): void
    {
        $this->assertSame($this->m->mask('42', 'username', 'token'), $this->m->mask(42, 'username', 'token'));
    }

    public function testInvalidUtf8IsRedacted(): void
    {
        $bin = "\xff\xfe\x00binary";
        foreach (['last4', 'initial', 'year', 'span'] as $format) {
            $this->assertSame(self::g(8), $this->m->mask($bin, 'free_text_pii', $format), $format);
        }
    }

    // ------------------------------------------------------------------ last4

    public static function last4Cases(): array
    {
        $g = fn (int $n) => str_repeat("\u{2022}", $n);

        return [
            'ssn' => ['123-45-6789', $g(3) . '-' . $g(2) . '-6789'],
            'card' => ['4111 1111 1111 1234', $g(4) . ' ' . $g(4) . ' ' . $g(4) . ' 1234'],
            'iban' => ['NL91 ABNA 0417 1643 00', $g(4) . ' ' . $g(4) . ' ' . $g(4) . ' ' . $g(2) . '43 00'],
            'phone' => ['+1 415-555-0132', '+' . $g(1) . ' ' . $g(3) . '-' . $g(3) . '-0132'],
            'four or fewer' => ['1234', $g(8)],
            'three' => ['abc', $g(8)],
            'five' => ['12345', $g(1) . '2345'],
            'unicode letters' => ["\u{00DC}n\u{00EF}c\u{00F6}d\u{00E9}123", $g(6) . "\u{00E9}123"],
            'emoji kept' => ["\u{1F4DE}555-0132", "\u{1F4DE}" . $g(3) . '-0132'],
            'only separators' => ['---', $g(8)],
        ];
    }

    #[DataProvider('last4Cases')]
    public function testLast4(string $in, string $out): void
    {
        $this->assertSame($out, $this->m->mask($in, 'national_id', 'last4'));
    }

    public function testLast4DropsCombiningMarksOnHiddenLetters(): void
    {
        $decomposed = "Jose\u{0301}phine99"; // e + combining acute
        $masked = $this->m->mask($decomposed, 'bank_account', 'last4');
        $this->assertStringNotContainsString("\u{0301}", $masked);
        $this->assertStringEndsWith('ne99', $masked);
    }

    // ------------------------------------------------------------------ initial

    public static function initialCases(): array
    {
        $g = fn (int $n) => str_repeat("\u{2022}", $n);

        return [
            'name' => ['Jane Doe', 'J' . $g(3) . ' D' . $g(2)],
            'email' => ['jane.doe@example.com', 'j' . $g(7) . '@' . $g(7) . '.com'],
            'short email' => ['j@x.io', 'j' . $g(1) . '@' . $g(1) . '.io'],
            'unicode name' => ["\u{00D6}laf \u{00C5}ngstr\u{00F6}m", "\u{00D6}" . $g(3) . " \u{00C5}" . $g(7)],
            'whitespace kept' => ["Jane  van\tDoe", 'J' . $g(3) . '  v' . $g(2) . "\tD" . $g(2)],
            'single letter words' => ['J R R Tolkien', 'J R R T' . $g(6)],
            'username' => ['jdoe84', 'j' . $g(5)],
            'no tld' => ['admin@localhost', 'a' . $g(4) . '@' . $g(9)],
        ];
    }

    #[DataProvider('initialCases')]
    public function testInitial(string $in, string $out): void
    {
        $this->assertSame($out, $this->m->mask($in, 'person_name', 'initial'));
    }

    // ------------------------------------------------------------------ year

    public static function yearCases(): array
    {
        $g = fn (int $n) => str_repeat("\u{2022}", $n);

        return [
            'iso date' => ['1984-03-12', '1984-' . $g(2) . '-' . $g(2)],
            'iso datetime' => ['1984-03-12T10:20:30Z', '1984-' . $g(2) . '-' . $g(2)],
            'us date' => ['03/12/1984', $g(2) . '/' . $g(2) . '/1984'],
            'dotted' => ['12.03.1984', $g(2) . '.' . $g(2) . '.1984'],
            'expiry' => ['07/28', $g(2) . '/28'],
            'expiry long' => ['07/2028', $g(2) . '/2028'],
            'mm/dd/yy' => ['12/03/84', $g(2) . '/' . $g(2) . '/84'],
            'year only' => ['1984', '1984'],
            'out of range year' => ['1899-01-01', $g(8)],
            'garbage' => ['unknown', $g(8)],
            'compact date' => ['19840312', $g(8)],
        ];
    }

    #[DataProvider('yearCases')]
    public function testYear(string $in, string $out): void
    {
        $this->assertSame($out, $this->m->mask($in, 'date_of_birth', 'year'));
    }

    // ------------------------------------------------------------------ token

    public function testTokenShapeAndStability(): void
    {
        $a = $this->m->mask('jane@example.com', 'email', 'token');
        $this->assertMatchesRegularExpression('/^EMAIL_[0-9a-f]{8}$/', $a);
        $this->assertSame($a, $this->m->mask('jane@example.com', 'email', 'token'));
        $this->assertSame($a, (new Masker(str_repeat("\x01", 32)))->mask('jane@example.com', 'email', 'token'));
    }

    public function testTokenIsHmacOfClassAndNormalizedValue(): void
    {
        $key = str_repeat("\x01", 32);
        $expected = 'EMAIL_' . substr(hash_hmac('sha256', "email\0jane@example.com", $key), 0, 8);
        $this->assertSame($expected, $this->m->mask('jane@example.com', 'email', 'token'));
    }

    public function testTokenNormalization(): void
    {
        $t = fn (string $v, string $c) => $this->m->mask($v, $c, 'token');
        $this->assertSame($t('jane@example.com', 'email'), $t('  Jane@Example.COM ', 'email'));
        $this->assertSame($t('jdoe', 'username'), $t('JDOE', 'username'));
        $this->assertSame($t('+1 (415) 555-0132', 'phone'), $t('14155550132', 'phone'));
        $this->assertSame($t('Jane   Doe', 'person_name'), $t('jane doe', 'person_name'));
        $this->assertSame($t('42 Market  Street', 'street_address'), $t('42 market street', 'street_address'));
        // Other classes are only trimmed: case is significant.
        $this->assertNotSame($t('ABC', 'postal_code'), $t('abc', 'postal_code'));
        $this->assertSame($t(' 94103 ', 'postal_code'), $t('94103', 'postal_code'));
    }

    public function testTokenDiffersByClassAndByInstanceKey(): void
    {
        $email = $this->m->mask('jdoe', 'email', 'token');
        $user = $this->m->mask('jdoe', 'username', 'token');
        $this->assertNotSame(substr($email, -8), substr($user, -8));
        $other = (new Masker(str_repeat("\x02", 32)))->mask('jdoe', 'email', 'token');
        $this->assertNotSame($email, $other);
    }

    public function testTokenPrefixesFollowTheCatalog(): void
    {
        foreach (Catalog::classes() as $class) {
            if ($class['tier'] === Catalog::TIER_RESTRICTED) {
                continue;
            }
            $this->assertStringStartsWith($class['token'] . '_', $this->m->mask('value', $class['id'], 'token'));
        }
    }

    public function testRestrictedNeverGetsAToken(): void
    {
        foreach (Catalog::classesInTier(Catalog::TIER_RESTRICTED) as $class) {
            $id = is_array($class) ? $class['id'] : $class;
            $this->assertSame(self::g(8), $this->m->mask('123-45-6789', $id, 'token'), $id);
        }
    }

    // ------------------------------------------------------------------ span

    public function testSpanMasksOnlyPersonalData(): void
    {
        $out = $this->m->mask('Call Jane at 415-555-0132 or jane@example.com', 'free_text_pii', 'span');
        $this->assertSame('Call Jane at ' . self::g(6) . ' or ' . self::g(6), $out);
    }

    public static function spanCases(): array
    {
        return [
            'card' => ['Card 4111 1111 1111 1111 on file', true],
            'ssn' => ['SSN 123-45-6788 noted', true],
            'iban' => ['IBAN NL91ABNA0417164300 please', true],
            'iban spaced' => ['IBAN NL91 ABNA 0417 1643 00 please', true],
            'ipv4' => ['from 203.0.113.42 today', true],
            'jwt' => ['token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc', true],
            'aws key' => ['key AKIAIOSFODNN7EXAMPLE found', true],
            'uk phone' => ['ring 020 7946 0958 now', true],
            'intl phone' => ['ring +44 20 7946 0958 now', true],
            'order number' => ['Order 12345 shipped', false],
            'date' => ['Visited on 2026-10-29', false],
            'invalid card' => ['Ref 4111 1111 1111 1112', false],
            'money' => ['Paid $84,500 in 2025', false],
        ];
    }

    #[DataProvider('spanCases')]
    public function testSpanDetection(string $text, bool $masked): void
    {
        $out = $this->m->mask($text, 'free_text_pii', 'span');
        if ($masked) {
            $this->assertStringContainsString(self::g(6), $out, $text);
        } else {
            $this->assertSame($text, $out);
        }
    }

    public function testSpanPrivateKeyBodyIsHidden(): void
    {
        $pem = "notes:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0123456789abcdef\n-----END RSA PRIVATE KEY-----\nthanks";
        $out = $this->m->maskSpans($pem);
        $this->assertStringNotContainsString('MIIEow', $out);
        $this->assertStringStartsWith('notes:', $out);
        $this->assertStringEndsWith('thanks', $out);
        $truncated = $this->m->maskSpans("x -----BEGIN PRIVATE KEY-----\nMIIEowsecret");
        $this->assertStringNotContainsString('MIIEow', $truncated);
    }

    public function testSpanOnVeryLongText(): void
    {
        $text = str_repeat('Lorem ipsum dolor sit amet, 12 consectetur. ', 25000) . ' reach me at jane@example.com';
        $start = microtime(true);
        $out = $this->m->mask($text, 'free_text_pii', 'span');
        $this->assertLessThan(5.0, microtime(true) - $start);
        $this->assertStringNotContainsString('jane@example.com', $out);
        $this->assertStringStartsWith('Lorem ipsum', $out);
    }

    public function testSpanOnJsonValue(): void
    {
        $out = $this->m->mask(['note' => 'mail jane@example.com', 'n' => 3, 'tags' => ['x', '415-555-0132']], 'free_text_pii', 'span');
        $this->assertSame(['note' => 'mail ' . self::g(6), 'n' => 3, 'tags' => ['x', self::g(6)]], $out);
    }

    public function testSpanUnicodeText(): void
    {
        $out = $this->m->maskSpans("Gr\u{00FC}\u{00DF}e an J\u{00FC}rgen: j\u{00FC}rgen@example.com \u{2014} danke");
        // The local part is not ASCII, so only the ASCII tail can match; nothing ASCII-email remains.
        $this->assertStringNotContainsString('@example.com', $out);
        $this->assertStringStartsWith("Gr\u{00FC}\u{00DF}e an J\u{00FC}rgen:", $out);
    }

    // ------------------------------------------------------------------ idempotency

    public static function idempotencyCases(): array
    {
        return [
            ['123-45-6789', 'national_id', 'last4'],
            ['123-45-6789', 'national_id', 'redact'],
            ['Jane Doe', 'person_name', 'initial'],
            ['jane.doe@example.com', 'email', 'initial'],
            ['jane.doe@example.com', 'email', 'token'],
            ['1984-03-12T10:00:00Z', 'date_of_birth', 'year'],
            ['07/28', 'card_expiry', 'year'],
            ['Call 415-555-0132 or jane@example.com', 'free_text_pii', 'span'],
            ['NL91 ABNA 0417 1643 00', 'bank_account', 'last4'],
            ["\u{00D6}laf \u{00C5}ngstr\u{00F6}m", 'person_name', 'initial'],
            ['42', 'age', 'redact'],
        ];
    }

    #[DataProvider('idempotencyCases')]
    public function testMaskIsIdempotent(string $value, string $class, string $format): void
    {
        $once = $this->m->mask($value, $class, $format);
        $this->assertSame($once, $this->m->mask($once, $class, $format));
        $this->assertNotSame($value, $once);
    }

    #[DataProvider('idempotencyCases')]
    public function testIsMaskedRecognizesOwnOutput(string $value, string $class, string $format): void
    {
        $this->assertTrue($this->m->isMasked($this->m->mask($value, $class, $format), $class, $format));
        $this->assertFalse($this->m->isMasked($value, $class, $format));
    }

    public function testIsMasked(): void
    {
        $this->assertTrue($this->m->isMasked(self::g(8), 'national_id', 'redact'));
        $this->assertTrue($this->m->isMasked(null, 'email', 'null'));
        $this->assertFalse($this->m->isMasked(null, 'email', 'redact'));
        $this->assertFalse($this->m->isMasked('', 'email', 'redact'));
        $this->assertFalse($this->m->isMasked(42, 'age', 'redact'));
        // Format changed between read and write: a token is still recognized.
        $token = $this->m->mask('jane@example.com', 'email', 'token');
        $this->assertTrue($this->m->isMasked($token, 'email', 'redact'));
        // Another class's token is a real value for this class.
        $this->assertFalse($this->m->isMasked($token, 'username', 'token'));
        $this->assertFalse($this->m->isMasked('EMAIL_DEADBEEF', 'email', 'token'));
        // Free text: a bullet list is not a masked value, a run of glyphs is.
        $this->assertFalse($this->m->isMasked("Notes:\n\u{2022} one\n\u{2022} two", 'free_text_pii', 'span'));
        $this->assertTrue($this->m->isMasked('Call ' . self::g(6), 'free_text_pii', 'span'));
    }

    public function testRedactedHelper(): void
    {
        $this->assertSame(self::g(Masker::REDACT_RUN), Masker::redacted());
        $this->assertSame("\u{2022}", Masker::GLYPH);
    }
}

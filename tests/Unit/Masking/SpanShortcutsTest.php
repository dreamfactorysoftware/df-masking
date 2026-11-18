<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Tests\Unit\Masking;

use DreamFactory\Core\Masking\Masking\SpanDetector;
use PHPUnit\Framework\TestCase;

/**
 * SpanDetector skips a digit pattern when the text has fewer digits than
 * any match of it holds, and searches once before replacing. Both are shortcuts only: the result
 * must be exactly what running every pattern gives.
 */
final class SpanShortcutsTest extends TestCase
{
    /** A shortest match of each digit pattern: it holds exactly MIN_DIGITS digits. */
    private const SHORTEST = [
        'iban.mod97' => 'DE12 ABCD EFGH',
        'card.luhn_iin' => '4111 1111 1111 1',
        'ssn_us.dashed' => '123-45-6789',
        'nino_uk' => 'AB 12 34 56 C',
        'nir_fr' => '1 85 05 2A 123 456 78',
        'dni_es' => '12345678Z',
        'nie_es' => 'X1234567L',
        'phone.formatted' => '12 34',
        'ip.v4' => '1.2.3.4',
    ];

    private static function patterns(): array
    {
        $out = [];
        foreach ((new \ReflectionClassConstant(SpanDetector::class, 'SPANS'))->getValue() as [$id, $re, $prefilter]) {
            $out[$id] = [$re, $prefilter];
        }

        return $out;
    }

    public function testDigitMinimumsMatchThePatterns(): void
    {
        $patterns = self::patterns();
        foreach ($patterns as $id => [$re, $prefilter]) {
            if ($prefilter === 'digit') {
                $this->assertArrayHasKey($id, SpanDetector::MIN_DIGITS, "$id needs a digit minimum");
            }
        }
        foreach (SpanDetector::MIN_DIGITS as $id => $min) {
            $this->assertSame(1, preg_match($patterns[$id][0], self::SHORTEST[$id], $m), $id);
            $this->assertSame($min, preg_match_all('/\d/u', $m[0]), "$id: the minimum is reachable");
        }
        // No match ever holds fewer digits than its minimum (biased random texts, Unicode digits too).
        mt_srand(29102026);
        $alphabet = array_merge(str_split('0123456789012345678901234567890123456789'), str_split('ABCDEFXYZLT  --..()+/'), ["\u{0663}", "\u{FF15}"]);
        for ($i = 0; $i < 4000; $i++) {
            $text = '';
            for ($j = 0, $n = mt_rand(4, 40); $j < $n; $j++) {
                $text .= $alphabet[mt_rand(0, count($alphabet) - 1)];
            }
            foreach (SpanDetector::MIN_DIGITS as $id => $min) {
                preg_match_all($patterns[$id][0], $text, $all);
                foreach ($all[0] as $match) {
                    $this->assertGreaterThanOrEqual($min, preg_match_all('/\d/u', $match), "$id matched '$match'");
                }
            }
        }
    }

    /** replace() equals the plain loop (every pattern, no shortcut) on varied texts. */
    public function testShortcutsNeverChangeTheResult(): void
    {
        $texts = [
            'Call me at 415-555-0132 or mail jane.doe@example.com', 'SSN 123-45-6789, card 4111 1111 1111 1111.',
            'Order 12345 shipped', 'version 1.2.3.4', 'IP 10.0.0.1', 'no digits here at all', 'ref 7', 'NIE X1234567L DNI 12345678Z',
            'NINO AB 12 34 56 C', 'IBAN DE89 3704 0044 0532 0130 00', 'N° 1 85 05 78 006 084 36', "\u{0663}\u{0664}\u{0665}-\u{0664}\u{0665}-1234",
            'key AKIA' . str_repeat('A', 16) . ' end', '12 34', 'a 1 b 2 c 3', '+33 6 12 34 56 78',
        ];
        mt_srand(4242);
        for ($i = 0; $i < 300; $i++) {
            $t = '';
            for ($j = 0, $n = mt_rand(5, 60); $j < $n; $j++) {
                $t .= '0123456789 -.@abcXYZ'[mt_rand(0, 20)];
            }
            $texts[] = $t;
        }
        foreach ($texts as $text) {
            $this->assertSame($this->plain($text, '######'), SpanDetector::replace($text, '######'), $text);
        }
    }

    /** SpanDetector::replace() without the shortcuts (the reference). */
    private function plain(string $text, string $replacement): string
    {
        $out = $text;
        foreach ((new \ReflectionClassConstant(SpanDetector::class, 'SPANS'))->getValue() as [$id, $re]) {
            $out = preg_replace_callback($re, fn (array $m) => SpanDetector::validate($id, $m[0]) ? $replacement : $m[0], $out);
        }

        return $out;
    }
}

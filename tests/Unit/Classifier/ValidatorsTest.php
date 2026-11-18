<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Classifier;

use DreamFactory\Core\Masking\Classifier\Profiler;
use DreamFactory\Core\Masking\Classifier\Validators as V;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The classifier's pure validators against the shared vector file (ported from the prototype's
 * tests/validators.php; synthetic vectors only).
 */
final class ValidatorsTest extends TestCase
{
    private const TEST_CARDS = ['4111111111111111', '5555555555554444', '371449635398431', '6011000990139424'];

    public static function vectors(): iterable
    {
        $vec = json_decode((string) file_get_contents(__DIR__ . '/fixtures/validators.vectors.json'), true, 512, JSON_THROW_ON_ERROR);
        foreach ($vec as $name => $cases) {
            if ($name[0] === '_') {
                continue;
            }
            foreach ($cases as $i => [$in, $want]) {
                yield "$name #$i" => [$name, $in, $want];
            }
        }
    }

    #[DataProvider('vectors')]
    public function testVector(string $fn, string $input, mixed $want): void
    {
        $got = match ($fn) {
            'luhn' => V::luhn($input),
            'card_number' => V::cardNumber($input, ['test_cards' => self::TEST_CARDS]),
            'iban' => V::ibanMod97($input),
            'ssn_us' => V::ssnUs($input),
            'nir_fr' => V::nirFr($input),
            'dni_es' => V::dniEs($input),
            'nie_es' => V::nieEs($input),
            'bsn_nl' => V::bsnNl($input),
            'pesel_pl' => V::peselPl($input),
            'cpf_br' => V::cpfBr($input),
            'steuer_id_de' => V::steuerIdDe($input),
            'cf_it' => V::cfIt($input),
            'aadhaar' => V::aadhaar($input),
            'email' => V::email($input),
            'phone_structure' => V::phoneStructure($input),
            'phone_digits' => V::phoneDigits($input),
            'ipv4' => V::ipv4($input),
            'ipv6' => V::ipv6($input),
            'jwt' => V::jwtHeaderHasAlg($input),
            'secret_entropy' => V::secretEntropy($input, ['min_len' => 24, 'min_bits_per_char' => 3.5, 'min_char_classes' => 3]),
            'parse_date_year' => V::parseDate($input)['y'] ?? null,
            'shape' => Profiler::shape($input),
            default => $this->fail("no function for vector group $fn"),
        };
        $this->assertSame($want, $got, "$fn(" . json_encode($input) . ')');
    }

    /** Our email rules never accept what egulias (DreamFactory's validator) rejects. */
    public function testEmailParityWithEgulias(): void
    {
        if (!class_exists(\Egulias\EmailValidator\EmailValidator::class)) {
            $this->markTestSkipped('egulias/email-validator not installed');
        }
        $eg = new \Egulias\EmailValidator\EmailValidator();
        $re = '#^[A-Za-z0-9.!\#$%&\'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.[A-Za-z]{2,63}$#';
        foreach (['a.b@example.com', 'first.last+tag@sub.example.co.uk', 'x_y-z@ex-ample.io', "o'brien@example.ie"] as $e) {
            $ours = preg_match($re, $e) === 1 && V::email($e);
            if ($ours) {
                $this->assertTrue($eg->isValid($e, new \Egulias\EmailValidator\Validation\RFCValidation()), $e);
            }
        }
    }

    public function testRepeatedAndSequentialDigits(): void
    {
        $this->assertTrue(V::isRepeatedOrSequential('1111111'));
        $this->assertTrue(V::isRepeatedOrSequential('1234567890'));
        $this->assertTrue(V::isRepeatedOrSequential('9876543210'));
        $this->assertFalse(V::isRepeatedOrSequential('4155550132'));
    }
}

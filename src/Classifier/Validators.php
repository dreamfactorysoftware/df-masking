<?php
declare(strict_types=1);

namespace DreamFactory\Core\Masking\Classifier;

/**
 * Pure, side-effect-free validators. Every function is deterministic and covered by
 * tests/Unit/Classifier/fixtures/validators.vectors.json.
 */
final class Validators
{
    // ---------------------------------------------------------------- digits helpers
    public static function digitsOnly(string $v): string
    {
        return preg_replace('/\D+/', '', $v) ?? '';
    }

    public static function isRepeatedOrSequential(string $d): bool
    {
        $n = strlen($d);
        if ($n < 2) {
            return false;
        }
        if (count(array_unique(str_split($d))) <= 2) {
            return true;
        }
        $up = $down = true;
        for ($i = 1; $i < $n; $i++) {
            $diff = (ord($d[$i]) - ord($d[$i - 1]) + 10) % 10;
            $up = $up && $diff === 1;
            $down = $down && $diff === 9;
        }
        return $up || $down;
    }

    public static function luhn(string $d): bool
    {
        $n = strlen($d);
        if ($n === 0 || !ctype_digit($d)) {
            return false;
        }
        $sum = 0;
        $alt = false;
        for ($i = $n - 1; $i >= 0; $i--) {
            $x = ord($d[$i]) - 48;
            if ($alt) {
                $x *= 2;
                if ($x > 9) {
                    $x -= 9;
                }
            }
            $sum += $x;
            $alt = !$alt;
        }
        return $sum % 10 === 0;
    }

    /** Card brand by IIN and length; 15-digit numbers must be Amex (34/37), so IMEIs (TAC 35..) fail. */
    public static function iinBrand(string $d): ?string
    {
        $n = strlen($d);
        $p2 = (int) substr($d, 0, 2);
        $p3 = (int) substr($d, 0, 3);
        $p4 = (int) substr($d, 0, 4);
        $p6 = (int) substr($d, 0, 6);
        if ($n === 15) {
            return ($p2 === 34 || $p2 === 37) ? 'amex' : null;
        }
        if ($d[0] === '4' && in_array($n, [13, 16, 19], true)) {
            return 'visa';
        }
        if ((($p2 >= 51 && $p2 <= 55) || ($p4 >= 2221 && $p4 <= 2720)) && $n === 16) {
            return 'mastercard';
        }
        if ($p4 >= 2200 && $p4 <= 2204 && $n === 16) {
            return 'mir';
        }
        if (($p4 === 6011 || ($p3 >= 644 && $p3 <= 649) || $p2 === 65 || ($p6 >= 622126 && $p6 <= 622925)) && $n >= 16) {
            return 'discover';
        }
        if ($p4 >= 3528 && $p4 <= 3589 && $n >= 16) {
            return 'jcb';
        }
        if ((($p3 >= 300 && $p3 <= 305) || $p2 === 36 || $p2 === 38 || $p2 === 39) && $n >= 14) {
            return 'diners';
        }
        if ($p2 === 62 && $n >= 16) {
            return 'unionpay';
        }
        if (($p2 === 50 || ($p2 >= 56 && $p2 <= 69)) && $n >= 12) {
            return 'maestro';
        }
        return null;
    }

    /** @param array{test_cards?:list<string>} $p */
    public static function cardNumber(string $v, array $p = []): bool
    {
        $d = self::digitsOnly($v);
        $n = strlen($d);
        if ($n < 13 || $n > 19 || self::isRepeatedOrSequential($d)) {
            return false;
        }
        if (in_array($d, $p['test_cards'] ?? [], true)) {
            return false;
        }
        return self::luhn($d) && self::iinBrand($d) !== null;
    }

    public static function notRepeatedOrSequential(string $v): bool
    {
        return !self::isRepeatedOrSequential(self::digitsOnly($v));
    }

    // ---------------------------------------------------------------- bank
    private const IBAN_LEN = ['AD' => 24, 'AE' => 23, 'AL' => 28, 'AT' => 20, 'AZ' => 28, 'BA' => 20, 'BE' => 16, 'BG' => 22, 'BH' => 22, 'BI' => 27, 'BR' => 29, 'BY' => 28, 'CH' => 21, 'CR' => 22, 'CY' => 28, 'CZ' => 24, 'DE' => 22, 'DJ' => 27, 'DK' => 18, 'DO' => 28, 'EE' => 20, 'EG' => 29, 'ES' => 24, 'FI' => 18, 'FK' => 18, 'FO' => 18, 'FR' => 27, 'GB' => 22, 'GE' => 22, 'GI' => 23, 'GL' => 18, 'GR' => 27, 'GT' => 28, 'HN' => 28, 'HR' => 21, 'HU' => 28, 'IE' => 22, 'IL' => 23, 'IQ' => 23, 'IS' => 26, 'IT' => 27, 'JO' => 30, 'KW' => 30, 'KZ' => 20, 'LB' => 28, 'LC' => 32, 'LI' => 21, 'LT' => 20, 'LU' => 20, 'LV' => 21, 'LY' => 25, 'MC' => 27, 'MD' => 24, 'ME' => 22, 'MK' => 19, 'MN' => 20, 'MR' => 27, 'MT' => 31, 'MU' => 30, 'NI' => 28, 'NL' => 18, 'NO' => 15, 'OM' => 23, 'PK' => 24, 'PL' => 28, 'PS' => 29, 'PT' => 25, 'QA' => 29, 'RO' => 24, 'RS' => 22, 'RU' => 33, 'SA' => 24, 'SC' => 31, 'SD' => 18, 'SE' => 24, 'SI' => 19, 'SK' => 24, 'SM' => 27, 'SO' => 23, 'ST' => 25, 'SV' => 28, 'TL' => 23, 'TN' => 24, 'TR' => 26, 'UA' => 29, 'VA' => 22, 'VG' => 24, 'XK' => 20, 'YE' => 30];

    public static function ibanMod97(string $v): bool
    {
        $s = strtoupper(str_replace([' ', '-'], '', $v));
        if (!preg_match('/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/', $s)) {
            return false;
        }
        $len = self::IBAN_LEN[substr($s, 0, 2)] ?? null;
        if ($len === null || strlen($s) !== $len) {
            return false;
        }
        $r = substr($s, 4) . substr($s, 0, 4);
        $num = '';
        foreach (str_split($r) as $ch) {
            $num .= ctype_alpha($ch) ? (string) (ord($ch) - 55) : $ch;
        }
        $rem = 0;
        foreach (str_split($num, 7) as $chunk) {
            $rem = (int) ($rem . $chunk) % 97;
        }
        return $rem === 1;
    }

    // ---------------------------------------------------------------- national ids
    private const SSN_DENY = ['078051120', '219099999', '123456789'];

    public static function ssnUs(string $v): bool
    {
        $d = self::digitsOnly($v);
        if (strlen($d) !== 9) {
            return false;
        }
        $area = (int) substr($d, 0, 3);
        $group = (int) substr($d, 3, 2);
        $serial = (int) substr($d, 5);
        if ($area === 0 || $area === 666 || $area >= 900 || $group === 0 || $serial === 0) {
            return false;
        }
        if (in_array($d, self::SSN_DENY, true) || count(array_unique(str_split($d))) === 1) {
            return false;
        }
        return !(substr($d, 0, 5) === '98765' && $d[5] === '4' && $d[6] === '3' && $d[7] === '2');
    }

    public static function nirFr(string $v): bool
    {
        $s = strtoupper(str_replace(' ', '', $v));
        if (!preg_match('/^([1-478]\d{4})(\d{2}|2[AB])(\d{6})(\d{2})$/', $s, $m)) {
            return false;
        }
        $dept = $m[2] === '2A' ? '19' : ($m[2] === '2B' ? '18' : $m[2]);
        $n = (int) ($m[1] . $dept . $m[3]);
        return 97 - ($n % 97) === (int) $m[4];
    }

    private const DNI_LETTERS = 'TRWAGMYFPDXBNJZSQVHLCKE';

    public static function dniEs(string $v): bool
    {
        $s = strtoupper(str_replace(['-', ' '], '', $v));
        return (bool) preg_match('/^(\d{8})([A-Z])$/', $s, $m) && self::DNI_LETTERS[(int) $m[1] % 23] === $m[2];
    }

    public static function nieEs(string $v): bool
    {
        $s = strtoupper(str_replace(['-', ' '], '', $v));
        if (!preg_match('/^([XYZ])(\d{7})([A-Z])$/', $s, $m)) {
            return false;
        }
        $n = (int) (strpos('XYZ', $m[1]) . $m[2]);
        return self::DNI_LETTERS[$n % 23] === $m[3];
    }

    public static function bsnNl(string $v): bool
    {
        $d = self::digitsOnly($v);
        if (strlen($d) !== 9 || $d === '000000000') {
            return false;
        }
        $sum = 0;
        for ($i = 0; $i < 8; $i++) {
            $sum += (9 - $i) * (int) $d[$i];
        }
        $sum -= (int) $d[8];
        return $sum % 11 === 0;
    }

    public static function peselPl(string $v): bool
    {
        if (!preg_match('/^\d{11}$/', $v)) {
            return false;
        }
        $w = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
        $sum = 0;
        for ($i = 0; $i < 10; $i++) {
            $sum += $w[$i] * (int) $v[$i];
        }
        if ((10 - $sum % 10) % 10 !== (int) $v[10]) {
            return false;
        }
        $mm = (int) substr($v, 2, 2) % 20;
        $dd = (int) substr($v, 4, 2);
        return $mm >= 1 && $mm <= 12 && $dd >= 1 && $dd <= 31 && !self::isRepeatedOrSequential($v);
    }

    public static function pnrSe(string $v): bool
    {
        $d = self::digitsOnly($v);
        if (strlen($d) === 12) {
            $d = substr($d, 2);
        }
        if (strlen($d) !== 10) {
            return false;
        }
        $mm = (int) substr($d, 2, 2);
        $dd = (int) substr($d, 4, 2);
        if ($dd > 60) {
            $dd -= 60; // coordination number
        }
        return $mm >= 1 && $mm <= 12 && $dd >= 1 && $dd <= 31 && self::luhn($d);
    }

    private const VERHOEFF_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1], [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]];
    private const VERHOEFF_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1], [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]];

    public static function verhoeff(string $d): bool
    {
        if ($d === '' || !ctype_digit($d)) {
            return false;
        }
        $c = 0;
        $r = strrev($d);
        for ($i = 0, $n = strlen($r); $i < $n; $i++) {
            $c = self::VERHOEFF_D[$c][self::VERHOEFF_P[$i % 8][(int) $r[$i]]];
        }
        return $c === 0;
    }

    public static function aadhaar(string $v): bool
    {
        $d = self::digitsOnly($v);
        return strlen($d) === 12 && $d[0] >= '2' && !self::isRepeatedOrSequential($d) && self::verhoeff($d);
    }

    // ---------------------------------------------------------------- tax ids
    public static function cpfBr(string $v): bool
    {
        $d = self::digitsOnly($v);
        if (strlen($d) !== 11 || count(array_unique(str_split($d))) === 1) {
            return false;
        }
        for ($t = 9; $t < 11; $t++) {
            $sum = 0;
            for ($i = 0; $i < $t; $i++) {
                $sum += (int) $d[$i] * ($t + 1 - $i);
            }
            if ((($sum * 10) % 11) % 10 !== (int) $d[$t]) {
                return false;
            }
        }
        return true;
    }

    public static function steuerIdDe(string $v): bool
    {
        $d = self::digitsOnly($v);
        if (!preg_match('/^[1-9]\d{10}$/', $d)) {
            return false;
        }
        $counts = array_count_values(str_split(substr($d, 0, 10)));
        $multi = array_filter($counts, static fn ($c) => $c > 1);
        if (count($multi) !== 1 || max($multi) > 3) {
            return false;
        }
        $product = 10;
        for ($i = 0; $i < 10; $i++) {
            $sum = ((int) $d[$i] + $product) % 10;
            if ($sum === 0) {
                $sum = 10;
            }
            $product = ($sum * 2) % 11;
        }
        $check = 11 - $product;
        if ($check === 10) {
            $check = 0;
        }
        return $check === (int) $d[10];
    }

    private const CF_ODD = ['0' => 1, '1' => 0, '2' => 5, '3' => 7, '4' => 9, '5' => 13, '6' => 15, '7' => 17, '8' => 19, '9' => 21, 'A' => 1, 'B' => 0, 'C' => 5, 'D' => 7, 'E' => 9, 'F' => 13, 'G' => 15, 'H' => 17, 'I' => 19, 'J' => 21, 'K' => 2, 'L' => 4, 'M' => 18, 'N' => 20, 'O' => 11, 'P' => 3, 'Q' => 6, 'R' => 8, 'S' => 12, 'T' => 14, 'U' => 16, 'V' => 10, 'W' => 22, 'X' => 25, 'Y' => 24, 'Z' => 23];

    public static function cfIt(string $v): bool
    {
        $s = strtoupper(str_replace(' ', '', $v));
        if (!preg_match('/^[A-Z0-9]{15}[A-Z]$/', $s)) {
            return false;
        }
        $sum = 0;
        for ($i = 0; $i < 15; $i++) {
            $ch = $s[$i];
            $sum += ($i % 2 === 0) ? self::CF_ODD[$ch] : (ctype_digit($ch) ? (int) $ch : ord($ch) - 65);
        }
        return chr(65 + $sum % 26) === $s[15];
    }

    // ---------------------------------------------------------------- contact
    public static function email(string $v): bool
    {
        if (strlen($v) > 254) {
            return false;
        }
        $at = strrpos($v, '@');
        if ($at === false) {
            return false;
        }
        $local = substr($v, 0, $at);
        return $local !== '' && $local[0] !== '.' && !str_ends_with($local, '.') && !str_contains($local, '..');
    }

    private const CC1 = ['1', '7'];
    private const CC2 = ['20', '27', '30', '31', '32', '33', '34', '36', '39', '40', '41', '43', '44', '45', '46', '47', '48', '49', '51', '52', '53', '54', '55', '56', '57', '58', '60', '61', '62', '63', '64', '65', '66', '81', '82', '84', '86', '90', '91', '92', '93', '94', '95', '98'];
    private const CC3_PREFIX = ['21', '22', '23', '24', '25', '26', '29', '35', '37', '38', '42', '50', '59', '67', '68', '69', '85', '87', '88', '96', '97', '99'];

    public static function countryCodeLen(string $d): int
    {
        if (in_array($d[0] ?? '', self::CC1, true)) {
            return 1;
        }
        if (in_array(substr($d, 0, 2), self::CC2, true)) {
            return 2;
        }
        if (in_array(substr($d, 0, 2), self::CC3_PREFIX, true)) {
            return 3;
        }
        return 0;
    }

    /** True if $v reads as a calendar date (rejects dd.mm.yyyy-style "phones"). */
    private static function looksLikeDate(string $v): bool
    {
        if (preg_match('/^(\d{4})[-.\/ ](\d{1,2})[-.\/ ](\d{1,2})$/', $v, $m)) {
            return (int) $m[2] >= 1 && (int) $m[2] <= 12 && (int) $m[3] >= 1 && (int) $m[3] <= 31;
        }
        if (preg_match('/^(\d{1,2})[-.\/ ](\d{1,2})[-.\/ ](\d{2}|\d{4})$/', $v, $m)) {
            $a = (int) $m[1];
            $b = (int) $m[2];
            return ($a >= 1 && $a <= 31 && $b >= 1 && $b <= 12) || ($b >= 1 && $b <= 31 && $a >= 1 && $a <= 12);
        }
        return false;
    }

    /** Formatted phone: separators or a leading +/00 are required; bare digits belong to phone.digits. */
    public static function phoneStructure(string $v): bool
    {
        $v = trim($v);
        if ($v === '' || !preg_match('/^[0-9+() .\-]+$/', $v)) {
            return false;
        }
        $d = self::digitsOnly($v);
        $n = strlen($d);
        if ($n < 7 || $n > 15 || self::isRepeatedOrSequential($d)) {
            return false;
        }
        if (self::looksLikeDate($v) || preg_match('/^\d{1,3}(\.\d{1,3}){3}$/', $v) || preg_match('/^\d+\.\d+$/', $v) || preg_match('/^\d{3}-\d{2}-\d{4}$/', $v)) {
            return false;
        }
        if (substr_count($v, '+') > 1 || (str_contains($v, '+') && $v[0] !== '+')) {
            return false;
        }
        if ($v[0] === '+' || (str_starts_with($v, '00') && preg_match('/^00\d{1,3}[ .\-(]/', $v))) {
            $cc = $v[0] === '+' ? $d : substr($d, 2);
            $ccl = self::countryCodeLen($cc);
            $national = strlen($cc) - $ccl;
            return $ccl > 0 && $national >= 6 && $national <= 14;
        }
        if (!preg_match('/[ ().\-]/', $v)) {
            return false;
        }
        $groups = preg_split('/[ ().\-]+/', trim($v, ' ().-'), -1, PREG_SPLIT_NO_EMPTY) ?: [];
        $k = count($groups);
        if ($k < 2) {
            return false;
        }
        $lens = array_map('strlen', $groups);
        // NANP: (415) 555-0132, 415-555-0132, 1-415-555-0132, 555-0132
        $d10 = ($n === 11 && $d[0] === '1') ? substr($d, 1) : $d;
        $nanpShaped = array_slice($lens, -3) === [3, 3, 4] && ($k === 3 || ($k === 4 && $lens[0] === 1));
        if (strlen($d10) === 10 && preg_match('/^[2-9]\d{2}[2-9]\d{6}$/', $d10)) {
            if ($nanpShaped || array_slice($lens, -2) === [3, 7]) {
                return true;
            }
        }
        if ($nanpShaped) {
            return false; // US-shaped grouping that fails the NANP area/exchange rules
        }
        if ($n === 7 && $lens === [3, 4] && $d[0] >= '2') {
            return true;
        }
        // Trunk-prefixed national numbers (EU/UK/AU/...): 020 7946 0958, 06-12345678, 01 23 45 67 89
        if ($d[0] === '0' && $n >= 9 && $n <= 12 && min($lens) >= 2 && max($lens) <= 8) {
            return true;
        }
        // Grouped subscriber numbers: 12 34 56 78, 345 678 9012 (3+ groups of 2-4 digits)
        return $k >= 3 && $n >= 8 && $n <= 12 && min($lens) >= 2 && max($lens) <= 4;
    }

    public static function phoneDigits(string $v): bool
    {
        if (!preg_match('/^\+?(\d{7,15})$/', $v, $m)) {
            return false;
        }
        $d = $m[1];
        if (self::isRepeatedOrSequential($d)) {
            return false;
        }
        if (strlen($d) === 8 && preg_match('/^(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])$/', $d)) {
            return false; // plausible Ymd date
        }
        return true;
    }

    public static function ipv4(string $v): bool
    {
        return filter_var($v, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }

    public static function ipv6(string $v): bool
    {
        return str_contains($v, ':') && filter_var($v, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    }

    // ---------------------------------------------------------------- secrets
    public static function jwtHeaderHasAlg(string $v): bool
    {
        $seg = explode('.', $v)[0];
        $b = base64_decode(strtr($seg, '-_', '+/') . str_repeat('=', (4 - strlen($seg) % 4) % 4), true);
        if ($b === false) {
            return false;
        }
        $h = json_decode($b, true);
        return is_array($h) && isset($h['alg']) && is_string($h['alg']);
    }

    public static function isUuid(string $v): bool
    {
        return (bool) preg_match('/^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$/', $v);
    }

    /** Shannon entropy in bits/char; counts summed in sorted-character order for cross-language parity. */
    public static function entropyBits(string $v): float
    {
        $n = strlen($v);
        if ($n === 0) {
            return 0.0;
        }
        $counts = count_chars($v, 1);
        ksort($counts);
        $h = 0.0;
        foreach ($counts as $c) {
            $p = $c / $n;
            $h -= $p * log($p, 2);
        }
        return $h;
    }

    /** @param array{min_len?:int,min_bits_per_char?:float,min_char_classes?:int} $p */
    public static function secretEntropy(string $v, array $p = []): bool
    {
        if (strlen($v) < ($p['min_len'] ?? 24) || preg_match('/\s/', $v) || self::isUuid($v)) {
            return false;
        }
        $classes = (int) preg_match('/[a-z]/', $v) + (int) preg_match('/[A-Z]/', $v) + (int) preg_match('/\d/', $v) + (int) preg_match('/[^A-Za-z0-9]/', $v);
        return $classes >= ($p['min_char_classes'] ?? 3) && self::entropyBits($v) >= ($p['min_bits_per_char'] ?? 3.5);
    }

    // ---------------------------------------------------------------- misc
    public static function geoRange(string $v): bool
    {
        return is_numeric($v) && abs((float) $v) <= 180.0;
    }

    /** @param array{min?:int,max?:int} $p */
    public static function intRange(string $v, array $p = []): bool
    {
        return preg_match('/^\d+$/', $v) === 1 && (int) $v >= ($p['min'] ?? 0) && (int) $v <= ($p['max'] ?? PHP_INT_MAX);
    }

    private const MONTHS = ['jan' => 1, 'feb' => 2, 'mar' => 3, 'apr' => 4, 'may' => 5, 'jun' => 6, 'jul' => 7, 'aug' => 8, 'sep' => 9, 'oct' => 10, 'nov' => 11, 'dec' => 12];

    /**
     * Lenient date parser: only the year must be exact (m/d vs d/m ambiguity is irrelevant
     * for DOB plausibility). Bare years are NOT dates.
     * @return ?array{y:int,m:int,d:int,time:bool,midnight:bool}
     */
    public static function parseDate(string $v): ?array
    {
        $v = trim($v);
        $len = strlen($v);
        if ($len < 8 || $len > 40 || !ctype_digit($v[0]) && !ctype_alpha($v[0]) || strpbrk($v, '0123456789') === false) {
            return null;
        }
        $time = false;
        $midnight = true;
        if (preg_match('/^(.+?)[ T](\d{1,2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?\s*(?:Z|[+-]\d{2}(?::?\d{2})?|[AaPp][Mm])?$/', $v, $tm)) {
            $v = $tm[1];
            $time = true;
            $midnight = ((int) $tm[2] === 0 && (int) $tm[3] === 0 && (int) ($tm[4] ?? 0) === 0);
        }
        $y = $m = $d = 0;
        if (preg_match('/^(\d{4})[-\/.](\d{1,2})[-\/.](\d{1,2})$/', $v, $x)) {
            [$y, $m, $d] = [(int) $x[1], (int) $x[2], (int) $x[3]];
        } elseif (preg_match('/^(\d{1,2})[-\/.](\d{1,2})[-\/.](\d{4})$/', $v, $x)) {
            [$a, $b, $y] = [(int) $x[1], (int) $x[2], (int) $x[3]];
            if ($a <= 12) {
                [$m, $d] = [$a, $b];
            } else {
                [$m, $d] = [$b, $a];
            }
        } elseif (preg_match('/^(\d{4})(\d{2})(\d{2})$/', $v, $x)) {
            [$y, $m, $d] = [(int) $x[1], (int) $x[2], (int) $x[3]];
        } elseif (preg_match('/^(\d{1,2})[ -]([A-Za-z]{3})[a-z]*\.?[ -,]+(\d{4})$/', $v, $x) && isset(self::MONTHS[strtolower($x[2])])) {
            [$d, $m, $y] = [(int) $x[1], self::MONTHS[strtolower($x[2])], (int) $x[3]];
        } elseif (preg_match('/^([A-Za-z]{3})[a-z]*\.? (\d{1,2}),? (\d{4})$/', $v, $x) && isset(self::MONTHS[strtolower($x[1])])) {
            [$m, $d, $y] = [self::MONTHS[strtolower($x[1])], (int) $x[2], (int) $x[3]];
        } else {
            return null;
        }
        if ($y < 1800 || $y > 2200 || $m < 1 || $m > 12 || $d < 1 || $d > 31) {
            return null;
        }
        return ['y' => $y, 'm' => $m, 'd' => $d, 'time' => $time, 'midnight' => $midnight];
    }
}

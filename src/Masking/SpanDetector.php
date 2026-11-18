<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Masking;

/**
 * Finds personal-data spans inside free text (the `span` mask format).
 *
 * The find patterns and checksum/structure validators are the classifier's free-text span
 * detectors (rule pack class free_text_pii: email, payment card, US SSN, IBAN, UK NINO, FR NIR,
 * ES DNI/NIE, phone, IPv4, JWT, private key, provider API keys), ported verbatim so a span the
 * scanner counted as evidence is exactly a span the masker hides. Candidates are confirmed by
 * their validator (Luhn + issuer range, IBAN mod-97, SSN area/group/serial rules, ...), which is
 * what keeps order numbers, dates and version strings readable.
 *
 * One deliberate difference from classification: classification ignores well-known test card
 * numbers (so demo data does not trigger a verdict); masking hides them too, because hiding a
 * test number costs nothing and a "test" number may be a real one.
 *
 * Pure and deterministic. Names inside free text are out of scope (see README "Limits").
 */
final class SpanDetector
{
    /**
     * [detector id, find regex, cheap prefilter]. Order matters: longer/more specific spans first,
     * so a card number is not half-eaten by the phone pattern, and replaced spans (mask glyphs)
     * can never match a later pattern.
     */
    private const SPANS = [
        // The whole PEM block (header, body, footer); a block without a footer is hidden to the end.
        ['cred.private_key', '/-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----(?:[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|[\s\S]*)/u', '-----BEGIN '],
        ['cred.jwt', '/\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/u', 'eyJ'],
        ['cred.provider_key', '/(?<![A-Za-z0-9_-])(?:(?:AKIA|ASIA)[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|xox[bpas]-[A-Za-z0-9-]{10,}|[sr]k_(?:live|test)_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{35}|sk-ant-[A-Za-z0-9_-]{20,}|glpat-[A-Za-z0-9_-]{20,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})(?![A-Za-z0-9_-])/u', null],
        ['email.syntax', "/(?<![A-Za-z0-9.!#$%&'*+\\/=?^_`{|}~-])[A-Za-z0-9.!#$%&'*+\\/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\\.[A-Za-z]{2,63}(?![A-Za-z0-9-])/u", '@'],
        ['iban.mod97', '/\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b/u', 'digit'],
        ['card.luhn_iin', '/(?<![0-9])\d(?:[ -]?\d){12,18}(?![0-9])/u', 'digit'],
        ['ssn_us.dashed', '/(?<![0-9-])(?!000|666|9\d\d)\d{3}([- ])(?!00)\d{2}\1(?!0000)\d{4}(?![0-9-])/u', 'digit'],
        ['nino_uk', '/\b(?!BG|GB|KN|NK|NT|TN|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b/u', 'digit'],
        ['nir_fr', '/\b[1-478] ?\d{2} ?(?:0[1-9]|1[0-2]|20|3\d|4[0-2]|[5-9]\d) ?(?:\d{2}|2[AB]) ?\d{3} ?\d{3} ?\d{2}\b/u', 'digit'],
        ['dni_es', '/\b\d{8}-?[TRWAGMYFPDXBNJZSQVHLCKE]\b/u', 'digit'],
        ['nie_es', '/\b[XYZ]-?\d{7}-?[TRWAGMYFPDXBNJZSQVHLCKE]\b/u', 'digit'],
        ['phone.formatted', '/(?<![\w.+\/-])(?:(?:\+|00)\d{1,3}[ .-]?)?(?:\(\d{1,4}\)[ .-]?)?\d{2,5}(?:[ .-]\d{2,5}){1,4}(?![\w\/-])/u', 'digit'],
        ['ip.v4', '/(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])/u', 'digit'],
    ];

    private const PROVIDER_PREFIXES = ['AKIA', 'ASIA', 'gh', 'github_pat_', 'xox', 'sk_', 'rk_', 'AIza', 'sk-', 'glpat-', 'SG.'];

    /**
     * Fewest digits (\d, as the patterns count them) a match of each digit pattern contains: a
     * text with fewer digits cannot hold that span, so the pattern is not run (performance only;
     * see SpanDetectorTest::testDigitMinimumsMatchThePatterns).
     */
    public const MIN_DIGITS = [
        'iban.mod97' => 2, 'card.luhn_iin' => 13, 'ssn_us.dashed' => 9, 'nino_uk' => 6, 'nir_fr' => 14,
        'dni_es' => 8, 'nie_es' => 7, 'phone.formatted' => 4, 'ip.v4' => 4,
    ];

    private function __construct()
    {
    }

    /**
     * Replace every validated span in $text with $replacement.
     *
     * @return string|null the text with spans replaced, or null when a pattern could not be
     *                     evaluated (invalid UTF-8, PCRE limits): callers must then fail closed
     */
    public static function replace(string $text, string $replacement): ?string
    {
        if ($text === '') {
            return '';
        }
        if (!mb_check_encoding($text, 'UTF-8')) {
            return null;
        }
        $hasDigit = strpbrk($text, '0123456789') !== false;
        // Digits as the patterns' \d counts them (Unicode digits too: /u implies UCP in PHP).
        $digits = $hasDigit ? preg_match_all('/\d/u', $text) : 0;
        if ($digits === false) {
            return null;
        }
        $out = $text;
        foreach (self::SPANS as [$id, $re, $prefilter]) {
            if ($prefilter === 'digit') {
                if (!$hasDigit || $digits < (self::MIN_DIGITS[$id] ?? 0)) {
                    continue;
                }
            } elseif ($prefilter !== null && !str_contains($out, $prefilter)) {
                continue;
            } elseif ($prefilter === null && $id === 'cred.provider_key' && !self::hasProviderPrefix($out)) {
                continue;
            }
            // Most texts hold no candidate: one cheap search before the replacing pass.
            $found = preg_match($re, $out);
            if ($found === false) {
                return null;
            }
            if ($found === 0) {
                continue;
            }
            $next = preg_replace_callback($re, static function (array $m) use ($id, $replacement): string {
                return self::validate($id, $m[0]) ? $replacement : $m[0];
            }, $out);
            if ($next === null) {
                return null;
            }
            $out = $next;
        }

        return $out;
    }

    /** Detector ids that validate somewhere in $text (tests and diagnostics). */
    public static function detect(string $text): array
    {
        $found = [];
        if ($text === '' || !mb_check_encoding($text, 'UTF-8')) {
            return $found;
        }
        foreach (self::SPANS as [$id, $re]) {
            if (preg_match_all($re, $text, $m) > 0) {
                foreach ($m[0] as $candidate) {
                    if (self::validate($id, $candidate)) {
                        $found[] = $id;
                        break;
                    }
                }
            }
        }

        return $found;
    }

    public static function validate(string $id, string $candidate): bool
    {
        return match ($id) {
            'cred.private_key' => true,
            'cred.jwt' => self::jwtHeaderHasAlg($candidate),
            'cred.provider_key' => true,
            'email.syntax' => self::email($candidate),
            'iban.mod97' => self::ibanMod97(strtoupper(str_replace(' ', '', $candidate))),
            'card.luhn_iin' => self::cardNumber(str_replace(['-', ' '], '', $candidate)),
            'ssn_us.dashed' => self::ssnUs($candidate),
            'nino_uk' => (bool)preg_match('/^(?!BG|GB|KN|NK|NT|TN|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]$/', strtoupper(str_replace(' ', '', $candidate))),
            'nir_fr' => self::nirFr($candidate),
            'dni_es' => self::dniEs($candidate),
            'nie_es' => self::nieEs($candidate),
            'phone.formatted' => self::phoneStructure($candidate),
            'ip.v4' => filter_var($candidate, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false,
            default => false,
        };
    }

    // ---------------------------------------------------------------------------- validators

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

    /** Card brand by IIN and length; 15-digit numbers must be Amex (34/37). */
    public static function iinBrand(string $d): ?string
    {
        $n = strlen($d);
        if ($n < 12) {
            return null;
        }
        $p2 = (int)substr($d, 0, 2);
        $p3 = (int)substr($d, 0, 3);
        $p4 = (int)substr($d, 0, 4);
        $p6 = (int)substr($d, 0, 6);
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

    /**
     * Luhn + issuer range. Unlike classification, repeated-digit numbers are not exempt: test
     * cards such as 4111 1111 1111 1111 are hidden too (masking errs on the side of hiding).
     */
    public static function cardNumber(string $d): bool
    {
        $n = strlen($d);
        if ($n < 13 || $n > 19 || !ctype_digit($d)) {
            return false;
        }

        return self::luhn($d) && self::iinBrand($d) !== null;
    }

    private const IBAN_LEN = ['AD' => 24, 'AE' => 23, 'AL' => 28, 'AT' => 20, 'AZ' => 28, 'BA' => 20, 'BE' => 16, 'BG' => 22, 'BH' => 22, 'BI' => 27, 'BR' => 29, 'BY' => 28, 'CH' => 21, 'CR' => 22, 'CY' => 28, 'CZ' => 24, 'DE' => 22, 'DJ' => 27, 'DK' => 18, 'DO' => 28, 'EE' => 20, 'EG' => 29, 'ES' => 24, 'FI' => 18, 'FK' => 18, 'FO' => 18, 'FR' => 27, 'GB' => 22, 'GE' => 22, 'GI' => 23, 'GL' => 18, 'GR' => 27, 'GT' => 28, 'HN' => 28, 'HR' => 21, 'HU' => 28, 'IE' => 22, 'IL' => 23, 'IQ' => 23, 'IS' => 26, 'IT' => 27, 'JO' => 30, 'KW' => 30, 'KZ' => 20, 'LB' => 28, 'LC' => 32, 'LI' => 21, 'LT' => 20, 'LU' => 20, 'LV' => 21, 'LY' => 25, 'MC' => 27, 'MD' => 24, 'ME' => 22, 'MK' => 19, 'MN' => 20, 'MR' => 27, 'MT' => 31, 'MU' => 30, 'NI' => 28, 'NL' => 18, 'NO' => 15, 'OM' => 23, 'PK' => 24, 'PL' => 28, 'PS' => 29, 'PT' => 25, 'QA' => 29, 'RO' => 24, 'RS' => 22, 'RU' => 33, 'SA' => 24, 'SC' => 31, 'SD' => 18, 'SE' => 24, 'SI' => 19, 'SK' => 24, 'SM' => 27, 'SO' => 23, 'ST' => 25, 'SV' => 28, 'TL' => 23, 'TN' => 24, 'TR' => 26, 'UA' => 29, 'VA' => 22, 'VG' => 24, 'XK' => 20, 'YE' => 30];

    public static function ibanMod97(string $s): bool
    {
        $s = strtoupper(str_replace([' ', '-'], '', $s));
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
            $num .= ctype_alpha($ch) ? (string)(ord($ch) - 55) : $ch;
        }
        $rem = 0;
        foreach (str_split($num, 7) as $chunk) {
            $rem = (int)($rem . $chunk) % 97;
        }

        return $rem === 1;
    }

    private const SSN_DENY = ['078051120', '219099999', '123456789'];

    public static function ssnUs(string $v): bool
    {
        $d = self::digitsOnly($v);
        if (strlen($d) !== 9) {
            return false;
        }
        $area = (int)substr($d, 0, 3);
        $group = (int)substr($d, 3, 2);
        $serial = (int)substr($d, 5);
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
        $n = (int)($m[1] . $dept . $m[3]);

        return 97 - ($n % 97) === (int)$m[4];
    }

    private const DNI_LETTERS = 'TRWAGMYFPDXBNJZSQVHLCKE';

    public static function dniEs(string $v): bool
    {
        $s = strtoupper(str_replace(['-', ' '], '', $v));

        return (bool)preg_match('/^(\d{8})([A-Z])$/', $s, $m) && self::DNI_LETTERS[(int)$m[1] % 23] === $m[2];
    }

    public static function nieEs(string $v): bool
    {
        $s = strtoupper(str_replace(['-', ' '], '', $v));
        if (!preg_match('/^([XYZ])(\d{7})([A-Z])$/', $s, $m)) {
            return false;
        }
        $n = (int)(strpos('XYZ', $m[1]) . $m[2]);

        return self::DNI_LETTERS[$n % 23] === $m[3];
    }

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

    private static function countryCodeLen(string $d): int
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

    private static function looksLikeDate(string $v): bool
    {
        if (preg_match('/^(\d{4})[-.\/ ](\d{1,2})[-.\/ ](\d{1,2})$/', $v, $m)) {
            return (int)$m[2] >= 1 && (int)$m[2] <= 12 && (int)$m[3] >= 1 && (int)$m[3] <= 31;
        }
        if (preg_match('/^(\d{1,2})[-.\/ ](\d{1,2})[-.\/ ](\d{2}|\d{4})$/', $v, $m)) {
            $a = (int)$m[1];
            $b = (int)$m[2];

            return ($a >= 1 && $a <= 31 && $b >= 1 && $b <= 12) || ($b >= 1 && $b <= 31 && $a >= 1 && $a <= 12);
        }

        return false;
    }

    /** Formatted phone number: separators or a leading +/00 are required. */
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
        $d10 = ($n === 11 && $d[0] === '1') ? substr($d, 1) : $d;
        $nanpShaped = array_slice($lens, -3) === [3, 3, 4] && ($k === 3 || ($k === 4 && $lens[0] === 1));
        if (strlen($d10) === 10 && preg_match('/^[2-9]\d{2}[2-9]\d{6}$/', $d10)) {
            if ($nanpShaped || array_slice($lens, -2) === [3, 7]) {
                return true;
            }
        }
        if ($nanpShaped) {
            return false;
        }
        if ($n === 7 && $lens === [3, 4] && $d[0] >= '2') {
            return true;
        }
        if ($d[0] === '0' && $n >= 9 && $n <= 12 && min($lens) >= 2 && max($lens) <= 8) {
            return true;
        }

        return $k >= 3 && $n >= 8 && $n <= 12 && min($lens) >= 2 && max($lens) <= 4;
    }

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

    private static function hasProviderPrefix(string $text): bool
    {
        foreach (self::PROVIDER_PREFIXES as $prefix) {
            if (str_contains($text, $prefix)) {
                return true;
            }
        }

        return false;
    }
}

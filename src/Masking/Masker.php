<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Masking;

use DreamFactory\Core\Masking\Support\Catalog;
use DreamFactory\Core\Masking\Support\Settings;

/**
 * Turns a real value into its masked form for a class and mask format.
 *
 * Formats:
 *  - redact   "••••••••" (fixed length: hides the length too)
 *  - last4    every letter/digit except the last four becomes "•", separators stay
 *             ("123-45-6789" -> "•••-••-6789"); four or fewer letters/digits -> redact
 *  - initial  first character of each word ("Jane Doe" -> "J••• D••"); emails keep the first
 *             character of the local part and the top-level domain ("j•••@•••••••.com")
 *  - year     keeps a 4-digit year (19xx/20xx) and hides every other digit ("1984-••-••"),
 *             MM/YY keeps the year ("••/28"); anything else -> redact
 *  - token    <PREFIX>_<8 lowercase hex> = first 8 hex of HMAC-SHA256(instance key,
 *             class "\0" normalized value): stable and joinable inside an instance
 *  - null     null
 *  - span     free text: only detected personal-data spans become "••••••"
 *
 * Rules: null stays null. Non-string scalars (int/float/bool) become null under every format
 * except token (which tokenizes their string form). Arrays/objects (JSON columns) become null,
 * except token (tokenizes the JSON) and span (masks spans in every string leaf). Restricted
 * classes never get a token (hashing a list of likely values would reverse it): token falls back to redact.
 * Values that are not valid UTF-8 (binary data) are redacted.
 *
 * mask() is pure, deterministic and idempotent: mask(mask(v)) === mask(v). isMasked()
 * recognizes the masker's own outputs, so a client that sends a masked value back (GET, edit
 * another field, PUT) does not overwrite the real value (write-back guard).
 */
final class Masker
{
    /** The mask character (U+2022 BULLET) in every masked value the API returns. */
    public const GLYPH = "\u{2022}";

    public const REDACT_RUN = 8;
    public const SPAN_RUN = 6;
    public const TOKEN_HEX = 8;

    private const FALLBACK_PREFIX = 'VAL';

    /** Upper bound of the per-instance token memo (one instance lives for one request). */
    private const TOKEN_MEMO_MAX = 20000;

    private ?string $key;
    private ?\HashContext $hmac = null;
    /** @var array<string,array{0:?string,1:string}> class => [tier, token prefix] */
    private array $classInfo = [];
    /** @var array<string,string> class "\0" normalized value => token */
    private array $tokens = [];

    /** @param string|null $tokenKey 32 raw bytes; null = Settings::tokenKey() on first token */
    public function __construct(?string $tokenKey = null)
    {
        $this->key = $tokenKey;
    }

    public static function redacted(): string
    {
        return str_repeat(self::GLYPH, self::REDACT_RUN);
    }

    public function mask(mixed $value, string $classId, string $format): mixed
    {
        if ($value === null || $format === 'null') {
            return null;
        }
        if ($format === 'token') {
            if ($this->info($classId)[0] === Catalog::TIER_RESTRICTED) {
                $format = 'redact';
            } else {
                return (is_string($value) && $this->isToken($value, $classId)) ? $value : $this->token($classId, $value);
            }
        }
        if (is_array($value) || is_object($value)) {
            return $format === 'span' ? $this->maskSpansDeep($value) : null;
        }
        if (!is_string($value)) {
            return null; // int, float, bool
        }
        if ($value === '') {
            return '';
        }
        if (!mb_check_encoding($value, 'UTF-8')) {
            return self::redacted();
        }

        return match ($format) {
            'redact' => self::redacted(),
            'last4' => $this->last4($value),
            'initial' => $this->initial($value),
            'year' => $this->year($value),
            'span' => $this->maskSpans($value),
            default => self::redacted(), // unknown format: fail closed
        };
    }

    /**
     * True when $value is one of the masker's own outputs for this class: contains a mask glyph
     * (for span: a run of three or more, so free text with a bullet list is not mistaken), or
     * is this class's token. For the null format a null is "masked". Format changes between a
     * read and a write are tolerated: any glyph or this class's token counts.
     */
    public function isMasked(mixed $value, string $classId, string $format): bool
    {
        if ($value === null) {
            return $format === 'null';
        }
        if (!is_string($value) || $value === '') {
            return false;
        }
        if (str_contains($value, self::GLYPH . self::GLYPH . self::GLYPH)) {
            return true;
        }
        if ($format !== 'span' && str_contains($value, self::GLYPH)) {
            return true;
        }

        return $this->isToken($value, $classId);
    }

    /** Free text: replace detected personal-data spans; on any evaluation failure redact. */
    public function maskSpans(string $text): string
    {
        $out = SpanDetector::replace($text, str_repeat(self::GLYPH, self::SPAN_RUN));

        return $out ?? self::redacted();
    }

    /** The typed token for a value (also used for the stored masked examples). */
    public function token(string $classId, mixed $value): string
    {
        $data = $classId . "\0" . self::normalizeForToken($classId, $value);
        if (isset($this->tokens[$data])) {
            return $this->tokens[$data];
        }
        // HMAC-SHA256(key, data): the keyed context is built once and copied per value.
        $this->hmac ??= hash_init('sha256', HASH_HMAC, $this->key());
        $ctx = hash_copy($this->hmac);
        hash_update($ctx, $data);
        $token = $this->info($classId)[1] . '_' . substr(hash_final($ctx), 0, self::TOKEN_HEX);
        if (count($this->tokens) >= self::TOKEN_MEMO_MAX) {
            $this->tokens = [];
        }

        return $this->tokens[$data] = $token;
    }

    public function isToken(string $value, string $classId): bool
    {
        $prefix = $this->info($classId)[1] . '_';
        if (strlen($value) !== strlen($prefix) + self::TOKEN_HEX || !str_starts_with($value, $prefix)) {
            return false;
        }
        $hex = substr($value, -self::TOKEN_HEX);

        return ctype_xdigit($hex) && strtolower($hex) === $hex;
    }

    /**
     * Token normalization: trim + lowercase for email/username, digits only
     * for phone, collapsed whitespace + lowercase for names/addresses, trim for everything else.
     */
    public static function normalizeForToken(string $classId, mixed $value): string
    {
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if (is_int($value) || is_float($value)) {
            return (string)$value;
        }
        if (is_array($value) || is_object($value)) {
            return (string)json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR);
        }
        $v = trim((string)$value);
        switch ($classId) {
            case 'email':
            case 'username':
                return mb_strtolower($v, 'UTF-8');
            case 'phone':
                $digits = preg_replace('/\D+/', '', $v) ?? '';

                return $digits !== '' ? $digits : mb_strtolower($v, 'UTF-8');
            case 'person_name':
            case 'street_address':
                return mb_strtolower(preg_replace('/\s+/u', ' ', $v) ?? $v, 'UTF-8');
            default:
                return $v;
        }
    }

    // ---------------------------------------------------------------------------- formats

    private function last4(string $v): string
    {
        if (!preg_match('/[^\x00-\x7F]/', $v)) {
            return self::last4Ascii($v);
        }
        $chars = mb_str_split($v, 1, 'UTF-8');
        $positions = [];
        foreach ($chars as $i => $ch) {
            if (self::isMaskable($ch)) {
                $positions[] = $i;
            }
        }
        $n = count($positions);
        if ($n <= 4) {
            return self::redacted();
        }
        $hide = array_flip(array_slice($positions, 0, $n - 4));
        $out = '';
        $prevHidden = false;
        foreach ($chars as $i => $ch) {
            if (isset($hide[$i])) {
                $out .= self::GLYPH;
                $prevHidden = true;
            } elseif ($prevHidden && self::isMark($ch)) {
                continue; // a combining accent on a hidden letter
            } else {
                $out .= $ch;
                $prevHidden = false;
            }
        }

        return $out;
    }

    private function initial(string $v): string
    {
        $at = mb_strrpos($v, '@', 0, 'UTF-8');
        $len = mb_strlen($v, 'UTF-8');
        if ($at !== false && $at > 0 && $at < $len - 1 && !preg_match('/\s/u', $v)) {
            $local = mb_substr($v, 0, $at, 'UTF-8');
            $domain = mb_substr($v, $at + 1, null, 'UTF-8');
            $dot = mb_strrpos($domain, '.', 0, 'UTF-8');
            $hasTld = $dot !== false && $dot > 0 && $dot < mb_strlen($domain, 'UTF-8') - 1;
            $host = $hasTld ? mb_substr($domain, 0, $dot, 'UTF-8') : $domain;
            $tld = $hasTld ? mb_substr($domain, $dot, null, 'UTF-8') : '';

            return self::firstChar($local) . self::run(mb_strlen($local, 'UTF-8') - 1)
                . '@' . self::run(mb_strlen($host, 'UTF-8')) . $tld;
        }

        $parts = preg_split('/(\s+)/u', $v, -1, PREG_SPLIT_DELIM_CAPTURE);
        if ($parts === false) {
            return self::redacted();
        }
        $out = '';
        foreach ($parts as $part) {
            if ($part === '' || preg_match('/^\s+$/u', $part)) {
                $out .= $part;
                continue;
            }
            $plen = mb_strlen($part, 'UTF-8');
            $out .= self::firstChar($part) . ($plen > 1 ? str_repeat(self::GLYPH, $plen - 1) : '');
        }

        return $out;
    }

    private function year(string $v): string
    {
        if (preg_match('/(?<!\d)(?:19|20)\d{2}(?!\d)/u', $v, $m, PREG_OFFSET_CAPTURE)) {
            $pos = $m[0][1];
            $before = substr($v, 0, $pos);
            $after = substr($v, $pos + 4);
            $after = preg_replace('/T.*$/su', '', $after) ?? '';

            return (preg_replace('/\d/u', self::GLYPH, $before) ?? '')
                . $m[0][0]
                . (preg_replace('/\d/u', self::GLYPH, $after) ?? '');
        }

        // MM/YY, MM/YYYY (card expiry) and MM/DD/YY: keep the trailing year group only.
        $trimmed = trim($v);
        if (preg_match('/^([\d\x{2022}]{1,2})([\/-])([\d\x{2022}]{1,2}[\/-])?(\d{2}|\d{4})$/u', $trimmed, $mm)) {
            $groups = preg_split('/([\/-])/u', $trimmed, -1, PREG_SPLIT_DELIM_CAPTURE) ?: [];
            $last = count($groups) - 1;
            $out = '';
            foreach ($groups as $i => $g) {
                $out .= ($i === $last || $g === '/' || $g === '-') ? $g : self::run(mb_strlen($g, 'UTF-8'));
            }

            return $out;
        }

        return self::redacted();
    }

    private function maskSpansDeep(mixed $value): mixed
    {
        if (is_object($value)) {
            $value = json_decode((string)json_encode($value), true);
        }
        if (is_string($value)) {
            return $this->maskSpans($value);
        }
        if (!is_array($value)) {
            return $value; // numbers/bools inside free-text JSON carry no span
        }
        foreach ($value as $k => $item) {
            $value[$k] = $this->maskSpansDeep($item);
        }

        return $value;
    }

    /** last4 for plain ASCII (the common case): byte loop, no multibyte handling needed. */
    private static function last4Ascii(string $v): string
    {
        $len = strlen($v);
        $alnum = 0;
        for ($i = 0; $i < $len; $i++) {
            if (ctype_alnum($v[$i])) {
                $alnum++;
            }
        }
        if ($alnum <= 4) {
            return self::redacted();
        }
        $hide = $alnum - 4;
        $out = '';
        for ($i = 0; $i < $len; $i++) {
            $ch = $v[$i];
            if ($hide > 0 && ctype_alnum($ch)) {
                $out .= self::GLYPH;
                $hide--;
            } else {
                $out .= $ch;
            }
        }

        return $out;
    }

    // ---------------------------------------------------------------------------- helpers

    /** @return array{0:?string,1:string} [tier, token prefix] */
    private function info(string $classId): array
    {
        return $this->classInfo[$classId] ??= [
            Catalog::tierOf($classId),
            Catalog::tokenPrefix($classId) ?? self::FALLBACK_PREFIX,
        ];
    }

    private function key(): string
    {
        return $this->key ??= Settings::tokenKey();
    }

    private static function run(int $n): string
    {
        return str_repeat(self::GLYPH, max(1, $n));
    }

    private static function firstChar(string $s): string
    {
        return mb_substr($s, 0, 1, 'UTF-8');
    }

    private static function isMaskable(string $ch): bool
    {
        if ($ch === self::GLYPH) {
            return true;
        }
        if (strlen($ch) === 1) {
            return ctype_alnum($ch);
        }

        return preg_match('/^[\p{L}\p{N}]$/u', $ch) === 1;
    }

    private static function isMark(string $ch): bool
    {
        return strlen($ch) > 1 && preg_match('/^\p{M}$/u', $ch) === 1;
    }
}

<?php

namespace DreamFactory\Core\Masking\Scanner;

use DreamFactory\Core\Masking\Masking\Masker;
use DreamFactory\Core\Masking\Support\Catalog;

/**
 * Masked examples for a classified column: one per format its class allows, each rendered from a
 * real sampled value by the same Masker enforcement uses, so the admin UI shows exactly what a
 * masked caller receives ("•••-••-6789" for last4, "EMAIL_3fa94c1d" for token, null for null).
 *
 * Only masked renderings are stored, never the raw value. Free text is the exception to "real
 * value": masking spans leaves the rest of the text readable (names in prose are out of scope for
 * span masking), so free-text examples always use the synthetic catalog sample. Columns without a
 * sampled value (name-only classification, empty tables) use the synthetic sample too.
 *
 * The value is typed the way DreamFactory returns it in API responses (integer columns as JSON
 * numbers, ...), because the Masker treats non-strings differently (masked to null except token).
 */
final class Examples
{
    /** Synthetic, obviously fake samples (the admin UI catalog's `sample` per class). */
    public const SAMPLES = [
        'national_id' => '123-45-6789',
        'tax_id' => '12-3456789',
        'passport_number' => 'X12345678',
        'drivers_license' => 'D123-4567-8901',
        'card_number' => '4111 1111 1111 1234',
        'card_security' => '123',
        'bank_account' => 'NL91 ABNA 0417 1643 00',
        'credential' => 'sk_live_4eC39HqLyjWDarjtT1',
        'special_category' => 'Type 2 diabetes',
        'email' => 'jane.doe@example.com',
        'phone' => '+1 415-555-0132',
        'person_name' => 'Jane Doe',
        'street_address' => '42 Market Street',
        'date_of_birth' => '1984-03-12',
        'ip_address' => '203.0.113.42',
        'username' => 'jdoe84',
        'geo_precise' => '37.77493, -122.41942',
        'postal_code' => '94103',
        'gender' => 'Female',
        'age' => '41',
        'card_expiry' => '07/28',
        'financial_personal' => '$84,500',
        'free_text_pii' => 'Call Jane at 415-555-0132 or jane@example.com',
    ];

    /** The mask character every masked value uses (U+2022). */
    public const GLYPH = Masker::GLYPH;

    private const MAX_INPUT_CHARS = 120;

    private Masker $masker;

    public function __construct(?Masker $masker = null)
    {
        $this->masker = $masker ?? new Masker();
    }

    /**
     * @param ?string $raw    first sampled non-null value of the column (text), or null
     * @param ?string $dfType DreamFactory simple type of the column (decides the JSON type)
     * @return list<array{format:string, value:mixed}>
     */
    public function build(string $classId, ?string $raw, ?string $dfType): array
    {
        if (!Catalog::has($classId)) {
            return [];
        }
        $synthetic = $raw === null || Catalog::tierOf($classId) === Catalog::TIER_FREE_TEXT;
        $value = $synthetic ? (self::SAMPLES[$classId] ?? '') : self::typed(mb_substr($raw, 0, self::MAX_INPUT_CHARS), $dfType);
        $out = [];
        foreach (Catalog::formatsAllowed($classId) as $format) {
            try {
                $masked = $this->masker->mask($value, $classId, $format);
            } catch (\Throwable $e) {
                $masked = null;
            }
            if (!$synthetic && !self::safe($masked, $value, $format)) {
                $masked = null;
            }
            $out[] = ['format' => $format, 'value' => $masked];
        }
        return $out;
    }

    /**
     * Examples kept from an earlier scan, completed for a (new) class without a raw value: formats
     * that only depend on the value (redact, last4, initial, year, null, span) are reused; token is
     * class-specific (prefix + keyed hash of the class), so it falls back to the synthetic sample.
     *
     * @param list<array{format:string, value:mixed}> $previous
     * @return list<array{format:string, value:mixed}>
     */
    public function reuse(string $classId, array $previous): array
    {
        if (!Catalog::has($classId)) {
            return [];
        }
        $byFormat = [];
        foreach ($previous as $e) {
            if (is_array($e) && isset($e['format']) && $e['format'] !== 'token' && array_key_exists('value', $e)) {
                $byFormat[(string) $e['format']] = $e['value'];
            }
        }
        $synthetic = $this->build($classId, null, null);
        $out = [];
        foreach ($synthetic as $e) {
            $out[] = array_key_exists($e['format'], $byFormat) && Catalog::tierOf($classId) !== Catalog::TIER_FREE_TEXT
                ? ['format' => $e['format'], 'value' => $byFormat[$e['format']]]
                : $e;
        }
        return $out;
    }

    /** JSON type DreamFactory gives this column's values in responses. */
    public static function typed(string $text, ?string $dfType): mixed
    {
        $php = 'string';
        if ($dfType !== null && class_exists(\DreamFactory\Core\Enums\DbSimpleTypes::class)) {
            try {
                $php = (string) \DreamFactory\Core\Enums\DbSimpleTypes::toPhpType($dfType);
            } catch (\Throwable $e) {
                $php = 'string';
            }
        }
        return match ($php) {
            'integer' => preg_match('/^-?\d{1,18}$/', $text) ? (int) $text : $text,
            'double' => is_numeric($text) ? (float) $text : $text,
            'boolean' => in_array(strtolower($text), ['1', 't', 'true', 'y', 'yes'], true),
            default => $text,
        };
    }

    /**
     * Defense in depth: a stored example must never be the raw value. Anything but null/token
     * must contain the mask glyph, and no example may equal the input.
     */
    private static function safe(mixed $masked, mixed $value, string $format): bool
    {
        if ($masked === null) {
            return true;
        }
        if (!is_string($masked)) {
            return false;
        }
        if (is_string($value) && $value !== '' && $masked === $value) {
            return false;
        }
        return $format === 'token' || str_contains($masked, self::GLYPH);
    }
}

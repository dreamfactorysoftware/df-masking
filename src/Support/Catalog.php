<?php

namespace DreamFactory\Core\Masking\Support;

/**
 * The fixed class catalog: class ids, tiers, default mask formats, allowed formats and token
 * prefixes. Mirrors the admin UI's catalog exactly
 * (df-admin-interface src/app/adf-data-masking/data-masking.catalog.ts); a unit test parses
 * that file and fails on any drift. English labels mirror the UI's i18n
 * (src/assets/i18n/dataMasking/en.json) and are only used for activity text.
 */
final class Catalog
{
    public const TIER_RESTRICTED = 'restricted';
    public const TIER_IDENTITY = 'identity';
    public const TIER_QUASI = 'quasi';
    public const TIER_FREE_TEXT = 'free_text';

    public const TIERS = [self::TIER_RESTRICTED, self::TIER_IDENTITY, self::TIER_QUASI, self::TIER_FREE_TEXT];

    /** Every mask format, in the UI's order. */
    public const FORMATS = ['redact', 'last4', 'initial', 'year', 'token', 'null', 'span'];

    /**
     * [id, tier, default format, allowed formats, token prefix] in UI order.
     * Restricted classes never allow `token` (hashing a list of likely values would reverse it).
     */
    private const CLASSES = [
        // restricted
        ['national_id', 'restricted', 'redact', ['redact', 'last4', 'null'], 'NID'],
        ['tax_id', 'restricted', 'redact', ['redact', 'last4', 'null'], 'TAX'],
        ['passport_number', 'restricted', 'redact', ['redact', 'last4', 'null'], 'PASS'],
        ['drivers_license', 'restricted', 'redact', ['redact', 'last4', 'null'], 'DL'],
        ['card_number', 'restricted', 'last4', ['last4', 'redact', 'null'], 'CARD'],
        ['card_security', 'restricted', 'redact', ['redact', 'null'], 'CVV'],
        ['bank_account', 'restricted', 'last4', ['last4', 'redact', 'null'], 'BANK'],
        ['credential', 'restricted', 'redact', ['redact', 'null'], 'CRED'],
        ['special_category', 'restricted', 'redact', ['redact', 'null'], 'HEALTH'],
        // identity
        ['email', 'identity', 'token', ['token', 'initial', 'redact', 'null'], 'EMAIL'],
        ['phone', 'identity', 'token', ['token', 'last4', 'redact', 'null'], 'PHONE'],
        ['person_name', 'identity', 'token', ['token', 'initial', 'redact', 'null'], 'NAME'],
        ['street_address', 'identity', 'redact', ['redact', 'token', 'null'], 'ADDR'],
        ['date_of_birth', 'identity', 'year', ['year', 'redact', 'token', 'null'], 'DOB'],
        ['ip_address', 'identity', 'token', ['token', 'redact', 'null'], 'IP'],
        ['username', 'identity', 'token', ['token', 'initial', 'redact', 'null'], 'USER'],
        ['geo_precise', 'identity', 'redact', ['redact', 'token', 'null'], 'GEO'],
        // quasi
        ['postal_code', 'quasi', 'redact', ['redact', 'token', 'null'], 'ZIP'],
        ['gender', 'quasi', 'redact', ['redact', 'token', 'null'], 'GENDER'],
        ['age', 'quasi', 'redact', ['redact', 'null'], 'AGE'],
        ['card_expiry', 'quasi', 'redact', ['redact', 'year', 'null'], 'EXP'],
        ['financial_personal', 'quasi', 'redact', ['redact', 'null'], 'FIN'],
        // free text
        ['free_text_pii', 'free_text', 'span', ['span', 'redact', 'null'], 'TEXT'],
    ];

    /** Synthetic, obviously fake sample per class (the UI's Masks tab before -> after). */
    private const SAMPLES = [
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

    private const LABELS = [
        'national_id' => 'National ID',
        'tax_id' => 'Tax ID',
        'passport_number' => 'Passport number',
        'drivers_license' => "Driver's license",
        'card_number' => 'Card number',
        'card_security' => 'Card security code',
        'bank_account' => 'Bank account',
        'credential' => 'Credential',
        'special_category' => 'Health & special category',
        'email' => 'Email',
        'phone' => 'Phone',
        'person_name' => 'Person name',
        'street_address' => 'Street address',
        'date_of_birth' => 'Date of birth',
        'ip_address' => 'IP address',
        'username' => 'Username',
        'geo_precise' => 'Precise location',
        'postal_code' => 'Postal code',
        'gender' => 'Gender',
        'age' => 'Age',
        'card_expiry' => 'Card expiry',
        'financial_personal' => 'Personal financial',
        'free_text_pii' => 'Free text with personal data',
    ];

    private const TIER_LABELS = [
        'restricted' => 'Restricted',
        'identity' => 'Identity',
        'quasi' => 'Quasi-identifiers',
        'free_text' => 'Free text',
    ];

    private const FORMAT_LABELS = [
        'redact' => 'Redact',
        'last4' => 'Last 4',
        'initial' => 'First letter',
        'year' => 'Year only',
        'token' => 'Token',
        'null' => 'Null',
        'span' => 'Detected spans',
    ];

    /**
     * Built-in detectors per class, as the admin UI's Detection tab lists them
     * (GET system/data_masking/rule/builtin). Names only; the engine owns the logic.
     */
    private const DETECTORS = [
        'national_id' => ['Dutch BSN', 'French NIR', 'Spanish DNI', 'Swedish personnummer', 'UK NI number', 'US SSN'],
        'tax_id' => ['Brazilian CPF', 'German Steuer-ID', 'Italian codice fiscale', 'US ITIN'],
        'passport_number' => ['Passport shape'],
        'drivers_license' => ["Driver's license shape"],
        'card_number' => ['Card checksum (Luhn)', 'Card shape'],
        'card_security' => ['Security code digits'],
        'bank_account' => ['Account digits', 'IBAN checksum'],
        'credential' => ['High-entropy secret', 'JWT', 'Password hash', 'Provider API key'],
        'special_category' => ['Blood type', 'ICD-10 code'],
        'email' => ['Email syntax'],
        'phone' => ['Formatted phone', 'Phone digits'],
        'person_name' => ['Name lexicon'],
        'street_address' => ['Street pattern'],
        'date_of_birth' => ['Birth date plausibility'],
        'ip_address' => ['IPv4'],
        'username' => ['Username shape'],
        'geo_precise' => ['Precise coordinates'],
        'postal_code' => ['Dutch postcode', 'Numeric postal code', 'UK postcode', 'US ZIP+4'],
        'gender' => ['Gender values'],
        'age' => ['Age range'],
        'card_expiry' => ['Expiry date'],
        'financial_personal' => ['Money amount'],
        'free_text_pii' => ['Email syntax', 'Formatted phone', 'Card checksum (Luhn)', 'US SSN'],
    ];

    /** @var array<string,array{id:string,tier:string,format:string,formats:string[],token:string}>|null */
    private static ?array $byId = null;

    private function __construct()
    {
    }

    /**
     * @return list<array{id:string,tier:string,format:string,formats:string[],token:string}> in UI order
     */
    public static function classes(): array
    {
        return array_values(self::index());
    }

    /** @return string[] every class id, in UI order */
    public static function ids(): array
    {
        return array_keys(self::index());
    }

    /** @return array{id:string,tier:string,format:string,formats:string[],token:string}|null */
    public static function get(string $id): ?array
    {
        return self::index()[$id] ?? null;
    }

    public static function has(?string $id): bool
    {
        return $id !== null && isset(self::index()[$id]);
    }

    /** @return string[] */
    public static function tiers(): array
    {
        return self::TIERS;
    }

    public static function tierOf(string $classId): ?string
    {
        return self::index()[$classId]['tier'] ?? null;
    }

    public static function defaultFormat(string $classId): ?string
    {
        return self::index()[$classId]['format'] ?? null;
    }

    /** @return string[] */
    public static function formatsAllowed(string $classId): array
    {
        return self::index()[$classId]['formats'] ?? [];
    }

    public static function tokenPrefix(string $classId): ?string
    {
        return self::index()[$classId]['token'] ?? null;
    }

    public static function isFormat(?string $format): bool
    {
        return $format !== null && in_array($format, self::FORMATS, true);
    }

    public static function isTier(?string $tier): bool
    {
        return $tier !== null && in_array($tier, self::TIERS, true);
    }

    /** @return string[] class ids of one tier, in UI order */
    public static function classesInTier(string $tier): array
    {
        $out = [];
        foreach (self::index() as $id => $def) {
            if ($def['tier'] === $tier) {
                $out[] = $id;
            }
        }

        return $out;
    }

    /** Synthetic sample value for a class (never real data); null for an unknown class. */
    public static function sample(string $classId): ?string
    {
        return self::SAMPLES[$classId] ?? null;
    }

    /** English label, as the admin UI shows it ("Card number"). Unknown ids are returned as-is. */
    public static function label(?string $classId): string
    {
        if ($classId === null) {
            return 'Not sensitive';
        }

        return self::LABELS[$classId] ?? $classId;
    }

    public static function tierLabel(string $tier): string
    {
        return self::TIER_LABELS[$tier] ?? $tier;
    }

    public static function formatLabel(string $format): string
    {
        return self::FORMAT_LABELS[$format] ?? $format;
    }

    /** @return list<array{class:string,detectors:string[]}> in UI order */
    public static function builtinDetectors(): array
    {
        $out = [];
        foreach (self::ids() as $id) {
            $detectors = self::DETECTORS[$id] ?? [];
            sort($detectors);
            $out[] = ['class' => $id, 'detectors' => $detectors];
        }

        return $out;
    }

    /** @return array<string,array{id:string,tier:string,format:string,formats:string[],token:string}> */
    private static function index(): array
    {
        if (self::$byId === null) {
            $byId = [];
            foreach (self::CLASSES as [$id, $tier, $format, $formats, $token]) {
                $byId[$id] = [
                    'id' => $id,
                    'tier' => $tier,
                    'format' => $format,
                    'formats' => $formats,
                    'token' => $token,
                ];
            }
            self::$byId = $byId;
        }

        return self::$byId;
    }
}

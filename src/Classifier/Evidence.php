<?php
declare(strict_types=1);

namespace DreamFactory\Core\Masking\Classifier;

use DreamFactory\Core\Masking\Support\Catalog;

/**
 * Turns one engine verdict into what df-masking stores and serves for a column:
 *
 *   verdict  enforce|review|clear  ->  masked|review|clear
 *   evidence {total, threshold_mask, threshold_review, lines:[{points,kind,text}], shapes:[[shape,pct],...]}
 *
 * Lines are the engine's "why" lines humanized for the admin UI's evidence ledger
 * ("+75 values 256/256 (100%) pass ssn_us.dashed (strong)" -> [75, values, "256 of 256 values are
 * valid US SSNs"]); detector noise is dropped. This is a line-for-line port of the admin UI's
 * fixture generator (e2e/fixtures/data-masking/generate-fixture.ts), which defined these shapes.
 *
 * Nothing here ever sees a sampled value: the engine output carries only tokens, rule ids,
 * counts, percentages and character-class shapes. Shapes are re-validated against the shape
 * alphabet anyway (defense in depth) and dropped if they could carry anything else.
 */
final class Evidence
{
    public const KIND_NAME = 'name';
    public const KIND_VALUES = 'values';
    public const KIND_CONTEXT = 'context';
    public const KIND_TEXT = 'text';
    public const KIND_PENALTY = 'penalty';

    /** Lines kept for clear columns (the UI shows a short explanation only). */
    private const CLEAR_LINES = 2;
    private const MAX_SHAPES = 3;

    /** Value detector id -> what passing values "are" (UI wording). */
    private const DETECTORS = [
        'email.syntax' => 'are valid email addresses',
        'phone.formatted' => 'are formatted phone numbers',
        'phone.digits' => 'are phone-length digit strings',
        'street.pattern' => 'look like street addresses',
        'postal.numeric' => 'look like postal codes',
        'postal.us_zip4' => 'are US ZIP+4 codes',
        'postal.nl' => 'are Dutch postcodes',
        'postal.uk' => 'are UK postcodes',
        'iban.mod97' => 'are valid IBANs',
        'account.digits' => 'look like account numbers',
        'ip.v4' => 'are IPv4 addresses',
        'gender.values' => 'are gender values',
        'money.amount' => 'are money amounts',
        'expiry.shape' => 'look like card expiry dates',
        'username.shape' => 'look like usernames',
        'cred.password_hash' => 'are password hashes',
        'cred.high_entropy' => 'look like secrets',
        'cred.provider_key' => 'are provider API keys',
        'cred.jwt' => 'are JSON web tokens',
        'geo.precise' => 'are precise coordinates',
        'age.range' => 'are plausible ages',
        'card.luhn_iin' => 'pass the card checksum',
        'card.shape' => 'look like card numbers',
        'card.already_masked' => 'are already-masked card numbers',
        'cvv.digits' => 'look like card security codes',
        'passport.shape' => 'look like passport numbers',
        'dl.shape' => "look like driver's license numbers",
        'icd10.shape' => 'are ICD-10 diagnosis codes',
        'blood_type.shape' => 'are blood types',
        'ssn_us.dashed' => 'are valid US SSNs',
        'ssn_us.digits' => 'are 9-digit SSN candidates',
        'itin_us.dashed' => 'are valid US ITINs',
        'dni_es' => 'are valid Spanish DNIs',
        'cpf_br' => 'are valid Brazilian CPFs',
        'cf_it' => 'are valid Italian tax codes',
        'nir_fr' => 'are valid French NIRs',
        'nino_uk' => 'are valid UK NI numbers',
        'bsn_nl' => 'are valid Dutch BSNs',
        'steuer_id_de' => 'are valid German tax IDs',
        'pnr_se' => 'are valid Swedish personal numbers',
    ];

    private function __construct()
    {
    }

    /** Engine verdict -> API verdict. */
    public static function verdict(string $engineVerdict): string
    {
        return match ($engineVerdict) {
            'enforce', 'masked' => 'masked',
            'review' => 'review',
            default => 'clear',
        };
    }

    /**
     * One engine column verdict -> stored classification.
     *
     * @param array $v       engine output for one column (verdict, class, tier, confidence, evidence)
     * @param bool  $nameOnly classified without sampled values (name-only bands apply)
     * @return array{verdict:string, class:?string, tier:?string, score:int, evidence:array}
     */
    public static function fromEngine(array $v, bool $nameOnly, RulePack $pack): array
    {
        $verdict = self::verdict((string) $v['verdict']);
        $class = $verdict === 'clear' ? null : ($v['class'] ?? null);
        if ($class !== null && !Catalog::has($class)) {
            // The pack and the catalog share ids; an unknown id would be a packaging error.
            // Fail closed: keep the column masked as restricted-tier credential data.
            $class = 'credential';
        }
        $sc = $pack->scoring();
        $bands = $nameOnly ? $sc['name_only'] : $sc['bands'];
        $total = (int) ($v['evidence']['score']['total'] ?? $v['confidence'] ?? 0);
        $evidence = [
            'total' => $total,
            'threshold_mask' => (int) $bands['enforce'],
            'threshold_review' => (int) $bands['review'],
            'lines' => self::lines($v['evidence']['why'] ?? [], $verdict),
            'shapes' => $verdict === 'clear' ? [] : self::shapes($v['evidence']['shapes'] ?? []),
        ];
        if ($nameOnly) {
            $evidence['lines'][] = self::line(0, self::KIND_CONTEXT, 'Classified from the column name only; values were not sampled');
            $evidence['name_only'] = true;
        }
        return [
            'verdict' => $verdict,
            'class' => $class,
            'tier' => $class !== null ? Catalog::tierOf($class) : null,
            'score' => max(0, min(100, (int) ($v['confidence'] ?? $total))),
            'evidence' => $evidence,
        ];
    }

    /**
     * Engine "why" lines -> ledger lines; clear columns keep only the first two.
     *
     * @param list<string> $why
     * @return list<array{points:int, kind:string, text:string}>
     */
    public static function lines(array $why, string $verdict): array
    {
        $out = [];
        foreach ($why as $w) {
            $l = self::humanize((string) $w);
            if ($l !== null) {
                $out[] = self::line($l[0], $l[1], $l[2]);
            }
        }
        return $verdict === 'clear' ? array_slice($out, 0, self::CLEAR_LINES) : $out;
    }

    /** @return array{points:int, kind:string, text:string} */
    public static function line(int $points, string $kind, string $text): array
    {
        return ['points' => $points, 'kind' => $kind, 'text' => $text];
    }

    /**
     * One engine "why" line -> [points, kind, text], or null to drop it.
     *
     * @return array{0:int, 1:string, 2:string}|null
     */
    public static function humanize(string $why): ?array
    {
        if (str_starts_with($why, '=')) {
            return null;
        }
        if (preg_match("/^([+-]\\d+) name '(.*?)' -> .*?(strong|weak) phrase/", $why, $m)) {
            $promoted = str_contains($why, 'promoted by person_table');
            return [(int) $m[1], self::KIND_NAME, sprintf('Column name "%s"%s', $m[2], $promoted ? ' in a person table' : '')];
        }
        if (preg_match("/^([+-]\\d+) name '(.*?)' -> /", $why, $m)) {
            return [(int) $m[1], self::KIND_NAME, sprintf('Column name "%s" matches no class', $m[2])];
        }
        if (preg_match('/^([+-]\d+) values (\d+)\/(\d+) \(\d+%\) pass ([a-z0-9_.]+) \(\w+\)(.*)$/', $why, $m)) {
            $phrase = self::DETECTORS[$m[4]] ?? 'pass ' . $m[4];
            $few = str_contains($m[5], 'halved') ? ' (few distinct values)' : '';
            return [(int) $m[1], self::KIND_VALUES, sprintf('%s of %s values %s%s', $m[2], $m[3], $phrase, $few)];
        }
        if (preg_match('/^([+-]\d+) values .*?, (\d+)% in the name lexicons/', $why, $m)) {
            return [(int) $m[1], self::KIND_VALUES, sprintf('%s%% of values are known names', $m[2])];
        }
        if (preg_match('/^([+-]\d+) values date-of-birth plausible: .*?(\d+) distinct years/', $why, $m)) {
            return [(int) $m[1], self::KIND_VALUES, sprintf('Values look like birth dates (%s distinct years)', $m[2])];
        }
        if (preg_match('/^([+-]\d+) values date-of-birth plausibility failed/', $why, $m)) {
            return [(int) $m[1], self::KIND_VALUES, "Values don't look like birth dates"];
        }
        if (preg_match('/^([+-]\d+) values contradict the class/', $why, $m)) {
            return [(int) $m[1], self::KIND_PENALTY, "Values don't fit the class"];
        }
        if (preg_match('/^([+-]\d+) text validated PII spans in (\d+) rows/', $why, $m)) {
            return [(int) $m[1], self::KIND_TEXT, sprintf('Personal data inside the text in %s rows', $m[2])];
        }
        if (preg_match('/^([+-]\d+) text a few PII spans .*medium rows (\d+)/', $why, $m)) {
            return [(int) $m[1], self::KIND_TEXT, sprintf('Possible personal data inside the text in %s rows', $m[2])];
        }
        if (preg_match('/^\. type surrogate key/', $why)) {
            return [0, self::KIND_CONTEXT, 'Key column, never classified'];
        }
        if (preg_match('/^\. sample only (\d+) non-null/', $why, $m)) {
            return [0, self::KIND_CONTEXT, sprintf('Only %s non-null values sampled', $m[1])];
        }
        if (preg_match('/^\. name phrase from ([a-z_]+)\.\S+ suppressed by negative "([^"]+)"/', $why, $m)) {
            return [0, self::KIND_CONTEXT, sprintf('"%s" rules out %s', $m[2], strtolower(self::classLabel($m[1])))];
        }
        if (preg_match('/^\. type ([a-z_]+)\.\S+ blocked by the type gate \(type:(\w+)\)/', $why, $m)) {
            $article = preg_match('/^[aeiou]/i', $m[2]) ? 'An' : 'A';
            return [0, self::KIND_CONTEXT, sprintf("%s %s column can't hold %s", $article, $m[2], strtolower(self::classLabel($m[1])))];
        }
        if (preg_match('/^\. values value-only date_of_birth evidence ignored/', $why)) {
            return [0, self::KIND_CONTEXT, 'The name says this is another kind of date'];
        }
        if (preg_match('/^([+-]\d+) (\w+) (.*)$/', $why, $m)) {
            return [(int) $m[1], $m[2] === 'text' ? self::KIND_TEXT : self::KIND_VALUES, $m[3]];
        }
        return null;
    }

    /**
     * Engine shapes -> at most three [shape, pct] pairs that pass the shape-alphabet check.
     *
     * @param list<array{0:string,1:int}> $shapes
     * @return list<array{0:string,1:int}>
     */
    public static function shapes(array $shapes): array
    {
        $out = [];
        foreach ($shapes as $s) {
            if (!is_array($s) || !isset($s[0], $s[1]) || !is_string($s[0]) || !self::isSafeShape($s[0])) {
                continue;
            }
            $out[] = [$s[0], (int) $s[1]];
            if (count($out) === self::MAX_SHAPES) {
                break;
            }
        }
        return $out;
    }

    /**
     * True when $shape uses only the shape alphabet (Profiler::shape): 9 for digits, A/a/A+/a+/Aa+/L+
     * for letter runs, ? for anything else, ASCII punctuation and space, and {n} run counts.
     * Anything else (a raw value that slipped through) is rejected.
     */
    public static function isSafeShape(string $shape): bool
    {
        if ($shape === '' || strlen($shape) > 512) {
            return false;
        }
        $rest = preg_replace('/\{\d{1,4}\}/', '', $shape);
        if ($rest === null) {
            return false;
        }
        // Letter runs must be exactly one of the run tokens; strip them, then nothing alphanumeric
        // except the digit placeholder 9 may remain.
        $rest = preg_replace('/Aa\+|A\+|a\+|L\+|A|a/', '', $rest);
        return $rest !== null && preg_match('/^[9?\x20-\x2F\x3A-\x40\x5B-\x60\x7B-\x7E]*$/', $rest) === 1;
    }

    /**
     * Mark for one column in the table sensitivity strip: the tier for masked columns, 'review'
     * for review (the UI outlines it in the class tier), 'clear' otherwise.
     */
    public static function stripMark(string $verdict, ?string $tier): string
    {
        return match ($verdict) {
            'review' => 'review',
            'masked' => $tier ?? 'restricted',
            default => 'clear',
        };
    }

    /** English class label (the UI's i18n labels); unknown ids are returned as-is. */
    public static function classLabel(?string $classId): string
    {
        if ($classId === null || $classId === '') {
            return '';
        }
        $label = Catalog::label($classId);
        return $label !== '' ? $label : $classId;
    }
}

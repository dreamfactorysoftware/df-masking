<?php
declare(strict_types=1);

namespace DreamFactory\Core\Masking\Classifier;

/**
 * Value detectors compiled from the pack. Detectors are data (regex, prefilter,
 * normalize, params); validators are code referenced by id.
 *
 * A result is an array: id, class, strength, scope, matched, valid, pct, formats?, stats?, note?
 */
final class Detectors
{
    /** @var list<array> */
    private array $detectors = [];
    /** @var array<string,array> */
    private array $byId = [];
    /** @var list<array{detector:string, re:string}> */
    private array $spans = [];
    /** @var array<string,array<string,string>> compiled any_of_regex pattern maps */
    private array $patternMaps = [];

    public function __construct(private readonly RulePack $pack, private readonly Normalizer $norm)
    {
        foreach ($pack->classes() as $class => $c) {
            foreach ($c['values'] ?? [] as $d) {
                $flags = $d['flags'] ?? 'u';
                $regexes = [];
                foreach (isset($d['regex_any']) ? $d['regex_any'] : (isset($d['regex']) ? [$d['regex']] : []) as $re) {
                    $regexes[] = self::compile($re, $flags);
                }
                $det = [
                    'id' => $d['id'], 'class' => $class, 'strength' => $d['strength'], 'discover' => (bool) ($d['discover'] ?? false),
                    'scope' => $d['scope'] ?? 'value', 'normalize' => $d['normalize'] ?? null, 'prefilter' => $d['prefilter'] ?? null,
                    'regexes' => $regexes, 'validator' => $d['validator'] ?? null, 'params' => $d['params'] ?? [],
                    'ignore_if_tokens' => $d['ignore_if_tokens'] ?? [], 'column_check' => $d['column_check'] ?? null, 'flag' => $d['flag'] ?? null,
                ];
                if ($det['validator'] === 'in_vocabulary') {
                    $det['params']['vocabulary'] = array_fill_keys($det['params']['vocabulary'] ?? [], true);
                }
                if ($det['validator'] === 'any_of_regex') {
                    foreach ($det['params']['patterns'] as $name => $re) {
                        $this->patternMaps[$det['id']][$name] = self::compile($re, 'u');
                    }
                }
                $this->detectors[] = $det;
                $this->byId[$det['id']] = $det;
            }
            foreach ($c['spans'] ?? [] as $s) {
                $this->spans[] = ['detector' => $s['detector'], 're' => self::compile($s['find'], 'u')];
            }
        }
    }

    public static function compile(string $re, string $flags): string
    {
        return '#' . str_replace('#', '\#', $re) . '#' . $flags;
    }

    public function get(string $id): ?array
    {
        return $this->byId[$id] ?? null;
    }

    /** @return list<array{detector:string, re:string}> */
    public function spanDefs(): array
    {
        return $this->spans;
    }

    /**
     * Run value detectors on one column's sampled values.
     *
     * @param list<string> $values non-null, normalized values
     * @param list<?string> $aligned row-aligned values (for column-scope detectors needing siblings)
     * @param array<string,true> $candidates classes with a name candidate (weak detectors only run for these)
     * @param array{tokens:list<string>, created:?list<?string>, ref:array{0:int,1:int,2:int}} $ctx
     * @return list<array>
     */
    public function run(array $values, array $aligned, array $candidates, array $ctx): array
    {
        $out = [];
        $n = count($values);
        if ($n === 0) {
            return $out;
        }
        $distinct = count(array_unique($values));
        $tokens = array_fill_keys($ctx['tokens'], true);
        foreach ($this->detectors as $d) {
            if (!$d['discover'] && !isset($candidates[$d['class']])) {
                continue;
            }
            $ignored = false;
            foreach ($d['ignore_if_tokens'] as $tk) {
                if (isset($tokens[$tk])) {
                    $ignored = true;
                }
            }
            if ($ignored) {
                continue;
            }
            if ($d['scope'] === 'column') {
                $r = $this->runColumnScope($d, $values, $aligned, $ctx);
            } else {
                $r = $this->runValueScope($d, $values);
            }
            if ($r === null) {
                continue;
            }
            $cc = $d['column_check'];
            if ($cc !== null && $r['valid'] > 0) {
                if (isset($cc['max_distinct']) && $distinct > $cc['max_distinct']) {
                    $r['note'] = 'too_many_distinct';
                    $r['valid'] = 0;
                }
                if (isset($cc['min_high_octet_pct'])) {
                    $high = 0;
                    foreach ($values as $v) {
                        if (Validators::ipv4($v) && max(array_map('intval', explode('.', $v))) >= 32) {
                            $high++;
                        }
                    }
                    if (intdiv($high * 100, $r['valid']) < $cc['min_high_octet_pct']) {
                        $r['note'] = 'low_octets_version_like';
                        $r['valid'] = 0;
                    }
                }
            }
            $r['pct'] = intdiv($r['valid'] * 100, $n);
            if ($r['matched'] > 0 || isset($candidates[$d['class']])) {
                $out[] = $r;
            }
        }
        return $out;
    }

    private function runValueScope(array $d, array $values): ?array
    {
        $matched = $valid = 0;
        $formats = [];
        foreach ($values as $v) {
            $x = self::normalizeValue($v, $d['normalize']);
            if ($d['prefilter'] !== null && !self::prefilter($x, $d['prefilter'])) {
                continue;
            }
            if ($d['regexes'] !== []) {
                $hit = false;
                foreach ($d['regexes'] as $re) {
                    if (preg_match($re, $x) === 1) {
                        $hit = true;
                        break;
                    }
                }
                if (!$hit) {
                    continue;
                }
            } elseif ($d['validator'] !== 'any_of_regex' && $d['validator'] !== 'secret_entropy' && $d['validator'] !== 'in_vocabulary') {
                continue;
            }
            $res = $this->validate($d, $x);
            if ($res === false) {
                if ($d['regexes'] !== []) {
                    $matched++;
                }
                continue;
            }
            $matched++;
            $valid++;
            if (is_string($res)) {
                $formats[$res] = ($formats[$res] ?? 0) + 1;
            }
        }
        $r = ['id' => $d['id'], 'class' => $d['class'], 'strength' => $d['strength'], 'scope' => 'value', 'matched' => $matched, 'valid' => $valid, 'pct' => 0];
        if ($formats !== []) {
            ksort($formats);
            $r['formats'] = $formats;
        }
        return $r;
    }

    private function runColumnScope(array $d, array $values, array $aligned, array $ctx): ?array
    {
        if ($d['validator'] === 'dob_plausibility') {
            $res = DobPlausibility::evaluate($aligned, $ctx['created'] ?? null, $ctx['ref'], $d['params']);
        } elseif ($d['validator'] === 'person_name_lexicon') {
            $res = NameLexicon::evaluate($values, $d['params'], $this->pack->lexicon('given_names'), $this->pack->lexicon('surnames'), $this->norm);
        } else {
            return null;
        }
        return ['id' => $d['id'], 'class' => $d['class'], 'strength' => $d['strength'], 'scope' => 'column', 'matched' => $res['pass'] ? $res['valid'] : 0, 'valid' => $res['valid'], 'pct' => 0, 'stats' => $res['stats']];
    }

    /** Validate one candidate string with a detector's normalize + regex + validator (used for spans). */
    public function validateOne(string $detectorId, string $candidate): bool
    {
        $d = $this->byId[$detectorId] ?? null;
        if ($d === null) {
            return false;
        }
        $x = self::normalizeValue($candidate, $d['normalize']);
        foreach ($d['regexes'] as $re) {
            if (preg_match($re, $x) === 1) {
                return $this->validate($d, $x) !== false;
            }
        }
        return $d['regexes'] === [] && $this->validate($d, $x) !== false;
    }

    /** @return bool|string false = fail, true = pass, string = pass with format name */
    private function validate(array $d, string $x): bool|string
    {
        $p = $d['params'];
        return match ($d['validator']) {
            null => true,
            'email_rfc5322_subset' => Validators::email($x),
            'phone_structure' => Validators::phoneStructure($x),
            'phone_digits' => Validators::phoneDigits($x),
            'ssn_us_rules' => Validators::ssnUs($x),
            'nir_fr_key97' => Validators::nirFr($x),
            'dni_es_mod23' => Validators::dniEs($x),
            'nie_es_mod23' => Validators::nieEs($x),
            'pesel_pl' => Validators::peselPl($x),
            'pnr_se' => Validators::pnrSe($x),
            'bsn_nl_11proof' => Validators::bsnNl($x),
            'aadhaar_verhoeff' => Validators::aadhaar($x),
            'luhn' => Validators::luhn(Validators::digitsOnly($x)),
            'cpf_br_mod11' => Validators::cpfBr($x),
            'cf_it_check' => Validators::cfIt($x),
            'steuer_id_de' => Validators::steuerIdDe($x),
            'iban_mod97' => Validators::ibanMod97($x),
            'luhn_iin_not_test' => Validators::cardNumber($x, $p),
            'not_repeated_or_sequential' => Validators::notRepeatedOrSequential($x),
            'jwt_header_has_alg' => Validators::jwtHeaderHasAlg($x),
            'secret_entropy' => Validators::secretEntropy($x, $p),
            'ip_v4' => Validators::ipv4($x),
            'ip_v6' => Validators::ipv6($x),
            'geo_range' => Validators::geoRange($x),
            'int_range' => Validators::intRange($x, $p),
            'in_vocabulary' => isset($p['vocabulary'][$this->norm->fold($x)]),
            'any_of_regex' => $this->anyOf($d['id'], $x),
            default => throw new \RuntimeException("unknown validator {$d['validator']}"),
        };
    }

    private function anyOf(string $id, string $x): bool|string
    {
        foreach ($this->patternMaps[$id] ?? [] as $name => $re) {
            if (preg_match($re, $x) === 1) {
                return (string) $name;
            }
        }
        return false;
    }

    public static function normalizeValue(string $v, ?string $op): string
    {
        return match ($op) {
            null => $v,
            'strip_dash_space' => str_replace(['-', ' '], '', $v),
            'strip_space' => str_replace(' ', '', $v),
            'strip_space_upper' => strtoupper(str_replace(' ', '', $v)),
            'strip_dash_space_upper' => strtoupper(str_replace(['-', ' '], '', $v)),
            'upper' => strtoupper($v),
            default => throw new \RuntimeException("unknown normalize op $op"),
        };
    }

    private static function prefilter(string $x, array $p): bool
    {
        if (isset($p['len']) && (strlen($x) < $p['len'][0] || strlen($x) > $p['len'][1])) {
            return false;
        }
        foreach ($p['contains'] ?? [] as $s) {
            if (!str_contains($x, $s)) {
                return false;
            }
        }
        if (isset($p['digits'])) {
            $dc = strlen(Validators::digitsOnly($x));
            if ($dc < $p['digits'][0] || $dc > $p['digits'][1]) {
                return false;
            }
        }
        if (isset($p['charset']) && strspn($x, $p['charset']) !== strlen($x)) {
            return false;
        }
        if (isset($p['starts_with'])) {
            $ok = false;
            foreach ($p['starts_with'] as $pre) {
                if (str_starts_with($x, $pre)) {
                    $ok = true;
                    break;
                }
            }
            if (!$ok) {
                return false;
            }
        }
        if (($p['has_digit'] ?? false) && strpbrk($x, '0123456789') === false) {
            return false;
        }
        if (($p['has_letter'] ?? false) && !preg_match('/\p{L}/u', $x)) {
            return false;
        }
        return true;
    }
}

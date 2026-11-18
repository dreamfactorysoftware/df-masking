<?php
declare(strict_types=1);

namespace DreamFactory\Core\Masking\Classifier;

/**
 * Column-scope person-name test: most values are 1-4 capitalized tokens AND most have a
 * known given name first or a known surname last. Never strong: cities and products collide.
 */
final class NameLexicon
{
    private const HONORIFICS = ['mr', 'mrs', 'ms', 'miss', 'mx', 'dr', 'prof', 'sir', 'madam', 'mme', 'mlle', 'sr', 'sra', 'srta', 'herr', 'frau', 'dott', 'dottssa', 'ing', 'rev', 'fr'];
    private const SUFFIXES = ['jr', 'sr', 'ii', 'iii', 'iv', 'phd', 'md', 'esq', 'dds', 'cpa'];
    /** Last tokens that mark a street, organisation or place, never a person. */
    private const NOT_PERSON_TAIL = ['street', 'st', 'avenue', 'ave', 'road', 'rd', 'lane', 'drive', 'boulevard', 'blvd', 'way', 'court', 'place', 'square', 'park', 'parkway', 'highway',
        'inc', 'llc', 'ltd', 'limited', 'corp', 'corporation', 'co', 'company', 'gmbh', 'ag', 'sa', 'srl', 'spa', 'bv', 'nv', 'plc', 'group', 'holdings', 'partners', 'associates', 'foundation', 'university', 'college', 'school', 'hospital', 'bank',
        'city', 'county', 'beach', 'springs', 'heights', 'valley', 'falls', 'island', 'islands', 'hills', 'airport', 'station', 'stadium', 'arena', 'center', 'centre'];

    /**
     * @param list<string> $values non-null values
     * @param array<string,true> $given
     * @param array<string,true> $surnames
     * @return array{pass:bool, pct:int, valid:int, stats:array<string,int>}
     */
    public static function evaluate(array $values, array $p, array $given, array $surnames, Normalizer $norm): array
    {
        [$minTok, $maxTok] = $p['tokens'] ?? [1, 4];
        $n = count($values);
        $minCap = $p['min_capitalized_pct'] ?? 60;
        // Cheap upper bound first: a value can only qualify if it is short and starts with an uppercase letter.
        $maybe = 0;
        foreach ($values as $v) {
            if (strlen($v) <= 80 && (ctype_upper($v[0]) || (ord($v[0]) > 127 && preg_match('/^\p{Lu}/u', $v)))) {
                $maybe++;
            }
        }
        $lowerOk = false;
        if ($n > 0 && $maybe * 100 < $minCap * $n) {
            // Lower-case name columns are accepted only with a much stronger lexicon signal.
            $lowerOk = self::lowercaseLexiconPct($values, $given, $surnames, $norm) >= ($p['min_lexicon_pct_uncapitalized'] ?? 80);
        }
        if ($n === 0 || ($maybe * 100 < $minCap * $n && !$lowerOk)) {
            return ['pass' => false, 'pct' => 0, 'valid' => 0, 'stats' => ['capitalized_pct' => $n ? intdiv($maybe * 100, $n) : 0, 'lexicon_pct' => 0]];
        }
        $hon = array_fill_keys(self::HONORIFICS, true) + array_fill_keys(self::SUFFIXES, true);
        $cap = $lex = 0;
        foreach ($values as $v) {
            if (strlen($v) > 80) {
                continue;
            }
            $v = trim($v);
            if (substr_count($v, ',') === 1) {
                [$a, $b] = array_map('trim', explode(',', $v));
                if ($a !== '' && $b !== '') {
                    $v = $b . ' ' . $a; // "Last, First"
                }
            }
            $toks = preg_split('/\s+/u', $v, -1, PREG_SPLIT_NO_EMPTY) ?: [];
            $core = [];
            foreach ($toks as $t) {
                $f = str_replace(['.', "'", '’'], '', $norm->fold($t));
                if (isset($hon[$f])) {
                    continue;
                }
                $core[] = $t;
            }
            $k = count($core);
            if ($k < $minTok || $k > $maxTok) {
                continue;
            }
            $allCap = true;
            foreach ($core as $t) {
                if (!preg_match("/^\\p{Lu}[\\p{L}'’.\\-]*$/u", $t)) {
                    $allCap = false;
                    break;
                }
            }
            if ($allCap) {
                $cap++;
            }
            $names = array_values(array_filter($core, static fn ($t) => mb_strlen(rtrim($t, '.')) > 1 || !str_ends_with($t, '.')));
            if ($names === []) {
                continue;
            }
            $first = self::keys($names[0], $norm);
            $last = self::keys($names[count($names) - 1], $norm);
            if ($k > 1 && in_array($last[0], self::NOT_PERSON_TAIL, true)) {
                continue;
            }
            $hit = self::anyIn($first, $given) || self::anyIn($last, $surnames) || ($k === 1 && (self::anyIn($first, $surnames)));
            if ($hit) {
                $lex++;
            }
        }
        $capPct = $n ? intdiv($cap * 100, $n) : 0;
        $lexPct = $n ? intdiv($lex * 100, $n) : 0;
        $pass = $n > 0 && ($capPct >= $minCap || $lowerOk) && $lexPct >= ($p['min_lexicon_pct'] ?? 60);
        return ['pass' => $pass, 'pct' => $pass ? $lexPct : 0, 'valid' => $pass ? $lex : 0, 'stats' => ['capitalized_pct' => $capPct, 'lexicon_pct' => $lexPct]];
    }

    private static function lowercaseLexiconPct(array $values, array $given, array $surnames, Normalizer $norm): int
    {
        $hit = 0;
        foreach ($values as $v) {
            $toks = preg_split('/\s+/u', trim($v), -1, PREG_SPLIT_NO_EMPTY) ?: [];
            if ($toks === [] || count($toks) > 4 || strlen($v) > 80 || !preg_match('/^[\p{L}\s\'’.-]+$/u', $v)) {
                continue;
            }
            $f = self::keys($toks[0], $norm);
            $l = self::keys($toks[count($toks) - 1], $norm);
            if (self::anyIn($f, $given) || self::anyIn($l, $surnames)) {
                $hit++;
            }
        }
        return intdiv($hit * 100, count($values));
    }

    /** @return list<string> folded lookup keys for a token, including hyphen parts */
    private static function keys(string $t, Normalizer $norm): array
    {
        $f = preg_replace("/['’.]/u", '', $norm->fold($t)) ?? '';
        $out = [$f];
        foreach (explode('-', $f) as $part) {
            if ($part !== '' && $part !== $f) {
                $out[] = $part;
            }
        }
        return $out;
    }

    private static function anyIn(array $keys, array $set): bool
    {
        foreach ($keys as $k) {
            if (isset($set[$k])) {
                return true;
            }
        }
        return false;
    }
}

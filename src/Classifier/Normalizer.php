<?php
declare(strict_types=1);

namespace DreamFactory\Core\Masking\Classifier;

/**
 * Identifier normalization. mbstring + PCRE only: no intl,
 * no iconv //TRANSLIT, so output is identical on every PHP build.
 */
final class Normalizer
{
    /** @var array<string,string> */
    private array $foldMap;
    /** @var array<string,true> */
    private array $stripPrefixes;
    /** @var array<string,true> */
    private array $compounds;
    /** @var array<string,list<string>> */
    private array $abbr;
    /** @var array<string,true> */
    private array $protected;
    /** @var array<string,true> */
    private array $vocab;
    /** @var array<string,true> */
    private array $segVocab = [];
    private int $minTokenLen;
    /** @var array<string,array> */
    private array $cache = [];
    /** @var array<string,?list<string>> */
    private array $segCache = [];
    /** @var array<string,string> */
    private array $foldCache = [];

    public function __construct(RulePack $pack)
    {
        $cfg = $pack->normalizerConfig();
        $this->foldMap = FoldTable::MAP + ($cfg['fold_extra'] ?? []);
        $this->stripPrefixes = array_fill_keys($cfg['strip_prefixes'] ?? [], true);
        $this->compounds = array_fill_keys($cfg['compounds'] ?? [], true);
        $this->abbr = $cfg['abbreviations'] ?? [];
        $this->protected = array_fill_keys($cfg['protected_words'] ?? [], true);
        $this->vocab = $pack->vocab();
        $seg = $cfg['segment'] ?? [];
        $this->minTokenLen = (int) ($seg['min_token_len'] ?? 6);
        $minPiece = (int) ($seg['min_piece_len'] ?? 4);
        $short = array_fill_keys($seg['short_pieces'] ?? [], true);
        foreach ($this->vocab as $w => $_) {
            $w = (string) $w;
            if (preg_match('/^\p{L}+$/u', $w) && (mb_strlen($w) >= $minPiece || isset($short[$w]))) {
                $this->segVocab[$w] = true;
            }
        }
        foreach ($short as $w => $_) {
            $this->segVocab[(string) $w] = true;
        }
        // Run-together vocabulary entries (creditcard, cellphone) are not used as
        // segmentation pieces, so creditcardexpiration splits as credit|card|expiration.
        $compoundEntries = [];
        foreach ($this->segVocab as $w => $_) {
            $parts = $this->cover((string) $w, true);
            if ($parts !== null && count($parts) >= 2) {
                $compoundEntries[] = (string) $w;
            }
        }
        foreach ($compoundEntries as $w) {
            unset($this->segVocab[$w]);
        }
        $this->segCache = [];
    }

    /**
     * @return array{tokens:list<string>, plural:list<bool>, ordinal:bool, folded:string}
     */
    public function normalize(string $identifier, bool $isIdentifier = true): array
    {
        $ck = ($isIdentifier ? 'i:' : 't:') . $identifier;
        if (isset($this->cache[$ck])) {
            return $this->cache[$ck];
        }
        $s = $identifier;
        if (!mb_check_encoding($s, 'UTF-8')) {
            $s = mb_convert_encoding($s, 'UTF-8', 'Windows-1252');
        }
        // 2. invisibles + full width
        $s = preg_replace('/[\x{200B}-\x{200D}\x{FEFF}\x{00AD}]/u', '', $s) ?? $s;
        $s = preg_replace_callback('/[\x{FF01}-\x{FF5E}]/u', static fn ($m) => mb_chr(mb_ord($m[0]) - 0xFEE0), $s) ?? $s;
        // 3. unqualify
        $s = str_replace(['"', '`', '[', ']'], '', $s);
        $dot = $isIdentifier ? strrpos($s, '.') : false;
        if ($dot !== false) {
            $s = substr($s, $dot + 1);
        }
        // 4. case and digit boundaries (before folding so camel case survives)
        $s = preg_replace('/(\p{Ll})(\p{Lu})/u', '$1 $2', $s) ?? $s;
        $s = preg_replace('/(\p{Lu})(\p{Lu}\p{Ll})/u', '$1 $2', $s) ?? $s;
        $s = preg_replace('/(\p{L})(\p{N})/u', '$1 $2', $s) ?? $s;
        $s = preg_replace('/(\p{N})(\p{L})/u', '$1 $2', $s) ?? $s;
        // 5-6. fold + lowercase
        $s = $this->fold($s);
        // 7. tokenize
        $raw = preg_split('/[^\p{L}\p{N}]+/u', $s, -1, PREG_SPLIT_NO_EMPTY) ?: [];
        // 8. compounds (single left-to-right pass)
        $toks = [];
        for ($i = 0, $n = count($raw); $i < $n; $i++) {
            if ($i + 1 < $n && isset($this->compounds[$raw[$i] . $raw[$i + 1]])) {
                $toks[] = $raw[$i] . $raw[$i + 1];
                $i++;
            } else {
                $toks[] = $raw[$i];
            }
        }
        // 9. ordinals
        $ordinal = false;
        $t2 = [];
        foreach ($toks as $t) {
            if (preg_match('/^\d+$/', $t)) {
                $ordinal = true;
                continue;
            }
            $t2[] = $t;
        }
        // 10. abbreviations (single, non-recursive pass)
        $t3 = [];
        foreach ($t2 as $t) {
            foreach ($this->abbr[$t] ?? [$t] as $x) {
                $t3[] = $x;
            }
        }
        // 11-12. singularize / segment
        $tokens = [];
        $plural = [];
        foreach ($t3 as $t) {
            if (isset($this->vocab[$t]) || isset($this->protected[$t])) {
                $tokens[] = $t;
                $plural[] = false;
                continue;
            }
            $sg = self::singular($t);
            if ($sg !== null && isset($this->vocab[$sg])) {
                $tokens[] = $sg;
                $plural[] = true;
                continue;
            }
            $pieces = (mb_strlen($t) >= $this->minTokenLen && preg_match('/^\p{L}+$/u', $t)) ? $this->cover($t, false) : null;
            if ($pieces === null || count($pieces) < 2) {
                $tokens[] = $t;
                $plural[] = false;
                continue;
            }
            foreach ($pieces as $p) {
                $pl = false;
                if (!isset($this->segVocab[$p])) {
                    $sg = self::singular($p);
                    if ($sg !== null && isset($this->vocab[$sg])) {
                        $p = $sg;
                        $pl = true;
                    }
                }
                foreach ($this->abbr[$p] ?? [$p] as $x) {
                    $tokens[] = $x;
                    $plural[] = $pl;
                }
            }
        }
        // 13. prefix strip
        if (count($tokens) > 1 && isset($this->stripPrefixes[$tokens[0]])) {
            array_shift($tokens);
            array_shift($plural);
        }
        return $this->cache[$ck] = ['tokens' => $tokens, 'plural' => $plural, 'ordinal' => $ordinal, 'folded' => $s];
    }

    /** Fold accents (FoldTable + pack extras), strip combining marks, lowercase. */
    public function fold(string $s): string
    {
        if (isset($this->foldCache[$s])) {
            return $this->foldCache[$s];
        }
        if (count($this->foldCache) > 50000) {
            $this->foldCache = [];
        }
        $in = $s;
        if (preg_match('/[^\x00-\x7F]/', $s) !== 1) {
            return $this->foldCache[$in] = strtolower($s);
        }
        $s = strtr($s, $this->foldMap);
        $s = preg_replace('/\p{Mn}+/u', '', $s) ?? $s;
        $s = mb_strtolower($s, 'UTF-8');
        return $this->foldCache[$in] = (preg_replace('/\p{Mn}+/u', '', $s) ?? $s);
    }

    /**
     * Fewest-pieces full cover of $t by segmentation vocabulary (ties: longer first
     * piece). A piece may also be a plural of a vocabulary word. null = no cover.
     * @return ?list<string>
     */
    private function cover(string $t, bool $excludeSelf): ?array
    {
        $key = ($excludeSelf ? '1' : '0') . $t;
        if (array_key_exists($key, $this->segCache)) {
            return $this->segCache[$key];
        }
        $len = strlen($t);
        $best = [$len => []];
        for ($i = $len - 1; $i >= 0; $i--) {
            $cand = null;
            for ($j = $len; $j > $i; $j--) {
                if (!array_key_exists($j, $best) || $best[$j] === null) {
                    continue;
                }
                $piece = substr($t, $i, $j - $i);
                if ($excludeSelf && $i === 0 && $j === $len) {
                    continue;
                }
                if (!$this->isPiece($piece)) {
                    continue;
                }
                $c = array_merge([$piece], $best[$j]);
                if ($cand === null || count($c) < count($cand)) {
                    $cand = $c;
                }
            }
            $best[$i] = $cand;
        }
        return $this->segCache[$key] = $best[0] ?? null;
    }

    private function isPiece(string $p): bool
    {
        if (isset($this->segVocab[$p])) {
            return true;
        }
        $sg = self::singular($p);
        return $sg !== null && isset($this->segVocab[$sg]);
    }

    /** English plural stripping; caller accepts it only if the result is vocabulary. */
    public static function singular(string $t): ?string
    {
        $n = strlen($t);
        if ($n <= 3) {
            return null;
        }
        if (str_ends_with($t, 'ies')) {
            return substr($t, 0, -3) . 'y';
        }
        if (str_ends_with($t, 'sses')) {
            return substr($t, 0, -2);
        }
        if (str_ends_with($t, 'xes') || str_ends_with($t, 'ches') || str_ends_with($t, 'shes')) {
            return substr($t, 0, -2);
        }
        if (str_ends_with($t, 's') && !str_ends_with($t, 'ss') && !str_ends_with($t, 'us') && !str_ends_with($t, 'is')) {
            return substr($t, 0, -1);
        }
        return null;
    }
}

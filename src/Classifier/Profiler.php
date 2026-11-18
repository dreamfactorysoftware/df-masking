<?php
declare(strict_types=1);

namespace DreamFactory\Core\Masking\Classifier;

/**
 * Per-column value profile. Everything returned is a count, a percentage or a
 * character-class shape; no value (or substring of one) ever leaves this class.
 */
final class Profiler
{
    public const SHAPE_MAX_LEN = 64;

    /**
     * @param list<string> $values non-null values
     * @return array{non_null:int, distinct:int, len_p50:int, len_p95:int, prose_pct:int, json_pct:int, shapes:list<array{0:string,1:int}>, kinds:array<string,int>, json_docs:list<array>}
     */
    public static function profile(array $values, bool $wantText): array
    {
        $n = count($values);
        $out = ['non_null' => $n, 'distinct' => count(array_unique($values)), 'len_p50' => 0, 'len_p95' => 0, 'prose_pct' => 0, 'json_pct' => 0, 'shapes' => [], 'kinds' => ['numeric' => 0, 'date' => 0, 'boolean' => 0], 'json_docs' => []];
        if ($n === 0) {
            return $out;
        }
        $lens = [];
        $shapes = [];
        $numeric = $date = $bool = $prose = $json = 0;
        foreach ($values as $v) {
            $len = mb_strlen($v);
            $lens[] = $len;
            if ($len <= self::SHAPE_MAX_LEN) {
                $s = self::shape($v);
                $shapes[$s] = ($shapes[$s] ?? 0) + 1;
            }
            if (preg_match('/^[-+]?\d+(?:\.\d+)?$/', $v)) {
                $numeric++;
            } elseif ($len <= 40 && Validators::parseDate($v) !== null) {
                $date++;
            }
            if (in_array(strtolower($v), ['t', 'f', 'true', 'false', 'yes', 'no', 'y', 'n'], true)) {
                $bool++;
            }
            if ($wantText) {
                if ($len >= 2 && ($v[0] === '{' || $v[0] === '[' || ltrim($v)[0] === '{' || ltrim($v)[0] === '[')) {
                    $doc = json_decode($v, true);
                    if (is_array($doc)) {
                        $json++;
                        $out['json_docs'][] = $doc;
                        continue;
                    }
                }
                if (self::isProse($v)) {
                    $prose++;
                }
            }
        }
        sort($lens);
        $out['len_p50'] = $lens[intdiv(($n - 1) * 50, 100)];
        $out['len_p95'] = $lens[intdiv(($n - 1) * 95, 100)];
        $out['prose_pct'] = intdiv($prose * 100, $n);
        $out['json_pct'] = intdiv($json * 100, $n);
        $out['kinds'] = ['numeric' => intdiv($numeric * 100, $n), 'date' => intdiv($date * 100, $n), 'boolean' => intdiv($bool * 100, $n)];
        uksort($shapes, static fn ($a, $b) => ($shapes[$b] <=> $shapes[$a]) ?: strcmp((string) $a, (string) $b));
        foreach (array_slice($shapes, 0, 5, true) as $s => $c) {
            $out['shapes'][] = [(string) $s, intdiv($c * 100, $n)];
        }
        return $out;
    }

    /** 4+ whitespace-separated tokens and at least 60% letters among non-space characters. */
    public static function isProse(string $v): bool
    {
        if (preg_match_all('/\S+/u', $v) < 4) {
            return false;
        }
        $nonSpace = preg_match_all('/\S/u', $v);
        $letters = preg_match_all('/\p{L}/u', $v);
        return $nonSpace > 0 && $letters * 100 >= 60 * $nonSpace;
    }

    /**
     * Character-class shape: digit->9, letter runs->A|a|A+|a+|Aa+ (case pattern only),
     * ASCII punctuation/space kept, runs of 4+ identical punctuation collapsed, anything
     * else -> '?'. Only for values of 64 characters or fewer.
     */
    public static function shape(string $v): string
    {
        $s = preg_replace('/[^\p{L}\p{N}\x20-\x7E]/u', '?', $v) ?? $v;
        $s = preg_replace('/\p{N}/u', '9', $s) ?? $s;
        $s = preg_replace_callback('/([\x20-\x2F\x3A-\x40\x5B-\x60\x7B-\x7E])\1{3,}/', static fn ($m) => $m[1] . '{' . strlen($m[0]) . '}', $s) ?? $s;
        return preg_replace_callback('/\p{L}+/u', static function ($m): string {
            $p = $m[0];
            if (preg_match('/^\p{Lu}+$/u', $p)) {
                return mb_strlen($p) === 1 ? 'A' : 'A+';
            }
            if (preg_match('/^\p{Ll}+$/u', $p)) {
                return mb_strlen($p) === 1 ? 'a' : 'a+';
            }
            if (preg_match('/^\p{Lu}/u', $p)) {
                return 'Aa+';
            }
            return preg_match('/^\p{Ll}/u', $p) ? 'a+' : 'L+';
        }, $s) ?? $s;
    }
}

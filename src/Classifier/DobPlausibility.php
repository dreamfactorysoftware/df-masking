<?php
declare(strict_types=1);

namespace DreamFactory\Core\Masking\Classifier;

/**
 * Column-scope test: do these dates look like a population's birth dates?
 * Integer statistics only; the reference date is an explicit input (determinism).
 */
final class DobPlausibility
{
    /**
     * @param list<?string> $values   row-aligned sampled values (null = SQL NULL)
     * @param ?list<?string> $created row-aligned created/registered timestamps, if a sibling exists
     * @param array{0:int,1:int,2:int} $ref reference date [Y, m, d]
     * @return array{pass:bool, pct:int, valid:int, stats:array<string,int>}
     */
    public static function evaluate(array $values, ?array $created, array $ref, array $p): array
    {
        $n = 0;
        $parsed = [];
        $total = 0;
        foreach ($values as $v) {
            $total += $v !== null ? 1 : 0;
        }
        $maxMiss = $total - intdiv($total * ($p['min_parse_pct'] ?? 80) + 99, 100);
        $miss = 0;
        foreach ($values as $i => $v) {
            if ($v === null) {
                continue;
            }
            $n++;
            $d = Validators::parseDate($v);
            if ($d !== null) {
                $parsed[$i] = $d;
            } elseif (++$miss > $maxMiss) {
                return ['pass' => false, 'pct' => 0, 'valid' => 0, 'stats' => ['non_null' => $total, 'parse_pct' => 0, 'failed' => 'parse']];
            }
        }
        $stats = ['non_null' => $n, 'parse_pct' => 0];
        $fail = static fn (string $why) => ['pass' => false, 'pct' => 0, 'valid' => 0, 'stats' => $stats + ['failed' => $why]];
        if ($n === 0) {
            return $fail('no_values');
        }
        $pc = count($parsed);
        $stats['parse_pct'] = intdiv($pc * 100, $n);
        if ($stats['parse_pct'] < ($p['min_parse_pct'] ?? 80) || $pc === 0) {
            return $fail('parse');
        }
        $refDay = self::days($ref[0], $ref[1], $ref[2]);
        $plausible = $recent = $withTime = $nonMidnight = 0;
        $years = [];
        foreach ($parsed as $d) {
            $years[] = $d['y'];
            $day = self::days($d['y'], $d['m'], min($d['d'], 28));
            $age = $ref[0] - $d['y'] - ((($ref[1] * 100 + $ref[2]) < ($d['m'] * 100 + $d['d'])) ? 1 : 0);
            if ($day <= $refDay && $age >= 0 && $age <= ($p['max_age'] ?? 120)) {
                $plausible++;
            }
            if ($refDay - $day >= 0 && $refDay - $day <= 365) {
                $recent++;
            }
            if ($d['time']) {
                $withTime++;
                if (!$d['midnight']) {
                    $nonMidnight++;
                }
            }
        }
        sort($years);
        $stats['plausible_pct'] = intdiv($plausible * 100, $pc);
        $stats['distinct_years'] = count(array_unique($years));
        $stats['year_iqr'] = $years[intdiv(3 * ($pc - 1), 4)] - $years[intdiv($pc - 1, 4)];
        $stats['recent_365d_pct'] = intdiv($recent * 100, $pc);
        $stats['non_midnight_pct'] = $withTime > 0 ? intdiv($nonMidnight * 100, $withTime) : 0;
        if ($stats['plausible_pct'] < ($p['min_plausible_pct'] ?? 95)) {
            return $fail('implausible_age');
        }
        if ($stats['distinct_years'] < ($p['min_distinct_years'] ?? 5)) {
            return $fail('few_years');
        }
        if ($stats['year_iqr'] < ($p['min_year_iqr'] ?? 8)) {
            return $fail('narrow_years');
        }
        if ($stats['recent_365d_pct'] > ($p['max_recent_365d_pct'] ?? 10)) {
            return $fail('recent');
        }
        if ($stats['non_midnight_pct'] > ($p['max_non_midnight_pct'] ?? 50)) {
            return $fail('has_times');
        }
        if ($created !== null) {
            $both = $gap = 0;
            foreach ($parsed as $i => $d) {
                $c = isset($created[$i]) ? Validators::parseDate((string) $created[$i]) : null;
                if ($c === null) {
                    continue;
                }
                $both++;
                if ($c['y'] - $d['y'] >= ($p['created_gap_years'] ?? 10)) {
                    $gap++;
                }
            }
            if ($both >= 5) {
                $stats['created_gap_pct'] = intdiv($gap * 100, $both);
                if ($stats['created_gap_pct'] < ($p['min_created_gap_pct'] ?? 90)) {
                    return $fail('close_to_created');
                }
            }
        }
        return ['pass' => true, 'pct' => intdiv($plausible * 100, $n), 'valid' => $plausible, 'stats' => $stats];
    }

    /** Days from civil date (proleptic Gregorian), integer-only. */
    public static function days(int $y, int $m, int $d): int
    {
        $y -= $m <= 2 ? 1 : 0;
        $era = intdiv($y >= 0 ? $y : $y - 399, 400);
        $yoe = $y - $era * 400;
        $doy = intdiv(153 * ($m + ($m > 2 ? -3 : 9)) + 2, 5) + $d - 1;
        $doe = $yoe * 365 + intdiv($yoe, 4) - intdiv($yoe, 100) + $doy;
        return $era * 146097 + $doe - 719468;
    }
}

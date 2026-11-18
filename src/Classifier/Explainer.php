<?php
declare(strict_types=1);

namespace DreamFactory\Core\Masking\Classifier;

/**
 * Deterministic "why" lines built only from evidence: tokens, rule ids, counts, percentages.
 * Evidence::lines() turns them into the admin UI evidence ledger.
 */
final class Explainer
{
    public function __construct(private readonly RulePack $pack)
    {
    }

    /** @return list<string> */
    public function lines(array $f, array $r, array $ev, string $mode): array
    {
        $out = [];
        $best = $r['best'];
        $tok = implode(' ', $f['norm']['tokens']);
        $m = $ev['name']['match'] ?? null;
        if ($m !== null) {
            $out[] = sprintf("%+d name '%s' -> [%s] %s \"%s\" (%s)", $m['points'], $f['name'], $tok, $this->how($m['strength'], (string) $m['how']), implode(' ', $m['seq']), $m['rule']);
        } else {
            $blocked = ($ev['name']['suppressed'] ?? []) !== [] || ($ev['name']['gated'] ?? []) !== [];
            $out[] = sprintf("+0 name '%s' -> [%s] %s", $f['name'], $tok, $blocked ? 'has no usable class phrase' : 'matches no class phrase');
        }
        foreach ($ev['name']['suppressed'] ?? [] as $s) {
            $out[] = sprintf('. name phrase from %s suppressed by negative "%s"', $s['rule'], implode(' ', $s['by']));
        }
        foreach ($ev['name']['gated'] ?? [] as $g) {
            $out[] = sprintf('. type %s blocked by the type gate (%s)', $g['rule'], $g['reason']);
        }
        if ($f['surrogate']) {
            $out[] = sprintf('. type surrogate key (%s, PK/FK/id) never classifies', $f['df']);
        }
        if ($mode === Engine::MODE_HYBRID && !$f['surrogate']) {
            $nn = count($f['values']);
            if (($ev['sample']['rows'] ?? 0) > 0 && $nn < 5) {
                $out[] = sprintf('. sample only %d non-null of %d sampled rows; value evidence needs at least 5', $nn, $ev['sample']['rows']);
            }
            $d = $best['detector'] ?? null;
            if ($d !== null) {
                $out[] = $this->detectorLine($d, (int) $best['value'], $nn, (int) ($ev['sample']['distinct'] ?? 0));
            }
            foreach ($f['detectors'] as $x) {
                if ($x['id'] === 'card.luhn_iin' && ($best['class'] ?? null) === 'card_number' && $x['matched'] > 0 && $x['pct'] < 30) {
                    $out[] = sprintf('. values %d/%d (%d%%) pass Luhn+IIN (card.luhn_iin): likely test or synthetic card data', $x['valid'], $nn, $x['pct']);
                }
            }
            if (($best['penalty'] ?? 0) > 0) {
                $out[] = sprintf('-%d values contradict the class (%s)', $best['penalty'], $best['penalty_why']);
            }
            foreach ($r['cands'] as $c) {
                if ($c !== $best && $c['penalty'] > 0 && $c['name'] > 0) {
                    $out[] = sprintf('. values contradict %s: name said %d, values penalty -%d (%s)', $c['class'], $c['name'], $c['penalty'], $c['penalty_why']);
                }
            }
            if (($best['free_why'] ?? null) !== null) {
                $w = $best['free_why'];
                $out[] = match ($w['by'] ?? '') {
                    'spans_strong' => sprintf('%+d text validated PII spans in %d rows (%s)', $best['value'], $w['strong_rows'], implode(', ', array_keys($ev['spans'] ?? []))),
                    'spans_some' => sprintf('%+d text a few PII spans (strong rows %d, medium rows %d)', $best['value'], $w['strong_rows'], $w['medium_rows']),
                    'json_path' => sprintf('%+d json key path %s classified %s (%d)', $best['value'], $ev['json_paths'][0]['path'] ?? '?', $ev['json_paths'][0]['class'] ?? '?', $ev['json_paths'][0]['total'] ?? 0),
                    'person_table_prose' => sprintf('%+d text prose in a person table with no validated spans: may contain names', $best['value']),
                    default => sprintf('%+d text', $best['value']),
                };
            }
            foreach ($r['discovery_suppressed'] as $cls => $why) {
                $out[] = sprintf('. values value-only %s evidence ignored: %s', $cls, $why === 'date_role_named' ? 'the name says this is another kind of date' : 'the column name already explains its content');
            }
        }
        $total = $best['total'] ?? 0;
        if ($r['verdict'] === 'clear') {
            $out[] = ($best !== null && $total >= 15)
                ? sprintf('= %d -> clear (below %d; suggestion: %s)', $total, $this->band($mode), $best['class'])
                : sprintf('= %d -> clear', $total);
        } else {
            $c = $this->pack->cls($r['class']);
            $out[] = sprintf('= %d -> %s %s (%s), mask %s', $total, strtoupper($r['verdict']), $r['class'], $c['tier'], $c['mask']);
        }
        if (($ev['runner_up'] ?? []) !== []) {
            $out[] = '. also considered: ' . implode(', ', array_map(static fn ($x) => $x['class'] . ' ' . $x['total'], $ev['runner_up']));
        }
        return $out;
    }

    private function band(string $mode): int
    {
        $sc = $this->pack->scoring();
        return $mode === Engine::MODE_HYBRID ? $sc['bands']['review'] : $sc['name_only']['review'];
    }

    private function how(string $strength, string $how): string
    {
        return match (true) {
            $how === 'strong' => 'strong phrase',
            $how === 'comment' => 'strong phrase in the column comment',
            $how === 'plural' => 'weak phrase on a plural word, not promoted',
            $how === 'weak' => 'weak phrase without supporting context',
            str_starts_with($how, 'promoted:') => 'weak phrase promoted by ' . substr($how, 9),
            str_starts_with($how, 'modifier:') => $strength . " phrase followed by modifier '" . substr($how, 9) . "' (demoted)",
            default => $strength . ' phrase',
        };
    }

    private function detectorLine(array $d, int $pts, int $nn, int $distinct): string
    {
        $half = $distinct < (int) $this->pack->scoring()['value']['min_distinct_full'] ? sprintf(' (halved: %d distinct values)', $distinct) : '';
        if ($d['id'] === 'dob.plausible') {
            $s = $d['stats'];
            return isset($s['failed'])
                ? sprintf('%+d values date-of-birth plausibility failed (%s; parse %d%%)', $pts, $s['failed'], $s['parse_pct'] ?? 0)
                : sprintf('%+d values date-of-birth plausible: parse %d%%, %d distinct years, IQR %dy, %d%% recent%s', $pts, $s['parse_pct'], $s['distinct_years'], $s['year_iqr'], $s['recent_365d_pct'], $half);
        }
        if ($d['id'] === 'name.lexicon') {
            return sprintf('%+d values %d%% capitalized 1-4 token values, %d%% in the name lexicons (name.lexicon, %s)%s', $pts, $d['stats']['capitalized_pct'], $d['stats']['lexicon_pct'], $d['strength'], $half);
        }
        return sprintf('%+d values %d/%d (%d%%) pass %s (%s)%s', $pts, $d['valid'], $nn, $d['pct'], $d['id'], $d['strength'], $half);
    }
}

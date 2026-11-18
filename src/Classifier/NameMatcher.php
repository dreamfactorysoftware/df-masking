<?php
declare(strict_types=1);

namespace DreamFactory\Core\Masking\Classifier;

/**
 * Whole-token phrase matching. Never substring: score_credit does
 * not hit "card", average does not contain "age".
 *
 * A hit is an array:
 *   class, rule, seq, strength (strong|weak), start, end, on (column|comment),
 *   demoted_by (?string modifier), plural (single-token match on a plural word),
 *   person_prefix (token before the match is a person noun), promote_if, types, requires
 */
final class NameMatcher
{
    /** @var array<string,list<array>> first token => phrases */
    private array $index = [];
    /** @var array<string,list<list<string>>> class => negative sequences */
    private array $negatives = [];
    /** @var array<string,list<array>> class => hint phrases (free text) */
    private array $hints = [];
    /** @var array<string,true> */
    private array $modifiers;
    /** @var array<string,true> */
    private array $personNouns;
    /** @var array<string,true> */
    private array $weakSingleName = [];

    public function __construct(private readonly RulePack $pack)
    {
        $ctx = $pack->context();
        $this->modifiers = array_fill_keys($ctx['modifiers'], true);
        $this->personNouns = array_fill_keys($ctx['person_nouns'], true);
        $order = 0;
        foreach ($pack->classes() as $class => $c) {
            foreach (['strong', 'weak'] as $strength) {
                foreach ($c['name'][$strength] ?? [] as $k => $p) {
                    $seq = RulePack::phraseSeq($p);
                    $opt = RulePack::phraseOpts($p);
                    if ($seq === []) {
                        continue;
                    }
                    $ph = [
                        'class' => $class, 'rule' => "$class.$strength.$k", 'seq' => $seq, 'len' => count($seq),
                        'strength' => $strength, 'promote_if' => $opt['promote_if'] ?? [], 'types' => $opt['types'] ?? null,
                        'requires' => $opt['requires'] ?? null, 'order' => $order++,
                        'modifiers_apply' => ($c['modifiers_apply'] ?? true) !== false,
                        'tier_rank' => $pack->tierRank($class), 'class_order' => $pack->classOrder($class),
                    ];
                    $this->index[$seq[0]][] = $ph;
                    if ($class === 'person_name' && $strength === 'weak' && count($seq) === 1) {
                        $this->weakSingleName[$seq[0]] = true;
                    }
                }
            }
            $this->negatives[$class] = array_map([RulePack::class, 'phraseSeq'], $c['name']['negative'] ?? []);
            foreach ($c['name']['hints'] ?? [] as $k => $p) {
                $this->hints[$class][] = ['rule' => "$class.hint.$k", 'seq' => RulePack::phraseSeq($p)];
            }
        }
    }

    /** True for a bare entity-name column ("name", "nombre", "nom" ...). */
    public function isBareEntityName(array $tokens): bool
    {
        return count($tokens) === 1 && isset($this->weakSingleName[$tokens[0]]);
    }

    /**
     * @param array{tokens:list<string>, plural:list<bool>, ordinal:bool} $norm
     * @param list<string> $qualifier extra leading tokens used ONLY for negative checks
     *                                (table noun for bare "name" columns: city.name -> "city name")
     * @return array{hits:list<array>, suppressed:list<array>, shadowed:list<array>}
     */
    public function match(array $norm, string $on = 'column', array $qualifier = []): array
    {
        $t = $norm['tokens'];
        $n = count($t);
        $occ = [];
        for ($i = 0; $i < $n; $i++) {
            foreach ($this->index[$t[$i]] ?? [] as $ph) {
                $len = $ph['len'];
                if ($i + $len > $n || array_slice($t, $i, $len) !== $ph['seq']) {
                    continue;
                }
                if ($ph['requires'] === 'ordinal' && !$norm['ordinal']) {
                    continue;
                }
                $j = $i + $len - 1;
                $next = $t[$j + 1] ?? null;
                $occ[] = $ph + [
                    'start' => $i, 'end' => $j, 'on' => $on,
                    'demoted_by' => ($ph['modifiers_apply'] && $next !== null && isset($this->modifiers[$next])) ? $next : null,
                    'plural' => $len === 1 && ($norm['plural'][$i] ?? false),
                    'person_prefix' => $i > 0 && isset($this->personNouns[$t[$i - 1]]),
                ];
            }
        }
        $suppressed = [];
        $live = [];
        $q = count($qualifier);
        $qt = array_merge($qualifier, $t);
        foreach ($occ as $o) {
            $neg = $this->negativeCover($t, $o['class'], $o['start'], $o['end'])
                ?? ($q > 0 ? $this->negativeCover($qt, $o['class'], $o['start'] + $q, $o['end'] + $q) : null);
            if ($neg !== null) {
                $suppressed[] = ['rule' => $o['rule'], 'class' => $o['class'], 'seq' => $o['seq'], 'by' => $neg];
                continue;
            }
            $live[] = $o;
        }
        usort($live, static fn ($a, $b) => [$b['end'], $b['len'], $a['strength'] === 'strong' ? 0 : 1, $b['tier_rank'], $a['class_order'], $a['order']]
            <=> [$a['end'], $a['len'], $b['strength'] === 'strong' ? 0 : 1, $a['tier_rank'], $b['class_order'], $b['order']]);
        $kept = [];
        $shadowed = [];
        foreach ($live as $o) {
            foreach ($kept as $k) {
                if ($o['start'] <= $k['end'] && $k['start'] <= $o['end']) {
                    $shadowed[] = ['rule' => $o['rule'], 'class' => $o['class'], 'by' => $k['rule']];
                    continue 2;
                }
            }
            $kept[] = $o;
        }
        return ['hits' => $kept, 'suppressed' => $suppressed, 'shadowed' => $shadowed];
    }

    /** Free-text hint phrases (notes, comment, payload ...) present in the tokens. */
    public function hints(array $tokens): array
    {
        $out = [];
        foreach ($this->hints as $list) {
            foreach ($list as $h) {
                $len = count($h['seq']);
                for ($i = 0; $i + $len <= count($tokens); $i++) {
                    if (array_slice($tokens, $i, $len) === $h['seq']) {
                        $out[] = $h['rule'];
                        break;
                    }
                }
            }
        }
        return $out;
    }

    /** @return ?list<string> the negative phrase whose occurrence covers [$s..$e] */
    private function negativeCover(array $t, string $class, int $s, int $e): ?array
    {
        $n = count($t);
        foreach ($this->negatives[$class] ?? [] as $neg) {
            $len = count($neg);
            for ($a = max(0, $e - $len + 1); $a <= $s && $a + $len <= $n; $a++) {
                if (array_slice($t, $a, $len) === $neg) {
                    return $neg;
                }
            }
        }
        return null;
    }
}

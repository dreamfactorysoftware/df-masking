<?php

namespace DreamFactory\Core\Masking\Scanner;

use DreamFactory\Core\Masking\Classifier\Evidence;
use DreamFactory\Core\Masking\Support\Catalog;
use DreamFactory\Core\Masking\Support\RulePattern;
use DreamFactory\Core\Masking\Support\Tables;
use Illuminate\Support\Facades\DB;

/**
 * Admin and baseline detection rules (dm_rule) applied on top of the built-in classifier.
 *
 *  - name rules match the column name (PCRE, case-insensitive, no delimiters);
 *  - value rules match sampled values, trimmed: a column matches when at least half of its
 *    sampled non-null values match (and at least VALUE_MIN_MATCHES do).
 *
 * Rules only ever ADD masking: a matching rule masks the column with the rule's class unless the
 * column is already masked at the same or a stricter level, in which case the match is noted in
 * the evidence. When several rules match, the strictest class wins (ties: oldest rule).
 * Every pattern evaluation goes through RulePattern (JIT off, lowered backtrack limit).
 */
final class Rules
{
    public const VALUE_MIN_MATCHES = 3;
    public const VALUE_MIN_PCT = 50;
    /** Score given to a column masked by a rule (the review/mask boundary). */
    public const RULE_SCORE = 70;

    /** @var list<array{id:int, match:string, pattern:string, compiled:string, class:string, source:string}> */
    private array $name = [];
    /** @var list<array{id:int, match:string, pattern:string, compiled:string, class:string, source:string}> */
    private array $value = [];

    /** @param iterable<object|array> $rows dm_rule rows */
    public function __construct(iterable $rows = [])
    {
        foreach ($rows as $row) {
            $r = (array) $row;
            $class = (string) ($r['class'] ?? '');
            $pattern = (string) ($r['pattern'] ?? '');
            $match = (string) ($r['match'] ?? '');
            if (!Catalog::has($class) || $pattern === '' || !in_array($match, ['name', 'value'], true)) {
                continue;
            }
            if (RulePattern::validate($pattern) !== null) {
                continue; // stored before validation tightened, or edited by hand: never evaluate it
            }
            $rule = [
                'id' => (int) ($r['id'] ?? 0),
                'match' => $match,
                'pattern' => $pattern,
                'compiled' => RulePattern::compile($pattern),
                'class' => $class,
                'source' => (string) ($r['source'] ?? 'admin'),
            ];
            if ($match === 'name') {
                $this->name[] = $rule;
            } else {
                $this->value[] = $rule;
            }
        }
        $byId = static fn ($a, $b) => $a['id'] <=> $b['id'];
        usort($this->name, $byId);
        usort($this->value, $byId);
    }

    /** Current rules from dm_rule (none when the table is missing). */
    public static function load(): self
    {
        try {
            return new self(DB::table(Tables::RULE)->orderBy('id')->get(['id', 'match', 'pattern', 'class', 'source']));
        } catch (\Throwable $e) {
            return new self();
        }
    }

    public function isEmpty(): bool
    {
        return $this->name === [] && $this->value === [];
    }

    public function hasValueRules(): bool
    {
        return $this->value !== [];
    }

    /** @return list<int> ids of the value rules (rules are added and deleted, never edited) */
    public function valueRuleIds(): array
    {
        return array_column($this->value, 'id');
    }

    /** Strictest name rule matching $column, or null. */
    public function matchName(string $column): ?array
    {
        $best = null;
        foreach ($this->name as $rule) {
            if (RulePattern::matches($rule['compiled'], $column) && ($best === null || self::classRank($rule['class']) > self::classRank($best['class']))) {
                $best = $rule;
            }
        }
        return $best;
    }

    /**
     * Strictest value rule matching the sampled values, with its match counts, or null.
     *
     * @param list<string> $values non-null sampled values
     * @return array{rule:array, matched:int, of:int}|null
     */
    public function matchValues(array $values): ?array
    {
        if ($values === [] || $this->value === []) {
            return null;
        }
        $best = null;
        foreach ($this->value as $rule) {
            $n = self::countMatches($rule['compiled'], $values);
            if (self::valueRuleMatches($n, count($values))
                && ($best === null || self::classRank($rule['class']) > self::classRank($best['rule']['class']))) {
                $best = ['rule' => $rule, 'matched' => $n, 'of' => count($values)];
            }
        }
        return $best;
    }

    /** The value-rule threshold, shared by scans and POST rule/test. */
    public static function valueRuleMatches(int $matched, int $nonNull): bool
    {
        return $matched >= self::VALUE_MIN_MATCHES && $matched * 100 >= self::VALUE_MIN_PCT * $nonNull;
    }

    /**
     * How many of $values match. Each value is trimmed first (SQL Server and Oracle CHAR(n)
     * values come space-padded, so an anchored ^...$ would never match); every value is still
     * one of the "of" in "N of M values match".
     *
     * @param list<string> $values
     */
    public static function countMatches(string $compiled, array $values): int
    {
        return RulePattern::withLimits(static function () use ($compiled, $values): int {
            $n = 0;
            foreach ($values as $v) {
                if (@preg_match($compiled, trim((string) $v)) === 1) {
                    $n++;
                }
            }
            return $n;
        });
    }

    /**
     * Applies matching rules to one column's automatic classification (Evidence::fromEngine shape
     * plus 'source'). Returns the result, possibly masked by a rule (source 'rule' or 'baseline').
     *
     * @param ?list<string> $values non-null sampled values, or null when the column was not sampled
     */
    public function apply(string $column, ?array $values, array $result): array
    {
        $result['source'] ??= 'detected';
        if ($this->isEmpty()) {
            return $result;
        }
        $hits = [];
        if (($r = $this->matchName($column)) !== null) {
            $hits[] = ['rule' => $r, 'line' => Evidence::line(self::RULE_SCORE, Evidence::KIND_CONTEXT, self::describe($r))];
        }
        if ($values !== null && ($v = $this->matchValues($values)) !== null) {
            $hits[] = ['rule' => $v['rule'], 'line' => Evidence::line(self::RULE_SCORE, Evidence::KIND_VALUES,
                sprintf('%s: %d of %d values match', self::describe($v['rule']), $v['matched'], $v['of']))];
        }
        if ($hits === []) {
            return $result;
        }
        usort($hits, static fn ($a, $b) => [self::classRank($b['rule']['class']), $a['rule']['id']] <=> [self::classRank($a['rule']['class']), $b['rule']['id']]);
        $best = $hits[0];
        $ruleClass = $best['rule']['class'];
        if (self::rank('masked', $ruleClass) > self::rank($result['verdict'], $result['class'])) {
            $result['verdict'] = 'masked';
            $result['class'] = $ruleClass;
            $result['tier'] = Catalog::tierOf($ruleClass);
            $result['score'] = max((int) $result['score'], self::RULE_SCORE);
            $result['source'] = str_starts_with($best['rule']['source'], 'baseline:') ? 'baseline' : 'rule';
            $result['evidence']['total'] = max((int) ($result['evidence']['total'] ?? 0), self::RULE_SCORE);
            $result['evidence']['lines'][] = $best['line'];
            array_shift($hits);
        }
        foreach ($hits as $h) {
            $line = $h['line'];
            $line['points'] = 0;
            $line['text'] = 'Also matches: ' . $line['text'];
            $result['evidence']['lines'][] = $line;
        }
        return $result;
    }

    /** "Custom rule (^|_)ssn$" / "Baseline rule (^|_)mrn$ (hipaa)". */
    public static function describe(array $rule): string
    {
        $kind = $rule['match'] === 'value' ? 'value rule' : 'rule';
        if (str_starts_with($rule['source'], 'baseline:')) {
            return sprintf('Baseline %s %s (%s)', $kind, $rule['pattern'], substr($rule['source'], 9));
        }
        return sprintf('Custom %s %s', $kind, $rule['pattern']);
    }

    /**
     * Strictness of a verdict + class, for add-only comparisons: clear < review < masked within a
     * tier, and any masked/review verdict of a stricter tier above a weaker tier.
     *
     * @return array{0:int,1:int,2:int}
     */
    public static function rank(string $verdict, ?string $class): array
    {
        if ($verdict === 'clear' || $class === null) {
            return [0, 0, 0];
        }
        return [1, self::classRank($class), $verdict === 'masked' ? 2 : 1];
    }

    /** Tier rank of a class: restricted 4, identity 3, quasi 2, free text 1, unknown 0. */
    public static function classRank(?string $class): int
    {
        return match ($class !== null ? Catalog::tierOf($class) : null) {
            Catalog::TIER_RESTRICTED => 4,
            Catalog::TIER_IDENTITY => 3,
            Catalog::TIER_QUASI => 2,
            Catalog::TIER_FREE_TEXT => 1,
            default => 0,
        };
    }
}

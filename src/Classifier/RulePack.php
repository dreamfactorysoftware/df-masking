<?php
declare(strict_types=1);

namespace DreamFactory\Core\Masking\Classifier;

/**
 * Versioned, data-only rule pack (resources/rules/pack.json + lexicons). Code references
 * validators by id; everything tunable (tokens, weights, thresholds) lives here.
 */
final class RulePack
{
    /** @var array<string,mixed> */
    private array $d;
    private string $sha;
    /** @var array<string,array<string,true>> */
    private array $lexicons = [];
    /** @var array<string,int> */
    private array $classOrder = [];
    /** @var array<string,true>|null */
    private ?array $vocab = null;

    private function __construct(array $d, string $sha, array $lexicons)
    {
        $this->d = $d;
        $this->sha = $sha;
        $this->lexicons = $lexicons;
        $i = 0;
        foreach (array_keys($d['classes']) as $c) {
            $this->classOrder[$c] = $i++;
        }
    }

    public static function load(string $path): self
    {
        $raw = @file_get_contents($path);
        if ($raw === false) {
            throw new \RuntimeException("rule pack not readable: $path");
        }
        $d = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        if (($d['format'] ?? null) !== 1) {
            throw new \RuntimeException('unsupported rule pack format');
        }
        $ctx = hash_init('sha256');
        hash_update($ctx, $raw);
        $lex = [];
        $names = array_keys($d['lexicons'] ?? []);
        sort($names);
        foreach ($names as $name) {
            $file = dirname($path) . '/' . $d['lexicons'][$name];
            $txt = @file_get_contents($file);
            if ($txt === false) {
                throw new \RuntimeException("lexicon not readable: $file");
            }
            hash_update($ctx, "\0" . $name . "\0" . $txt);
            $set = [];
            foreach (preg_split('/\R/', $txt) as $line) {
                $line = trim($line);
                if ($line !== '' && $line[0] !== '#') {
                    $set[$line] = true;
                }
            }
            $lex[$name] = $set;
        }
        return new self($d, hash_final($ctx), $lex);
    }

    public function version(): string { return (string) $this->d['version']; }
    public function sha256(): string { return $this->sha; }
    /** @return array<string,array> */
    public function classes(): array { return $this->d['classes']; }
    public function cls(string $id): array { return $this->d['classes'][$id]; }
    public function context(): array { return $this->d['context']; }
    public function scoring(): array { return $this->d['scoring']; }
    public function normalizerConfig(): array { return $this->d['normalizer']; }
    public function tierOf(string $class): string { return (string) $this->d['classes'][$class]['tier']; }
    public function tierRank(string $class): int { return (int) $this->d['tiers'][$this->tierOf($class)]['rank']; }
    public function classOrder(string $class): int { return $this->classOrder[$class] ?? PHP_INT_MAX; }

    /** @return array<string,true> */
    public function lexicon(string $name): array { return $this->lexicons[$name] ?? []; }

    /**
     * Every token that appears in any phrase, negative, hint, context list or
     * extra_vocab. Used by the segmenter and to decide when singularizing is safe.
     * @return array<string,true>
     */
    public function vocab(): array
    {
        if ($this->vocab !== null) {
            return $this->vocab;
        }
        $v = [];
        $add = static function (array $seq) use (&$v): void {
            foreach ($seq as $t) {
                if (is_string($t)) {
                    $v[$t] = true;
                }
            }
        };
        foreach ($this->d['classes'] as $c) {
            foreach (['strong', 'weak', 'negative', 'hints'] as $k) {
                foreach ($c['name'][$k] ?? [] as $p) {
                    $add(self::phraseSeq($p));
                }
            }
        }
        $ctx = $this->d['context'];
        foreach ($ctx['known_clear'] as $p) {
            $add($p);
        }
        foreach (['person_nouns', 'modifiers', 'address_siblings', 'date_roles', 'created_tokens'] as $k) {
            $add($ctx[$k] ?? []);
        }
        $n = $this->d['normalizer'];
        $add($n['segment']['extra_vocab'] ?? []);
        foreach ($n['abbreviations'] as $k => $exp) {
            $v[$k] = true;
            $add($exp);
        }
        ksort($v, SORT_STRING);
        return $this->vocab = $v;
    }

    /** A phrase is either ["tok", ...] or {"seq": [...], ...}. */
    public static function phraseSeq(mixed $p): array
    {
        if (is_array($p) && array_key_exists('seq', $p)) {
            return $p['seq'];
        }
        return is_array($p) ? array_values(array_filter($p, 'is_string')) : [];
    }

    public static function phraseOpts(mixed $p): array
    {
        return (is_array($p) && array_key_exists('seq', $p)) ? $p : [];
    }
}

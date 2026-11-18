<?php
declare(strict_types=1);

namespace DreamFactory\Core\Masking\Classifier;


/**
 * Deterministic two-signal column classifier: column-name phrases (whole tokens, never substrings)
 * plus validated sample values, with table context, combined into a 0-100 score per class.
 * Pure: no I/O. Samples are handed in by the caller and never retained; the output carries only
 * tokens, rule ids, counts, percentages and character-class shapes, never a value.
 *
 * Verdicts use the engine vocabulary (enforce|review|clear); Evidence maps them to the API
 * vocabulary (masked|review|clear).
 */
final class Engine
{
    public const MODE_HYBRID = 'hybrid';
    public const MODE_NAME_ONLY = 'name-only';
    private const INT_TYPES = ['integer', 'bigint', 'smallint', 'id', 'bigid', 'smallid', 'mediumid'];
    private const DATE_TYPES = ['date', 'timestamp', 'timestamptz', 'datetime', 'string'];

    private Normalizer $norm;
    private NameMatcher $matcher;
    private Detectors $det;
    private Explainer $explainer;
    private array $sc;
    /** @var array<string,true> */
    private array $personNouns;
    /** @var list<list<string>> */
    private array $knownClear;
    /** @var array<string,true> */
    private array $dateRoles;
    /** @var list<string> */
    private array $createdTokens;
    /** @var array{0:int,1:int,2:int} */
    private array $ref;

    public function __construct(private readonly RulePack $pack, string $referenceDate)
    {
        if (!preg_match('/^(\d{4})-(\d{2})-(\d{2})$/', $referenceDate, $m)) {
            throw new \InvalidArgumentException('reference date must be YYYY-MM-DD');
        }
        $this->ref = [(int) $m[1], (int) $m[2], (int) $m[3]];
        $this->norm = new Normalizer($pack);
        $this->matcher = new NameMatcher($pack);
        $this->det = new Detectors($pack, $this->norm);
        $this->explainer = new Explainer($pack);
        $this->sc = $pack->scoring();
        $ctx = $pack->context();
        $this->personNouns = array_fill_keys($ctx['person_nouns'], true);
        $this->knownClear = $ctx['known_clear'];
        $this->dateRoles = array_fill_keys($ctx['date_roles'], true);
        $this->createdTokens = $ctx['created_tokens'];
    }

    public function normalizer(): Normalizer
    {
        return $this->norm;
    }

    /**
     * @param list<TableMeta> $tables
     * @param null|callable(TableMeta):array{rows:list<array<string,?string>>, ordered:string|false, error:?string} $sample
     * @return array<string,array> "<dfTable>.<column>" => verdict
     */
    public function classifyDatabase(array $tables, ?callable $sample, string $mode, ?callable $onTable = null): array
    {
        usort($tables, static fn (TableMeta $a, TableMeta $b) => strcmp($a->dfName, $b->dfName));
        $contexts = $this->tableContexts($tables);
        $out = [];
        foreach ($tables as $t) {
            $tctx = $contexts[$t->dfName];
            $t0 = hrtime(true);
            $s = ($mode === self::MODE_HYBRID && $sample !== null) ? $sample($t) : null;
            $t1 = hrtime(true);
            foreach ($this->classifyTable($t, $tctx, $s, $mode) as $col => $v) {
                $out[$t->dfName . '.' . $col] = $v;
            }
            if ($onTable !== null) {
                $onTable($t, intdiv($t1 - $t0, 1000000), intdiv(hrtime(true) - $t1, 1000000), $s);
            }
            unset($s); // values never outlive the table
        }
        return $out;
    }

    /**
     * Table context for every table of one database: name tokens, whether the table holds people
     * (a person noun in its name), and whether it links to another person table by a foreign key.
     * Callers that classify table by table (the scanner streams samples) compute this once for the
     * whole database and pass each table's entry to classifyTable().
     *
     * @param list<TableMeta> $tables
     * @return array<string,array{tokens:list<string>, person_table:bool, person_linked:bool}> keyed by dfName
     */
    public function tableContexts(array $tables): array
    {
        $tokens = [];
        $person = [];
        foreach ($tables as $t) {
            $tokens[$t->dfName] = $this->norm->normalize($t->name)['tokens'];
            $person[$t->dfName] = $this->intersects($tokens[$t->dfName], $this->personNouns);
        }
        $out = [];
        foreach ($tables as $t) {
            $linked = false;
            foreach ($t->columns as $c) {
                if ($c->isForeignKey && $c->refTable !== null && ($person[$c->refTable] ?? false) && $c->refTable !== $t->dfName) {
                    $linked = true;
                }
            }
            $out[$t->dfName] = ['tokens' => $tokens[$t->dfName], 'person_table' => $person[$t->dfName], 'person_linked' => $linked];
        }
        return $out;
    }

    /** @return array<string,array> column => verdict */
    public function classifyTable(TableMeta $t, array $tctx, ?array $sample, string $mode): array
    {
        $hybrid = $mode === self::MODE_HYBRID;
        $rows = $sample['rows'] ?? [];
        $facts = [];
        foreach ($t->columns as $c) {
            $facts[$c->name] = $this->columnFacts($c, $tctx);
        }
        $tokCols = [];
        foreach ($facts as $name => $f) {
            foreach (array_unique($f['norm']['tokens']) as $tok) {
                $tokCols[$tok][$name] = true;
            }
        }
        $created = null;
        if ($hybrid) {
            foreach ($facts as $name => $f) {
                if (array_intersect($f['norm']['tokens'], $this->createdTokens) && in_array($f['df'], self::DATE_TYPES, true)) {
                    $created = $name;
                    break;
                }
            }
            foreach ($facts as $name => &$f) {
                $aligned = [];
                foreach ($rows as $r) {
                    $aligned[] = self::cleanValue($r[$name] ?? null);
                }
                $f['aligned'] = $aligned;
                $f['values'] = array_values(array_filter($aligned, static fn ($v) => $v !== null));
            }
            unset($f);
            foreach ($facts as $name => &$f) {
                if ($f['surrogate'] || $f['values'] === []) {
                    continue;
                }
                $this->analyzeValues($f, $tctx, $created !== null && $created !== $name ? $facts[$created]['aligned'] : null);
            }
            unset($f);
        }
        $res = [];
        foreach ($facts as $name => $f) {
            $res[$name] = $this->score($f, $tctx, $tokCols, [], $mode);
        }
        // Sibling pass: one iteration, only for weak phrases that reference sibling_class:*.
        foreach ($facts as $name => $f) {
            if (!$f['uses_sibling_class']) {
                continue;
            }
            $sib = [];
            foreach ($res as $other => $r) {
                if ($other !== $name && $r['verdict'] !== 'clear' && $r['class'] !== null) {
                    $sib[$r['class']] = true;
                }
            }
            $res[$name] = $this->score($f, $tctx, $tokCols, $sib, $mode);
            $res[$name]['siblings'] = array_keys($sib);
        }
        $out = [];
        foreach ($facts as $name => $f) {
            $out[$name] = $this->render($f, $res[$name], $tctx, $sample, $mode);
        }
        return $out;
    }

    // ------------------------------------------------------------------ facts

    private function columnFacts(ColumnMeta $c, array $tctx): array
    {
        $norm = $this->norm->normalize($c->name);
        $qualifier = (!$tctx['person_table'] && $this->matcher->isBareEntityName($norm['tokens']) && $tctx['tokens'] !== [])
            ? [end($tctx['tokens'])] : [];
        $m = $this->matcher->match($norm, 'column', $qualifier);
        $cm = ['hits' => [], 'suppressed' => []];
        if ($c->comment !== null && trim($c->comment) !== '') {
            $cm = $this->matcher->match($this->norm->normalize($c->comment, false), 'comment');
        }
        $usesSibling = false;
        $idInPhrase = false;
        foreach ($m['hits'] as $h) {
            foreach ($h['promote_if'] as $p) {
                if (str_starts_with($p, 'sibling_class:')) {
                    $usesSibling = true;
                }
            }
            if (in_array('id', $h['seq'], true)) {
                $idInPhrase = true;
            }
        }
        $tokens = $norm['tokens'];
        $surrogate = $c->dfType === 'uuid'
            || (in_array($c->dfType, self::INT_TYPES, true) && ($c->isPrimaryKey || $c->isForeignKey || (end($tokens) === 'id' && !$idInPhrase)));
        return [
            'name' => $c->name, 'norm' => $norm, 'df' => $c->dfType, 'db' => $c->dbType, 'size' => $c->size,
            'hits' => $m['hits'], 'suppressed' => array_merge($m['suppressed'], $cm['suppressed']), 'shadowed' => $m['shadowed'] ?? [],
            'comment_hits' => $cm['hits'], 'hints' => $this->matcher->hints($tokens),
            'surrogate' => $surrogate, 'explained' => $this->isKnownClear($tokens) || $m['suppressed'] !== [],
            'date_role' => $this->intersects($tokens, $this->dateRoles),
            'uses_sibling_class' => $usesSibling, 'sampleable' => $c->sampleable,
            'aligned' => [], 'values' => [], 'detectors' => [], 'profile' => null, 'free' => null,
        ];
    }

    private function analyzeValues(array &$f, array $tctx, ?array $createdAligned): void
    {
        $cands = [];
        foreach ($f['hits'] as $h) {
            $cands[$h['class']] = true;
        }
        foreach ($f['comment_hits'] as $h) {
            $cands[$h['class']] = true;
        }
        // Under an IP name (x_forwarded_for, client_ip ...), an IP list ("203.0.113.7,
        // 198.51.100.4", a proxy chain) is an IP sample for the value detectors (its first
        // address), so the IP class gets the value evidence. Without an IP name an IP list stays
        // what it was (no new discoveries: precision first).
        $detValues = $f['values'];
        $detAligned = $f['aligned'];
        $lists = 0;
        foreach (isset($cands['ip_address']) ? $detValues : [] as $i => $v) {
            if (($head = self::ipListHead($v)) !== null) {
                $detValues[$i] = $head;
                $lists++;
            }
        }
        if ($lists > 0) {
            foreach ($detAligned as $i => $v) {
                if ($v !== null && ($head = self::ipListHead($v)) !== null) {
                    $detAligned[$i] = $head;
                }
            }
        }
        $f['detectors'] = $this->det->run($detValues, $detAligned, $cands, ['tokens' => $f['norm']['tokens'], 'created' => $createdAligned, 'ref' => $this->ref]);
        $ft = $this->pack->cls('free_text_pii');
        $textual = $this->gate('free_text_pii', null, $f) === null;
        $f['profile'] = Profiler::profile($f['values'], $textual);
        if (!$textual) {
            return;
        }
        $g = $ft['profile_gate'];
        $p = $f['profile'];
        $passes = ($p['len_p50'] >= $g['min_p50_len'] && $p['prose_pct'] >= $g['min_prose_pct']) || $p['json_pct'] >= $g['or_min_json_pct'];
        if (!$passes) {
            // Short or mostly empty text ("Call me on +1 ...", "card 4111 ...", notes that are
            // mostly "ok"): the prose gate is for the "prose may contain names" signal only.
            // Validated identifiers embedded in words still count; a value that is only
            // identifiers (an email column, a timestamp, an IP list) is the column detectors'
            // business, not free text.
            $spans = $this->scanSpans($f['values'], true);
            $free = ['spans' => $spans, 'json_paths' => [], 'short' => true, 'non_null' => count($f['values'])];
            if ($spans !== [] && $this->freeTextPoints($free, $tctx)[0] > 0) {
                $f['free'] = $free; // only when it scores: other columns keep their exact evidence
            }
            return;
        }
        $f['free'] = ['spans' => $this->scanSpans($f['values']), 'json_paths' => $this->jsonPaths($p['json_docs'], $tctx)];
    }

    /**
     * @param bool $embeddedOnly count a span only when the value holds other text too
     * @return array<string,int> detector id => number of rows with a validated span
     */
    private function scanSpans(array $values, bool $embeddedOnly = false): array
    {
        $rows = [];
        foreach ($values as $v) {
            if ($embeddedOnly && !$this->hasWordOutsideSpans($v)) {
                continue;
            }
            foreach ($this->det->spanDefs() as $s) {
                if (preg_match_all($s['re'], $v, $m) < 1) {
                    continue;
                }
                foreach ($m[0] as $cand) {
                    if ($this->det->validateOne($s['detector'], $cand)) {
                        $rows[$s['detector']] = ($rows[$s['detector']] ?? 0) + 1;
                        break;
                    }
                }
            }
        }
        ksort($rows);
        return $rows;
    }

    /**
     * True when a word (3+ letters) remains once every span candidate is cut out of the value
     * (all candidates located in the original value): identifiers set in words, not an
     * identifier list, a timestamp, an IBAN or an address range.
     */
    private function hasWordOutsideSpans(string $v): bool
    {
        $covered = [];
        foreach ($this->det->spanDefs() as $s) {
            if (preg_match_all($s['re'], $v, $m, PREG_OFFSET_CAPTURE) > 0) {
                foreach ($m[0] as [$text, $at]) {
                    $covered[] = [$at, $at + strlen($text)];
                }
            }
        }
        if ($covered === []) {
            return (bool) preg_match('/\p{L}{3,}/u', $v);
        }
        usort($covered, static fn ($a, $b) => $a[0] <=> $b[0]);
        $rest = '';
        $pos = 0;
        foreach ($covered as [$from, $to]) {
            if ($from > $pos) {
                $rest .= substr($v, $pos, $from - $pos) . ' ';
            }
            $pos = max($pos, $to);
        }
        $rest .= substr($v, $pos);
        return (bool) preg_match('/\p{L}{3,}/u', $rest);
    }

    /** Classify JSON leaf key paths with the same name + value machinery. */
    private function jsonPaths(array $docs, array $tctx): array
    {
        if ($docs === []) {
            return [];
        }
        $cfg = $this->pack->cls('free_text_pii')['json'];
        $leaves = [];
        foreach ($docs as $doc) {
            $budget = $cfg['max_leaves'];
            $this->walk($doc, '$', 0, $cfg['max_depth'], $budget, $leaves);
        }
        $min = $this->sc['free_text']['json_min_leaf_values'];
        $out = [];
        ksort($leaves, SORT_STRING);
        foreach ($leaves as $path => $vals) {
            if (count($vals) < $min) {
                continue;
            }
            $key = (string) preg_replace('/^.*[.\]]/', '', $path);
            $norm = $this->norm->normalize($key === '*' ? '' : $key);
            $m = $this->matcher->match($norm);
            $vf = ['name' => $key, 'norm' => $norm, 'df' => 'string', 'db' => 'json', 'size' => null, 'hits' => $m['hits'], 'suppressed' => $m['suppressed'], 'shadowed' => [],
                'comment_hits' => [], 'hints' => [], 'surrogate' => false, 'explained' => $this->isKnownClear($norm['tokens']) || $m['suppressed'] !== [],
                'date_role' => $this->intersects($norm['tokens'], $this->dateRoles), 'uses_sibling_class' => false, 'sampleable' => true,
                'aligned' => $vals, 'values' => $vals, 'detectors' => [], 'profile' => null, 'free' => null];
            $cands = [];
            foreach ($m['hits'] as $h) {
                $cands[$h['class']] = true;
            }
            $vf['detectors'] = $this->det->run($vals, $vals, $cands, ['tokens' => $norm['tokens'], 'created' => null, 'ref' => $this->ref]);
            $vf['profile'] = Profiler::profile($vals, false);
            $r = $this->score($vf, $tctx, [], [], self::MODE_HYBRID);
            if ($r['class'] !== null && $r['confidence'] >= $this->sc['bands']['review']) {
                $out[] = ['path' => $path, 'class' => $r['class'], 'total' => $r['confidence']];
            }
        }
        usort($out, static fn ($a, $b) => [$b['total'], $a['path']] <=> [$a['total'], $b['path']]);
        return array_slice($out, 0, 8);
    }

    private function walk(mixed $node, string $path, int $depth, int $maxDepth, int &$budget, array &$leaves): void
    {
        if ($budget <= 0) {
            return;
        }
        if (!is_array($node)) {
            if (is_string($node) || is_int($node) || is_float($node)) {
                $v = trim((string) $node);
                if ($v !== '') {
                    $leaves[$path][] = mb_substr($v, 0, 1000);
                    $budget--;
                }
            }
            return;
        }
        if ($depth >= $maxDepth) {
            return;
        }
        $isList = array_is_list($node);
        foreach ($node as $k => $child) {
            $seg = $isList ? '[*]' : '.' . self::safeKey((string) $k);
            $this->walk($child, $path . $seg, $depth + 1, $maxDepth, $budget, $leaves);
        }
    }

    /** JSON keys are data: keep only identifier-looking keys, otherwise '*'. */
    private static function safeKey(string $k): string
    {
        if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,39}$/', $k) || preg_match('/[0-9a-fA-F]{16,}/', $k) || preg_match('/\d{4,}/', $k)) {
            return '*';
        }
        return $k;
    }

    // ------------------------------------------------------------------ scoring

    private function score(array $f, array $tctx, array $tokCols, array $sib, string $mode): array
    {
        $hybrid = $mode === self::MODE_HYBRID;
        $cands = [];
        $gated = [];
        $discoverySuppressed = [];
        if (!$f['surrogate']) {
            foreach (array_merge($f['hits'], $f['comment_hits']) as $h) {
                $g = $this->gate($h['class'], $h['types'], $f);
                if ($g !== null) {
                    $gated[] = ['rule' => $h['rule'], 'reason' => $g];
                    continue;
                }
                [$pts, $how] = $this->namePoints($h, $tctx, $tokCols, $f['name'], $sib);
                $c = $cands[$h['class']] ?? self::emptyCand();
                if ($c['name_hit'] === null || $pts > $c['name']) {
                    $c['name'] = $pts;
                    $c['name_hit'] = $h;
                    $c['name_how'] = $how;
                }
                $cands[$h['class']] = $c;
            }
        }
        if ($hybrid && !$f['surrogate']) {
            foreach ($f['detectors'] as $r) {
                $cls = $r['class'];
                if ($this->gate($cls, null, $f) !== null) {
                    continue;
                }
                $hasName = isset($cands[$cls]) && $cands[$cls]['name_hit'] !== null;
                $pts = $this->valuePoints($r, $f);
                if (!$hasName && $pts > 0) {
                    $tier = $this->pack->tierOf($cls);
                    if ($f['explained'] && ($tier === 'identity' || $tier === 'quasi')) {
                        $discoverySuppressed[$cls] = 'explained_name';
                        continue;
                    }
                    if ($cls === 'date_of_birth' && $f['date_role']) {
                        $discoverySuppressed[$cls] = 'date_role_named';
                        continue;
                    }
                }
                if (!$hasName && $pts === 0) {
                    continue;
                }
                $c = $cands[$cls] ?? self::emptyCand();
                if ($c['detector'] === null || $pts > $c['value'] || ($pts === $c['value'] && $r['pct'] > $c['detector']['pct'])) {
                    $c['value'] = $pts;
                    $c['detector'] = $r;
                }
                $cands[$cls] = $c;
            }
            foreach ($cands as $cls => $c) {
                if ($c['name'] > 0) {
                    [$cands[$cls]['penalty'], $cands[$cls]['penalty_why']] = $this->penalty($cls, $f);
                }
            }
            if ($f['free'] !== null) {
                [$pts, $why] = $this->freeTextPoints($f['free'], $tctx);
                if ($pts > 0) {
                    $c = self::emptyCand();
                    $c['value'] = $pts;
                    $c['free_why'] = $why;
                    $cands['free_text_pii'] = $c;
                }
            }
        }
        $list = [];
        foreach ($cands as $cls => $c) {
            $c['class'] = $cls;
            $c['total'] = max(0, min(100, $c['name'] + $c['value'] - $c['penalty']));
            $list[] = $c;
        }
        usort($list, fn ($a, $b) => [$b['total'], $this->pack->tierRank($b['class']), $this->pack->classOrder($a['class'])]
            <=> [$a['total'], $this->pack->tierRank($a['class']), $this->pack->classOrder($b['class'])]);
        $bands = $hybrid ? $this->sc['bands'] : $this->sc['name_only'];
        $best = $list[0] ?? null;
        $total = $best['total'] ?? 0;
        $verdict = $total >= $bands['enforce'] ? 'enforce' : ($total >= $bands['review'] ? 'review' : 'clear');
        $class = $verdict === 'clear' ? null : $best['class'];
        if ($class === 'free_text_pii' && self::onlyIpSpans($f['free']['spans'] ?? [])
            && ($cands['ip_address']['name_hit'] ?? null) !== null) {
            // IP lists ("10.0.0.1, 192.0.2.7") under an IP name (x_forwarded_for). The values
            // are not single IPs, so the IP class itself is contradicted, but the only personal data
            // in them are IPs: report the IP class (same score, so review), not free text.
            $class = 'ip_address';
        }
        return [
            'verdict' => $verdict, 'class' => $class,
            'tier' => $class === null ? null : $this->pack->tierOf($class), 'confidence' => $total,
            'best' => $best, 'cands' => $list, 'gated' => $gated, 'discovery_suppressed' => $discoverySuppressed, 'siblings' => [],
        ];
    }

    /** @param array<string,int> $spans detector id => rows: true when every span found is an IP address */
    private static function onlyIpSpans(array $spans): bool
    {
        if ($spans === []) {
            return false;
        }
        foreach (array_keys($spans) as $id) {
            if (!str_starts_with((string) $id, 'ip.')) {
                return false;
            }
        }
        return true;
    }

    private static function emptyCand(): array
    {
        return ['name' => 0, 'value' => 0, 'penalty' => 0, 'penalty_why' => null, 'name_hit' => null, 'name_how' => null, 'detector' => null, 'free_why' => null];
    }

    /** @return ?string null when the class may hold this column's type, else the reason */
    private function gate(string $class, ?array $phraseTypes, array $f): ?string
    {
        if ($f['surrogate']) {
            return 'surrogate';
        }
        $c = $this->pack->cls($class);
        $types = $phraseTypes ?? $c['types'];
        if (!in_array($f['df'], $types, true)) {
            return 'type:' . $f['df'];
        }
        if (isset($c['min_size']) && $f['df'] === 'string' && $f['size'] !== null && $f['size'] < $c['min_size']) {
            return 'size:' . $f['size'];
        }
        return null;
    }

    /** @return array{0:int,1:string} */
    private function namePoints(array $h, array $tctx, array $tokCols, string $self, array $sib): array
    {
        $s = $this->sc['name'];
        if ($h['on'] === 'comment') {
            return ($h['strength'] === 'strong' && $h['demoted_by'] === null) ? [$s['strong_in_comment'], 'comment'] : [0, 'comment_weak_ignored'];
        }
        if ($h['strength'] === 'strong') {
            return $h['demoted_by'] === null ? [$s['strong'], 'strong'] : [$s['demoted_strong'], 'modifier:' . $h['demoted_by']];
        }
        if ($h['demoted_by'] !== null) {
            return [0, 'modifier:' . $h['demoted_by']];
        }
        if ($h['plural']) {
            return [$s['weak'], 'plural'];
        }
        $linked = false;
        foreach ($h['promote_if'] as $pred) {
            $ok = match (true) {
                $pred === 'person_table' => $tctx['person_table'] || $h['person_prefix'],
                $pred === 'person_linked' => false,
                str_starts_with($pred, 'sibling_class:') => isset($sib[substr($pred, 14)]),
                str_starts_with($pred, 'sibling_name:') => array_diff_key($tokCols[substr($pred, 13)] ?? [], [$self => true]) !== [],
                str_starts_with($pred, 'table_token:') => in_array(substr($pred, 12), $tctx['tokens'], true),
                default => false,
            };
            if ($pred === 'person_linked' && $tctx['person_linked']) {
                $linked = true;
            }
            if ($ok) {
                return [$s['weak_promoted'], 'promoted:' . $pred];
            }
        }
        return $linked ? [$s['weak_promoted_linked'], 'promoted:person_linked'] : [$s['weak'], 'weak'];
    }

    private function valuePoints(array $r, array $f): int
    {
        $v = $this->sc['value'];
        $nn = count($f['values']);
        if ($nn < $v['min_non_null'] || $r['valid'] === 0) {
            return 0;
        }
        $idx = null;
        foreach ($v['bands_pct'] as $i => $min) {
            if ($r['pct'] >= $min) {
                $idx = $i;
                break;
            }
        }
        if ($idx === null) {
            return 0;
        }
        $pts = (int) $v[$r['strength']][$idx];
        if (($f['profile']['distinct'] ?? 0) < $v['min_distinct_full']) {
            $pts = intdiv($pts, 2);
        }
        return $pts;
    }

    /** @return array{0:int,1:?string} */
    private function penalty(string $cls, array $f): array
    {
        $c = $this->pack->cls($cls);
        $nn = count($f['values']);
        $con = $this->sc['contradiction'];
        if (($c['shape'] ?? null) !== null && $nn >= $con['min_non_null']) {
            $ok = 0;
            foreach ($f['values'] as $v) {
                if (self::shapeOk($c['shape'], $v)) {
                    $ok++;
                }
            }
            $pct = intdiv($ok * 100, $nn);
            if ($pct <= $con['max_shape_pct']) {
                // Restricted classes with identifier-like variety (e.g. hashed SSNs) stay in review
                // (masked until reviewed); fixed value lists such as Y/N or card brands are fully contradicted.
                $varied = ($f['profile']['distinct'] ?? 0) >= $this->sc['value']['min_distinct_full'];
                $pen = ($c['tier'] === 'restricted' && $varied) ? ($con['penalty_restricted_varied'] ?? $con['penalty']) : $con['penalty'];
                return [$pen, "shape:{$c['shape']}:$pct"];
            }
        }
        $kc = $this->sc['kind_contradiction'];
        if (($c['kind_contradiction'] ?? []) !== [] && $nn >= $kc['min_non_null'] && $f['profile'] !== null) {
            $pct = 0;
            foreach ($c['kind_contradiction'] as $k) {
                $pct += $f['profile']['kinds'][$k] ?? 0;
            }
            if ($pct >= $kc['min_kind_pct']) {
                return [$kc['penalty'], 'kind:' . implode('|', $c['kind_contradiction']) . ":$pct"];
            }
        }
        return [0, null];
    }

    /** @return array{0:int,1:array} */
    private function freeTextPoints(array $free, array $tctx): array
    {
        $ft = $this->sc['free_text'];
        $strongRows = $mediumRows = 0;
        $strongIds = $mediumIds = [];
        foreach ($free['spans'] as $id => $rows) {
            $d = $this->det->get($id);
            if (($d['strength'] ?? '') === 'strong') {
                $strongRows = max($strongRows, $rows);
                $strongIds[] = $id;
            } else {
                $mediumRows = max($mediumRows, $rows);
                $mediumIds[] = $id;
            }
        }
        $pts = 0;
        $why = ['strong_rows' => $strongRows, 'medium_rows' => $mediumRows];
        if (!empty($free['short'])) {
            // Short text: spans only, and a share of the rows, so a few incidental matches in a
            // large column (an id that happens to pass a checksum) do not flag it.
            $nn = max(1, (int) ($free['non_null'] ?? 1));
            $share = static fn (int $rows): bool => $rows * 100 >= $ft['short_min_pct'] * $nn;
            if ($strongRows >= $ft['strong_hit_rows'] && $share($strongRows)) {
                $pts = $ft['hits_strong'];
                $why['by'] = 'spans_strong';
            } elseif (max($strongRows, $mediumRows) >= $ft['strong_hit_rows'] && $share(max($strongRows, $mediumRows) * 2)) {
                $pts = $ft['hits_some'];
                $why['by'] = 'spans_some';
            }
            return [$pts, $why];
        }
        if ($strongRows >= $ft['strong_hit_rows']) {
            $pts = $ft['hits_strong'];
            $why['by'] = 'spans_strong';
        } elseif ($strongRows >= 1 || $mediumRows >= $ft['strong_hit_rows']) {
            $pts = $ft['hits_some'];
            $why['by'] = 'spans_some';
        }
        $bestPath = $free['json_paths'][0]['total'] ?? 0;
        if ($bestPath >= $this->sc['bands']['enforce'] && $ft['json_path'] > $pts) {
            $pts = $ft['json_path'];
            $why['by'] = 'json_path';
        } elseif ($bestPath >= $this->sc['bands']['review'] && $ft['json_path_review'] > $pts) {
            $pts = $ft['json_path_review'];
            $why['by'] = 'json_path';
        }
        if ($pts === 0 && $tctx['person_table']) {
            $pts = $ft['person_table_no_hits'];
            $why['by'] = 'person_table_prose';
        }
        return [$pts, $why];
    }

    public static function shapeOk(string $shape, string $v): bool
    {
        return match ($shape) {
            'contains_at' => str_contains($v, '@'),
            'min_7_digits' => strlen(Validators::digitsOnly($v)) >= 7,
            'digits_13_19' => (bool) preg_match('/^\d{13,19}$/', str_replace([' ', '-'], '', $v)) || (bool) preg_match('/[*xX#•]{4,}.*\d{4}$/u', $v),
            'id_like' => (bool) preg_match('/^(?=.*\d)[A-Za-z0-9]{5,30}$/', str_replace(['-', '.', ' ', '/'], '', $v)),
            'digits_3_4' => (bool) preg_match('/^\d{3,4}$/', $v),
            'postal_like' => (bool) preg_match('/^(?=.*\d)[A-Za-z0-9 \-]{3,10}$/', $v),
            'parseable_date' => Validators::parseDate($v) !== null || (bool) preg_match('/^(1[89]|20)\d{2}$/', $v),
            'ip_like' => Validators::ipv4($v) || Validators::ipv6($v) || self::ipListHead($v) !== null,
            'expiry_like' => (bool) preg_match('/^(?:\d{1,2}\s?[\/-]\s?\d{2,4}|\d{4}[\/-]\d{1,2}|\d{3,4}|\d{1,2})$/', $v) || Validators::parseDate($v) !== null,
            'small_int' => (bool) preg_match('/^\d{1,3}$/', $v),
            'short_code' => mb_strlen($v) <= 12,
            'decimal_like' => is_numeric($v),
            'numeric_like' => is_numeric(str_replace([',', '$', '€', '£', ' '], '', $v)),
            default => true,
        };
    }

    /**
     * The first address of an IP list: a value that splits on commas and/or whitespace into two
     * or more valid IPv4/IPv6 addresses and nothing else ("203.0.113.7, 198.51.100.4",
     * "2001:db8::1 10.0.0.4"); null for anything else (one address, or any other token).
     */
    public static function ipListHead(string $v): ?string
    {
        $v = trim($v);
        if (strlen($v) > 2000 || !preg_match('/^[0-9A-Fa-f:.]+(?:[\s,]+[0-9A-Fa-f:.]+)+$/', $v)) {
            return null;
        }
        $parts = preg_split('/[\s,]+/', $v, -1, PREG_SPLIT_NO_EMPTY) ?: [];
        if (count($parts) < 2) {
            return null;
        }
        foreach ($parts as $p) {
            if (!Validators::ipv4($p) && !Validators::ipv6($p)) {
                return null;
            }
        }
        return $parts[0];
    }

    // ------------------------------------------------------------------ helpers

    private function isKnownClear(array $tokens): bool
    {
        $n = count($tokens);
        foreach ($this->knownClear as $p) {
            $len = count($p);
            if ($len <= $n && array_slice($tokens, $n - $len) === $p) {
                return true;
            }
        }
        return false;
    }

    private function intersects(array $tokens, array $set): bool
    {
        foreach ($tokens as $t) {
            if (isset($set[$t])) {
                return true;
            }
        }
        return false;
    }

    /** trim, empty->null, strip zero-width, full-width digits->ASCII. */
    public static function cleanValue(mixed $v): ?string
    {
        if ($v === null) {
            return null;
        }
        $s = (string) $v;
        if (preg_match('/[^\x00-\x7F]/', $s)) {
            $s = preg_replace('/[\x{200B}-\x{200D}\x{FEFF}]/u', '', $s) ?? $s;
            $s = preg_replace_callback('/[\x{FF10}-\x{FF19}]/u', static fn ($m) => (string) (mb_ord($m[0]) - 0xFF10), $s) ?? $s;
        }
        $s = trim($s);
        return $s === '' ? null : $s;
    }

    // ------------------------------------------------------------------ output

    private function render(array $f, array $r, array $tctx, ?array $sample, string $mode): array
    {
        $hybrid = $mode === self::MODE_HYBRID;
        $best = $r['best'];
        $ev = [];
        $name = ['tokens' => $f['norm']['tokens']];
        if ($f['norm']['ordinal']) {
            $name['ordinal'] = true;
        }
        $hitCand = $best !== null && $best['name_hit'] !== null ? $best : null;
        if ($hitCand === null) {
            foreach ($r['cands'] as $c) {
                if ($c['name_hit'] !== null) {
                    $hitCand = $c;
                    break;
                }
            }
        }
        if ($hitCand !== null) {
            $h = $hitCand['name_hit'];
            $name['match'] = ['rule' => $h['rule'], 'seq' => $h['seq'], 'strength' => $h['strength'], 'on' => $h['on'], 'points' => $hitCand['name'], 'how' => $hitCand['name_how']];
        }
        if ($f['suppressed'] !== []) {
            $name['suppressed'] = array_map(static fn ($s) => ['rule' => $s['rule'], 'by' => $s['by']], $f['suppressed']);
        }
        if ($r['gated'] !== []) {
            $name['gated'] = $r['gated'];
        }
        if ($f['hints'] !== []) {
            $name['hints'] = $f['hints'];
        }
        $ev['name'] = $name;
        $ev['type'] = ['db' => $f['db'], 'df' => $f['df'], 'gate' => $f['surrogate'] ? 'surrogate' : 'pass'];
        if ($hybrid) {
            $ev['sample'] = [
                'rows' => count($f['aligned']), 'non_null' => count($f['values']), 'distinct' => $f['profile']['distinct'] ?? count(array_unique($f['values'])),
                'ordered' => $sample['ordered'] ?? false,
            ];
            $dets = [];
            foreach ($f['detectors'] as $d) {
                if ($d['matched'] === 0 && $d['valid'] === 0 && !($best !== null && $best['class'] === $d['class'])) {
                    continue;
                }
                $e = ['id' => $d['id'], 'matched' => $d['matched'], 'valid' => $d['valid'], 'pct' => $d['pct']];
                if ($d['matched'] > 0) {
                    $e['pass_pct'] = intdiv($d['valid'] * 100, $d['matched']);
                }
                foreach (['formats', 'stats', 'note'] as $k) {
                    if (isset($d[$k])) {
                        $e[$k] = $d[$k];
                    }
                }
                $dets[] = $e;
            }
            usort($dets, static fn ($a, $b) => strcmp($a['id'], $b['id']));
            if ($dets !== []) {
                $ev['detectors'] = $dets;
            }
            if (($f['profile']['shapes'] ?? []) !== []) {
                $ev['shapes'] = array_slice($f['profile']['shapes'], 0, 3);
            }
            if ($f['free'] !== null) {
                $p = $f['profile'];
                $ev['profile'] = ['len_p50' => $p['len_p50'], 'len_p95' => $p['len_p95'], 'prose_pct' => $p['prose_pct'], 'json_pct' => $p['json_pct']];
                if ($f['free']['spans'] !== []) {
                    $ev['spans'] = $f['free']['spans'];
                }
                if ($f['free']['json_paths'] !== []) {
                    $ev['json_paths'] = $f['free']['json_paths'];
                }
            }
        }
        $ctx = ['person_table' => $tctx['person_table'], 'person_linked' => $tctx['person_linked']];
        if ($r['siblings'] !== []) {
            sort($r['siblings']);
            $ctx['siblings'] = $r['siblings'];
        }
        $ev['context'] = $ctx;
        $ev['score'] = ['name' => $best['name'] ?? 0, 'value' => $best['value'] ?? 0, 'penalty' => $best['penalty'] ?? 0, 'total' => $best['total'] ?? 0];
        $ru = [];
        foreach (array_slice($r['cands'], 1) as $c) {
            if ($c['class'] === $r['class']) {
                continue; // the reported class came from another candidate (IP lists, see score())
            }
            if ($c['total'] >= $this->sc['runner_up_min'] && count($ru) < $this->sc['runner_up_max']) {
                $ru[] = ['class' => $c['class'], 'total' => $c['total']];
            }
        }
        if ($ru !== []) {
            $ev['runner_up'] = $ru;
        }
        if ($r['verdict'] === 'clear' && $best !== null && $best['total'] >= $this->sc['bands']['suggest']) {
            $ev['suggestion'] = ['class' => $best['class'], 'total' => $best['total']];
        }
        $flags = $this->flags($f, $r, $sample, $hybrid);
        if ($flags !== []) {
            $ev['flags'] = $flags;
        }
        $ev['why'] = $this->explainer->lines($f, $r, $ev, $mode);
        return ['verdict' => $r['verdict'], 'class' => $r['class'], 'tier' => $r['tier'], 'confidence' => $r['confidence'], 'evidence' => $ev];
    }

    private function flags(array $f, array $r, ?array $sample, bool $hybrid): array
    {
        $flags = [];
        $best = $r['best'];
        if ($hybrid) {
            if (($sample['error'] ?? null) !== null) {
                $flags[] = 'sample_error';
            } elseif (($sample['rows'] ?? []) === []) {
                $flags[] = 'no_rows';
            } elseif (!$f['surrogate'] && count($f['values']) < $this->sc['value']['min_non_null']) {
                $flags[] = 'insufficient_sample';
            }
            if ($sample !== null && ($sample['ordered'] ?? false) === false) {
                $flags[] = 'unordered_sample';
            }
            if (!$f['sampleable']) {
                $flags[] = 'not_sampled_binary';
            }
            $pct = [];
            foreach ($f['detectors'] as $d) {
                $pct[$d['id']] = $d['pct'];
            }
            if ($best !== null && $best['class'] === 'card_number' && ($pct['card.shape'] ?? 0) >= 80 && ($pct['card.luhn_iin'] ?? 0) < 30) {
                $flags[] = 'likely_synthetic_card_data';
            }
            if (($pct['card.already_masked'] ?? 0) >= 50) {
                $flags[] = 'already_masked';
            }
            if ($r['discovery_suppressed'] !== []) {
                $flags[] = 'explained_name';
            }
            foreach ($r['cands'] as $c) {
                if ($c['penalty'] > 0) {
                    $flags[] = 'contradicted';
                    break;
                }
            }
            if ($best !== null && $r['verdict'] !== 'clear' && $best['name'] === 0) {
                $flags[] = 'value_only';
            }
        } else {
            $flags[] = 'name_only';
        }
        if ($best !== null && is_string($best['name_how']) && str_starts_with($best['name_how'], 'promoted:sibling_class:')) {
            $flags[] = 'promoted_by_sibling';
        }
        return $flags;
    }
}

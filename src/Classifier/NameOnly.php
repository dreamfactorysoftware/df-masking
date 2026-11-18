<?php
declare(strict_types=1);

namespace DreamFactory\Core\Masking\Classifier;

use DreamFactory\Core\Masking\Support\Catalog;

/**
 * Fast name-only verdicts for columns that were never scanned (a table or column added after the
 * last scan). Enforcement calls this inline so nothing is ever served unclassified, caches the
 * result in dm_column (source 'detected', scanned_at null) and queues a background scan, whose
 * sampled result then replaces this provisional one.
 *
 * Name-only classification uses the rule pack's name-only bands: masked >= 70, review >= 15.
 * Without values a weak name signal can be neither confirmed nor refuted, so it fails closed into
 * review (masked until an admin decides or the scan clears it).
 *
 * A text or string column the name says nothing about is not served in clear either:
 * until a scan reads it, it is span-masked (review, free text), so an email, phone, card or
 * SSN in it is hidden while UUIDs, codes, keys and prose pass unchanged.
 *
 * Pure: no I/O beyond loading the rule pack once per process. Results are memoized per process.
 */
final class NameOnly
{
    private const MEMO_MAX = 20000;

    /** @var array<string,array> */
    private static array $memo = [];

    private function __construct()
    {
    }

    /**
     * @param string  $table  DreamFactory table name ("customers", or "sales.customers" outside the default schema)
     * @param string  $column column name
     * @param ?string $dbType native type (ColumnSchema::$dbType) or a DreamFactory simple type; null = unknown (string)
     * @return array{class:?string, score:int, verdict:string, tier:?string, evidence:array}
     *               verdict is 'masked'|'review'|'clear'; evidence is the dm_column evidence document
     */
    public static function classify(string $table, string $column, ?string $dbType = null): array
    {
        $key = $table . "\0" . $column . "\0" . ($dbType ?? '');
        if (isset(self::$memo[$key])) {
            return self::$memo[$key];
        }
        $out = self::classifyTable($table, [$column => $dbType])[$column];
        return self::remember($key, $out);
    }

    /**
     * Name-only verdicts for several columns of one table at once. Sibling columns are context for
     * the classifier (a weak "pan" next to a card expiry column is promoted), so prefer this when
     * a whole table is unscanned.
     *
     * @param array<string,?string> $columns column name => native type (or DreamFactory simple type, or null)
     * @param ?string               $driver  Illuminate driver name, when known (improves type mapping)
     * @return array<string,array{class:?string, score:int, verdict:string, tier:?string, evidence:array}>
     */
    public static function classifyTable(string $table, array $columns, ?string $driver = null): array
    {
        $metas = [];
        foreach ($columns as $name => $dbType) {
            $name = (string) $name;
            [$type, $size] = TypeMap::map($dbType, $dbType, $driver);
            $metas[] = new ColumnMeta($name, (string) ($dbType ?? ''), $type, $size, false, false, null, false, null, !in_array($type, TypeMap::UNSAMPLED, true));
        }
        $dot = strrpos($table, '.');
        $meta = new TableMeta($dot === false ? '' : substr($table, 0, $dot), $dot === false ? $table : substr($table, $dot + 1), $table, 'table', $metas);
        $engine = Ruleset::engine();
        $pack = Ruleset::pack();
        $verdicts = $engine->classifyTable($meta, $engine->tableContexts([$meta])[$table], null, Engine::MODE_NAME_ONLY);
        $out = [];
        foreach ($metas as $meta) {
            $name = $meta->name;
            $r = Evidence::fromEngine($verdicts[$name], true, $pack);
            if ($r['verdict'] === 'clear' && in_array($meta->dfType, ['text', 'string'], true)) {
                $r = self::spanMaskedUntilScanned($r, self::looksLikeFreeText($meta, $pack, $engine)
                    ? 'Free text not scanned yet: personal data in it is masked until a scan reads the values'
                    : 'Not scanned yet: personal data in its values is masked until a scan reads them');
            }
            $out[$name] = ['class' => $r['class'], 'score' => $r['score'], 'verdict' => $r['verdict'], 'tier' => $r['tier'], 'evidence' => $r['evidence']];
        }
        return $out;
    }

    /**
     * A free-text column (notes, comments, description, message ... of a text type): its values
     * usually hold personal data in prose (emails, phones in notes). Only the evidence wording
     * differs from any other never-scanned text column; both are span-masked until scanned.
     */
    private static function looksLikeFreeText(ColumnMeta $c, RulePack $pack, Engine $engine): bool
    {
        $ft = $pack->cls('free_text_pii');
        if (!in_array($c->dfType, ['text', 'string'], true)) {
            return false; // JSON documents are left to the scan
        }
        if ($c->dfType === 'string' && $c->size !== null && $c->size < (int) ($ft['min_size'] ?? 0)) {
            return false;
        }
        $tokens = $engine->normalizer()->normalize($c->name)['tokens'];
        foreach ($ft['name']['hints'] ?? [] as $seq) {
            $len = count($seq);
            for ($i = 0; $i + $len <= count($tokens); $i++) {
                if (array_slice($tokens, $i, $len) === $seq) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Review, free text (mask: span) until the scan reads the values: only validated spans are
     * hidden (Masking\SpanDetector), the rest of each value stays readable.
     */
    private static function spanMaskedUntilScanned(array $r, string $why): array
    {
        $r['verdict'] = 'review';
        $r['class'] = 'free_text_pii';
        $r['tier'] = Catalog::tierOf('free_text_pii');
        $r['score'] = max((int) $r['score'], 40);
        $r['evidence']['total'] = max((int) ($r['evidence']['total'] ?? 0), 40);
        $r['evidence']['lines'][] = Evidence::line(40, Evidence::KIND_CONTEXT, $why);
        return $r;
    }

    /** Drops the per-process memo (tests). */
    public static function forget(): void
    {
        self::$memo = [];
    }

    private static function remember(string $key, array $value): array
    {
        if (count(self::$memo) >= self::MEMO_MAX) {
            self::$memo = [];
        }
        return self::$memo[$key] = $value;
    }
}

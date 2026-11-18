<?php

namespace DreamFactory\Core\Masking\Scanner;

use DreamFactory\Core\Masking\Classifier\Evidence;
use DreamFactory\Core\Masking\Enforcement\DerivedFields;
use DreamFactory\Core\Masking\Support\Retry;
use DreamFactory\Core\Masking\Support\Tables;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * Writes one table's classification into dm_column, merging with what is stored:
 *
 *  - admin decisions are sticky: verdict, class, source and decided_* stay; evidence and examples
 *    are refreshed (examples for the admin's class);
 *  - provisional rows (inline name-only verdicts written by enforcement before any scan, and
 *    name-only rows once values have been sampled) are replaced by the new result;
 *  - otherwise automatic changes only ever ADD masking: the new result replaces the stored one
 *    when it is at least as strict (Rules::rank); a weaker result keeps the stored verdict and
 *    class, with the new evidence and a line saying so. A column is never silently cleared.
 *
 * Columns that no longer exist in the table are deleted. No raw value is ever written: evidence
 * holds counts and shapes, examples hold masked renderings only.
 */
final class ColumnWriter
{
    public const KEPT_PREFIX = 'An earlier scan classified this as ';
    public const KEPT_RULE_PREFIX = 'Masked as ';

    private const SELECT = ['id', 'table_name', 'column_name', 'verdict', 'class', 'tier', 'score', 'source', 'decided_by_id', 'decided_by',
        'decided_at', 'scanned_at', 'evidence', 'examples'];

    public function __construct(private readonly Examples $examples)
    {
    }

    /**
     * @param array<string,array> $columns column name => [db_type, ordinal, fingerprint, result, raw, df_type, name_only]
     *                                     (result = Rules::apply() output; raw = first sampled value or null)
     * @return array{inserted:int, updated:int, changed:int, deleted:int, masked:int, review:int, clear:int}
     */
    public function write(int $serviceId, string $table, array $columns, string $rulesetVersion, bool $deleteMissing = true): array
    {
        $now = now();
        $stats = [];
        Retry::transaction(function () use ($serviceId, $table, $columns, $rulesetVersion, $deleteMissing, $now, &$stats): void {
            $stats = ['inserted' => 0, 'updated' => 0, 'changed' => 0, 'deleted' => 0, 'masked' => 0, 'review' => 0, 'clear' => 0];
            $existing = [];
            foreach (DB::table(Tables::COLUMN)->where('service_id', $serviceId)->where('table_name', $table)->get(self::SELECT) as $row) {
                // Names are identities and compare byte for byte (a case- or accent-insensitive
                // system database collation must never merge "Email" and "email").
                if ((string) $row->table_name === $table) {
                    $existing[(string) $row->column_name] = (array) $row;
                }
            }
            foreach ($columns as $name => $c) {
                $old = $existing[$name] ?? null;
                unset($existing[$name]);
                $row = $this->merge($old, $c);
                $stats[$row['verdict']]++;
                $row += [
                    'db_type' => self::clip($c['db_type'], 100),
                    'detected_class' => $c['result']['detected_class'],
                    'detected_score' => $c['result']['detected_score'],
                    'scanned_at' => $now,
                    'ruleset_version' => self::clip($rulesetVersion, 32),
                    'fingerprint' => $c['fingerprint'],
                    'ordinal' => $c['ordinal'],
                    'updated_at' => $now,
                ];
                if ($old === null) {
                    $row += ['service_id' => $serviceId, 'table_name' => $table, 'column_name' => $name, 'created_at' => $now];
                    try {
                        // A nested transaction is a savepoint: on PostgreSQL a failed INSERT would
                        // otherwise abort the whole transaction (25P02) and stop the scan.
                        DB::transaction(static fn () => DB::table(Tables::COLUMN)->insert($row));
                    } catch (\Illuminate\Database\QueryException $e) {
                        // Lost a race with enforcement's inline name-only insert: update that row.
                        $id = self::exactRowId($serviceId, $table, (string) $name);
                        if ($id === null) {
                            Log::warning(sprintf("df-masking: could not store column '%s' of table '%s' (service %d): %s",
                                $name, $table, $serviceId, Sampler::sqlState($e)));
                            $stats[$row['verdict']]--;
                            continue;
                        }
                        DB::table(Tables::COLUMN)->where('id', $id)
                            ->update(array_diff_key($row, array_flip(['service_id', 'table_name', 'column_name', 'created_at'])));
                    }
                    $stats['inserted']++;
                    $stats['changed'] += $row['verdict'] !== 'clear' ? 1 : 0;
                } else {
                    DB::table(Tables::COLUMN)->where('id', $old['id'])->update($row);
                    $stats['updated']++;
                    if ($row['verdict'] !== $old['verdict'] || ($row['class'] ?? null) !== $old['class']) {
                        $stats['changed']++;
                    }
                }
            }
            if ($deleteMissing && $existing !== []) {
                $ids = array_map(static fn ($r) => $r['id'], array_values($existing));
                foreach (array_chunk($ids, 500) as $chunk) {
                    $stats['deleted'] += DB::table(Tables::COLUMN)->whereIn('id', $chunk)->delete();
                }
            }
        });
        return $stats;
    }

    /** Deletes the rows of tables that no longer exist in the service (names compared exactly). */
    public static function deleteTablesExcept(int $serviceId, array $keepTables): int
    {
        $stored = array_unique(array_map('strval', DB::table(Tables::COLUMN)->where('service_id', $serviceId)->pluck('table_name')->all()));
        $keep = array_fill_keys(array_map('strval', $keepTables), true);
        $gone = array_values(array_filter($stored, static fn (string $t) => !isset($keep[$t])));
        $n = 0;
        foreach (array_chunk($gone, 200) as $chunk) {
            $wanted = array_fill_keys($chunk, true);
            $ids = [];
            foreach (DB::table(Tables::COLUMN)->where('service_id', $serviceId)->whereIn('table_name', $chunk)->get(['id', 'table_name']) as $r) {
                if (isset($wanted[(string) $r->table_name])) {
                    $ids[] = $r->id;
                }
            }
            foreach (array_chunk($ids, 500) as $idChunk) {
                $n += DB::table(Tables::COLUMN)->whereIn('id', $idChunk)->delete();
            }
        }
        return $n;
    }

    /**
     * dm_column id of exactly (service, table, column), or null. A locking read: under MySQL's
     * REPEATABLE READ a plain SELECT would not see the row a concurrent request just committed.
     */
    private static function exactRowId(int $serviceId, string $table, string $column): ?int
    {
        $rows = DB::table(Tables::COLUMN)->where('service_id', $serviceId)->where('table_name', $table)->where('column_name', $column)
            ->lockForUpdate()->get(['id', 'table_name', 'column_name']);
        foreach ($rows as $r) {
            if ((string) $r->table_name === $table && (string) $r->column_name === $column) {
                return (int) $r->id;
            }
        }
        return null;
    }

    /**
     * Merge decision for one column. Returns the decision fields: verdict, class, tier, score,
     * source, evidence, examples (+ decided_* untouched unless inserting).
     */
    public function merge(?array $old, array $c): array
    {
        $new = $c['result'];
        $newEvidence = $new['evidence'];
        if ($old !== null && $old['source'] === 'admin') {
            return [
                'verdict' => $old['verdict'],
                'class' => $old['class'],
                'tier' => $old['tier'],
                'score' => (int) $old['score'],
                'source' => 'admin',
                'evidence' => self::json($newEvidence),
                'examples' => $this->examplesFor($old['verdict'], $old['class'], $c, $old),
            ];
        }
        $provisional = $old !== null && ($old['scanned_at'] === null || (self::wasNameOnly($old) && !$c['name_only']));
        if ($old === null || $provisional || Rules::rank($new['verdict'], $new['class']) >= Rules::rank($old['verdict'], $old['class'])) {
            return [
                'verdict' => $new['verdict'],
                'class' => $new['class'],
                'tier' => $new['tier'],
                'score' => (int) $new['score'],
                'source' => $new['source'],
                'evidence' => self::json($newEvidence),
                'examples' => $this->examplesFor($new['verdict'], $new['class'], $c, null),
            ];
        }
        // Weaker than what is stored: keep the stored (stricter) classification.
        if (($was = DerivedFields::wasBuiltFrom($old['evidence'] ?? null)) !== null) {
            $newEvidence['lines'][] = Evidence::line(0, Evidence::KIND_CONTEXT, $was); // its expression changed or is gone
        }
        $newEvidence['lines'][] = Evidence::line(0, Evidence::KIND_CONTEXT, in_array($old['source'], ['rule', 'baseline'], true)
            // A rule that still matched would have been applied again, so this one was removed or changed.
            ? sprintf('%s%s by a detection rule that no longer matches; automatic changes never remove masking (mark it not sensitive to clear it)',
                self::KEPT_RULE_PREFIX, Evidence::classLabel($old['class']))
            : sprintf('%s%s (%s); automatic rescans never remove masking (mark it not sensitive to clear it)',
                self::KEPT_PREFIX, Evidence::classLabel($old['class']), $old['verdict'] === 'masked' ? 'masked' : 'review'));
        return [
            'verdict' => $old['verdict'],
            'class' => $old['class'],
            'tier' => $old['tier'],
            'score' => (int) $old['score'],
            'source' => $old['source'],
            'evidence' => self::json($newEvidence),
            'examples' => $this->examplesFor($old['verdict'], $old['class'], $c, $old),
        ];
    }

    private function examplesFor(string $verdict, ?string $class, array $c, ?array $old): ?string
    {
        if ($verdict === 'clear' || $class === null) {
            return null;
        }
        if ($c['raw'] !== null || $old === null) {
            return self::json($this->examples->build($class, $c['raw'], $c['df_type']));
        }
        $previous = json_decode((string) ($old['examples'] ?? ''), true);
        return self::json($this->examples->reuse($class, is_array($previous) ? $previous : []));
    }

    private static function wasNameOnly(array $old): bool
    {
        $ev = json_decode((string) ($old['evidence'] ?? ''), true);
        return is_array($ev) && !empty($ev['name_only']);
    }

    public static function json(mixed $v): string
    {
        return json_encode($v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
    }

    private static function clip(?string $s, int $max): ?string
    {
        if ($s === null) {
            return null;
        }
        return mb_strlen($s) > $max ? mb_substr($s, 0, $max) : $s;
    }
}

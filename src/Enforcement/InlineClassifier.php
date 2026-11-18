<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Enforcement;

use DreamFactory\Core\Masking\Classifier\TypeMap;
use DreamFactory\Core\Masking\Support\Activity;
use DreamFactory\Core\Masking\Support\PolicyVersion;
use DreamFactory\Core\Masking\Support\Tables;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * Nothing is served unclassified: columns of a covered table that dm_column does not know yet
 * (a table or column created after the last scan) are classified inline from their names
 * (Classifier\NameOnly), stored in dm_column (source 'detected', scanned_at null) and enforced
 * immediately. A text column whose name says nothing is span-masked until scanned.
 * A scan of the service starts right away (at most one such scan per service per
 * minute, a later request is deferred, never dropped), so sampled evidence replaces the
 * name-only verdict within seconds.
 */
final class InlineClassifier
{
    private const NAME_ONLY = 'DreamFactory\\Core\\Masking\\Classifier\\NameOnly';
    private const SCAN_LAUNCHER = 'DreamFactory\\Core\\Masking\\Scanner\\ScanLauncher';

    /** At most one "unknown columns" scan per service per this many seconds. */
    public const UNKNOWN_SCAN_DEDUPE_SECONDS = 60;

    /** DreamFactory simple types whose values are never text. */
    private const NON_TEXT_TYPES = ['integer', 'bigint', 'smallint', 'id', 'reference', 'user_id', 'user_id_on_create',
        'user_id_on_update', 'boolean', 'float', 'double', 'decimal', 'money', 'date', 'time', 'datetime', 'timestamp',
        'timestamp_on_create', 'timestamp_on_update', 'binary'];

    private function __construct()
    {
    }

    /**
     * @param array<string,true> $known  column names dm_column already holds (exact)
     * @param array<string,array> $masked the table's masked columns (real name => policy entry):
     *                                    computed fields inherit from the columns they read
     * @return array<string,array{class:?string,tier:?string,verdict:string}>|null new rows by real
     *         column name, or null when nothing was unknown
     */
    public static function classifyUnknown(TableTarget $target, array $known, array $masked = []): ?array
    {
        $unknown = [];
        $dbTypes = [];
        $ordinal = [];
        $position = 0;
        foreach ($target->fields as $field) {
            $position++;
            if (!isset($known[$field['column']])) { // exact names (Policy::table)
                $dbTypes[$field['column']] = $field['db_type'] ?? $field['type'];
                $unknown[$field['column']] = self::classifiedType($field);
                $ordinal[$field['column']] = $position;
            }
        }
        if ($unknown === []) {
            return null;
        }

        $verdicts = self::withDerived($target, self::classify($target, $unknown), $masked);
        $now = now();
        $inserted = [];
        foreach ($verdicts as $column => $v) {
            $evidence = $v['evidence'] ?? null;
            try {
                DB::table(Tables::COLUMN)->insert([
                    'service_id' => $target->serviceId,
                    'table_name' => $target->table,
                    'column_name' => (string)$column,
                    'db_type' => self::clip($dbTypes[$column] ?? null, 100),
                    'verdict' => $v['verdict'],
                    'class' => $v['class'],
                    'tier' => $v['tier'],
                    'score' => (int)$v['score'],
                    'source' => 'detected',
                    'detected_class' => $v['class'],
                    'detected_score' => (int)$v['score'],
                    'evidence' => is_array($evidence) ? json_encode($evidence, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : null,
                    'examples' => null,
                    'scanned_at' => null,
                    'ordinal' => $ordinal[$column] ?? null,
                    'created_at' => $now,
                    'updated_at' => $now,
                ]);
                $inserted[(string)$column] = ['class' => $v['class'], 'tier' => $v['tier'], 'verdict' => $v['verdict']];
            } catch (\Throwable $e) {
                // A concurrent request inserted it first (unique service/table/column): fine.
                Log::debug('df-masking: inline classification row not inserted: ' . $e->getMessage());
            }
        }

        PolicyVersion::bump();
        Policy::forget();
        self::queueScan($target, count($unknown));

        return $verdicts === [] ? null : array_map(
            fn (array $v) => ['class' => $v['class'], 'tier' => $v['tier'], 'verdict' => $v['verdict']],
            $verdicts
        );
    }

    /**
     * @param array<string,?string> $columns real column name => native type
     * @return array<string,array{class:?string,score:int,verdict:string,tier:?string,evidence?:array}>
     */
    private static function classify(TableTarget $target, array $columns): array
    {
        if (class_exists(self::NAME_ONLY)) {
            try {
                return call_user_func([self::NAME_ONLY, 'classifyTable'], $target->table, $columns, self::driverHint($target->serviceType));
            } catch (\Throwable $e) {
                Log::warning('df-masking: name-only classification failed, masking the new columns: ' . $e->getMessage());
            }
        }
        // Classifier unavailable: fail closed (review = masked until an admin decides).
        $out = [];
        foreach ($columns as $column => $_) {
            $out[$column] = [
                'class' => null,
                'score' => 40,
                'verdict' => 'review',
                'tier' => null,
                'evidence' => ['total' => 40, 'threshold_mask' => 70, 'threshold_review' => 40, 'lines' => [
                    ['points' => 40, 'kind' => 'context', 'text' => 'Not scanned yet: masked until a scan or an admin decides'],
                ], 'shapes' => []],
            ];
        }

        return $out;
    }

    /**
     * Unknown computed fields (SELECT db_function) take the verdict DerivedFields gives them when
     * that is stricter than the name-only one, with the evidence line "Built from: ...".
     *
     * @param array<string,array> $verdicts real column name => name-only verdict
     * @return array<string,array>
     */
    private static function withDerived(TableTarget $target, array $verdicts, array $masked): array
    {
        $real = null;
        foreach ($target->fields as $field) {
            $column = $field['column'];
            $fn = $field['select_fn'] ?? null;
            if (!is_string($fn) || !isset($verdicts[$column])) {
                continue;
            }
            $real ??= $target->realColumns();
            $derived = DerivedFields::derive($fn, $real, $masked);
            if ($derived === null || !DerivedFields::stricter($derived['entry'], $verdicts[$column])) {
                continue;
            }
            $entry = $derived['entry'];
            $score = $entry['verdict'] === 'masked' ? 70 : 40;
            $verdicts[$column] = [
                'class' => $entry['class'],
                'score' => $score,
                'verdict' => $entry['verdict'],
                'tier' => $entry['class'] !== null ? $entry['tier'] : null,
                'evidence' => ['total' => $score, 'threshold_mask' => 70, 'threshold_review' => 40, 'lines' => [
                    ['points' => $score, 'kind' => 'context', 'text' => DerivedFields::evidenceText($derived['from'], $derived['unresolved'])],
                ], 'shapes' => []],
            ];
        }

        return $verdicts;
    }

    private static function queueScan(TableTarget $target, int $newColumns): void
    {
        if (!class_exists(self::SCAN_LAUNCHER)) {
            return;
        }
        try {
            // Now, unless an unknown-columns scan of this service started in the last minute (then
            // at the end of that minute). One scan at a time: with another scan running, this
            // service is scanned at its end. Never sampling warehouses.
            call_user_func([self::SCAN_LAUNCHER, 'startThrottled'], $target->service, Activity::SYSTEM, self::UNKNOWN_SCAN_DEDUPE_SECONDS);
            Log::info("df-masking: {$newColumns} unscanned column(s) in {$target->service}.{$target->table} classified by name; scan of the service requested.");
        } catch (\Throwable $e) {
            Log::warning('df-masking: could not queue a background scan: ' . $e->getMessage());
        }
    }

    /**
     * The type name-only classification sees: the native type, unless DreamFactory's simple type
     * says the value is not text (a computed field typed integer over a varchar expression, ...):
     * a never-scanned text column is span-masked, a number never is.
     */
    private static function classifiedType(array $field): ?string
    {
        $db = $field['db_type'] ?? null;
        $df = $field['type'] ?? null;
        if (is_string($df) && in_array(strtolower($df), self::NON_TEXT_TYPES, true) && is_string($db) && class_exists(TypeMap::class)
            && in_array(TypeMap::map($db, $db)[0], ['string', 'text'], true)) {
            return $df;
        }
        return $db ?? $df;
    }

    private static function driverHint(string $serviceType): ?string
    {
        return match (strtolower($serviceType)) {
            'mysql', 'mariadb', 'memsql' => 'mysql',
            'pgsql', 'alloydb' => 'pgsql',
            'sqlite' => 'sqlite',
            'sqlsrv' => 'sqlsrv',
            'oracle' => 'oracle',
            'snowflake' => 'snowflake',
            default => null,
        };
    }

    private static function clip(?string $value, int $max): ?string
    {
        return $value === null ? null : mb_substr($value, 0, $max);
    }
}

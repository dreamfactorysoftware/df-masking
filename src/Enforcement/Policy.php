<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Enforcement;

use DreamFactory\Core\Masking\Support\Catalog;
use DreamFactory\Core\Masking\Support\Formats;
use DreamFactory\Core\Masking\Support\PolicyVersion;
use DreamFactory\Core\Masking\Support\Tables;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * The masking policy of a table: which columns are masked (verdict masked, or review = masked
 * until an admin decides), with their class, tier and current mask format.
 *
 * Read from dm_column + the current mask formats, cached in the application cache and in a
 * per-process memo, both keyed by PolicyVersion::current() (every decision, rule, format change,
 * scan and inline classification bumps it), so a steady-state request costs no database query.
 *
 * Table names are DreamFactory table names as the scanner stores them (TableSchema::$name:
 * "customers", or "sales.customers" outside the default schema). Lookups are exact first, then
 * case-insensitive, so a URL that differs in case from the stored name still finds its policy.
 */
final class Policy
{
    private const CACHE_TTL = 3600;
    private const VERDICTS_MASKED = ['masked', 'review'];

    /** Tier order used to pick the strictest entry when one column name means several things. */
    private const TIER_RANK = [Catalog::TIER_RESTRICTED => 0, Catalog::TIER_FREE_TEXT => 1, Catalog::TIER_IDENTITY => 2, Catalog::TIER_QUASI => 3];

    /** @var array<string,mixed> */
    private static array $memo = [];
    private static ?int $memoVersion = null;

    private function __construct()
    {
    }

    /**
     * @return array<string,array{class:?string,tier:string,format:string,verdict:string}>
     *         real column name => entry, for masked and review columns only
     */
    public static function forTable(int $serviceId, string $table): array
    {
        return self::table($serviceId, $table)['masked'];
    }

    /**
     * The full snapshot of a table: masked columns plus every column name dm_column knows
     * (any verdict, exact names), so enforcement can spot columns that were never classified,
     * and the columns an admin decided (their decision is never overridden).
     *
     * @return array{masked:array<string,array{class:?string,tier:string,format:string,verdict:string}>,known:array<string,true>,admin:array<string,true>}
     */
    public static function table(int $serviceId, string $table): array
    {
        $key = 't2:' . $serviceId . ':' . $table; // exact: "Clients" and "clients" may be different tables

        return self::remember($key, function () use ($serviceId, $table): array {
            $rows = self::rows($serviceId, $table);
            $masked = [];
            $known = [];
            $admin = [];
            foreach ($rows as $row) {
                $column = (string)$row->column_name;
                $known[$column] = true; // exact (byte) names: "ÉMAIL" and "émail", "Email" and "email" are different columns
                if ((string)($row->source ?? '') === 'admin') {
                    $admin[strtolower($column)] = true;
                }
                if (in_array((string)$row->verdict, self::VERDICTS_MASKED, true)) {
                    $masked[$column] = self::entry($row->class, $row->tier, (string)$row->verdict);
                }
            }

            return ['masked' => $masked, 'known' => $known, 'admin' => $admin];
        });
    }

    /**
     * Every masked column of a service by lower-cased column name (strictest entry when the same
     * name is masked differently in several tables). Used for best-effort stored procedure and
     * function results, whose cells cannot be traced back to a table.
     *
     * @return array<string,array{class:?string,tier:string,format:string,verdict:string}>
     */
    public static function forService(int $serviceId): array
    {
        return self::remember('s:' . $serviceId, function () use ($serviceId): array {
            $out = [];
            $rows = DB::table(Tables::COLUMN)
                ->where('service_id', $serviceId)
                ->whereIn('verdict', self::VERDICTS_MASKED)
                ->get(['column_name', 'verdict', 'class', 'tier']);
            foreach ($rows as $row) {
                $name = strtolower((string)$row->column_name);
                $entry = self::entry($row->class, $row->tier, (string)$row->verdict);
                if (!isset($out[$name]) || self::rank($entry['tier']) < self::rank($out[$name]['tier'])) {
                    $out[$name] = $entry;
                }
            }

            return $out;
        });
    }

    /**
     * The masked columns enforcement applies to a covered table right now: the stored policy,
     * plus columns dm_column did not know yet, classified inline by name (and stored) first, so
     * nothing is ever served unclassified.
     *
     * @return array<string,array{class:?string,tier:string,format:string,verdict:string}>
     */
    public static function effective(TableTarget $target): array
    {
        $snapshot = self::table($target->serviceId, $target->table);
        $new = InlineClassifier::classifyUnknown($target, $snapshot['known'], $snapshot['masked']);
        if ($new === null) {
            return self::withDerived($target, $snapshot['masked'], $snapshot['admin'] ?? []);
        }
        $snapshot = self::table($target->serviceId, $target->table);
        $masked = $snapshot['masked'];
        foreach ($new as $column => $verdict) {
            if (!isset($masked[$column]) && in_array($verdict['verdict'], self::VERDICTS_MASKED, true)) {
                $masked[$column] = self::entry($verdict['class'], $verdict['tier'], $verdict['verdict']);
            }
        }

        return self::withDerived($target, $masked, $snapshot['admin'] ?? []);
    }

    /**
     * Computed fields (a SELECT db_function: virtual fields, or a real column with a SELECT
     * override) inherit the masking of the columns their expression reads (DerivedFields), on
     * every request, so a decision on email or ssn reaches a field built from them at once.
     * An admin's own decision on the computed field stands.
     *
     * @param array<string,array{class:?string,tier:string,format:string,verdict:string}> $masked
     * @param array<string,true> $admin lower-cased columns an admin decided
     * @return array<string,array{class:?string,tier:string,format:string,verdict:string}>
     */
    public static function withDerived(TableTarget $target, array $masked, array $admin = []): array
    {
        $real = null;
        $out = $masked;
        foreach ($target->fields as $field) {
            $fn = $field['select_fn'] ?? null;
            if (!is_string($fn) || isset($admin[strtolower($field['column'])])) {
                continue;
            }
            $real ??= $target->realColumns();
            $derived = DerivedFields::derive($fn, $real, $masked);
            if ($derived === null) {
                continue;
            }
            $column = $field['column']; // exact names, like dm_column (Policy::table)
            if (DerivedFields::stricter($derived['entry'], $out[$column] ?? null)) {
                $out[$column] = $derived['entry'];
            }
        }

        return $out;
    }

    /** @return int[] ids of the services Data Masking covers (df-sqldb family). */
    public static function coveredServiceIds(): array
    {
        return ServiceClass::coveredServiceIds();
    }

    /** Drops the per-process memo (tests, long-running processes, after inline writes). */
    public static function forget(): void
    {
        self::$memo = [];
        self::$memoVersion = null;
    }

    /**
     * Policy entry for a stored class/tier. A masked column without a known class fails closed:
     * restricted tier, redact.
     *
     * @return array{class:?string,tier:string,format:string,verdict:string}
     */
    public static function entry(mixed $class, mixed $tier, string $verdict): array
    {
        $class = is_string($class) && Catalog::has($class) ? $class : null;
        if ($class === null) {
            return ['class' => null, 'tier' => Catalog::TIER_RESTRICTED, 'format' => 'redact', 'verdict' => $verdict];
        }
        $tier = Catalog::tierOf($class) ?? (is_string($tier) && Catalog::isTier($tier) ? $tier : Catalog::TIER_RESTRICTED);
        $format = Formats::current($class) ?? 'redact';
        if ($format === 'token' && $tier === Catalog::TIER_RESTRICTED) {
            $format = 'redact';
        }

        return ['class' => $class, 'tier' => $tier, 'format' => $format, 'verdict' => $verdict];
    }

    private static function rank(string $tier): int
    {
        return self::TIER_RANK[$tier] ?? 0;
    }

    /** @return iterable<object> */
    private static function rows(int $serviceId, string $table): iterable
    {
        $columns = ['table_name', 'column_name', 'verdict', 'class', 'tier', 'source'];
        $rows = DB::table(Tables::COLUMN)->where('service_id', $serviceId)->where('table_name', $table)->get($columns);
        // Exact (byte) table names first: a case- or accent-insensitive system DB collation also
        // returns the rows of "clients" for "Clients".
        $exact = $rows->filter(static fn ($r) => (string)$r->table_name === $table);
        if ($exact->isNotEmpty()) {
            return $exact->values();
        }
        if ($rows->isEmpty()) {
            $rows = DB::table(Tables::COLUMN)
                ->where('service_id', $serviceId)
                ->whereRaw('LOWER(table_name) = ?', [strtolower($table)])
                ->get($columns);
        }

        return $rows;
    }

    /**
     * Memo + cache under the current policy version. A database failure is NOT cached and is
     * rethrown: enforcement then fails closed rather than serving a table as unmasked.
     */
    private static function remember(string $key, \Closure $load): array
    {
        $version = PolicyVersion::current();
        if (self::$memoVersion !== $version) {
            self::$memo = [];
            self::$memoVersion = $version;
        }
        if (isset(self::$memo[$key])) {
            return self::$memo[$key];
        }
        $cacheKey = 'df-masking:policy:v' . $version . ':' . sha1($key);
        if ($version > 0) {
            try {
                $cached = Cache::get($cacheKey);
                if (is_array($cached)) {
                    return self::$memo[$key] = $cached;
                }
            } catch (\Throwable $e) {
                Log::debug('df-masking: policy cache read failed: ' . $e->getMessage());
            }
        }
        $value = $load();
        if ($version > 0) {
            try {
                Cache::put($cacheKey, $value, self::CACHE_TTL);
            } catch (\Throwable $e) {
                Log::debug('df-masking: policy cache write failed: ' . $e->getMessage());
            }
        }

        return self::$memo[$key] = $value;
    }
}

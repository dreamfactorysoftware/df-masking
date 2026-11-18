<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Enforcement;

use DreamFactory\Core\Masking\Enforcement\Filter\FieldToken;
use DreamFactory\Core\Masking\Enforcement\Filter\FilterRewriter;
use DreamFactory\Core\Masking\Masking\Masker;
use DreamFactory\Core\Masking\Support\Catalog;

/**
 * Request-side protection for one table request, for the columns the caller does not see in
 * clear. Pure: works on the request's parameter and payload arrays and
 * returns new ones; the event listener applies them.
 *
 * Reads: comparisons in filter / having that touch a masked column the caller may not compare
 * are unknown (FilterRewriter: they match no rows); order, group and aggregate
 * functions in fields are dropped when they touch a masked column. Each is reported as
 * "filter:ssn", "order:email", ... for the X-DreamFactory-Masking-Rewrites header. Server-side
 * filters (role record filters, ss_filters) are never touched: they are the admin's access
 * filters.
 *
 * Writes: filters are checked, not rewritten (a violation refuses the request); values for
 * masked columns that are masked outputs (the client sent back what it read) are removed, i.e.
 * treated as "unchanged"; expressions are refused on tables with masked columns.
 *
 * Every parser here mirrors df-sqldb's own (Table::runQuery/parseSelect/parseGroupBy): order is
 * split on commas and the field is the first space-separated word; group and fields are split on
 * commas; aggregates are SUM|COUNT|AVG|MIN|MAX(column). Field tokens are then normalized
 * (Filter\FieldToken: quotes, table/schema qualifiers, function wrappers, DISTINCT, "AS alias")
 * and matched by DreamFactory field name AND real column name, so the guards never rely on
 * DreamFactory rejecting an unusual spelling.
 */
final class RequestGuard
{
    private const AGGREGATE = '/^(SUM|COUNT|AVG|MIN|MAX)\s*\(\s*(.+?)\s*\)$/i';

    /** DreamFactory simple types whose masked value is null (numbers, booleans): a null sent back means "unchanged". */
    private const NULL_MASKED_TYPES = [
        'integer', 'bigint', 'smallint', 'tinyint', 'mediumint', 'float', 'double', 'decimal', 'money',
        'boolean', 'id', 'bigid', 'smallid', 'mediumid', 'reference', 'user_id', 'user_id_on_create',
        'user_id_on_update',
    ];

    private readonly FilterRewriter $filters;

    /** @var array<string,array> $hidden plus the real column names of aliased fields (request-side matching) */
    private readonly array $match;

    /**
     * @param array<string,array{name:string,column:string,class:?string,tier:string,format:string,type?:?string}> $hidden
     *        lower-cased field name (alias or column name as clients write it) => policy entry
     * @param array<string,array> $filterGuard fields whose FILTER db_function reads masked
     *        columns (Listener::filterGuard): guarded in filters only
     * @param list<string> $falseFields real columns for the always-false filter (FilterRewriter)
     */
    public function __construct(private readonly array $hidden, private readonly ?Masker $masker = null, array $filterGuard = [], array $falseFields = [])
    {
        $match = $hidden;
        foreach ($hidden as $entry) {
            $column = strtolower((string)($entry['column'] ?? ''));
            if ($column !== '' && !isset($match[$column])) {
                $match[$column] = $entry;
            }
        }
        $this->match = $match;
        $this->filters = new FilterRewriter(array_merge($match, $filterGuard), $falseFields);
    }

    public function filters(): FilterRewriter
    {
        return $this->filters;
    }

    /**
     * @param array<string,mixed> $params request parameters (DreamFactory option names)
     * @return array{params:array<string,mixed>,dropped:list<string>,changed:bool}
     */
    public function guardRead(array $params): array
    {
        $dropped = [];
        $changed = false;
        if ($this->hidden === [] && !$this->filters->guardsAnything()) {
            return ['params' => $params, 'dropped' => [], 'changed' => false];
        }

        foreach (['filter', 'having'] as $key) {
            if (!array_key_exists($key, $params)) {
                continue;
            }
            $value = $params[$key];
            if (is_string($value)) {
                $r = $this->filters->forRead($value);
                if ($r['changed']) {
                    $changed = true;
                    $this->setOrUnset($params, $key, $r['filter']);
                    foreach ($r['dropped'] as $name) {
                        $dropped[] = $key . ':' . $name;
                    }
                }
            }
            // Any other form (filter[]=..., having[]=...) is left alone, as DreamFactory leaves it:
            // its SQL services ignore a filter that is not a string (Table::convertFilterToNative
            // keeps only the role's server-side filters), so nothing is evaluated and nothing is
            // reported as dropped. (DreamFactory 7.7 does not read `having` at all; a string
            // `having` is still guarded in case a connector does.)
        }

        if (isset($params['order']) && is_string($params['order'])) {
            [$order, $names] = $this->guardOrder($params['order']);
            if ($names !== []) {
                $changed = true;
                $this->setOrUnset($params, 'order', $order);
                foreach ($names as $name) {
                    $dropped[] = 'order:' . $name;
                }
            }
        }

        $droppedGroupColumns = [];
        if (isset($params['group']) && (is_string($params['group']) || is_array($params['group']))) {
            [$group, $names, $lowers] = $this->guardList($params['group'], false);
            if ($names !== []) {
                $changed = true;
                $droppedGroupColumns = $lowers;
                $this->setOrUnset($params, 'group', $group);
                foreach ($names as $name) {
                    $dropped[] = 'group:' . $name;
                }
            }
        }

        if (isset($params['fields']) && (is_string($params['fields']) || is_array($params['fields'])) && $params['fields'] !== '*') {
            [$fields, $names] = $this->guardFields($params['fields'], $droppedGroupColumns);
            if ($names !== [] || $fields !== $params['fields']) {
                $changed = true;
                // An emptied field list makes DreamFactory return the key fields only.
                $params['fields'] = $fields ?? '';
                foreach ($names as $name) {
                    $dropped[] = 'fields:' . $name;
                }
            }
        }

        return ['params' => $params, 'dropped' => array_values(array_unique($dropped)), 'changed' => $changed];
    }

    /**
     * Masked id fields a by-id request may not compare. Records addressed by id (a
     * path id, "ids", or records sent with the request) are found by an equality comparison
     * DreamFactory makes on their id fields (id_field, else the primary key). On a masked column
     * that is allowed only for identity and quasi columns and up to 25 values; otherwise the
     * comparison is unknown: a read finds no record, a write is refused.
     *
     * @param list<string> $idFields DreamFactory field names (any case)
     * @param int          $count    number of values compared
     * @return list<string> display names
     */
    public function unknownIdFields(array $idFields, int $count): array
    {
        $out = [];
        foreach ($idFields as $field) {
            $lower = strtolower(trim((string)$field));
            $key = isset($this->match[$lower]) ? $lower : FieldToken::hiddenKey($lower, $this->match);
            if ($key === null) {
                continue;
            }
            $tier = (string)($this->match[$key]['tier'] ?? '');
            $exact = $tier === Catalog::TIER_IDENTITY || $tier === Catalog::TIER_QUASI;
            if (!$exact || $count > FilterRewriter::MAX_IN_VALUES) {
                $out[] = (string)$this->match[$key]['name'];
            }
        }

        return array_values(array_unique($out));
    }

    /**
     * Filter of a write (PUT/PATCH/DELETE by filter): checked, never rewritten.
     *
     * @return array{ok:bool,violations:list<string>,uncertain:bool}
     */
    public function checkWriteFilter(array $params): array
    {
        $ok = ['ok' => true, 'violations' => [], 'uncertain' => false];
        if (($this->hidden === [] && !$this->filters->guardsAnything()) || !array_key_exists('filter', $params)) {
            return $ok;
        }
        $filters = is_array($params['filter']) ? $params['filter'] : [$params['filter']];
        $violations = [];
        foreach ($filters as $filter) {
            if (!is_string($filter)) {
                continue;
            }
            $r = $this->filters->forWrite($filter);
            if ($r['uncertain']) {
                return ['ok' => false, 'violations' => [], 'uncertain' => true];
            }
            array_push($violations, ...$r['violations']);
        }
        $violations = array_values(array_unique($violations));

        return ['ok' => $violations === [], 'violations' => $violations, 'uncertain' => false];
    }

    /**
     * True when the payload or the filter parameters carry an {"expression": ...} value.
     * DreamFactory turns those into raw SQL (Table::valueToExpression), which could copy a masked
     * column into a visible one, so they are refused on tables with masked columns.
     */
    public function hasExpression(mixed $payload, array $params): bool
    {
        if ($this->hidden === []) {
            return false;
        }
        foreach (self::records($payload) as $record) {
            foreach ($record as $value) {
                if (self::isExpression($value)) {
                    return true;
                }
            }
        }
        if (isset($params['params']) && is_array($params['params'])) {
            foreach ($params['params'] as $value) {
                if (self::isExpression($value)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Write-back guard: drop values for masked columns that are masked outputs.
     *
     * @return array{payload:mixed,removed:list<string>}
     */
    public function stripMaskedValues(mixed $payload, string $wrapper = 'resource'): array
    {
        if ($this->hidden === [] || !is_array($payload) || $this->masker === null) {
            return ['payload' => $payload, 'removed' => []];
        }
        $removed = [];
        if (isset($payload[$wrapper]) && is_array($payload[$wrapper])) {
            foreach ($payload[$wrapper] as $i => $record) {
                if (is_array($record)) {
                    $payload[$wrapper][$i] = $this->stripRecord($record, $removed);
                }
            }
        } elseif (array_is_list($payload)) {
            foreach ($payload as $i => $record) {
                if (is_array($record)) {
                    $payload[$i] = $this->stripRecord($record, $removed);
                }
            }
        } else {
            $payload = $this->stripRecord($payload, $removed);
        }

        return ['payload' => $payload, 'removed' => array_values(array_unique($removed))];
    }

    /**
     * Masked fields of an insert payload that carry a masked output (glyphs or this class's
     * token): inserting them would store a placeholder or nothing. Nulls are real nulls here.
     *
     * @return list<string> display names
     */
    public function maskedValuesIn(mixed $payload, string $wrapper = 'resource'): array
    {
        if ($this->hidden === [] || $this->masker === null) {
            return [];
        }
        $found = [];
        foreach (self::records($payload, $wrapper) as $record) {
            foreach ($record as $key => $value) {
                $entry = $this->hidden[strtolower((string)$key)] ?? null;
                if ($entry !== null && $value !== null && $this->masker->isMasked($value, (string)($entry['class'] ?? ''), $entry['format'])) {
                    $found[] = $entry['name'];
                }
            }
        }

        return array_values(array_unique($found));
    }

    // ------------------------------------------------------------------------------ internals

    /** @return list<array<string,mixed>> */
    public static function records(mixed $payload, string $wrapper = 'resource'): array
    {
        if (!is_array($payload) || $payload === []) {
            return [];
        }
        if (isset($payload[$wrapper]) && is_array($payload[$wrapper])) {
            return array_values(array_filter($payload[$wrapper], 'is_array'));
        }
        if (array_is_list($payload)) {
            return array_values(array_filter($payload, 'is_array'));
        }

        return [$payload];
    }

    private static function isExpression(mixed $value): bool
    {
        return is_array($value) && array_key_exists('expression', $value);
    }

    private function stripRecord(array $record, array &$removed): array
    {
        foreach ($record as $key => $value) {
            $entry = $this->hidden[strtolower((string)$key)] ?? null;
            if ($entry === null) {
                continue;
            }
            $class = $entry['class'] ?? '';
            $format = $entry['format'];
            if ($value === null) {
                $type = strtolower((string)($entry['type'] ?? ''));
                if ($format === 'null' || in_array($type, self::NULL_MASKED_TYPES, true)) {
                    unset($record[$key]);
                    $removed[] = $entry['name'];
                }
                continue;
            }
            if ($this->masker->isMasked($value, (string)$class, $format)) {
                unset($record[$key]);
                $removed[] = $entry['name'];
            }
        }

        return $record;
    }

    /** @return array{0:?string,1:list<string>} new order (null = none left), dropped names */
    private function guardOrder(string $order): array
    {
        if (str_contains($order, ';')) {
            return [$order, []]; // DreamFactory rejects it anyway
        }
        $kept = [];
        $names = [];
        foreach (explode(',', $order) as $component) {
            $trimmed = trim($component);
            $key = $trimmed === '' ? null : $this->orderKey($trimmed);
            if ($key !== null) {
                $names[] = $this->match[$key]['name'];
                continue;
            }
            $kept[] = $component;
        }
        if ($names === []) {
            return [$order, []];
        }
        $out = trim(implode(',', $kept));

        return [$out === '' ? null : $out, array_values(array_unique($names))];
    }

    /**
     * @return array{0:string|array|null,1:list<string>,2:list<string>} new list (null = none
     *         left), dropped display names, dropped lower-cased fields
     */
    private function guardList(string|array $list, bool $aggregatesOnly): array
    {
        $items = is_array($list) ? $list : explode(',', trim($list, ','));
        $kept = [];
        $names = [];
        $lowers = [];
        foreach ($items as $item) {
            $key = $aggregatesOnly ? null : FieldToken::hiddenKey((string)$item, $this->match);
            if ($key !== null) {
                $names[] = $this->match[$key]['name'];
                $lowers[] = $key;
                continue;
            }
            $kept[] = $item;
        }
        if ($names === []) {
            return [$list, [], []];
        }
        $out = is_array($list) ? array_values($kept) : implode(',', array_map('trim', $kept));

        return [($out === '' || $out === []) ? null : $out, array_values(array_unique($names)), $lowers];
    }

    /**
     * Drops aggregate functions other than COUNT over masked columns, and plain columns whose
     * GROUP BY was dropped (they could not be selected without it).
     *
     * @param list<string> $droppedGroup lower-cased fields removed from group
     * @return array{0:string|array|null,1:list<string>}
     */
    private function guardFields(string|array $fields, array $droppedGroup): array
    {
        $items = is_array($fields) ? $fields : explode(',', trim($fields, ','));
        $kept = [];
        $names = [];
        $hasAggregate = false;
        foreach ($items as $item) {
            $trimmed = self::withoutAlias(trim((string)$item));
            if (preg_match(self::AGGREGATE, $trimmed, $m)) {
                $hasAggregate = true;
                $inner = preg_replace('/^(?:DISTINCT|ALL)\s+/i', '', trim($m[2])) ?? $m[2];
                $key = FieldToken::hiddenKey($inner, $this->match);
                if (strtoupper($m[1]) !== 'COUNT' && $key !== null) {
                    $names[] = $this->match[$key]['name'];
                    continue;
                }
            } elseif (!isset($this->match[strtolower($trimmed)]) && FieldToken::isExpression($trimmed)
                && ($key = FieldToken::hiddenKey($trimmed, $this->match)) !== null) {
                // An expression over a masked column ("upper(ssn)", "ssn)" from a split CONCAT).
                $names[] = $this->match[$key]['name'];
                continue;
            }
            $kept[] = $item;
        }
        if ($droppedGroup !== [] && $hasAggregate) {
            $kept = array_values(array_filter($kept, fn ($item) => !in_array(FieldToken::bare((string)$item) ?? strtolower(trim((string)$item)), $droppedGroup, true)));
        }
        if ($names === [] && count($kept) === count($items)) {
            return [$fields, []];
        }
        $out = is_array($fields) ? array_values($kept) : implode(',', array_map('trim', $kept));

        return [($out === '' || $out === []) ? null : $out, array_values(array_unique($names))];
    }

    /**
     * The masked field an order component sorts by: its first word, normalized (DreamFactory's
     * field), or any masked column the component mentions (direction words aside).
     */
    private function orderKey(string $component): ?string
    {
        $first = explode(' ', $component)[0];
        $key = FieldToken::hiddenKey($first, $this->match);
        if ($key !== null) {
            return $key;
        }
        $rest = preg_replace('/\b(?:asc|desc|nulls|first|last)\b/i', ' ', $component) ?? $component;

        return FieldToken::hiddenKey($rest, $this->match);
    }

    /** "MAX(ssn) AS m" -> "MAX(ssn)". */
    private static function withoutAlias(string $item): string
    {
        return preg_replace('/\s+AS\s+[^\s()]+$/i', '', $item) ?? $item;
    }

    private function setOrUnset(array &$params, string $key, mixed $value): void
    {
        if ($value === null) {
            unset($params[$key]);
        } else {
            $params[$key] = $value;
        }
    }
}

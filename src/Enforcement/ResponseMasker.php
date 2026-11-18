<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Enforcement;

use DreamFactory\Core\Masking\Masking\Masker;

/**
 * Masks response content (PHP arrays, before DreamFactory formats them as JSON, XML or CSV).
 *
 * Table shapes handled (df-database BaseDbTableResource + ResourcesWrapper):
 *  - wrapped list   {"resource": [record, ...], "meta": {...}}   (meta untouched)
 *  - bare list      [record, ...]                                 (always_wrap off, no meta)
 *  - single record  {"id": 1, ...}                                (GET/PUT/PATCH/DELETE by id)
 *  - as_list        {"resource": ["a@b.c", ...]}                  (id field values)
 *  - count_only     42                                            (left alone)
 *  - related        record[relation] = record | [record, ...] | null, masked with the policy
 *                   of the relation's target table (resolved lazily, recursively)
 *
 * Keys are matched case-insensitively against DreamFactory field names (alias when one is
 * defined, otherwise the column name), which is also how DreamFactory itself resolves fields.
 *
 * Stored procedure / function results (best effort): cells whose key matches a masked column
 * name of the service use that column's class and format; every other string cell is span
 * masked.
 */
final class ResponseMasker
{
    private const MAX_DEPTH = 8;

    /** @var array<string,string> response key => lower-cased key (keys repeat on every row) */
    private array $lower = [];

    /** @var array<string,true>|null masked fields seen while masking (maskTableReporting), null = not collecting */
    private ?array $seen = null;

    /** Whether maskRoutine() masked anything (maskRoutineReporting), null = not collecting. */
    private ?bool $routineHit = null;

    public function __construct(private readonly Masker $masker, private readonly string $wrapper = 'resource')
    {
    }

    public function masker(): Masker
    {
        return $this->masker;
    }

    /**
     * @param array<string,array{class:?string,format:string}> $hidden lower-cased field => entry
     * @param \Closure|null $relations fn(string $lowerRelationName): ?array{hidden:array,relations:?\Closure}
     *                                 null when the key is not a relation of this table
     * @param list<string>|null $asListIds lower-cased id fields when the response is an as_list
     *                                     (a list of id values instead of records)
     */
    public function maskTable(mixed $content, array $hidden, ?\Closure $relations = null, ?array $asListIds = null): mixed
    {
        if (!is_array($content) || ($hidden === [] && $relations === null)) {
            return $content;
        }
        if (isset($content[$this->wrapper]) && is_array($content[$this->wrapper]) && array_is_list($content[$this->wrapper])
            && self::onlyWrapperKeys($content, $this->wrapper)) {
            $content[$this->wrapper] = $this->maskList($content[$this->wrapper], $hidden, $relations, $asListIds, 0);

            return $content;
        }
        if (array_is_list($content)) {
            return $this->maskList($content, $hidden, $relations, $asListIds, 0);
        }

        return $this->maskRecord($content, $hidden, $relations, 0);
    }

    /**
     * maskTable() and presentHidden() in one pass over the records (mode On masks and reports
     * every response; walking it once is measurably cheaper on large responses).
     *
     * @return array{0:mixed,1:list<string>} masked content, present names (as presentHidden)
     */
    public function maskTableReporting(mixed $content, array $hidden, ?\Closure $relations = null, ?array $asListIds = null): array
    {
        if (!is_array($content) || ($hidden === [] && $relations === null)) {
            return [$content, []];
        }
        $this->seen = [];
        try {
            $list = $content;
            if (isset($content[$this->wrapper]) && is_array($content[$this->wrapper]) && array_is_list($content[$this->wrapper])
                && self::onlyWrapperKeys($content, $this->wrapper)) {
                $list = $content[$this->wrapper];
            }
            if ($asListIds !== null && array_is_list($list) && $list !== [] && !is_array($list[0] ?? null)) {
                foreach ($asListIds as $id) {
                    if (isset($hidden[$id])) {
                        $this->seen[(string)($hidden[$id]['name'] ?? $id)] = true;
                    }
                }
            }
            $masked = $this->maskTable($content, $hidden, $relations, $asListIds);

            return [$masked, array_keys($this->seen)];
        } finally {
            $this->seen = null;
        }
    }

    /**
     * Masked fields that occur in a table response (same shapes as maskTable): display names of
     * this table's fields ("email") and of related records' fields ("orders_by_customer_id.card").
     * Used for the masking headers and the Preview activity, which name only what a response
     * actually contains.
     *
     * @param array<string,array{name?:string}> $hidden
     * @return list<string>
     */
    public function presentHidden(mixed $content, array $hidden, ?\Closure $relations = null, ?array $asListIds = null): array
    {
        if (!is_array($content) || ($hidden === [] && $relations === null)) {
            return [];
        }
        if (isset($content[$this->wrapper]) && is_array($content[$this->wrapper]) && array_is_list($content[$this->wrapper])
            && self::onlyWrapperKeys($content, $this->wrapper)) {
            $content = $content[$this->wrapper];
        }
        $found = [];
        if (array_is_list($content)) {
            if ($asListIds !== null) {
                foreach ($asListIds as $id) {
                    if (isset($hidden[$id]) && $content !== [] && !is_array($content[0] ?? null)) {
                        $found[(string)($hidden[$id]['name'] ?? $id)] = true;
                    }
                }
            }
            $this->presentInList($content, $hidden, $relations, '', 0, $found);
        } else {
            $this->presentInList([$content], $hidden, $relations, '', 0, $found);
        }

        return array_keys($found);
    }

    /** @param array<string,true> $found */
    private function presentInList(array $records, array $hidden, ?\Closure $relations, string $prefix, int $depth, array &$found): void
    {
        $seen = [];
        $related = [];
        foreach ($records as $record) {
            if (!is_array($record) || array_is_list($record)) {
                continue;
            }
            foreach ($record as $key => $value) {
                $lower = $this->lower[$key] ??= strtolower((string)$key);
                if (!isset($seen[$lower])) {
                    $seen[$lower] = true;
                    if (isset($hidden[$lower])) {
                        $found[$prefix . (string)($hidden[$lower]['name'] ?? $key)] = true;
                        continue;
                    }
                }
                if ($relations === null || !is_array($value) || $value === [] || $depth >= self::MAX_DEPTH || isset($hidden[$lower])) {
                    continue;
                }
                $related[$lower]['key'] ??= (string)$key;
                if (array_is_list($value)) {
                    foreach ($value as $item) {
                        $related[$lower]['records'][] = $item;
                    }
                } else {
                    $related[$lower]['records'][] = $value;
                }
            }
        }
        foreach ($related as $lower => $info) {
            $target = $relations($lower);
            if ($target === null) {
                continue;
            }
            $this->presentInList($info['records'] ?? [], $target['hidden'], $target['relations'] ?? null, $prefix . $info['key'] . '.', $depth + 1, $found);
        }
    }

    /**
     * @param array<string,array{class:?string,format:string}> $hidden
     */
    public function maskRecord(array $record, array $hidden, ?\Closure $relations = null, int $depth = 0, string $prefix = ''): array
    {
        foreach ($record as $key => $value) {
            $lower = $this->lower[$key] ??= strtolower((string)$key);
            if (isset($hidden[$lower])) {
                $entry = $hidden[$lower];
                $record[$key] = $this->masker->mask($value, (string)($entry['class'] ?? ''), $entry['format']);
                if ($this->seen !== null && !array_is_list($record)) {
                    $this->seen[$prefix . (string)($entry['name'] ?? $key)] = true;
                }
                continue;
            }
            if ($relations === null || !is_array($value) || $depth >= self::MAX_DEPTH) {
                continue;
            }
            $target = $relations($lower);
            if ($target === null) {
                continue;
            }
            $record[$key] = array_is_list($value)
                ? $this->maskList($value, $target['hidden'], $target['relations'] ?? null, null, $depth + 1, $prefix . $key . '.')
                : $this->maskRecord($value, $target['hidden'], $target['relations'] ?? null, $depth + 1, $prefix . $key . '.');
        }

        return $record;
    }

    /**
     * maskRoutine() plus whether it masked anything: a key matching a masked column at any
     * depth (whatever its value, null included), or a string whose spans were masked. The
     * masking header depends on this, never on whether a masked value happened to be null.
     *
     * @return array{0:mixed,1:bool} masked content, masked anything
     */
    public function maskRoutineReporting(mixed $content, array $byColumn): array
    {
        $this->routineHit = false;
        try {
            $masked = $this->maskRoutine($content, $byColumn);

            return [$masked, $this->routineHit];
        } finally {
            $this->routineHit = null;
        }
    }

    /**
     * Best-effort masking of stored procedure / function output.
     *
     * @param array<string,array{class:?string,format:string}> $byColumn lower-cased column name => entry
     */
    public function maskRoutine(mixed $content, array $byColumn, int $depth = 0): mixed
    {
        if (is_string($content)) {
            $masked = $this->masker->maskSpans($content);
            if ($this->routineHit === false && $masked !== $content) {
                $this->routineHit = true;
            }

            return $masked;
        }
        if (!is_array($content) || $depth >= self::MAX_DEPTH * 2) {
            return $content;
        }
        foreach ($content as $key => $value) {
            $entry = is_string($key) ? ($byColumn[strtolower($key)] ?? null) : null;
            if ($entry !== null && $this->routineHit === false) {
                $this->routineHit = true;
            }
            if ($entry !== null && !is_array($value)) {
                $content[$key] = $this->masker->mask($value, (string)($entry['class'] ?? ''), $entry['format']);
            } elseif ($entry !== null && is_array($value) && array_is_list($value) && $value !== [] && !is_array($value[0])) {
                // a column of values (e.g. an OUT parameter returned as a list)
                $content[$key] = array_map(fn ($v) => $this->masker->mask($v, (string)($entry['class'] ?? ''), $entry['format']), $value);
            } elseif (is_array($value) || is_string($value)) {
                $content[$key] = $this->maskRoutine($value, $byColumn, $depth + 1);
            }
        }

        return $content;
    }

    private function maskList(array $list, array $hidden, ?\Closure $relations, ?array $asListIds, int $depth, string $prefix = ''): array
    {
        $idEntry = null;
        $composite = false;
        if ($asListIds !== null) {
            foreach ($asListIds as $id) {
                if (isset($hidden[$id])) {
                    $idEntry = $hidden[$id];
                    break;
                }
            }
            $composite = count($asListIds) > 1;
        }
        foreach ($list as $i => $item) {
            if (is_array($item)) {
                $list[$i] = $this->maskRecord($item, $hidden, $relations, $depth, $prefix);
            } elseif ($idEntry !== null && $item !== null) {
                $list[$i] = $composite
                    ? Masker::redacted()
                    : $this->masker->mask($item, (string)($idEntry['class'] ?? ''), $idEntry['format']);
            }
        }

        return $list;
    }

    private static function onlyWrapperKeys(array $content, string $wrapper): bool
    {
        foreach ($content as $key => $_) {
            if ($key !== $wrapper && $key !== 'meta') {
                return false;
            }
        }

        return true;
    }
}

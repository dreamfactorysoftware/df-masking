<?php

namespace DreamFactory\Core\Masking\Resources\Handlers;

/**
 * Column ids on the wire: "service.table.column". Service names cannot contain dots; table
 * names can (schema-qualified tables: "crm.sales.orders.email" -> table "sales.orders"); the
 * column is everything after the LAST dot.
 */
final class ColumnId
{
    private function __construct()
    {
    }

    public static function format(string $service, string $table, string $column): string
    {
        return $service . '.' . $table . '.' . $column;
    }

    /**
     * @return array{service:string,table:string,column:string}|null null when malformed
     */
    public static function parse(string $id): ?array
    {
        $first = strpos($id, '.');
        $last = strrpos($id, '.');
        if ($first === false || $last === false || $last <= $first) {
            return null;
        }
        $service = substr($id, 0, $first);
        $table = substr($id, $first + 1, $last - $first - 1);
        $column = substr($id, $last + 1);
        if ($service === '' || $table === '' || $column === '') {
            return null;
        }

        return ['service' => $service, 'table' => $table, 'column' => $column];
    }

    /**
     * Every (table, column) split of an id, the canonical parse() split first. Lets a lookup
     * resolve the rare column name that itself contains a dot.
     *
     * @return list<array{service:string,table:string,column:string}>
     */
    public static function candidates(string $id): array
    {
        $canonical = self::parse($id);
        if ($canonical === null) {
            return [];
        }
        $out = [$canonical];
        $service = $canonical['service'];
        $rest = substr($id, strlen($service) + 1);
        $offset = 0;
        while (($pos = strpos($rest, '.', $offset)) !== false) {
            $table = substr($rest, 0, $pos);
            $column = substr($rest, $pos + 1);
            $offset = $pos + 1;
            if ($table === '' || $column === '' || ($table === $canonical['table'] && $column === $canonical['column'])) {
                continue;
            }
            $out[] = ['service' => $service, 'table' => $table, 'column' => $column];
        }

        return $out;
    }
}

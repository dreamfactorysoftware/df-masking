<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Enforcement;

/**
 * Masks the LLM data model returned by GET {service}/_spec?model=true (df-core
 * BaseRestService::buildDataModel), which MCP's get_data_model hands to AI clients.
 *
 * The model carries real values in two places per table:
 *  - tables.<t>.sample_data: up to three raw rows (keys are database column names). Masked
 *    columns are masked like any response value, so the model stays useful (shapes, tokens).
 *  - tables.<t>.enum_values.<column>: the distinct values of low-cardinality text columns.
 *    Removed for masked columns: a list of masked values says nothing useful and its size
 *    would still describe the column.
 * Everything else (column names and types, keys, relationships, query templates) has no values.
 * A table whose policy cannot be resolved ($hiddenFor returns null) loses both, fail closed.
 */
final class SpecMasker
{
    public function __construct(private readonly ResponseMasker $masker)
    {
    }

    /**
     * @param array    $model     decoded model document
     * @param \Closure $hiddenFor fn(string $table): ?array lower-cased column/field name => entry
     *                            (null: the table could not be resolved)
     * @return array{model:array,changed:bool}
     */
    public function mask(array $model, \Closure $hiddenFor): array
    {
        if (!isset($model['tables']) || !is_array($model['tables'])) {
            return ['model' => $model, 'changed' => false];
        }
        $changed = false;
        foreach ($model['tables'] as $table => $entry) {
            if (!is_array($entry)) {
                continue;
            }
            $hidden = $hiddenFor((string)$table);
            if ($hidden === null) {
                $withheld = isset($entry['sample_data']) || isset($entry['enum_values']);
                unset($entry['sample_data'], $entry['enum_values']);
                if ($withheld) {
                    $model['tables'][$table] = $entry;
                    $changed = true;
                }
                continue;
            }
            if ($hidden === []) {
                continue;
            }
            if (isset($entry['sample_data']) && is_array($entry['sample_data'])) {
                foreach ($entry['sample_data'] as $i => $row) {
                    if (is_array($row)) {
                        $entry['sample_data'][$i] = $this->masker->maskRecord($row, $hidden);
                    }
                }
                $changed = true;
            }
            if (isset($entry['enum_values']) && is_array($entry['enum_values'])) {
                foreach (array_keys($entry['enum_values']) as $column) {
                    if (isset($hidden[strtolower((string)$column)])) {
                        unset($entry['enum_values'][$column]);
                        $changed = true;
                    }
                }
                if ($entry['enum_values'] === []) {
                    unset($entry['enum_values']);
                }
            }
            $model['tables'][$table] = $entry;
        }

        return ['model' => $model, 'changed' => $changed];
    }
}

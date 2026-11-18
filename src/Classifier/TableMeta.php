<?php
declare(strict_types=1);

namespace DreamFactory\Core\Masking\Classifier;

/** Table metadata, mirroring DF's TableSchema (name is schema-qualified outside the default schema). */
final class TableMeta
{
    /**
     * @param list<ColumnMeta> $columns
     * @param list<string> $primaryKey
     */
    public function __construct(
        public readonly string $schema,
        public readonly string $name,
        public readonly string $dfName,
        public readonly string $kind,
        public readonly array $columns,
        public readonly array $primaryKey = [],
        public readonly ?string $uniqueKey = null,
        public readonly ?string $comment = null,
    ) {
    }
}

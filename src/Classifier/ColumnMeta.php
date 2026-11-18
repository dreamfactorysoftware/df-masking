<?php
declare(strict_types=1);

namespace DreamFactory\Core\Masking\Classifier;

/** Column metadata, mirroring what DF's cached ColumnSchema provides. */
final class ColumnMeta
{
    public function __construct(
        public readonly string $name,
        public readonly string $dbType,
        public readonly string $dfType,
        public readonly ?int $size = null,
        public readonly bool $isPrimaryKey = false,
        public readonly bool $isForeignKey = false,
        public readonly ?string $refTable = null,
        public readonly bool $isUnique = false,
        public readonly ?string $comment = null,
        public readonly bool $sampleable = true,
    ) {
    }
}

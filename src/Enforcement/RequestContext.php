<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Enforcement;

/**
 * What enforcement resolved for one service request (one ServiceRequest object): the target,
 * the mode at the time, the columns this caller does not see in clear, and what was dropped.
 * Built in the pre-process stage and reused by the post-process and final stages.
 */
final class RequestContext
{
    public const TABLE = 'table';
    public const ROUTINE = 'routine';
    /** A covered table enforcement could not resolve: successful responses are withheld. */
    public const UNRESOLVED = 'unresolved';

    /** @var list<string> "filter:ssn", "order:email", ... */
    public array $dropped = [];

    /**
     * Position in the request-scoped dropped collector when this context was created: items
     * collected from then on (this request's and those of internal requests DreamFactory made
     * while serving it, such as related records) are reported in this response's Rewrites header.
     */
    public int $collectFrom = 0;

    /**
     * @var array<string,array> lower-cased field => entry, for fields whose FILTER db_function
     *      reads masked columns (filters on them are guarded like filters on those columns)
     */
    public array $filterGuard = [];

    /**
     * @param array<string,array> $hidden lower-cased field => policy entry + name/column/type
     *                                    (tables) or lower-cased column => entry (routines)
     * @param \Closure|null       $relations related-records resolver (tables)
     * @param bool                $maskedCaller the caller lacks real-value access to some tier
     */
    public function __construct(
        public readonly string $kind,
        public readonly string $mode,
        public readonly string $service,
        public readonly int $serviceId,
        public readonly ?TableTarget $target,
        public readonly array $hidden,
        public readonly ?\Closure $relations,
        public readonly bool $maskedCaller,
        public readonly string $resourceName,
    ) {
    }

    public function enforcing(): bool
    {
        return $this->mode === 'on';
    }

    /** Identifiers that error scrubbing may leave quoted. */
    public function keepIdentifiers(): array
    {
        $keep = [$this->service, $this->resourceName];
        if ($this->target !== null) {
            $keep[] = $this->target->table;
            foreach ($this->target->fields as $field) {
                $keep[] = $field['name'];
                $keep[] = $field['column'];
            }
            foreach ($this->target->relations as $relation) {
                $keep[] = $relation['name'];
            }
        }

        return array_values(array_unique(array_filter($keep, fn ($v) => $v !== '')));
    }

    /** Display names of the hidden fields, in table order. */
    public function hiddenNames(): array
    {
        $names = [];
        foreach ($this->hidden as $entry) {
            $names[] = (string)($entry['name'] ?? '');
        }

        return array_values(array_filter($names, fn ($n) => $n !== ''));
    }
}

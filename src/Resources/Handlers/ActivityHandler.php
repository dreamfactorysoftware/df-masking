<?php

namespace DreamFactory\Core\Masking\Resources\Handlers;

use DreamFactory\Core\Exceptions\BadRequestException;
use DreamFactory\Core\Masking\Support\Activity;
use DreamFactory\Core\Masking\Support\Tables;
use DreamFactory\Core\Masking\Support\Time;
use Illuminate\Support\Facades\DB;

/**
 * GET system/data_masking/activity?kind=&limit=&before= : newest first, default 200, max 1000.
 * `kind` takes one kind or a comma list (mode,decision,access,scan,blocked,rule,baseline,preview);
 * `before` an activity id (rows older than it: the next page). `has_more` says whether older rows
 * of the same kinds exist. Rule rows also carry `match` (name|value, from meta), so the admin app
 * can read their target, the pattern, back as the rule's sentence.
 */
final class ActivityHandler
{
    public const DEFAULT_LIMIT = 200;
    public const MAX_LIMIT = 1000;

    /** @throws BadRequestException */
    public function list(mixed $kind, mixed $limit, mixed $before = null): array
    {
        $query = DB::table(Tables::ACTIVITY);

        if ($kind !== null && $kind !== '') {
            $kinds = array_values(array_filter(array_map('trim', explode(',', (string)$kind)), 'strlen'));
            $unknown = array_diff($kinds, Activity::KINDS);
            if ($unknown !== []) {
                throw new BadRequestException('Unknown activity kind: ' . implode(', ', $unknown) . '. Use ' . implode(', ', Activity::KINDS) . '.');
            }
            $query->whereIn('kind', $kinds);
        }

        $n = self::DEFAULT_LIMIT;
        if ($limit !== null && $limit !== '') {
            if (filter_var($limit, FILTER_VALIDATE_INT) === false || (int)$limit < 1) {
                throw new BadRequestException('limit must be a positive integer.');
            }
            $n = min(self::MAX_LIMIT, (int)$limit);
        }

        if ($before !== null && $before !== '') {
            if (filter_var($before, FILTER_VALIDATE_INT) === false || (int)$before < 1) {
                throw new BadRequestException('before must be an activity id.');
            }
            $query->where('id', '<', (int)$before);
        }

        // Ids grow with time (rows are only ever appended), so id order is time order and pages
        // never overlap or skip rows that share a timestamp.
        $rows = $query->orderByDesc('id')->limit($n + 1)
            ->get(['id', 'created_at', 'actor', 'kind', 'text', 'target', 'meta'])->all();
        $hasMore = count($rows) > $n;
        $rows = array_slice($rows, 0, $n);

        $out = [];
        foreach ($rows as $row) {
            $event = [
                'id' => (int)$row->id,
                'at' => Time::iso($row->created_at),
                'actor' => (string)$row->actor,
                'kind' => (string)$row->kind,
                'text' => (string)$row->text,
                'target' => $row->target === null ? null : (string)$row->target,
            ];
            if ($event['kind'] === 'rule' && null !== ($match = self::ruleMatch($row->meta))) {
                $event['match'] = $match;
            }
            $out[] = $event;
        }

        return ['resource' => $out, 'has_more' => $hasMore];
    }

    /** A rule row's match from its meta; null when it has none (rows logged before it was). */
    private static function ruleMatch(mixed $meta): ?string
    {
        $decoded = is_string($meta) ? json_decode($meta, true) : null;
        $match = is_array($decoded) ? ($decoded['match'] ?? null) : null;

        return in_array($match, ['name', 'value'], true) ? $match : null;
    }
}

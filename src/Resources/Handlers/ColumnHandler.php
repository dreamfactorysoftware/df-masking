<?php

namespace DreamFactory\Core\Masking\Resources\Handlers;

use DreamFactory\Core\Exceptions\BadRequestException;
use DreamFactory\Core\Exceptions\NotFoundException;
use DreamFactory\Core\Masking\Support\Activity;
use DreamFactory\Core\Masking\Support\Caller;
use DreamFactory\Core\Masking\Support\Catalog;
use DreamFactory\Core\Masking\Support\Coverage;
use DreamFactory\Core\Masking\Support\Formats;
use DreamFactory\Core\Masking\Support\PolicyVersion;
use DreamFactory\Core\Masking\Support\ScanHistory;
use DreamFactory\Core\Masking\Support\Tables;
use DreamFactory\Core\Masking\Support\Time;
use Illuminate\Support\Facades\DB;

/**
 * GET system/data_masking/table, GET system/data_masking/column,
 * PATCH system/data_masking/column/{service.table.column} (or PATCH column {id, class}).
 *
 * Responses are built from dm_column (verdicts, evidence, masked examples) and the current
 * mask formats. Nothing here ever reads customer data.
 */
final class ColumnHandler
{
    private const MASKER = 'DreamFactory\\Core\\Masking\\Masking\\Masker';

    private const COLUMNS = [
        'id', 'service_id', 'table_name', 'column_name', 'db_type', 'verdict', 'class', 'tier', 'score',
        'source', 'evidence', 'examples', 'decided_by', 'decided_at', 'ordinal',
    ];

    /** @var object|null|false lazily built Masker (false = unavailable) */
    private $masker = null;

    public function tables(): array
    {
        $services = Coverage::covered();
        $byService = [];
        foreach ($services as $s) {
            $byService[$s['id']] = [];
        }
        if ($byService !== []) {
            try {
                $rows = DB::table(Tables::COLUMN)
                    ->whereIn('service_id', array_keys($byService))
                    ->orderBy('service_id')
                    ->orderBy('table_name')
                    ->orderByRaw('CASE WHEN ordinal IS NULL THEN 1 ELSE 0 END')
                    ->orderBy('ordinal')
                    ->orderBy('id')
                    ->get(['service_id', 'table_name', 'column_name', 'verdict', 'tier']);
            } catch (\Throwable $e) {
                $rows = [];
            }
            foreach ($rows as $row) {
                $sid = (int)$row->service_id;
                $table = (string)$row->table_name;
                if (!isset($byService[$sid][$table])) {
                    $byService[$sid][$table] = [
                        'name' => $table,
                        'rows' => null,
                        'columns' => ['masked' => 0, 'review' => 0, 'clear' => 0],
                        'strip' => [],
                    ];
                }
                $verdict = self::verdict($row->verdict);
                $tier = $verdict === 'clear' ? null : (Catalog::isTier($row->tier) ? $row->tier : null);
                $byService[$sid][$table]['columns'][$verdict]++;
                $byService[$sid][$table]['strip'][] = [
                    'column' => (string)$row->column_name,
                    'mark' => match ($verdict) {
                        'review' => 'review',
                        'clear' => 'clear',
                        default => $tier ?? Catalog::TIER_RESTRICTED,
                    },
                    'tier' => $tier,
                ];
            }
        }

        $history = ScanHistory::services(array_keys($byService));
        $out = [];
        foreach ($services as $s) {
            $tables = array_values($byService[$s['id']]);
            usort($tables, fn ($a, $b) => strnatcasecmp($a['name'], $b['name']));
            $out[] = [
                'service' => $s['name'],
                'label' => $s['label'],
                // Tells a scanned empty database (tables: [], scanned_at set) from one never scanned.
                // A scan that could not read the service does not advance it.
                'scanned_at' => Time::iso($history[$s['id']]['scanned_at'] ?? null),
                // Why the latest scan of this service failed (value-free), null when it did not.
                'scan_error' => $history[$s['id']]['scan_error'] ?? null,
                // The scan history could not be read: scanned_at / scan_error are unknown, not "never".
                'scan_unknown' => (bool)($history[$s['id']]['unknown'] ?? false),
                'tables' => $tables,
            ];
        }

        return ['resource' => $out];
    }

    /** @throws NotFoundException|BadRequestException */
    public function columns(?string $service, ?string $table): array
    {
        $query = DB::table(Tables::COLUMN);
        $names = [];
        if ($service !== null && $service !== '') {
            $info = self::coveredService($service);
            $query->where('service_id', $info['id']);
            $names[$info['id']] = $info['name'];
        } else {
            foreach (Coverage::covered() as $s) {
                $names[$s['id']] = $s['name'];
            }
            if ($names === []) {
                return ['resource' => []];
            }
            $query->whereIn('service_id', array_keys($names));
        }
        if ($table !== null && $table !== '') {
            $query->where('table_name', $table);
        }

        $rows = $query
            ->orderBy('service_id')
            ->orderBy('table_name')
            ->orderByRaw('CASE WHEN ordinal IS NULL THEN 1 ELSE 0 END')
            ->orderBy('ordinal')
            ->orderBy('id')
            ->get(self::COLUMNS);

        $out = [];
        foreach ($rows as $row) {
            if ($table !== null && $table !== '' && (string)$row->table_name !== $table) {
                continue; // exact table names (a case-insensitive collation also matches "Clients" for "clients")
            }
            $out[] = $this->wire($row, $names[(int)$row->service_id] ?? '');
        }

        return ['resource' => $out];
    }

    /**
     * PATCH column/{id} {class: string|null}.
     *
     * @throws BadRequestException|NotFoundException|\DreamFactory\Core\Exceptions\ForbiddenException
     */
    public function decide(string $id, array $payload): array
    {
        $id = trim($id);
        Guard::denyAi('Blocked an attempt to change a column decision', $id);

        if (!array_key_exists('class', $payload)) {
            throw new BadRequestException('Send class: a class id to mask the column, or null to mark it not sensitive.');
        }
        $class = $payload['class'];
        if ($class !== null && (!is_string($class) || !Catalog::has($class))) {
            throw new BadRequestException('Unknown class. Use one of: ' . implode(', ', Catalog::ids()) . ', or null.');
        }
        if ($class === null) {
            Guard::requireSysAdmin('Blocked an attempt to mark a column not sensitive', Guard::SYS_ADMIN_MESSAGE, $id);
        }

        [$row, $serviceName] = $this->find($id);
        $canonicalId = ColumnId::format($serviceName, (string)$row->table_name, (string)$row->column_name);

        $verdict = $class === null ? 'clear' : 'masked';
        $previous = self::verdict($row->verdict);
        $unchanged = $row->source === 'admin' && $previous === $verdict && $row->class === $class;
        if (!$unchanged) {
            $caller = Caller::current();
            DB::table(Tables::COLUMN)->where('id', $row->id)->update([
                'verdict' => $verdict,
                'class' => $class,
                'tier' => $class === null ? null : Catalog::tierOf($class),
                'source' => 'admin',
                'decided_by_id' => $caller->userId(),
                'decided_by' => mb_substr($caller->label(), 0, 255),
                'decided_at' => now(),
                'updated_at' => now(),
            ]);
            PolicyVersion::bump();

            if ($class === null) {
                $text = 'Marked not sensitive';
            } elseif ($previous !== 'clear' && $row->class === $class) {
                $text = 'Kept masked as ' . Catalog::label($class);
            } else {
                $text = 'Set class to ' . Catalog::label($class);
            }
            Activity::log('decision', $text, $canonicalId, ['from' => $row->class, 'to' => $class]);
        }

        $fresh = DB::table(Tables::COLUMN)->where('id', $row->id)->first(self::COLUMNS);

        return $this->wire($fresh, $serviceName);
    }

    /** The wire shape of one dm_column row (Column). */
    public function wire(object $row, string $serviceName): array
    {
        $verdict = self::verdict($row->verdict);
        $class = Catalog::has($row->class) ? (string)$row->class : null;
        $tier = $class !== null ? Catalog::tierOf($class) : null;
        $score = max(0, min(100, (int)$row->score));

        $evidence = self::decodeJson($row->evidence);
        $lines = [];
        foreach ((array)($evidence['lines'] ?? []) as $line) {
            if (is_array($line) && isset($line['text'])) {
                $lines[] = [
                    'points' => (int)($line['points'] ?? 0),
                    'kind' => (string)($line['kind'] ?? 'context'),
                    'text' => (string)$line['text'],
                ];
            }
        }
        $shapes = [];
        foreach ((array)($evidence['shapes'] ?? []) as $shape) {
            if (is_array($shape) && count($shape) >= 2) {
                $shapes[] = [(string)$shape[0], (int)$shape[1]];
            }
        }

        $format = ($verdict === 'clear' || $class === null) ? null : Formats::current($class);
        $example = $format === null ? null : $this->example($row->examples, $class, $format);

        return [
            'id' => ColumnId::format($serviceName, (string)$row->table_name, (string)$row->column_name),
            'service' => $serviceName,
            'table' => (string)$row->table_name,
            'column' => (string)$row->column_name,
            'type' => (string)($row->db_type ?? ''),
            'verdict' => $verdict,
            'class' => $verdict === 'clear' ? null : $class,
            'tier' => $verdict === 'clear' ? null : $tier,
            'source' => $row->source === 'admin' ? 'admin' : 'detected',
            'decided_by' => $row->source === 'admin' ? $row->decided_by : null,
            'decided_at' => $row->source === 'admin' ? Time::iso($row->decided_at) : null,
            'confidence' => $score,
            'example' => $example,
            'format' => $format,
            'evidence' => [
                'total' => (int)($evidence['total'] ?? $score),
                'threshold_mask' => (int)($evidence['threshold_mask'] ?? 70),
                'threshold_review' => (int)($evidence['threshold_review'] ?? 40),
                'lines' => $lines,
                'shapes' => $shapes,
            ],
        ];
    }

    /**
     * @return array{0:object,1:string} the dm_column row and the service name
     * @throws BadRequestException|NotFoundException
     */
    private function find(string $id): array
    {
        $candidates = ColumnId::candidates($id);
        if ($candidates === []) {
            throw new BadRequestException("Invalid column id '$id'. Use service.table.column.");
        }
        $info = self::coveredService($candidates[0]['service']);
        foreach ($candidates as $c) {
            $rows = DB::table(Tables::COLUMN)
                ->where('service_id', $info['id'])
                ->where('table_name', $c['table'])
                ->where('column_name', $c['column'])
                ->get(self::COLUMNS);
            foreach ($rows as $row) {
                // Exact names only: a case- or accent-insensitive collation must not pick "Email" for "email".
                if ((string)$row->table_name === $c['table'] && (string)$row->column_name === $c['column']) {
                    return [$row, $info['name']];
                }
            }
        }

        throw new NotFoundException("Column '$id' not found. Scan the service first.");
    }

    /** @throws NotFoundException */
    private static function coveredService(string $name): array
    {
        $info = Coverage::byName($name);
        if ($info === null || !$info['covered']) {
            throw new NotFoundException("'$name' is not a database service Data Masking covers.");
        }

        return $info;
    }

    /** Stored masked example for $format; else the masked synthetic class sample. */
    private function example(?string $examples, string $class, string $format): ?string
    {
        foreach ((array)self::decodeJson($examples) as $e) {
            if (is_array($e) && ($e['format'] ?? null) === $format) {
                $value = $e['value'] ?? null;

                return $value === null ? null : (string)$value;
            }
        }
        if ($format === 'null') {
            return null;
        }
        $masker = $this->masker();
        $sample = Catalog::sample($class);
        if ($masker === null || $sample === null) {
            return null;
        }
        try {
            $masked = $masker->mask($sample, $class, $format);

            return $masked === null ? null : (string)$masked;
        } catch (\Throwable $e) {
            return null;
        }
    }

    private function masker(): ?object
    {
        if ($this->masker === null) {
            $this->masker = false;
            if (class_exists(self::MASKER)) {
                try {
                    $this->masker = app()->bound(self::MASKER) ? app(self::MASKER) : new (self::MASKER)();
                } catch (\Throwable $e) {
                    $this->masker = false;
                }
            }
        }

        return $this->masker === false ? null : $this->masker;
    }

    private static function verdict(mixed $verdict): string
    {
        return in_array($verdict, ['masked', 'review', 'clear'], true) ? $verdict : 'review';
    }

    private static function decodeJson(mixed $json): array
    {
        if (!is_string($json) || $json === '') {
            return [];
        }
        $value = json_decode($json, true);

        return is_array($value) ? $value : [];
    }
}

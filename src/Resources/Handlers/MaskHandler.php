<?php

namespace DreamFactory\Core\Masking\Resources\Handlers;

use DreamFactory\Core\Exceptions\BadRequestException;
use DreamFactory\Core\Masking\Support\Activity;
use DreamFactory\Core\Masking\Support\Caller;
use DreamFactory\Core\Masking\Support\Catalog;
use DreamFactory\Core\Masking\Support\Formats;
use DreamFactory\Core\Masking\Support\PolicyVersion;
use DreamFactory\Core\Masking\Support\Retry;
use DreamFactory\Core\Masking\Support\Tables;
use Illuminate\Support\Facades\DB;

/**
 * GET/PATCH system/data_masking/mask: the mask format per class.
 */
final class MaskHandler
{
    public function list(): array
    {
        $out = [];
        foreach (Catalog::classes() as $c) {
            $out[] = [
                'class' => $c['id'],
                'tier' => $c['tier'],
                'format' => Formats::current($c['id']),
                'formats_allowed' => $c['formats'],
            ];
        }

        return ['resource' => $out];
    }

    /** @throws BadRequestException|\DreamFactory\Core\Exceptions\ForbiddenException */
    public function patch(array $payload): array
    {
        Guard::denyAi('Blocked an attempt to change mask formats');

        $items = $payload['resource'] ?? null;
        if (!is_array($items) || !array_is_list($items) || $items === []) {
            throw new BadRequestException('Send a resource list of {class, format} items.');
        }
        $changes = [];
        foreach ($items as $item) {
            $class = is_array($item) ? ($item['class'] ?? null) : null;
            $format = is_array($item) ? ($item['format'] ?? null) : null;
            if (!is_string($class) || !Catalog::has($class)) {
                throw new BadRequestException('Unknown class ' . (is_scalar($class) ? "'" . $class . "'" : '') . '. Use one of: ' . implode(', ', Catalog::ids()) . '.');
            }
            if (!is_string($format) || !in_array($format, Catalog::formatsAllowed($class), true)) {
                throw new BadRequestException(
                    Catalog::label($class) . ' can be masked as: ' . implode(', ', Catalog::formatsAllowed($class)) . '.'
                );
            }
            $changes[$class] = $format; // last one wins
        }

        $label = mb_substr(Caller::current()->label(), 0, 255);
        $logged = [];
        Retry::transaction(function () use ($changes, $label, &$logged) {
            $logged = [];
            foreach ($changes as $class => $format) {
                $stored = DB::table(Tables::MASK_FORMAT)->where('class', $class)->value('format');
                if ($stored === $format) {
                    continue;
                }
                if (Formats::current($class) !== $format) {
                    $logged[$class] = $format;
                }
                $values = ['format' => $format, 'updated_by' => $label, 'updated_at' => now()];
                if ($stored === null) {
                    DB::table(Tables::MASK_FORMAT)->insert($values + ['class' => $class]);
                } else {
                    DB::table(Tables::MASK_FORMAT)->where('class', $class)->update($values);
                }
            }
        });
        PolicyVersion::bump();
        Formats::forget();

        foreach ($logged as $class => $format) {
            Activity::log(
                'decision',
                Catalog::label($class) . ' now masked as ' . mb_strtolower(Catalog::formatLabel($format)),
                null,
                ['class' => $class, 'format' => $format]
            );
        }

        return $this->list();
    }
}

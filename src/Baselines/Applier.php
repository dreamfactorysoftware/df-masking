<?php

namespace DreamFactory\Core\Masking\Baselines;

use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use Illuminate\Support\Facades\DB;

/**
 * Writes a Planner plan. Called inside a database transaction by BaselineService::apply().
 *
 * Every write is conditional so it can only tighten, even when another admin changed the same
 * setting between planning and writing: a grant is only shortened, a role scope only narrowed
 * from 'all', a rule only added when no equivalent rule exists.
 */
final class Applier
{
    private function __construct()
    {
    }

    /**
     * @param list<array{id:string,text:string,op:array}> $changes
     */
    public static function write(array $changes, string $actor, int $now): void
    {
        $stamp = Time::carbon($now);
        foreach ($changes as $change) {
            $op = $change['op'];
            switch ($op['type']) {
                case 'mode':
                    Settings::set(Settings::MODE, $op['to']);
                    break;
                case 'ai':
                    Settings::set(Settings::AI, $op['to']);
                    break;
                case 'admins_mode':
                    Settings::set(Settings::ADMINS_MODE, $op['to']);
                    break;
                case 'grant':
                    $cap = Time::carbon($op['expires_at']);
                    DB::table(Tables::ADMIN_GRANT)
                        ->where('admin_id', $op['admin_id'])
                        ->where(function ($q) use ($cap) {
                            $q->whereNull('expires_at')->orWhere('expires_at', '>', $cap);
                        })
                        ->update(['expires_at' => $cap, 'updated_at' => $stamp]);
                    break;
                case 'role':
                    DB::table(Tables::ROLE_ACCESS)
                        ->where('role_id', $op['role_id'])
                        ->where('enabled', true)
                        ->where('scope', 'all')
                        ->update(['scope' => $op['scope'], 'updated_by' => self::clip($actor), 'updated_at' => $stamp]);
                    break;
                case 'format':
                    DB::table(Tables::MASK_FORMAT)->updateOrInsert(
                        ['class' => $op['class']],
                        ['format' => $op['to'], 'updated_by' => self::clip($actor), 'updated_at' => $stamp]
                    );
                    break;
                case 'rule':
                    $exists = DB::table(Tables::RULE)
                        ->where('match', $op['match'])
                        ->where('class', $op['class'])
                        ->where('pattern', $op['pattern'])
                        ->exists();
                    if (!$exists) {
                        DB::table(Tables::RULE)->insert([
                            'match' => $op['match'],
                            'pattern' => $op['pattern'],
                            'class' => $op['class'],
                            'source' => $op['source'],
                            'created_by' => self::clip($actor),
                            'created_at' => $stamp,
                            'updated_at' => $stamp,
                        ]);
                    }
                    break;
                default:
                    throw new \LogicException("Unknown change type '{$op['type']}'.");
            }
        }
    }

    /** Records adoption: first Apply sets adopted_at/by; every Apply sets applied_at. */
    public static function adopt(string $baselineId, string $actor, int $now): void
    {
        $stamp = Time::carbon($now);
        $exists = DB::table(Tables::BASELINE)->where('baseline_id', $baselineId)->exists();
        if ($exists) {
            DB::table(Tables::BASELINE)->where('baseline_id', $baselineId)->update(['applied_at' => $stamp]);
        } else {
            DB::table(Tables::BASELINE)->insert([
                'baseline_id' => $baselineId,
                'adopted_at' => $stamp,
                'adopted_by' => self::clip($actor),
                'applied_at' => $stamp,
            ]);
        }
    }

    private static function clip(string $value): string
    {
        return mb_strlen($value) > 255 ? mb_substr($value, 0, 254) . '…' : $value;
    }
}

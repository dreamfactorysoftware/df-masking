<?php

namespace DreamFactory\Core\Masking\Baselines;

use DreamFactory\Core\Masking\Support\Catalog;

/**
 * Computes exactly what a baseline's Apply would change right now, from a State snapshot.
 * Pure: the same list is shown as `changes` on the detail endpoint and executed by Applier.
 *
 * Semantics (never loosen anything):
 * - Add-only: Apply only tightens settings and adds detection rules. It never clears masking,
 *   never deletes an admin decision, grant, role access row or rule.
 * - Mode is raised to at least Preview; to On only when explicitly asked (`mode: 'on'`).
 * - Strictest wins: when Apply has to change a value, it picks one that also satisfies every
 *   other adopted baseline (the smallest grant limit, a mask format allowed by all of them).
 *   Settings this baseline does not require are left alone; the other baselines' checks
 *   report them and their own Apply fixes them.
 */
final class Planner
{
    /**
     * How much of a value each format reveals (higher = stricter). `token` ranks lowest: it
     * keeps values linkable and is derived from the value itself.
     */
    public const FORMAT_RANK = [
        'null' => 60,
        'redact' => 50,
        'last4' => 30,
        'year' => 30,
        'initial' => 30,
        'span' => 20,
        'token' => 10,
    ];

    private const ADMINS_RANK = ['none' => 0, 'selected' => 1, 'all' => 2];

    /** Same slack as the grant check, so planned changes and check results always agree. */
    private const GRANT_SLACK_SECONDS = 60;

    private function __construct()
    {
    }

    /**
     * @return list<array{id:string,text:string,op:array}> in the order Apply executes them
     */
    public static function plan(array $baseline, State $s, bool $modeOn = false): array
    {
        $apply = $baseline['apply'] ?? [];
        $others = self::otherAdopted($baseline['id'], $s);
        $changes = [];

        // Mode: at least Preview; On only when asked.
        $target = null;
        if ($modeOn && $s->mode !== 'on') {
            $target = 'on';
        } elseif ($s->mode === 'off') {
            $target = 'preview';
        }
        if ($target !== null) {
            $changes[] = [
                'id' => 'mode',
                'text' => $target === 'on'
                    ? ($s->mode === 'preview' ? 'Turn masking on (now Preview).' : 'Turn masking on.')
                    : 'Set masking to Preview (values unchanged).',
                'op' => ['type' => 'mode', 'to' => $target],
            ];
        }

        // AI and MCP sessions.
        if (($apply['ai'] ?? null) === 'masked' && $s->ai !== 'masked') {
            $changes[] = [
                'id' => 'ai',
                'text' => 'Mask values for AI and MCP sessions (now the same as admins).',
                'op' => ['type' => 'ai', 'to' => 'masked'],
            ];
        }

        // Admins mode.
        $adminsAfter = $s->adminsMode;
        $maxAdmins = $apply['admins_mode_max'] ?? null;
        if ($maxAdmins !== null && (self::ADMINS_RANK[$s->adminsMode] ?? 0) > (self::ADMINS_RANK[$maxAdmins] ?? 2)) {
            $adminsAfter = $maxAdmins;
            $changes[] = [
                'id' => 'admins_mode',
                'text' => $maxAdmins === 'selected'
                    ? 'Admins see real values only with a time-limited grant (now all admins).'
                    : 'Admins see masked values (now all admins).',
                'op' => ['type' => 'admins_mode', 'to' => $maxAdmins],
            ];
        }

        // Admin grants longer than the limit get capped (never removed).
        $maxHours = (int)($apply['grant_max_hours'] ?? 0);
        if ($maxHours > 0 && $adminsAfter !== 'none' && $s->grants !== null) {
            $capHours = $maxHours;
            foreach ($others as $other) {
                $h = (int)($other['apply']['grant_max_hours'] ?? 0);
                if ($h > 0) {
                    $capHours = min($capHours, $h);
                }
            }
            $limit = $s->now + $maxHours * 3600 + self::GRANT_SLACK_SECONDS;
            $capAt = $s->now + $capHours * 3600;
            foreach ($s->grants as $grant) {
                if ($grant['expires_at'] !== null && $grant['expires_at'] <= $limit) {
                    continue;
                }
                $was = $grant['expires_at'] === null
                    ? 'no end date'
                    : Time::duration($grant['expires_at'] - $s->now) . ' left';
                $changes[] = [
                    'id' => 'grant:' . $grant['admin_id'],
                    'text' => sprintf(
                        "Limit %s's access to real values to %s (now %s).",
                        $grant['name'],
                        Time::hours($capHours),
                        $was
                    ),
                    'op' => ['type' => 'grant', 'admin_id' => $grant['admin_id'], 'expires_at' => $capAt],
                ];
            }
        }

        // Roles: real values except restricted classes.
        if (($apply['role_scope'] ?? null) === 'except_restricted' && $s->roles !== null) {
            foreach ($s->roles as $role) {
                if ($role['enabled'] && $role['scope'] === 'all') {
                    $changes[] = [
                        'id' => 'role:' . $role['role_id'],
                        'text' => sprintf(
                            'Role %s: real values except restricted data (now all data).',
                            $role['name']
                        ),
                        'op' => ['type' => 'role', 'role_id' => $role['role_id'], 'scope' => 'except_restricted'],
                    ];
                }
            }
        }

        // Mask formats: at least as strict as required.
        if ($s->formats !== null) {
            foreach ($apply['formats'] ?? [] as $rule) {
                $class = $rule['class'];
                $current = $s->formatOf($class);
                if ($current !== null && in_array($current, $rule['allowed'], true)) {
                    continue;
                }
                $to = self::chooseFormat($rule, $current, $others);
                if ($to === null || $to === $current) {
                    continue;
                }
                $changes[] = [
                    'id' => 'format:' . $class,
                    'text' => sprintf(
                        '%s: mask as %s (now %s).',
                        Catalog::label($class),
                        Catalog::formatLabel($to),
                        $current === null ? 'no format' : Catalog::formatLabel($current)
                    ),
                    'op' => ['type' => 'format', 'class' => $class, 'to' => $to],
                ];
            }
        }

        // Vertical detection rules, added once (an equivalent rule from any source counts).
        if ($s->rules !== null) {
            foreach ($apply['rules'] ?? [] as $i => $rule) {
                if (self::ruleExists($rule, $s->rules)) {
                    continue;
                }
                $changes[] = [
                    'id' => 'rule:' . $i,
                    'text' => sprintf(
                        'Add a detection rule: %s are %s.',
                        $rule['title'],
                        Catalog::label($rule['class'])
                    ),
                    'op' => [
                        'type' => 'rule',
                        'match' => $rule['match'],
                        'pattern' => $rule['pattern'],
                        'class' => $rule['class'],
                        'source' => 'baseline:' . $baseline['id'],
                    ],
                ];
            }
        }

        return $changes;
    }

    /** @return list<array{id:string,text:string}> the wire shape of a plan */
    public static function wire(array $changes): array
    {
        return array_map(fn (array $c) => ['id' => $c['id'], 'text' => $c['text']], $changes);
    }

    /**
     * Picks the format Apply sets for a class whose current format the baseline does not allow:
     * among the formats this baseline allows (and the catalog offers), prefer ones every other
     * adopted baseline allows too; then the baseline's target if it is at least as strict as
     * the current format; else the least revealing-but-useful option that is at least as
     * strict; else the strictest available.
     */
    public static function chooseFormat(array $rule, ?string $current, array $others): ?string
    {
        $class = $rule['class'];
        $candidates = array_values(array_filter(
            $rule['allowed'],
            fn ($f) => in_array($f, Catalog::formatsAllowed($class), true)
        ));
        if (empty($candidates)) {
            return null;
        }

        $preferred = $candidates;
        foreach ($others as $other) {
            foreach ($other['apply']['formats'] ?? [] as $otherRule) {
                if ($otherRule['class'] === $class) {
                    $preferred = array_values(array_filter(
                        $preferred,
                        fn ($f) => in_array($f, $otherRule['allowed'], true)
                    ));
                }
            }
        }
        $pool = empty($preferred) ? $candidates : $preferred;

        $currentRank = $current === null ? 0 : (self::FORMAT_RANK[$current] ?? 0);
        $target = $rule['target'] ?? null;
        if ($target !== null && in_array($target, $pool, true) && self::FORMAT_RANK[$target] >= $currentRank) {
            return $target;
        }

        $atLeast = array_values(array_filter($pool, fn ($f) => self::FORMAT_RANK[$f] >= $currentRank));
        if (!empty($atLeast)) {
            usort($atLeast, fn ($a, $b) => self::FORMAT_RANK[$a] <=> self::FORMAT_RANK[$b]);

            return $atLeast[0];
        }

        usort($pool, fn ($a, $b) => self::FORMAT_RANK[$b] <=> self::FORMAT_RANK[$a]);

        return $pool[0];
    }

    /** True when an equivalent rule (same match, pattern and class) exists, whatever its source. */
    public static function ruleExists(array $rule, array $existing): bool
    {
        foreach ($existing as $row) {
            if ($row['match'] === $rule['match'] && $row['class'] === $rule['class']
                && $row['pattern'] === $rule['pattern']) {
                return true;
            }
        }

        return false;
    }

    /** @return list<array> definitions of the other adopted baselines */
    private static function otherAdopted(string $id, State $s): array
    {
        $out = [];
        foreach (array_keys($s->adopted ?? []) as $adoptedId) {
            if ($adoptedId === $id) {
                continue;
            }
            $definition = BaselineRegistry::get($adoptedId);
            if ($definition !== null) {
                $out[] = $definition;
            }
        }

        return $out;
    }
}

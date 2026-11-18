<?php

namespace DreamFactory\Core\Masking\Baselines;

use DreamFactory\Core\Masking\Baselines\Definitions\Cjis;
use DreamFactory\Core\Masking\Baselines\Definitions\Gdpr;
use DreamFactory\Core\Masking\Baselines\Definitions\Glba;
use DreamFactory\Core\Masking\Baselines\Definitions\Hipaa;
use DreamFactory\Core\Masking\Baselines\Definitions\Iso27001;
use DreamFactory\Core\Masking\Baselines\Definitions\PciDss;
use DreamFactory\Core\Masking\Baselines\Definitions\Soc2;

/**
 * The fixed Compliance baseline catalog, in display order.
 *
 * A baseline definition:
 *   id, name, vertical, frameworks[], summary,
 *   protected_classes[]  - classes masking.classes guards against "not sensitive" overrides
 *   controls[]           - {id, title, refs[], params?} for checks (see Checks), or
 *                          {id: "manual.*", title, refs[], detail} for hand-checked items
 *   apply                - {ai, admins_mode_max, grant_max_hours, role_scope|null,
 *                           formats[{class, allowed[], target}], rules[{match, pattern, class, title}]}
 *
 * Baselines map DreamFactory-owned controls to framework references. They are never a claim of
 * certification ("baseline", not "compliant").
 */
final class BaselineRegistry
{
    /** Definition classes in display order. */
    private const DEFINITIONS = [
        Hipaa::class,
        PciDss::class,
        Glba::class,
        Cjis::class,
        Gdpr::class,
        Soc2::class,
        Iso27001::class,
    ];

    /** @var array<string,array>|null */
    private static ?array $byId = null;

    private function __construct()
    {
    }

    /** @return list<array> every baseline definition, in display order */
    public static function all(): array
    {
        return array_values(self::index());
    }

    public static function get(string $id): ?array
    {
        return self::index()[$id] ?? null;
    }

    /** @return string[] */
    public static function ids(): array
    {
        return array_keys(self::index());
    }

    /** @return array<string,array> */
    private static function index(): array
    {
        if (self::$byId === null) {
            $byId = [];
            foreach (self::DEFINITIONS as $class) {
                $definition = $class::definition();
                $byId[$definition['id']] = $definition;
            }
            self::$byId = $byId;
        }

        return self::$byId;
    }
}

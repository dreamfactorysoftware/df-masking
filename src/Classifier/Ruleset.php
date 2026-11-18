<?php
declare(strict_types=1);

namespace DreamFactory\Core\Masking\Classifier;

/**
 * The built-in rule pack shipped with df-masking (resources/rules/pack.json + lexicons), loaded
 * once per process, and engine instances built from it.
 */
final class Ruleset
{
    /** Name of the built-in rule pack (GET system/data_masking/rule/builtin -> ruleset). */
    public const NAME = 'dreamfactory.core';

    private static ?RulePack $pack = null;
    /** @var array<string,Engine> reference date => engine */
    private static array $engines = [];

    private function __construct()
    {
    }

    public static function path(): string
    {
        return dirname(__DIR__, 2) . '/resources/rules/pack.json';
    }

    public static function pack(): RulePack
    {
        return self::$pack ??= RulePack::load(self::path());
    }

    /** Rule pack version stamped on every classified column (dm_column.ruleset_version). */
    public static function version(): string
    {
        return self::pack()->version();
    }

    /**
     * An engine for one reference date (YYYY-MM-DD; birth-date plausibility is measured against
     * it). Engines are pure and reusable; building one costs ~20 ms, so they are memoized.
     */
    public static function engine(?string $referenceDate = null): Engine
    {
        $date = $referenceDate ?? gmdate('Y-m-d');
        if (!isset(self::$engines[$date])) {
            if (count(self::$engines) >= 4) {
                self::$engines = [];
            }
            self::$engines[$date] = new Engine(self::pack(), $date);
        }
        return self::$engines[$date];
    }

    /** Drops the memoized pack and engines (tests). */
    public static function reset(): void
    {
        self::$pack = null;
        self::$engines = [];
    }
}

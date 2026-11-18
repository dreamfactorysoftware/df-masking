<?php

namespace DreamFactory\Core\Masking\Support;

use DreamFactory\Core\Enums\LicenseLevel;
use DreamFactory\Core\Exceptions\ForbiddenException;
use DreamFactory\Core\Utility\Environment;

/**
 * Data Masking and Compliance baselines are DreamFactory Gold features, like df-compliance's
 * service reports and restricted admins. They are available when the instance's license level
 * (DreamFactory\Core\Utility\Environment::getLicenseLevel()) is Gold:
 *
 *  - system/data_masking and system/security_baseline answer 403 with MESSAGE / BASELINES_MESSAGE
 *    on other license levels (Resources\Handlers\Guard::requireSysAdminAccess);
 *  - `php artisan df:masking` keeps status, help, revoke and `mode off` and refuses the rest;
 *  - service changes do not start background scans.
 *
 * Masking an admin already turned on keeps applying to responses, so a change of license level
 * never returns values that were masked before.
 */
final class License
{
    public const MESSAGE = 'Data Masking is not available for your license. Please upgrade to Gold.';
    public const BASELINES_MESSAGE = 'Compliance baselines are not available for your license. Please upgrade to Gold.';

    /** @var \Closure():string|null returns a LicenseLevel value; null = Environment::getLicenseLevel() */
    private static ?\Closure $resolver = null;

    private function __construct()
    {
    }

    /** True when the instance's license level is Gold. Any failure to tell counts as not Gold. */
    public static function isGold(): bool
    {
        try {
            $level = self::$resolver !== null ? (self::$resolver)() : Environment::getLicenseLevel();
        } catch (\Throwable $e) {
            return false;
        }

        return $level === LicenseLevel::GOLD;
    }

    /** @throws ForbiddenException */
    public static function requireGold(string $message = self::MESSAGE): void
    {
        if (!self::isGold()) {
            throw new ForbiddenException($message);
        }
    }

    /** Tests: a closure returning a LicenseLevel value, or null for the instance's real level. */
    public static function resolveUsing(?\Closure $resolver): void
    {
        self::$resolver = $resolver;
    }
}

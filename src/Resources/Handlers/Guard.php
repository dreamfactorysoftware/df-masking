<?php

namespace DreamFactory\Core\Masking\Resources\Handlers;

use DreamFactory\Core\Exceptions\ForbiddenException;
use DreamFactory\Core\Masking\Support\Activity;
use DreamFactory\Core\Masking\Support\Caller;
use DreamFactory\Core\Masking\Support\License;

/**
 * Access rules shared by every data_masking (and security_baseline) endpoint.
 *
 * DreamFactory's own access check has already run (system service permissions: full sys
 * admins, or roles explicitly given access to system/data_masking). On top of that:
 *  - every read and write needs a full sys admin (requireSysAdminAccess): a role or API key
 *    that was merely granted access to the system service cannot read or change masking;
 *  - AI and MCP sessions can never change masking settings (403 + activity `blocked`);
 *  - loosening real-value access, and lowering the mode from On, need the super admin
 *    (Caller::isSuperAdmin: the df-compliance root admin, or any full sys admin when none is
 *    designated);
 *  - marking a column "not sensitive" needs a full sys admin;
 *  - the instance's license level must be Gold (Support\License), checked after the sys admin rule.
 */
final class Guard
{
    public const AI_MESSAGE = 'AI and MCP sessions cannot change Data Masking settings.';
    public const SUPER_ADMIN_MESSAGE = 'Only the super admin can give access.';
    public const LOWER_MODE_MESSAGE = 'Only the super admin can lower the masking mode.';
    public const SYS_ADMIN_MESSAGE = 'Only a system administrator can mark a column not sensitive.';

    private function __construct()
    {
    }

    /**
     * @param string      $blockedText activity text, e.g. "Blocked an attempt to change access"
     * @param string|null $target      activity target
     *
     * @throws ForbiddenException
     */
    public static function denyAi(string $blockedText, ?string $target = null): void
    {
        if (Caller::current()->isAi()) {
            Activity::log('blocked', $blockedText, $target);
            throw new ForbiddenException(self::AI_MESSAGE);
        }
    }

    /** @throws ForbiddenException */
    public static function requireSuperAdmin(string $blockedText, ?string $target = null, string $message = self::SUPER_ADMIN_MESSAGE): void
    {
        self::denyAi($blockedText, $target);
        if (!Caller::current()->isSuperAdmin()) {
            Activity::log('blocked', $blockedText, $target);
            throw new ForbiddenException($message);
        }
    }

    /**
     * Any request to system/data_masking or system/security_baseline: a full sys admin only, on
     * an instance whose license level is Gold. Blocked writes by other callers are recorded
     * (activity `blocked`); blocked reads are not (no noise).
     *
     * @param string $what "Data Masking settings" | "Compliance baselines"
     * @throws ForbiddenException
     */
    public static function requireSysAdminAccess(bool $write, string $what = 'Data Masking settings'): void
    {
        if (!Caller::current()->isSysAdmin()) {
            if ($write) {
                Activity::log('blocked', 'Blocked an attempt to change ' . $what . ' by a caller that is not a system administrator');
            }
            throw new ForbiddenException('Only a system administrator can ' . ($write ? 'change ' : 'view ') . $what . '.');
        }
        License::requireGold($what === 'Compliance baselines' ? License::BASELINES_MESSAGE : License::MESSAGE);
    }

    /** @throws ForbiddenException */
    public static function requireSysAdmin(string $blockedText, string $message, ?string $target = null): void
    {
        self::denyAi($blockedText, $target);
        if (!Caller::current()->isSysAdmin()) {
            Activity::log('blocked', $blockedText, $target);
            throw new ForbiddenException($message);
        }
    }
}

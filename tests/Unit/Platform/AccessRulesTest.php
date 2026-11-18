<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Platform;

use DreamFactory\Core\Exceptions\BadRequestException;
use DreamFactory\Core\Exceptions\ConflictResourceException;
use DreamFactory\Core\Exceptions\ForbiddenException;
use DreamFactory\Core\Masking\Resources\Handlers\AccessHandler;
use DreamFactory\Core\Masking\Support\Access;
use DreamFactory\Core\Masking\Support\Caller;
use DreamFactory\Core\Masking\Support\PolicyVersion;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use DreamFactory\Core\Masking\Tests\TestCase;

/**
 * Real-value access: loosening vs tightening, grant expiry and the role
 * scope rule.
 */
final class AccessRulesTest extends TestCase
{
    use ActsAsCaller;

    private const NOW = 1_800_000_000;

    protected function setUp(): void
    {
        parent::setUp();
        $this->bootHarness();
        $this->db()->table('user')->insert([
            ['id' => 1, 'name' => 'Alex Admin', 'email' => 'alex@example.com', 'is_sys_admin' => true, 'is_active' => true],
            ['id' => 2, 'name' => 'Priya Shah', 'email' => 'priya@example.com', 'is_sys_admin' => true, 'is_active' => true],
            ['id' => 3, 'name' => 'Restricted Admin', 'email' => 'ra@example.com', 'is_sys_admin' => true, 'is_active' => true],
            ['id' => 4, 'name' => 'App User', 'email' => 'user@example.com', 'is_sys_admin' => false, 'is_active' => true],
            ['id' => 5, 'name' => 'Gone Admin', 'email' => 'gone@example.com', 'is_sys_admin' => true, 'is_active' => false],
        ]);
        // df-compliance restricted admin: an admin with a role
        $this->db()->table('user_to_app_to_role')->insert(['user_id' => 3, 'app_id' => 1, 'role_id' => 1]);
        $this->db()->table('role')->insert([['id' => 1, 'name' => 'support'], ['id' => 2, 'name' => 'billing']]);
    }

    private function plan(array $payload): array
    {
        return (new AccessHandler())->plan($payload, self::NOW);
    }

    private function grant(int $adminId, ?int $expires): void
    {
        $this->db()->table(Tables::ADMIN_GRANT)->insert([
            'admin_id' => $adminId,
            'expires_at' => $expires === null ? null : gmdate('Y-m-d H:i:s', $expires),
        ]);
        PolicyVersion::bump();
    }

    public function testAdminModeUpIsLooseningDownIsTightening(): void
    {
        $p = $this->plan(['admins' => ['mode' => 'selected']]);
        $this->assertTrue($p['loosens']);
        $this->assertSame('selected', $p['admins_mode']);
        $this->assertSame(['Admin access set to selected'], $p['changes']);

        Settings::set(Settings::ADMINS_MODE, 'all');
        $p = $this->plan(['admins' => ['mode' => 'selected']]);
        $this->assertFalse($p['loosens']);
        $p = $this->plan(['admins' => ['mode' => 'none']]);
        $this->assertFalse($p['loosens']);
        $this->assertSame(['Admin access set to no one'], $p['changes']);

        $p = $this->plan(['admins' => ['mode' => 'all']]);
        $this->assertSame([], $p['changes'], 'no-op');
        $this->assertFalse($p['loosens']);
    }

    public function testGrantChanges(): void
    {
        // new grant: loosening, gets a fresh expiry
        $p = $this->plan(['admins' => ['grants' => [['admin_id' => 2, 'duration' => '1h']]]]);
        $this->assertTrue($p['loosens']);
        $this->assertSame([2 => self::NOW + 3600], $p['grant_upserts']);
        $this->assertSame(['Priya Shah was given real values for 1 hour'], $p['changes']);

        // a grant listed without a duration for an admin with no live grant is refused:
        // it is what a stale screen sends after someone else revoked the grant
        try {
            $this->plan(['admins' => ['grants' => [['admin_id' => 2]]]]);
            $this->fail('expected 409');
        } catch (ConflictResourceException $e) {
            $this->assertSame('Priya Shah has no current grant to keep. Reload and try again, or send a duration to give a new grant.', $e->getMessage());
        }

        $this->grant(2, self::NOW + 3600);
        // kept without duration: unchanged
        $p = $this->plan(['admins' => ['grants' => [['admin_id' => 2]]]]);
        $this->assertSame([], $p['changes']);
        $this->assertFalse($p['loosens']);
        // re-timed longer: loosening
        $p = $this->plan(['admins' => ['grants' => [['admin_id' => 2, 'duration' => '7d']]]]);
        $this->assertTrue($p['loosens']);
        $p = $this->plan(['admins' => ['grants' => [['admin_id' => 2, 'duration' => 'forever']]]]);
        $this->assertTrue($p['loosens']);
        $this->assertNull($p['grant_upserts'][2]);
        $this->assertSame(['Priya Shah was given real values until turned off'], $p['changes']);
        // removed: tightening
        $p = $this->plan(['admins' => ['grants' => []]]);
        $this->assertFalse($p['loosens']);
        $this->assertSame([2], $p['grant_deletes']);
        $this->assertSame(['Real values removed for Priya Shah'], $p['changes']);
    }

    public function testShorteningAForeverGrantIsTightening(): void
    {
        $this->grant(2, null);
        $p = $this->plan(['admins' => ['grants' => [['admin_id' => 2, 'duration' => '1h']]]]);
        $this->assertFalse($p['loosens']);
        $this->assertSame([2 => self::NOW + 3600], $p['grant_upserts']);
    }

    public function testExpiredGrantsAreNotGrants(): void
    {
        $this->grant(2, self::NOW - 1);
        $p = $this->plan(['admins' => ['grants' => [['admin_id' => 2, 'duration' => '1h']]]]);
        $this->assertTrue($p['loosens'], 're-adding an expired grant gives access again');
        try {
            $this->plan(['admins' => ['grants' => [['admin_id' => 2]]]]);
            $this->fail('an expired grant is never re-created without a duration');
        } catch (ConflictResourceException $e) {
            $this->assertStringContainsString('no current grant', $e->getMessage());
        }
        $p = $this->plan(['admins' => ['grants' => []]]);
        $this->assertSame([2], $p['grant_deletes'], 'expired rows are cleaned up');
        $this->assertSame([], $p['changes'], 'silently');
    }

    public function testAiAndRoles(): void
    {
        $p = $this->plan(['ai' => 'same_as_admins']);
        $this->assertTrue($p['loosens']);
        $this->assertSame(['AI and MCP sessions now match admins'], $p['changes']);
        Settings::set(Settings::AI, 'same_as_admins');
        $p = $this->plan(['ai' => 'masked']);
        $this->assertFalse($p['loosens']);
        $this->assertSame(['AI and MCP sessions set to always masked'], $p['changes']);

        $p = $this->plan(['roles' => [['role_id' => 1, 'enabled' => true, 'scope' => 'except_restricted']]]);
        $this->assertTrue($p['loosens']);
        $this->assertSame(['support now sees real values (all except restricted)'], $p['changes']);

        $this->db()->table(Tables::ROLE_ACCESS)->insert(['role_id' => 1, 'enabled' => true, 'scope' => 'except_restricted']);
        PolicyVersion::bump();
        $p = $this->plan(['roles' => [['role_id' => 1, 'enabled' => true, 'scope' => 'all']]]);
        $this->assertTrue($p['loosens'], 'widening the scope');
        $p = $this->plan(['roles' => [['role_id' => 1, 'enabled' => false, 'scope' => 'except_restricted']]]);
        $this->assertFalse($p['loosens']);
        $this->assertSame(['support is masked again'], $p['changes']);
        $p = $this->plan(['roles' => [['role_id' => 1, 'enabled' => true, 'scope' => 'except_restricted']]]);
        $this->assertSame([], $p['changes']);
    }

    public function testNarrowingAScopeIsTightening(): void
    {
        $this->db()->table(Tables::ROLE_ACCESS)->insert(['role_id' => 2, 'enabled' => true, 'scope' => 'all']);
        PolicyVersion::bump();
        $p = $this->plan(['roles' => [['role_id' => 2, 'enabled' => true, 'scope' => 'except_restricted']]]);
        $this->assertFalse($p['loosens']);
        $this->assertSame(['billing now sees real values for all except restricted'], $p['changes']);
    }

    /** @return iterable<string,array{0:array,1:string}> */
    public static function invalidPayloads(): iterable
    {
        yield 'empty' => [[], 'Nothing to change'];
        yield 'admins not object' => [['admins' => 'all'], 'admins must be an object'];
        yield 'bad admin mode' => [['admins' => ['mode' => 'some']], 'Invalid admins.mode'];
        yield 'grants not list' => [['admins' => ['grants' => ['x' => 1]]], 'admins.grants must be a list'];
        yield 'unknown admin' => [['admins' => ['grants' => [['admin_id' => 99]]]], 'Admin 99 is not an active'];
        yield 'not an admin' => [['admins' => ['grants' => [['admin_id' => 4]]]], 'Admin 4 is not an active'];
        yield 'restricted admin' => [['admins' => ['grants' => [['admin_id' => 3]]]], 'Admin 3 is not an active'];
        yield 'inactive admin' => [['admins' => ['grants' => [['admin_id' => 5]]]], 'Admin 5 is not an active'];
        yield 'duplicate grant' => [['admins' => ['grants' => [['admin_id' => 1], ['admin_id' => 1]]]], 'appears twice'];
        yield 'bad duration' => [['admins' => ['grants' => [['admin_id' => 1, 'duration' => '2h']]]], 'Invalid duration'];
        yield 'bad ai' => [['ai' => 'yes'], 'Invalid ai'];
        yield 'unknown role' => [['roles' => [['role_id' => 9, 'enabled' => true]]], 'Role 9 does not exist'];
        yield 'bad scope' => [['roles' => [['role_id' => 1, 'enabled' => true, 'scope' => 'most']]], 'Invalid scope'];
        yield 'bad enabled' => [['roles' => [['role_id' => 1, 'enabled' => 'maybe']]], 'Invalid enabled'];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('invalidPayloads')]
    public function testValidation(array $payload, string $message): void
    {
        try {
            $this->plan($payload);
            $this->fail('expected a 400');
        } catch (BadRequestException $e) {
            $this->assertStringContainsString($message, $e->getMessage());
        }
    }

    public function testPatchRefusesLooseningWithoutTheSuperAdminButAllowsTightening(): void
    {
        // The harness has no DreamFactory session: the caller is not a sys admin, so not super admin.
        $this->grant(2, self::NOW + 999_999_999);
        try {
            (new AccessHandler())->patch(['ai' => 'same_as_admins']);
            $this->fail('loosening must be refused');
        } catch (ForbiddenException $e) {
            $this->assertSame('Only the super admin can give access.', $e->getMessage());
        }
        $this->assertSame('masked', Settings::ai());
        $blocked = $this->db()->table(Tables::ACTIVITY)->where('kind', 'blocked')->value('text');
        $this->assertSame('Blocked an attempt to change access', $blocked);

        $result = (new AccessHandler())->patch(['admins' => ['grants' => []]]);
        $this->assertSame([], $result['admins']['grants']);
        $this->assertSame(0, $this->db()->table(Tables::ADMIN_GRANT)->count());
        $this->assertSame('Real values removed for Priya Shah', $this->db()->table(Tables::ACTIVITY)->where('kind', 'access')->value('text'));
    }

    public function testGetListsFullAdminsAndAllRoles(): void
    {
        $this->grant(1, null);
        $this->grant(2, time() - 10); // expired
        $access = (new AccessHandler())->get();
        $this->assertSame([1, 2], array_column($access['admins']['available'], 'admin_id'));
        $this->assertSame([['admin_id' => 1, 'name' => 'Alex Admin', 'email' => 'alex@example.com', 'expires_at' => null]], $access['admins']['grants']);
        $this->assertSame([
            ['role_id' => 2, 'name' => 'billing', 'enabled' => false, 'scope' => 'except_restricted'],
            ['role_id' => 1, 'name' => 'support', 'enabled' => false, 'scope' => 'except_restricted'],
        ], $access['roles']);
        $this->assertSame('none', $access['admins']['mode']);
        $this->assertSame('masked', $access['ai']);
    }

    public function testAccessLookups(): void
    {
        $now = time();
        $this->grant(1, $now + 60);
        $this->grant(2, $now - 60);
        $this->assertSame(['expires_at' => $now + 60], Access::activeGrant(1));
        $this->assertNull(Access::activeGrant(2), 'expired');
        $this->assertNull(Access::activeGrant(3), 'none');
        $this->assertNull(Access::activeGrant(1, $now + 61), 'expiry is checked against the clock on every call');

        $this->assertFalse(Access::adminSeesRealValues(1), 'mode none');
        Settings::set(Settings::ADMINS_MODE, 'selected');
        $this->assertTrue(Access::adminSeesRealValues(1));
        $this->assertFalse(Access::adminSeesRealValues(2));
        Settings::set(Settings::ADMINS_MODE, 'all');
        $this->assertTrue(Access::adminSeesRealValues(2));

        $this->assertSame(['enabled' => false, 'scope' => 'except_restricted'], Access::roleAccess(1));
        $this->db()->table(Tables::ROLE_ACCESS)->insert([
            ['role_id' => 1, 'enabled' => true, 'scope' => 'except_restricted'],
            ['role_id' => 2, 'enabled' => true, 'scope' => 'all'],
        ]);
        PolicyVersion::bump();
        $this->assertTrue(Access::roleSeesTier(1, 'identity'));
        $this->assertFalse(Access::roleSeesTier(1, 'restricted'));
        $this->assertTrue(Access::roleSeesTier(2, 'restricted'));
        $this->assertFalse(Access::roleSeesTier(9, 'identity'));

        $this->assertSame(self::NOW + 86400, Access::expiryFor('24h', self::NOW));
        $this->assertNull(Access::expiryFor('forever', self::NOW));
        $this->expectException(\InvalidArgumentException::class);
        Access::expiryFor('2h');
    }

    /** Builds a Caller without a DreamFactory session (private constructor, via reflection). */
    private function caller(?int $userId, ?int $roleId, bool $sysAdmin, ?string $ai = null, bool $console = false): Caller
    {
        $ref = new \ReflectionClass(Caller::class);
        $caller = $ref->newInstanceWithoutConstructor();
        $ref->getConstructor()->invoke($caller, $userId, $roleId, null, $sysAdmin, $userId ? 'User ' . $userId : null, $ai, $console);

        return $caller;
    }

    public function testCallerSeesRealValuesFollowsGrantAndRoleScope(): void
    {
        $now = time();
        $this->grant(1, $now + 600);
        $this->db()->table(Tables::ROLE_ACCESS)->insert(['role_id' => 1, 'enabled' => true, 'scope' => 'except_restricted']);
        PolicyVersion::bump();

        $admin = $this->caller(1, null, true);
        $this->assertFalse(Access::callerSeesRealValues($admin, 'identity'), 'admins are masked by default (mode none)');
        Settings::set(Settings::ADMINS_MODE, 'selected');
        $this->assertTrue(Access::callerSeesRealValues($admin, 'restricted'), 'selected + unexpired grant');
        $this->assertFalse(Access::callerSeesRealValues($this->caller(2, null, true), 'identity'), 'no grant');

        $aiAdmin = $this->caller(1, null, true, 'ai');
        $this->assertTrue($aiAdmin->isAi());
        $this->assertSame('User 1 (AI session)', $aiAdmin->label());
        $this->assertFalse(Access::callerSeesRealValues($aiAdmin, 'identity'), 'AI is masked by default');
        Settings::set(Settings::AI, 'same_as_admins');
        $this->assertTrue(Access::callerSeesRealValues($aiAdmin, 'identity'), 'AI same as admins');
        Settings::set(Settings::AI, 'masked');

        $roleUser = $this->caller(4, 1, false);
        $this->assertTrue(Access::callerSeesRealValues($roleUser, 'identity'));
        $this->assertFalse(Access::callerSeesRealValues($roleUser, 'restricted'), 'except_restricted');
        $this->assertFalse(Access::callerSeesRealValues($this->caller(4, 2, false), 'identity'), 'role without access');
        $this->assertFalse(Access::callerSeesRealValues($this->caller(null, 1, false, 'ai'), 'identity'), 'AI on a role');

        $console = $this->caller(null, null, false, null, true);
        $this->assertTrue($console->isConsole());
        $this->assertSame('System', $console->label());
        $this->assertFalse(Access::callerSeesRealValues($console, 'identity'), 'internal console calls are masked');
        $this->assertFalse($console->isSuperAdmin());
        $this->assertFalse($aiAdmin->isSuperAdmin(), 'an AI session is never the super admin');
        $this->assertTrue($admin->isSuperAdmin(), 'no df-compliance: any full sys admin');
    }

    /** A stale Access screen can never restore what someone else removed. */
    public function testStaleAccessWritesAreRefused(): void
    {
        $this->actAs(1); // Alex, super admin (no root admin designated)
        $h = new AccessHandler();
        $h->patch(['admins' => ['mode' => 'selected', 'grants' => [['admin_id' => 2, 'duration' => '8h']]]]);
        $loaded = $h->get();
        $this->assertMatchesRegularExpression('/^[0-9a-f]{20}$/', $loaded['version']);
        $this->assertSame([2], array_column($loaded['admins']['grants'], 'admin_id'));

        // someone else revokes every grant (df:masking revoke --all does exactly this)
        $this->db()->table(Tables::ADMIN_GRANT)->delete();
        PolicyVersion::bump();

        // the stale page ticks Marco... here: re-sends Priya without a duration, with its old version
        try {
            $h->patch(['version' => $loaded['version'], 'admins' => ['grants' => [['admin_id' => 2], ['admin_id' => 1, 'duration' => '8h']]]]);
            $this->fail('expected 409 for a stale version');
        } catch (ConflictResourceException $e) {
            $this->assertSame(AccessHandler::STALE_MESSAGE, $e->getMessage());
        }
        // without the version (an older client), the duration-less grant still cannot come back
        try {
            $h->patch(['admins' => ['grants' => [['admin_id' => 2], ['admin_id' => 1, 'duration' => '8h']]]]);
            $this->fail('expected 409 for a grant that no longer exists');
        } catch (ConflictResourceException $e) {
            $this->assertStringContainsString('Priya Shah has no current grant', $e->getMessage());
        }
        $this->assertSame(0, $this->db()->table(Tables::ADMIN_GRANT)->count(), 'nothing was re-granted');

        // a fresh read works
        $fresh = $h->get();
        $this->assertNotSame($loaded['version'], $fresh['version']);
        $out = $h->patch(['version' => $fresh['version'], 'admins' => ['grants' => [['admin_id' => 1, 'duration' => '1h']]]]);
        $this->assertSame([1], array_column($out['admins']['grants'], 'admin_id'));
        $this->assertNotSame($fresh['version'], $out['version'], 'the response carries the new version');
    }

    public function testVersionChangesWhenAGrantExpires(): void
    {
        $this->actAs(1);
        $this->grant(2, time() + 3600);
        $v1 = AccessHandler::version();
        $this->assertSame($v1, AccessHandler::version(), 'stable while nothing changes');
        $this->assertNotSame($v1, AccessHandler::version(time() + 7200), 'the grant has expired by then');
    }

    /** Partial role lists change only the listed role; a disabled role's scope change is stored. */
    public function testRolePatchesArePartialAndScopeOnlyChangesAreStored(): void
    {
        $this->actAs(1);
        $h = new AccessHandler();
        $h->patch(['roles' => [['role_id' => 1, 'enabled' => true, 'scope' => 'except_restricted']]]);
        $h->patch(['roles' => [['role_id' => 2, 'enabled' => false, 'scope' => 'all']]]);
        $rows = $this->db()->table(Tables::ROLE_ACCESS)->orderBy('role_id')->get(['role_id', 'enabled', 'scope'])->all();
        $this->assertSame([[1, true, 'except_restricted'], [2, false, 'all']],
            array_map(fn ($r) => [(int)$r->role_id, (bool)$r->enabled, $r->scope], $rows));
    }
}

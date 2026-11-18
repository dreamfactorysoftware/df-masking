<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Platform;

use DreamFactory\Core\Components\InternalServiceRequest;
use DreamFactory\Core\Masking\Resources\DataMasking;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use DreamFactory\Core\Masking\Tests\TestCase;
use Illuminate\Support\Facades\Schema;

/**
 * Routing of system/data_masking through DreamFactory's RestHandler (request -> handle{VERB} ->
 * ServiceResponse), with the isolated harness. The caller is the full sys admin Alex (user 1)
 * unless a test says otherwise.
 */
final class DataMaskingResourceTest extends TestCase
{
    use ActsAsCaller;

    protected function setUp(): void
    {
        parent::setUp();
        $this->bootHarness();
        $this->db()->table('user')->insert([
            ['id' => 1, 'name' => 'Alex Admin', 'email' => 'k@example.com', 'is_sys_admin' => true],
            ['id' => 2, 'name' => 'Priya Shah', 'email' => 'p@example.com', 'is_sys_admin' => true],
            ['id' => 4, 'name' => 'App User', 'email' => 'u@example.com', 'is_sys_admin' => false],
        ]);
        $this->db()->table('role')->insert(['id' => 1, 'name' => 'support']);
        $this->actAs(1);
    }

    private function call(string $verb, string $path, array $payload = [], array $params = []): array
    {
        $request = new InternalServiceRequest();
        $request->setMethod($verb);
        $request->setParameters($params);
        $request->setPayloadData($payload);
        $resource = new DataMasking(['name' => 'data_masking']);
        $response = $resource->handleRequest($request, $path);

        return [$response->getStatusCode(), $response->getContent()];
    }

    public function testRoutes(): void
    {
        [$status, $body] = $this->call('GET', '');
        $this->assertSame(200, $status);
        $this->assertSame(['mode', 'scan', 'counts', 'you', 'coverage'], array_keys($body));
        $this->assertSame('off', $body['mode']);
        $this->assertSame(['can_grant' => true, 'sees_real_values' => false, 'grant_expires_at' => null], $body['you']);
        $this->assertSame(['status', 'progress', 'finished_at', 'columns', 'last_status', 'failed', 'unknown'], array_keys($body['scan']));
        $this->assertNull($body['scan']['last_status']);
        $this->assertFalse($body['scan']['unknown']);
        $this->assertSame([], $body['scan']['failed']);

        [$status, $body] = $this->call('GET', 'mask');
        $this->assertSame(200, $status);
        $this->assertCount(23, $body['resource']);

        [$status, $body] = $this->call('GET', 'access');
        $this->assertSame(200, $status);
        $this->assertSame('none', $body['admins']['mode']);

        [$status, $body] = $this->call('GET', 'rule/builtin');
        $this->assertSame(200, $status);
        $this->assertSame('dreamfactory.core', $body['ruleset']);

        [$status, $body] = $this->call('GET', 'activity', [], ['limit' => '5']);
        $this->assertSame(200, $status);
        $this->assertSame(['resource' => [], 'has_more' => false], $body);

        [$status] = $this->call('PATCH', '', ['mode' => 'preview']);
        $this->assertSame(200, $status);
        [, $body] = $this->call('GET', '');
        $this->assertSame('preview', $body['mode']);
        [, $body] = $this->call('GET', 'activity');
        $this->assertSame('Masking set to Preview', $body['resource'][0]['text']);

        // PUT is an alias of PATCH
        [$status, $body] = $this->call('PUT', 'mask', ['resource' => [['class' => 'email', 'format' => 'redact']]]);
        $this->assertSame(200, $status);
        $this->assertSame('redact', array_values(array_filter($body['resource'], fn ($m) => $m['class'] === 'email'))[0]['format']);
    }

    public function testErrors(): void
    {
        $this->assertSame(404, $this->call('GET', 'nothing')[0]);
        $this->assertSame(400, $this->call('POST', '')[0]);
        $this->assertSame(400, $this->call('DELETE', 'mask')[0]);
        $this->assertSame(400, $this->call('GET', 'table/extra')[0]);
        $this->assertSame(400, $this->call('PATCH', 'column')[0]);
        $this->assertSame(400, $this->call('PATCH', 'column/crm.only')[0]);
        $this->assertSame(404, $this->call('PATCH', 'column/crm.t.c', ['class' => 'email'])[0], 'unknown service');
        $this->assertSame(400, $this->call('PATCH', '', ['mode' => 'loud'])[0]);
        $this->assertSame(404, $this->call('DELETE', 'rule/12')[0]);
        $this->assertSame(404, $this->call('GET', 'column', [], ['service' => 'nope'])[0]);

        $this->designateRootAdmin(2);
        [$status, $body] = $this->call('PATCH', 'access', ['ai' => 'same_as_admins']);
        $this->assertSame(403, $status, 'Priya is the root admin: Alex is not the super admin');
        $this->assertSame('Only the super admin can give access.', $body['error']['message']);
    }

    /** Every read and write needs a full sys admin, not just system-service RBAC. */
    public function testEveryRequestNeedsAFullSysAdmin(): void
    {
        $callers = [
            'API key app, no user' => fn () => $this->actAs(null, false, 1, 7),
            'role user' => fn () => $this->actAs(4, false, 1),
            'restricted admin (sys admin with a role)' => fn () => $this->actAs(2, true, 1),
        ];
        foreach ($callers as $who => $act) {
            $act();
            [$status, $body] = $this->call('GET', '');
            $this->assertSame(403, $status, "$who: GET");
            $this->assertSame('Only a system administrator can view Data Masking settings.', $body['error']['message']);
            $this->assertSame(403, $this->call('GET', 'access')[0], "$who: GET access");
            $this->assertSame(403, $this->call('GET', 'activity')[0], "$who: GET activity");
            [$status, $body] = $this->call('PATCH', '', ['mode' => 'off']);
            $this->assertSame(403, $status, "$who: PATCH mode");
            $this->assertSame('Only a system administrator can change Data Masking settings.', $body['error']['message']);
            $this->assertSame(403, $this->call('PATCH', 'mask', ['resource' => [['class' => 'email', 'format' => 'redact']]])[0], "$who: PATCH mask");
            $this->assertSame(403, $this->call('POST', 'rule', ['match' => 'name', 'pattern' => 'x', 'class' => 'email'])[0], "$who: POST rule");
            $this->assertSame(403, $this->call('DELETE', 'rule/1')[0], "$who: DELETE rule");
            $this->assertSame(403, $this->call('PATCH', 'column', ['id' => 'crm.t.c', 'class' => 'phone'])[0], "$who: PATCH column");
            $this->assertSame(403, $this->call('POST', 'scan')[0], "$who: POST scan");
        }
        $this->assertSame([], $this->db()->table(Tables::MASK_FORMAT)->get()->all(), 'nothing was written');
        $this->assertGreaterThanOrEqual(3, $this->db()->table(Tables::ACTIVITY)->where('kind', 'blocked')->count(), 'blocked writes are recorded');
        $this->actAs(1);
        $this->assertSame(200, $this->call('GET', '')[0], 'a full sys admin passes');
    }

    /** Lowering from On needs the super admin when a root admin is designated; raising never does. */
    public function testLoweringTheModeFromOnNeedsTheSuperAdmin(): void
    {
        $this->db()->table(Tables::SCAN)->insert(['status' => 'done', 'columns_done' => 12, 'started_at' => now(), 'finished_at' => now()]);
        $this->designateRootAdmin(2);
        $this->assertSame(200, $this->call('PATCH', '', ['mode' => 'on'])[0], 'raising: any sys admin');
        foreach (['preview', 'off'] as $lower) {
            [$status, $body] = $this->call('PATCH', '', ['mode' => $lower]);
            $this->assertSame(403, $status, "on -> $lower");
            $this->assertSame('Only the super admin can lower the masking mode.', $body['error']['message']);
        }
        $this->assertSame('on', $this->call('GET', '')[1]['mode']);
        $this->assertSame('Blocked an attempt to lower the masking mode',
            $this->db()->table(Tables::ACTIVITY)->where('kind', 'blocked')->orderByDesc('id')->value('text'));

        $this->actAs(2); // the root admin
        $this->assertSame(200, $this->call('PATCH', '', ['mode' => 'preview'])[0]);
        $this->actAs(1);
        $this->assertSame(200, $this->call('PATCH', '', ['mode' => 'off'])[0], 'preview -> off is not loosening');
        $this->assertSame(200, $this->call('PATCH', '', ['mode' => 'preview'])[0], 'off -> preview is not loosening');

        // without a designated root admin every full sys admin is the super admin
        $this->db()->table('user')->update(['is_root_admin' => false]);
        $this->actAs(1);
        $this->assertSame(200, $this->call('PATCH', '', ['mode' => 'on'])[0]);
        $this->assertSame(200, $this->call('PATCH', '', ['mode' => 'off'])[0]);
    }

    /** No mode On before the first completed scan. */
    public function testModeOnNeedsACompletedScan(): void
    {
        [$status, $body] = $this->call('PATCH', '', ['mode' => 'on']);
        $this->assertSame(409, $status);
        $this->assertSame('Scan your databases before turning masking on.', $body['error']['message']);
        $this->assertSame('off', $this->call('GET', '')[1]['mode']);
        $this->assertSame(200, $this->call('PATCH', '', ['mode' => 'preview'])[0], 'Preview is allowed before a scan');

        $this->db()->table(Tables::SCAN)->insert(['status' => 'failed', 'started_at' => now(), 'finished_at' => now()]);
        $this->assertSame(409, $this->call('PATCH', '', ['mode' => 'on'])[0], 'a failed scan is not a completed scan');
        // A scan of empty databases found nothing to classify.
        $this->db()->table(Tables::SCAN)->insert(['status' => 'done', 'columns_done' => 0, 'started_at' => now(), 'finished_at' => now()]);
        [$status, $body] = $this->call('PATCH', '', ['mode' => 'on']);
        $this->assertSame(409, $status, 'a scan that found no column is not a first scan');
        $this->assertSame('Scan your databases before turning masking on.', $body['error']['message']);
        $this->assertSame('preview', $this->call('GET', '')[1]['mode'], 'viewing the overview does not record it as a first scan');
        $this->assertFalse(Settings::has(Settings::FIRST_SCAN_AT));
        $this->db()->table(Tables::SCAN)->insert(['status' => 'done', 'columns_done' => 3, 'started_at' => now(), 'finished_at' => now()]);
        $this->assertSame(200, $this->call('PATCH', '', ['mode' => 'on'])[0]);
    }

    /** PATCH column takes the id in the body (names the route pattern rejects). */
    public function testColumnIdInTheBody(): void
    {
        [$status, $body] = $this->call('PATCH', 'column', ['class' => 'phone']);
        $this->assertSame(400, $status);
        $this->assertSame('Send the column id (service.table.column) as id in the body, with class.', $body['error']['message']);
        [$status, $body] = $this->call('PATCH', 'column', ['id' => "crm.people.\u{7535}\u{8BDD}", 'class' => 'phone']);
        $this->assertSame(404, $status, 'the body id reached the column lookup');
        $this->assertSame("'crm' is not a database service Data Masking covers.", $body['error']['message']);
    }

    /** Activity pages server-side (kind, limit, before, has_more). */
    public function testActivityPaging(): void
    {
        for ($i = 1; $i <= 7; $i++) {
            $this->db()->table(Tables::ACTIVITY)->insert(['created_at' => '2026-10-29 10:00:00', 'actor' => 'System',
                'kind' => $i % 2 ? 'mode' : 'blocked', 'text' => "row $i"]);
        }
        [, $page] = $this->call('GET', 'activity', [], ['limit' => '3']);
        $this->assertSame(['row 7', 'row 6', 'row 5'], array_column($page['resource'], 'text'));
        $this->assertTrue($page['has_more']);
        [, $next] = $this->call('GET', 'activity', [], ['limit' => '3', 'before' => (string)$page['resource'][2]['id']]);
        $this->assertSame(['row 4', 'row 3', 'row 2'], array_column($next['resource'], 'text'), 'same timestamp: no overlap, no gap');
        [, $last] = $this->call('GET', 'activity', [], ['limit' => '3', 'before' => (string)$next['resource'][2]['id']]);
        $this->assertSame(['row 1'], array_column($last['resource'], 'text'));
        $this->assertFalse($last['has_more']);
        [, $blocked] = $this->call('GET', 'activity', [], ['kind' => 'blocked', 'limit' => '2']);
        $this->assertSame(['row 6', 'row 4'], array_column($blocked['resource'], 'text'));
        $this->assertTrue($blocked['has_more']);
        $this->assertSame(400, $this->call('GET', 'activity', [], ['before' => 'x'])[0]);
    }

    public function testRulesLifecycle(): void
    {
        [$status, $rule] = $this->call('POST', 'rule', ['match' => 'name', 'pattern' => '(^|_)ssn($|_)', 'class' => 'national_id']);
        $this->assertSame(200, $status);
        $this->assertSame(['id', 'match', 'pattern', 'class', 'source', 'matches', 'scan_started'], array_keys($rule));
        $this->assertSame(0, $rule['matches']);
        $this->assertFalse($rule['scan_started'], 'name rules apply at once');

        $this->assertSame(400, $this->call('POST', 'rule', ['match' => 'name', 'pattern' => '(^|_)ssn($|_)', 'class' => 'national_id'])[0], 'duplicate');
        $this->assertSame(400, $this->call('POST', 'rule', ['match' => 'name', 'pattern' => '(x', 'class' => 'email'])[0]);
        $this->assertSame(400, $this->call('POST', 'rule', ['match' => 'regex', 'pattern' => 'x', 'class' => 'email'])[0]);
        $this->assertSame(400, $this->call('POST', 'rule', ['match' => 'name', 'pattern' => 'x', 'class' => 'nope'])[0]);

        [$status, $value] = $this->call('POST', 'rule', ['match' => 'value', 'pattern' => '^EMP-\d{6}$', 'class' => 'national_id']);
        $this->assertSame(200, $status);
        $this->assertFalse($value['scan_started'], 'never scanned: the first scan applies it');

        [, $list] = $this->call('GET', 'rule');
        $this->assertCount(2, $list['resource']);
        $this->assertSame(['id', 'match', 'pattern', 'class', 'source', 'matches'], array_keys($list['resource'][1]), 'scan_started only answers a create');
        [$status, $deleted] = $this->call('DELETE', 'rule/' . $rule['id']);
        $this->assertSame(200, $status);
        $this->assertSame(['id' => $rule['id']], $deleted);

        $texts = $this->db()->table(Tables::ACTIVITY)->orderBy('id')->pluck('text')->all();
        $this->assertSame(['Added a column name rule for National ID', 'Added a value rule for National ID', 'Deleted a column name rule for National ID'], $texts);

        // Rule rows carry the rule's match, so the admin app reads the pattern back as a sentence.
        $this->db()->table(Tables::ACTIVITY)->insert(['created_at' => now(), 'actor' => 'System', 'kind' => 'rule',
            'text' => 'Deleted a rule', 'target' => '^x$', 'meta' => json_encode(['rule_id' => 9])]);
        [, $activity] = $this->call('GET', 'activity');
        $events = array_map(static fn ($e) => [$e['text'], $e['target'], $e['match'] ?? null], $activity['resource']);
        $this->assertSame([
            ['Deleted a rule', '^x$', null],
            ['Deleted a column name rule for National ID', '(^|_)ssn($|_)', 'name'],
            ['Added a value rule for National ID', '^EMP-\d{6}$', 'value'],
            ['Added a column name rule for National ID', '(^|_)ssn($|_)', 'name'],
        ], $events, 'a row logged before rules kept their match has none');
        $this->assertArrayNotHasKey('match', $activity['resource'][0]);
    }

    /** A rule a baseline added is listed with its definition's title, so the app names it instead of showing its regex. */
    public function testBaselineRulesCarryTheirTitle(): void
    {
        $hipaa = \DreamFactory\Core\Masking\Baselines\BaselineRegistry::get('hipaa')['apply']['rules'][0];
        $row = static fn (string $pattern, string $source) => ['match' => 'name', 'pattern' => $pattern, 'class' => 'special_category',
            'source' => $source, 'created_at' => now(), 'updated_at' => now()];
        $this->db()->table(Tables::RULE)->insert([
            $row($hipaa['pattern'], 'baseline:hipaa'),
            $row($hipaa['pattern'], 'admin'),
            $row('^old_mrn$', 'baseline:hipaa'),
            $row($hipaa['pattern'] . '|x', 'baseline:no_such_baseline'),
        ]);
        [, $list] = $this->call('GET', 'rule');
        $this->assertSame('Medical record, patient and chart numbers', $list['resource'][0]['title']);
        $this->assertSame(['id', 'match', 'pattern', 'class', 'source', 'matches', 'title'], array_keys($list['resource'][0]));
        foreach ([1, 2, 3] as $i) {
            $this->assertArrayNotHasKey('title', $list['resource'][$i], 'admin rules, and baseline rules the definition no longer has, have none');
        }
    }

    public function testNotMigratedYieldsA503(): void
    {
        Schema::drop(Tables::ROLE_ACCESS);
        Schema::drop(Tables::COLUMN);
        [$status, $body] = $this->call('GET', 'access');
        $this->assertSame(503, $status);
        $this->assertStringContainsString('df:masking setup', $body['error']['message']);
        // the overview still answers (defaults), so the admin UI can show its empty state
        $this->assertSame(200, $this->call('GET', '')[0]);
    }
}

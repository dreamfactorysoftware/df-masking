<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Baselines;

use DreamFactory\Core\Masking\Baselines\BaselineRegistry;
use DreamFactory\Core\Masking\Baselines\Evaluator;
use DreamFactory\Core\Masking\Baselines\Planner;
use DreamFactory\Core\Masking\Baselines\State;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Apply planning on hand-built snapshots (no database). */
final class PlannerTest extends TestCase
{
    private const NOW = 1_800_000_000;

    private static function state(array $override = []): State
    {
        return new State(...array_replace(['now' => self::NOW], $override));
    }

    private static function ids(array $changes): array
    {
        return array_column($changes, 'id');
    }

    private static function loose(): State
    {
        return self::state([
            'mode' => 'off',
            'ai' => 'same_as_admins',
            'adminsMode' => 'all',
            'formats' => ['date_of_birth' => 'token'],
            'grants' => [
                ['admin_id' => 7, 'name' => 'Priya Shah', 'email' => null, 'expires_at' => null],
                ['admin_id' => 8, 'name' => 'Lee Chen', 'email' => null, 'expires_at' => self::NOW + 3600],
                ['admin_id' => 9, 'name' => 'Sam Ortiz', 'email' => null, 'expires_at' => self::NOW + 7 * 86400],
            ],
            'roles' => [
                ['role_id' => 3, 'name' => 'support', 'enabled' => true, 'scope' => 'all'],
                ['role_id' => 4, 'name' => 'billing', 'enabled' => false, 'scope' => 'all'],
                ['role_id' => 5, 'name' => 'analytics', 'enabled' => true, 'scope' => 'except_restricted'],
            ],
        ]);
    }

    public function testFreshInstanceHipaa(): void
    {
        $changes = Planner::plan(BaselineRegistry::get('hipaa'), self::state());
        $this->assertSame(['mode', 'rule:0', 'rule:1'], self::ids($changes));
        $this->assertSame(['type' => 'mode', 'to' => 'preview'], $changes[0]['op']);
        $this->assertSame('baseline:hipaa', $changes[1]['op']['source']);
        $this->assertSame(
            'Add a detection rule: Medical record, patient and chart numbers are Health & special category.',
            $changes[1]['text']
        );
    }

    public function testLooseInstanceHipaaChangesEverythingItOwns(): void
    {
        $changes = Planner::plan(BaselineRegistry::get('hipaa'), self::loose());
        $this->assertSame(
            ['mode', 'ai', 'admins_mode', 'grant:7', 'grant:9', 'role:3', 'format:date_of_birth', 'rule:0', 'rule:1'],
            self::ids($changes)
        );
        $byId = array_column($changes, null, 'id');
        $this->assertSame(self::NOW + 8 * 3600, $byId['grant:7']['op']['expires_at']);
        $this->assertSame("Limit Priya Shah's access to real values to 8 hours (now no end date).", $byId['grant:7']['text']);
        $this->assertSame("Limit Sam Ortiz's access to real values to 8 hours (now 7 days left).", $byId['grant:9']['text']);
        $this->assertSame('Role support: real values except restricted data (now all data).', $byId['role:3']['text']);
        $this->assertSame(['type' => 'format', 'class' => 'date_of_birth', 'to' => 'year'], $byId['format:date_of_birth']['op']);
        $this->assertSame('Date of birth: mask as Year only (now Token).', $byId['format:date_of_birth']['text']);
        $this->assertSame('Admins see real values only with a time-limited grant (now all admins).', $byId['admins_mode']['text']);

        // The wire shape carries id + text only.
        foreach (Planner::wire($changes) as $change) {
            $this->assertSame(['id', 'text'], array_keys($change));
        }
    }

    public function testSoc2LeavesRoleScopesAlone(): void
    {
        $ids = self::ids(Planner::plan(BaselineRegistry::get('soc2'), self::loose()));
        $this->assertSame(['mode', 'ai', 'admins_mode', 'grant:7', 'grant:9'], $ids);
    }

    public function testModeOnOnlyWhenAsked(): void
    {
        $preview = self::state(['mode' => 'preview']);
        $this->assertSame([], array_values(array_filter(
            self::ids(Planner::plan(BaselineRegistry::get('gdpr'), $preview)),
            fn ($id) => $id === 'mode'
        )));
        $on = Planner::plan(BaselineRegistry::get('gdpr'), $preview, true);
        $this->assertSame(['type' => 'mode', 'to' => 'on'], $on[0]['op']);
        $this->assertSame('Turn masking on (now Preview).', $on[0]['text']);
        $this->assertSame('Turn masking on.', Planner::plan(BaselineRegistry::get('gdpr'), self::state(), true)[0]['text']);
        $this->assertSame([], Planner::plan(BaselineRegistry::get('gdpr'), self::state(['mode' => 'on']), true));
    }

    public function testNoGrantChangesWhenAdminsNeverSeeRealValues(): void
    {
        $state = self::state([
            'mode' => 'on',
            'adminsMode' => 'none',
            'grants' => [['admin_id' => 7, 'name' => 'Priya', 'email' => null, 'expires_at' => null]],
        ]);
        $this->assertSame([], Planner::plan(BaselineRegistry::get('soc2'), $state));
    }

    public function testExistingEquivalentRuleIsNotAddedAgain(): void
    {
        $hipaa = BaselineRegistry::get('hipaa');
        $existing = [];
        foreach ($hipaa['apply']['rules'] as $i => $rule) {
            $existing[] = ['id' => $i + 1, 'match' => 'name', 'pattern' => $rule['pattern'], 'class' => $rule['class'], 'source' => 'admin'];
        }
        $this->assertSame([], Planner::plan($hipaa, self::state(['mode' => 'on', 'rules' => $existing])));
        // Same pattern, different class: a different rule.
        $existing[0]['class'] = 'national_id';
        $this->assertSame(['rule:0'], self::ids(Planner::plan($hipaa, self::state(['mode' => 'on', 'rules' => $existing]))));
    }

    public function testStrictestGrantLimitWinsWhenSeveralBaselinesAreAdopted(): void
    {
        $state = self::state([
            'mode' => 'on',
            'adminsMode' => 'selected',
            'grants' => [
                ['admin_id' => 7, 'name' => 'Priya', 'email' => null, 'expires_at' => null],
                ['admin_id' => 8, 'name' => 'Lee', 'email' => null, 'expires_at' => self::NOW + 12 * 3600],
            ],
            'adopted' => ['hipaa' => ['adopted_at' => self::NOW - 10, 'adopted_by' => 'x', 'applied_at' => null, 'last_status' => null]],
        ]);
        $changes = Planner::plan(BaselineRegistry::get('soc2'), $state);
        // SOC 2 (24 h) only touches the grant that breaks its own limit, and caps it at HIPAA's 8 h.
        $this->assertSame(['grant:7'], self::ids($changes));
        $this->assertSame(self::NOW + 8 * 3600, $changes[0]['op']['expires_at']);
    }

    public function testChooseFormat(): void
    {
        $dob = ['class' => 'date_of_birth', 'allowed' => ['year', 'redact', 'null'], 'target' => 'year'];
        $this->assertSame('year', Planner::chooseFormat($dob, 'token', []));
        // A stricter adopted baseline narrows the choice.
        $strict = ['apply' => ['formats' => [['class' => 'date_of_birth', 'allowed' => ['redact', 'null'], 'target' => 'redact']]]];
        $this->assertSame('redact', Planner::chooseFormat($dob, 'token', [$strict]));
        // Unknown current format: the target.
        $this->assertSame('year', Planner::chooseFormat($dob, null, []));
        // Disagreeing baselines fall back to this baseline's own list.
        $disjoint = ['apply' => ['formats' => [['class' => 'date_of_birth', 'allowed' => ['token'], 'target' => 'token']]]];
        $this->assertSame('year', Planner::chooseFormat($dob, 'token', [$disjoint]));
        // Formats the class cannot use are ignored.
        $this->assertNull(Planner::chooseFormat(['class' => 'card_number', 'allowed' => ['token'], 'target' => 'token'], 'last4', []));
    }

    public static function baselineIds(): array
    {
        return array_combine(BaselineRegistry::ids(), array_map(fn ($id) => [$id], BaselineRegistry::ids()));
    }

    /**
     * After applying a plan (simulated on the snapshot), nothing is left to change and every
     * control Apply owns passes, except masking.mode which needs mode 'on'.
     */
    #[DataProvider('baselineIds')]
    public function testApplyingThePlanFixesEverythingApplyOwns(string $id): void
    {
        $baseline = BaselineRegistry::get($id);
        $before = self::loose();
        $after = self::simulate($before, Planner::plan($baseline, $before, true));
        $this->assertSame([], Planner::plan($baseline, $after, true), "$id plan is idempotent");

        foreach (Evaluator::controls($baseline, $after) as $control) {
            if ($control['status'] === 'fail') {
                $this->assertNotSame('apply', $control['fix']['kind'], "$id {$control['id']} still fails: {$control['detail']}");
            }
        }
    }

    /** Applies plan ops to a snapshot, the way Applier does to the database. */
    private static function simulate(State $s, array $changes): State
    {
        $args = [
            'now' => $s->now, 'mode' => $s->mode, 'ai' => $s->ai, 'adminsMode' => $s->adminsMode,
            'formats' => $s->formats, 'grants' => $s->grants, 'roles' => $s->roles, 'rules' => $s->rules,
            'verdicts' => $s->verdicts, 'adminCleared' => $s->adminCleared, 'covered' => $s->covered,
            'platform' => $s->platform, 'adopted' => $s->adopted,
        ];
        foreach ($changes as $change) {
            $op = $change['op'];
            switch ($op['type']) {
                case 'mode':
                    $args['mode'] = $op['to'];
                    break;
                case 'ai':
                    $args['ai'] = $op['to'];
                    break;
                case 'admins_mode':
                    $args['adminsMode'] = $op['to'];
                    break;
                case 'grant':
                    foreach ($args['grants'] as &$g) {
                        if ($g['admin_id'] === $op['admin_id']) {
                            $g['expires_at'] = $op['expires_at'];
                        }
                    }
                    unset($g);
                    break;
                case 'role':
                    foreach ($args['roles'] as &$r) {
                        if ($r['role_id'] === $op['role_id']) {
                            $r['scope'] = $op['scope'];
                        }
                    }
                    unset($r);
                    break;
                case 'format':
                    $args['formats'][$op['class']] = $op['to'];
                    break;
                case 'rule':
                    $args['rules'][] = ['id' => count($args['rules']) + 1, 'match' => $op['match'], 'pattern' => $op['pattern'], 'class' => $op['class'], 'source' => $op['source']];
                    break;
            }
        }

        return new State(...$args);
    }
}

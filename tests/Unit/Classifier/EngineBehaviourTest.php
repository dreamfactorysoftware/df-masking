<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Classifier;

use DreamFactory\Core\Masking\Classifier\CanonicalJson;
use DreamFactory\Core\Masking\Classifier\ColumnMeta;
use DreamFactory\Core\Masking\Classifier\Engine;
use DreamFactory\Core\Masking\Classifier\RulePack;
use DreamFactory\Core\Masking\Classifier\Ruleset;
use DreamFactory\Core\Masking\Classifier\TableMeta;
use PHPUnit\Framework\TestCase;

/**
 * Engine behaviours not covered by fixtures (ported from the prototype's tests/engine.php).
 * The wide-table chunking check lives in Scanner\SamplerTest (sampling is the scanner's job).
 */
final class EngineBehaviourTest extends TestCase
{
    private Engine $engine;

    protected function setUp(): void
    {
        $this->engine = Ruleset::engine('2026-10-28');
    }

    private static function rows(int $n, callable $f): array
    {
        return array_map($f, range(0, $n - 1));
    }

    private static function sample(array $rows): array
    {
        return ['rows' => $rows, 'ordered' => 'pk', 'error' => null, 'queries' => 1];
    }

    public function testStrongPhraseInACommentOnlyGivesReview(): void
    {
        $t = new TableMeta('public', 'acct', 'acct', 'table', [new ColumnMeta('fld7', 'varchar(20)', 'string', 20, false, false, null, false, 'Social security number of the account holder')]);
        $v = $this->engine->classifyDatabase([$t], null, Engine::MODE_NAME_ONLY)['acct.fld7'];
        $this->assertSame(['review', 'national_id', 45], [$v['verdict'], $v['class'], $v['confidence']]);
    }

    public function testSiblingClassPromotesWeakPan(): void
    {
        $t = new TableMeta('public', 'wallet', 'wallet', 'table', [new ColumnMeta('pan', 'varchar(19)', 'string', 19), new ColumnMeta('card_exp', 'varchar(5)', 'string', 5)]);
        $s = self::sample(self::rows(40, static fn ($i) => ['pan' => null, 'card_exp' => sprintf('%02d/%02d', $i % 12 + 1, 27)]));
        $out = $this->engine->classifyDatabase([$t], static fn () => $s, Engine::MODE_HYBRID);
        $this->assertSame('card_number', $out['wallet.pan']['class']);
        $this->assertSame('enforce', $out['wallet.pan']['verdict']);
        $this->assertContains('promoted_by_sibling', $out['wallet.pan']['evidence']['flags'] ?? []);
    }

    public function testJsonKeysThatLookLikeValuesAreRedactedAndNoValueReachesTheOutput(): void
    {
        $t = new TableMeta('public', 'evt', 'evt', 'table', [new ColumnMeta('payload', 'jsonb', 'jsonb')]);
        $s = self::sample(self::rows(30, static fn ($i) => ['payload' => json_encode(['by_email' => ["jane.doe$i@example.com" => ['email' => "jane.doe$i@example.com"]], 'n' => $i])]));
        $out = $this->engine->classifyDatabase([$t], static fn () => $s, Engine::MODE_HYBRID);
        $paths = array_column($out['evt.payload']['evidence']['json_paths'] ?? [], 'path');
        $this->assertContains('$.by_email.*.email', $paths);
        $this->assertSame('free_text_pii', $out['evt.payload']['class']);
        $json = CanonicalJson::encode($out);
        $this->assertStringNotContainsString('jane.doe', $json);
        $this->assertStringNotContainsString('example.com', $json);
    }

    public function testContradictingValues(): void
    {
        $t = new TableMeta('public', 'legacy', 'legacy', 'table', [new ColumnMeta('email', 'char(1)', 'string', 1), new ColumnMeta('ssn', 'char(64)', 'string', 64)]);
        $s = self::sample(self::rows(50, static fn ($i) => ['email' => $i % 2 ? 'Y' : 'N', 'ssn' => hash('sha256', "s$i")]));
        $out = $this->engine->classifyDatabase([$t], static fn () => $s, Engine::MODE_HYBRID);
        // email holding Y/N: name 70 - contradiction 40 -> clear 30
        $this->assertSame(['clear', 30], [$out['legacy.email']['verdict'], $out['legacy.email']['confidence']]);
        // ssn holding hashes: restricted + varied -> penalty 25 -> stays in review (fail closed)
        $this->assertSame(['review', 'national_id'], [$out['legacy.ssn']['verdict'], $out['legacy.ssn']['class']]);
    }

    public function testDeterminism(): void
    {
        $t = new TableMeta('public', 'legacy', 'legacy', 'table', [new ColumnMeta('email', 'char(1)', 'string', 1), new ColumnMeta('ssn', 'char(64)', 'string', 64)]);
        $s = self::sample(self::rows(50, static fn ($i) => ['email' => $i % 2 ? 'Y' : 'N', 'ssn' => hash('sha256', "s$i")]));
        $a = CanonicalJson::encode($this->engine->classifyDatabase([$t], static fn () => $s, Engine::MODE_HYBRID));
        $b = CanonicalJson::encode((new Engine(RulePack::load(Ruleset::path()), '2026-10-28'))->classifyDatabase([$t], static fn () => $s, Engine::MODE_HYBRID));
        $this->assertSame(hash('sha256', $a), hash('sha256', $b));
    }

    public function testTableContextsMatchClassifyDatabase(): void
    {
        $customers = new TableMeta('public', 'customers', 'customers', 'table', [new ColumnMeta('id', 'integer', 'integer', null, true), new ColumnMeta('name', 'text', 'text')]);
        $orders = new TableMeta('public', 'orders', 'orders', 'table', [new ColumnMeta('id', 'integer', 'integer', null, true), new ColumnMeta('customer_id', 'integer', 'integer', null, false, true, 'customers')]);
        $ctx = $this->engine->tableContexts([$customers, $orders]);
        $this->assertTrue($ctx['customers']['person_table']);
        $this->assertFalse($ctx['orders']['person_table']);
        $this->assertTrue($ctx['orders']['person_linked']);
        $whole = $this->engine->classifyDatabase([$customers, $orders], null, Engine::MODE_NAME_ONLY);
        $one = $this->engine->classifyTable($customers, $ctx['customers'], null, Engine::MODE_NAME_ONLY);
        $this->assertSame(CanonicalJson::encode($whole['customers.name']), CanonicalJson::encode($one['name']));
    }

    public function testReferenceDateIsValidated(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Engine(Ruleset::pack(), '28/10/2026');
    }
}

<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Classifier;

use DreamFactory\Core\Masking\Classifier\ColumnMeta;
use DreamFactory\Core\Masking\Classifier\Engine;
use DreamFactory\Core\Masking\Classifier\Evidence;
use DreamFactory\Core\Masking\Classifier\Ruleset;
use DreamFactory\Core\Masking\Classifier\TableMeta;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Engine verdict -> stored evidence (port of the admin UI fixture generator's humanize/shapes/strip).
 */
final class EvidenceTest extends TestCase
{
    public static function lines(): iterable
    {
        yield 'strong name' => ["+70 name 'cust_email' -> [email] strong phrase \"email\" (email.strong.0)", [70, 'name', 'Column name "cust_email"']];
        yield 'promoted by person table' => ["+70 name 'name' -> [name] weak phrase promoted by person_table \"name\" (person_name.weak.0)", [70, 'name', 'Column name "name" in a person table']];
        yield 'no class' => ["+0 name 'qty' -> [qty] matches no class phrase", [0, 'name', 'Column name "qty" matches no class']];
        yield 'quote in name' => ["+70 name 'o'brien_email' -> [o brien email] strong phrase \"email\" (email.strong.0)", [70, 'name', 'Column name "o\'brien_email"']];
        yield 'detector' => ['+75 values 256/256 (100%) pass ssn_us.dashed (strong)', [75, 'values', '256 of 256 values are valid US SSNs']];
        yield 'detector halved' => ['+37 values 40/40 (100%) pass email.syntax (strong) (halved: 3 distinct values)', [37, 'values', '40 of 40 values are valid email addresses (few distinct values)']];
        yield 'unknown detector' => ['+20 values 10/20 (50%) pass foo.bar (weak)', [20, 'values', '10 of 20 values pass foo.bar']];
        yield 'lexicon' => ['+45 values 97% capitalized 1-4 token values, 88% in the name lexicons (name.lexicon, medium)', [45, 'values', '88% of values are known names']];
        yield 'dob' => ['+60 values date-of-birth plausible: parse 100%, 45 distinct years, IQR 21y, 0% recent', [60, 'values', 'Values look like birth dates (45 distinct years)']];
        yield 'dob failed' => ['+0 values date-of-birth plausibility failed (recent; parse 100%)', [0, 'values', "Values don't look like birth dates"]];
        yield 'penalty' => ['-40 values contradict the class (shape:contains_at:0)', [-40, 'penalty', "Values don't fit the class"]];
        yield 'spans' => ['+75 text validated PII spans in 12 rows (email.syntax)', [75, 'text', 'Personal data inside the text in 12 rows']];
        yield 'few spans' => ['+45 text a few PII spans (strong rows 1, medium rows 4)', [45, 'text', 'Possible personal data inside the text in 4 rows']];
        yield 'surrogate' => ['. type surrogate key (integer, PK/FK/id) never classifies', [0, 'context', 'Key column, never classified']];
        yield 'small sample' => ['. sample only 3 non-null of 10 sampled rows; value evidence needs at least 5', [0, 'context', 'Only 3 non-null values sampled']];
        yield 'negative' => ['. name phrase from person_name.weak.0 suppressed by negative "product name"', [0, 'context', '"product name" rules out person name']];
        yield 'type gate' => ['. type email.strong.0 blocked by the type gate (type:integer)', [0, 'context', "An integer column can't hold email"]];
        yield 'type gate consonant' => ['. type email.strong.0 blocked by the type gate (type:boolean)', [0, 'context', "A boolean column can't hold email"]];
        yield 'dob role' => ['. values value-only date_of_birth evidence ignored: the name says this is another kind of date', [0, 'context', 'The name says this is another kind of date']];
        yield 'fallback text' => ['+40 text prose in a person table with no validated spans: may contain names', [40, 'text', 'prose in a person table with no validated spans: may contain names']];
        yield 'fallback json' => ['+75 json key path $.customer.email classified email (85)', [75, 'values', 'key path $.customer.email classified email (85)']];
    }

    #[DataProvider('lines')]
    public function testHumanize(string $why, array $want): void
    {
        $this->assertSame($want, Evidence::humanize($why));
    }

    public function testDroppedLines(): void
    {
        $this->assertNull(Evidence::humanize('= 100 -> ENFORCE email (identity), mask token'));
        $this->assertNull(Evidence::humanize('. also considered: username 15'));
        $this->assertNull(Evidence::humanize('. type card_number.strong.0 blocked by the type gate (size:4)'));
        $this->assertNull(Evidence::humanize('. values contradict email: name said 70, values penalty -40 (shape:contains_at:0)'));
    }

    public function testVerdictMappingAndStripMarks(): void
    {
        $this->assertSame('masked', Evidence::verdict('enforce'));
        $this->assertSame('review', Evidence::verdict('review'));
        $this->assertSame('clear', Evidence::verdict('clear'));
        $this->assertSame('identity', Evidence::stripMark('masked', 'identity'));
        $this->assertSame('review', Evidence::stripMark('review', 'restricted'));
        $this->assertSame('clear', Evidence::stripMark('clear', null));
    }

    public function testShapeAlphabet(): void
    {
        foreach (['999-99-9999', 'a+.a+@a+.a+', 'Aa+ Aa+', '(999) 999-9999', 'A+-9999', 'L+ ?', '9{12}', '*{4}9999'] as $ok) {
            $this->assertTrue(Evidence::isSafeShape($ok), $ok);
        }
        foreach (['jane@example.com', 'John Smith', '123-45-6789', 'Aa+ Bob', '', 'Ab'] as $bad) {
            $this->assertFalse(Evidence::isSafeShape($bad), $bad);
        }
        $this->assertSame([['999-99-9999', 100]], Evidence::shapes([['999-99-9999', 100], ['jane@example.com', 5]]));
        $this->assertCount(3, Evidence::shapes([['9', 1], ['99', 1], ['999', 1], ['9999', 1]]));
    }

    public function testFromEngineHybridAndNameOnly(): void
    {
        $engine = Ruleset::engine('2026-10-28');
        $t = new TableMeta('public', 'customers', 'customers', 'table', [new ColumnMeta('email', 'varchar(100)', 'string', 100), new ColumnMeta('qty', 'integer', 'integer')]);
        $rows = array_map(static fn ($i) => ['email' => "user$i@example.com", 'qty' => (string) $i], range(1, 40));
        $s = ['rows' => $rows, 'ordered' => 'pk', 'error' => null, 'queries' => 1];
        $hy = $engine->classifyDatabase([$t], static fn () => $s, Engine::MODE_HYBRID);
        $email = Evidence::fromEngine($hy['customers.email'], false, Ruleset::pack());
        $this->assertSame(['masked', 'email', 'identity', 100], [$email['verdict'], $email['class'], $email['tier'], $email['score']]);
        $this->assertSame([70, 40], [$email['evidence']['threshold_mask'], $email['evidence']['threshold_review']]);
        $this->assertSame(100, $email['evidence']['total']);
        $this->assertSame('name', $email['evidence']['lines'][0]['kind']);
        $this->assertNotEmpty($email['evidence']['shapes']);
        $this->assertArrayNotHasKey('name_only', $email['evidence']);
        $this->assertStringNotContainsString('example.com', json_encode($email));

        $qty = Evidence::fromEngine($hy['customers.qty'], false, Ruleset::pack());
        $this->assertSame(['clear', null, null], [$qty['verdict'], $qty['class'], $qty['tier']]);
        $this->assertLessThanOrEqual(2, count($qty['evidence']['lines']));
        $this->assertSame([], $qty['evidence']['shapes']);

        $no = $engine->classifyDatabase([$t], null, Engine::MODE_NAME_ONLY);
        $ne = Evidence::fromEngine($no['customers.email'], true, Ruleset::pack());
        $this->assertSame([70, 15], [$ne['evidence']['threshold_mask'], $ne['evidence']['threshold_review']]);
        $this->assertTrue($ne['evidence']['name_only']);
        $this->assertSame('context', end($ne['evidence']['lines'])['kind']);
    }
}

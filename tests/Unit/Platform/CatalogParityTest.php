<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Platform;

use DreamFactory\Core\Masking\Support\Catalog;
use PHPUnit\Framework\TestCase;

/**
 * Support\Catalog must mirror the admin UI catalog exactly (ids, order, tiers, default and allowed
 * formats, token prefixes, samples) and its English labels must match the UI's i18n.
 *
 * The UI files are mounted by bin/test.sh (DM_UI_CATALOG, DM_UI_I18N); without them the parity
 * tests are skipped and only the catalog's own invariants run.
 */
final class CatalogParityTest extends TestCase
{
    public function testMatchesTheAdminUiCatalog(): void
    {
        $ui = $this->uiClasses();
        $php = Catalog::classes();

        $this->assertSame(array_column($ui, 'id'), array_column($php, 'id'), 'class ids / order differ from the UI catalog');
        foreach ($ui as $i => $def) {
            $mine = $php[$i];
            $this->assertSame($def['tier'], $mine['tier'], "tier of {$def['id']}");
            $this->assertSame($def['format'], $mine['format'], "default format of {$def['id']}");
            $this->assertSame($def['formats'], $mine['formats'], "allowed formats of {$def['id']}");
            $this->assertSame($def['token'], $mine['token'], "token prefix of {$def['id']}");
            $this->assertSame($def['sample'], Catalog::sample($def['id']), "sample of {$def['id']}");
            $this->assertSame(['id', 'tier', 'format', 'formats', 'token'], array_keys($mine));
        }
    }

    public function testTiersMatchTheAdminUi(): void
    {
        $source = $this->uiSource();
        $this->assertSame(1, preg_match('/export const TIERS: Tier\[\] = \[([^\]]*)\]/', $source, $m));
        preg_match_all("/'([a-z_]+)'/", $m[1], $tiers);
        $this->assertSame($tiers[1], Catalog::tiers());

        $this->assertSame(1, preg_match('/export type MaskFormat =([^;]+);/', $source, $f));
        preg_match_all("/'([a-z0-9_]+)'/", $f[1], $formats);
        $this->assertSame($formats[1], Catalog::FORMATS);
    }

    public function testLabelsMatchTheAdminUiI18n(): void
    {
        $file = getenv('DM_UI_I18N') ?: '';
        if ($file === '' || !is_file($file)) {
            $this->markTestSkipped('Admin UI i18n not mounted (set DM_UI_I18N; bin/test.sh does).');
        }
        $i18n = json_decode((string)file_get_contents($file), true, 64, JSON_THROW_ON_ERROR);
        foreach (Catalog::ids() as $id) {
            $this->assertSame($i18n['classes'][$id], Catalog::label($id), "label of $id");
        }
        foreach (Catalog::tiers() as $tier) {
            $this->assertSame($i18n['tiers'][$tier], Catalog::tierLabel($tier), "label of tier $tier");
        }
        foreach (Catalog::FORMATS as $format) {
            $this->assertSame($i18n['formats'][$format], Catalog::formatLabel($format), "label of format $format");
        }
        $this->assertSame($i18n['notSensitive'], Catalog::label(null));
    }

    public function testCatalogInvariants(): void
    {
        $prefixes = [];
        foreach (Catalog::classes() as $c) {
            $this->assertContains($c['tier'], Catalog::tiers());
            $this->assertContains($c['format'], $c['formats'], "{$c['id']}: default format must be allowed");
            $this->assertSame($c['format'], $c['formats'][0], "{$c['id']}: default format comes first");
            foreach ($c['formats'] as $f) {
                $this->assertTrue(Catalog::isFormat($f), "{$c['id']}: unknown format $f");
            }
            if ($c['tier'] === Catalog::TIER_RESTRICTED) {
                $this->assertNotContains('token', $c['formats'], "{$c['id']}: restricted classes never use token");
            }
            if ($c['tier'] !== Catalog::TIER_FREE_TEXT) {
                $this->assertNotContains('span', $c['formats'], "{$c['id']}: span is for free text only");
            }
            $this->assertMatchesRegularExpression('/^[A-Z]+$/', $c['token']);
            $prefixes[] = $c['token'];
            $this->assertNotNull(Catalog::sample($c['id']));
            $this->assertNotSame($c['id'], Catalog::label($c['id']), "{$c['id']} has a label");
        }
        $this->assertSame(count($prefixes), count(array_unique($prefixes)), 'token prefixes are unique');
    }

    public function testAccessors(): void
    {
        $this->assertSame('restricted', Catalog::tierOf('national_id'));
        $this->assertSame('last4', Catalog::defaultFormat('card_number'));
        $this->assertSame(['redact', 'null'], Catalog::formatsAllowed('card_security'));
        $this->assertSame('EMAIL', Catalog::tokenPrefix('email'));
        $this->assertNull(Catalog::get('nope'));
        $this->assertNull(Catalog::tierOf('nope'));
        $this->assertNull(Catalog::defaultFormat('nope'));
        $this->assertSame([], Catalog::formatsAllowed('nope'));
        $this->assertNull(Catalog::tokenPrefix('nope'));
        $this->assertFalse(Catalog::has(null));
        $this->assertSame(['free_text_pii'], Catalog::classesInTier('free_text'));
        $this->assertSame('nope', Catalog::label('nope'));

        $builtin = Catalog::builtinDetectors();
        $this->assertSame(Catalog::ids(), array_column($builtin, 'class'));
        foreach ($builtin as $row) {
            $sorted = $row['detectors'];
            sort($sorted);
            $this->assertSame($sorted, $row['detectors']);
        }
    }

    /** @return list<array{id:string,tier:string,format:string,formats:string[],sample:string,token:string}> */
    private function uiClasses(): array
    {
        $source = $this->uiSource();
        $start = strpos($source, 'export const CLASSES');
        $this->assertNotFalse($start);
        $end = strpos($source, '];', $start);
        $block = substr($source, $start, $end - $start);

        preg_match_all('/\{(.*?)\n\s*\},?/s', $block, $objects);
        $out = [];
        foreach ($objects[1] as $object) {
            $def = [];
            foreach (['id', 'tier', 'format', 'token'] as $key) {
                $this->assertSame(1, preg_match("/\\b$key: '([^']*)'/", $object, $m), "missing $key");
                $def[$key] = $m[1];
            }
            $this->assertSame(1, preg_match("/\\bformats: \\[([^\\]]*)\\]/", $object, $m));
            preg_match_all("/'([^']*)'/", $m[1], $formats);
            $def['formats'] = $formats[1];
            $this->assertSame(1, preg_match("/\\bsample: (['\"])(.*?)\\1,/s", $object, $m));
            $def['sample'] = $m[2];
            $out[] = $def;
        }
        $this->assertNotEmpty($out, 'no classes parsed from the UI catalog');

        return $out;
    }

    private function uiSource(): string
    {
        $file = getenv('DM_UI_CATALOG') ?: '';
        if ($file === '' || !is_file($file)) {
            $this->markTestSkipped('Admin UI catalog not mounted (set DM_UI_CATALOG; bin/test.sh does).');
        }

        return (string)file_get_contents($file);
    }
}

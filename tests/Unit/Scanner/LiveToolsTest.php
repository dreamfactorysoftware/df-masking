<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Scanner;

use PHPUnit\Framework\TestCase;

/**
 * The live verification tools leave the instance as they found it. valuecheck.php re-samples
 * every covered service like the scanner; like the scanner it must skip a SQLite service whose
 * database file does not exist before anything opens its connection (PDO would create the empty
 * file, e.g. the built-in `db` service's storage/databases/db.sqlite). The script boots a full
 * DreamFactory install, so this checks its code path statically; tests/Live/run.sh values runs it.
 */
final class LiveToolsTest extends TestCase
{
    public function testValuecheckSkipsMissingSqliteFilesBeforeConnecting(): void
    {
        $src = (string) file_get_contents(dirname(__DIR__, 2) . '/Live/valuecheck.php');
        $loop = strpos($src, 'foreach (Services::covered() as $info)');
        $this->assertNotFalse($loop, 'the per-service loop');
        $skip = strpos($src, 'Services::isMissingSqliteFile($svc)', $loop);
        $this->assertNotFalse($skip, 'missing SQLite files are skipped');
        $this->assertMatchesRegularExpression('/if \(Services::isMissingSqliteFile\(\$svc\)\) \{\s*(\/\/[^\n]*\n\s*)*continue;/', substr($src, $skip - 4, 400));
        foreach (['new SchemaReader(', '->getConnection()', '->getTableNames(', '->driver()'] as $opens) {
            $at = strpos($src, $opens, $loop);
            $this->assertNotFalse($at, $opens);
            $this->assertGreaterThan($skip, $at, "$opens comes after the skip");
        }
    }
}

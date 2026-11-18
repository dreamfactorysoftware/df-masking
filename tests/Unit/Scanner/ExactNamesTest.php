<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Scanner;

use DreamFactory\Core\Masking\Enforcement\InlineClassifier;
use DreamFactory\Core\Masking\Enforcement\Policy;
use DreamFactory\Core\Masking\Enforcement\TableTarget;
use DreamFactory\Core\Masking\Resources\Handlers\ColumnHandler;
use DreamFactory\Core\Masking\Scanner\ColumnWriter;
use DreamFactory\Core\Masking\Scanner\Examples;
use DreamFactory\Core\Masking\Scanner\ScanRunner;
use DreamFactory\Core\Masking\Scanner\ScanState;
use DreamFactory\Core\Masking\Support\Catalog;
use DreamFactory\Core\Masking\Support\Coverage;
use DreamFactory\Core\Masking\Support\PolicyVersion;
use DreamFactory\Core\Masking\Support\Tables;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\TestCase;

/**
 * The dm_column identity is the exact (byte) table and column name, whatever the system
 * database collation. A case-insensitive collation is simulated with SQLite NOCASE columns
 * (what MySQL's utf8mb4_unicode_ci and SQL Server's *_CI_AS do for ASCII case); the migration
 * that makes MySQL/SQL Server compare exactly is proven on those databases by
 * SystemDbPortabilityTest. A lost insert race is absorbed.
 */
final class ExactNamesTest extends TestCase
{
    private int $svc;

    protected function setUp(): void
    {
        Harness::boot();
        $this->svc = Harness::addService('crm', Harness::sqlite([]));
    }

    /** dm_column whose names compare case-insensitively, with a unique key that does too ($ciIndex) or not. */
    private function caseInsensitiveColumns(bool $ciIndex): void
    {
        Schema::drop(Tables::COLUMN);
        Schema::create(Tables::COLUMN, function (Blueprint $t) use ($ciIndex) {
            $t->bigIncrements('id');
            $t->unsignedInteger('service_id');
            $t->string('table_name', 255)->collation('NOCASE');
            $t->string('column_name', 255)->collation('NOCASE');
            foreach (['db_type', 'verdict', 'class', 'tier', 'source', 'detected_class', 'decided_by', 'ruleset_version', 'fingerprint'] as $c) {
                $t->string($c, 255)->nullable();
            }
            foreach (['score', 'detected_score', 'decided_by_id', 'ordinal'] as $c) {
                $t->integer($c)->nullable();
            }
            $t->text('evidence')->nullable();
            $t->text('examples')->nullable();
            $t->timestamp('decided_at')->nullable();
            $t->timestamp('scanned_at')->nullable();
            $t->timestamps();
        });
        DB::statement('CREATE UNIQUE INDEX dm_column_svc_tbl_col_unique ON dm_column (service_id, table_name'
            . ($ciIndex ? '' : ' COLLATE BINARY') . ', column_name' . ($ciIndex ? '' : ' COLLATE BINARY') . ')');
    }

    private static function col(string $verdict, ?string $class, int $score): array
    {
        return [
            'db_type' => 'text', 'ordinal' => 1, 'fingerprint' => str_repeat('a', 64), 'raw' => null, 'df_type' => 'string', 'name_only' => false,
            'result' => ['verdict' => $verdict, 'class' => $class, 'tier' => $class ? Catalog::tierOf($class) : null, 'score' => $score, 'source' => 'detected',
                'detected_class' => $class, 'detected_score' => $score,
                'evidence' => ['total' => $score, 'threshold_mask' => 70, 'threshold_review' => 40, 'lines' => [], 'shapes' => []]],
        ];
    }

    private function rows(): array
    {
        return array_map(fn ($r) => [$r->table_name, $r->column_name, $r->verdict, $r->class],
            DB::table(Tables::COLUMN)->orderBy('id')->get(['table_name', 'column_name', 'verdict', 'class'])->all());
    }

    public function testACaseVariantTableNeverOverwritesAnotherTablesRows(): void
    {
        $this->caseInsensitiveColumns(true);
        $w = new ColumnWriter(new Examples());
        $w->write($this->svc, 'clients', ['email' => self::col('masked', 'email', 100)], 'v');

        // a scan of "Clients" (another table, or the same one renamed) must not adopt "clients"' row
        $stats = $w->write($this->svc, 'Clients', ['email' => self::col('clear', null, 0)], 'v', false);

        $this->assertSame([['clients', 'email', 'masked', 'email']], $this->rows(), 'the masked row was not turned clear');
        $this->assertSame(0, $stats['inserted'] + $stats['updated'], 'nothing could be stored for the colliding name');
    }

    public function testAccentAndCaseVariantColumnsAreSeparateRows(): void
    {
        $w = new ColumnWriter(new Examples());
        $w->write($this->svc, 'collide', [
            "r\u{E9}sum\u{E9}" => self::col('masked', 'free_text_pii', 75),
            'resume' => self::col('clear', null, 0),
            "\u{C9}MAIL" => self::col('masked', 'email', 100),
            "\u{E9}mail" => self::col('clear', null, 30),
            "stra\u{DF}e" => self::col('masked', 'street_address', 70),
            'strasse' => self::col('clear', null, 0),
            'Email' => self::col('masked', 'email', 100),
            'email' => self::col('clear', null, 0),
        ], 'v');
        $this->assertCount(8, $this->rows());
        $byName = array_column(array_map(fn ($r) => ['n' => $r[1], 'v' => $r[2]], $this->rows()), 'v', 'n');
        $this->assertSame('masked', $byName["\u{C9}MAIL"]);
        $this->assertSame('clear', $byName["\u{E9}mail"]);
        $this->assertSame('masked', $byName['Email']);
        $this->assertSame('clear', $byName['email']);
    }

    public function testPolicyReadsExactTableNamesFirst(): void
    {
        $this->caseInsensitiveColumns(false);
        $w = new ColumnWriter(new Examples());
        $w->write($this->svc, 'Clients', ['email' => self::col('masked', 'email', 100)], 'v');
        $w->write($this->svc, 'clients', ['email' => self::col('clear', null, 0)], 'v');
        PolicyVersion::bump();
        Policy::forget();

        $this->assertSame([], Policy::forTable($this->svc, 'clients'), "clients' own row is clear");
        $this->assertSame(['email'], array_keys(Policy::forTable($this->svc, 'Clients')));
        $this->assertSame(['email'], array_keys(Policy::forTable($this->svc, 'CLIENTS')), 'a URL in another case still finds a policy');
    }

    public function testInlineClassificationComparesColumnNamesExactly(): void
    {
        DB::table(Tables::COLUMN)->insert(['service_id' => $this->svc, 'table_name' => 'people', 'column_name' => 'email', 'verdict' => 'clear',
            'score' => 0, 'source' => 'detected', 'scanned_at' => now()]);
        ScanState::create(null, 'test'); // a scan is running: the background re-scan waits for it
        PolicyVersion::bump();
        $target = new TableTarget('crm', $this->svc, 'sqlite', 'people', [
            'email' => ['name' => 'email', 'column' => 'email', 'type' => 'string', 'db_type' => 'text'],
            'Email' => ['name' => 'Email', 'column' => 'Email', 'type' => 'string', 'db_type' => 'text'],
        ], [], []);

        Policy::effective($target);

        $this->assertSame(['email', 'Email'], DB::table(Tables::COLUMN)->where('table_name', 'people')->orderBy('id')->pluck('column_name')->all(),
            '"Email" is a column of its own and was classified');
    }

    /**
     * The insert that loses a race with enforcement is absorbed (the row is updated). On
     * PostgreSQL that needs the savepoint: SystemDbPortabilityTest replays it there.
     */
    public function testALostInsertRaceIsAbsorbed(): void
    {
        $w = new ColumnWriter(new Examples());
        $fired = false;
        $conn = DB::connection();
        $conn->setEventDispatcher(new \Illuminate\Events\Dispatcher());
        $conn->listen(function ($q) use (&$fired, $conn) {
            if (!$fired && str_starts_with(strtolower(ltrim($q->sql)), 'select') && str_contains($q->sql, 'dm_column')) {
                $fired = true; // a concurrent request's inline insert, right after the scan read the table
                $conn->table(Tables::COLUMN)->insert(['service_id' => $this->svc, 'table_name' => 'race_t', 'column_name' => 'contact_email',
                    'verdict' => 'clear', 'score' => 0, 'source' => 'detected']);
            }
        });

        $stats = $w->write($this->svc, 'race_t', ['contact_email' => self::col('masked', 'email', 100), 'other' => self::col('clear', null, 0)], 'v');

        $this->assertTrue($fired, 'the concurrent insert happened inside the scan');
        $this->assertSame([['race_t', 'contact_email', 'masked', 'email'], ['race_t', 'other', 'clear', null]], $this->rows());
        $this->assertSame(2, $stats['inserted']);
    }

    public function testColumnsWithNamesOutsideLatin1CanBeDecided(): void
    {
        $id = Harness::addService('shop', Harness::sqlite(["CREATE TABLE people (id integer primary key, \"\u{7535}\u{8BDD}\" text, \"wojew\u{F3}dztwo\u{142}\" text)"]));
        Coverage::forget();
        (new ScanRunner())->run('shop');

        $wire = (new ColumnHandler())->decide("shop.people.\u{7535}\u{8BDD}", ['class' => 'phone']);
        $this->assertSame(['masked', 'phone', 'admin'], [$wire['verdict'], $wire['class'], $wire['source']]);
        $wire = (new ColumnHandler())->decide("shop.people.wojew\u{F3}dztwo\u{142}", ['class' => 'street_address']);
        $this->assertSame("shop.people.wojew\u{F3}dztwo\u{142}", $wire['id']);
        $this->assertSame(2, DB::table(Tables::COLUMN)->where('service_id', $id)->where('source', 'admin')->count());
    }
}

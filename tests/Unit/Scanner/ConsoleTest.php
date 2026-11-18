<?php

namespace DreamFactory\Core\Masking\Tests\Unit\Scanner;

use DreamFactory\Core\Enums\LicenseLevel;
use DreamFactory\Core\Masking\Console\MaskingCommand;
use DreamFactory\Core\Masking\Support\License;
use DreamFactory\Core\Masking\Scanner\ScanRunner;
use DreamFactory\Core\Masking\Support\Coverage;
use DreamFactory\Core\Masking\Support\Settings;
use DreamFactory\Core\Masking\Support\Tables;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\TestCase;
use Illuminate\Console\OutputStyle;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * php artisan df:masking: setup never lowers the mode, its "Next:" line
 * follows the review queue and the mode, and mode On needs a completed scan
 * while lowering stays the operator's escape hatch.
 */
final class ConsoleTest extends TestCase
{
    protected function setUp(): void
    {
        $app = Harness::boot();
        $files = glob(dirname(__DIR__, 3) . '/database/migrations/*.php') ?: [];
        $ran = array_map(fn ($f) => basename($f, '.php'), $files);
        $app->instance('migrator', new class ($ran) {
            public function __construct(private array $ran)
            {
            }

            public function getRepository(): object
            {
                return new class ($this->ran) {
                    public function __construct(private array $ran)
                    {
                    }

                    public function getRan(): array
                    {
                        return $this->ran;
                    }
                };
            }
        });
    }

    /** @return array{0:int,1:string} exit code, output */
    private function artisan(array $args): array
    {
        $cmd = new MaskingCommand();
        $cmd->setLaravel(\Illuminate\Container\Container::getInstance());
        $input = new ArrayInput($args);
        $input->bind($cmd->getDefinition());
        $out = new BufferedOutput();
        $cmd->setInput($input);
        $cmd->setOutput(new OutputStyle($input, $out));
        $code = $cmd->handle();

        return [$code, $out->fetch()];
    }

    private function addCrm(bool $reviewColumn = false): void
    {
        // "ssn" holding varied words: a restricted name contradicted by its values = to review
        $ddl = $reviewColumn
            ? ['CREATE TABLE people (id integer primary key, email text, ssn text)']
            : ['CREATE TABLE people (id integer primary key, email text)'];
        $rows = [];
        for ($i = 1; $i <= 30; $i++) {
            $rows[] = ['id' => $i, 'email' => "p$i@example.org"] + ($reviewColumn ? ['ssn' => 'code' . str_repeat(chr(97 + $i % 26), 1 + intdiv($i, 26))] : []);
        }
        Harness::addService('crm', Harness::sqlite($ddl, ['people' => $rows]));
        Coverage::forget();
    }

    public function testModeOnNeedsACompletedScan(): void
    {
        $this->addCrm();
        [$code, $out] = $this->artisan(['action' => 'mode', 'args' => ['on']]);
        $this->assertSame(1, $code);
        $this->assertStringContainsString('Scan your databases before turning masking on.', $out);
        $this->assertSame('off', Settings::mode());

        [$code, $out] = $this->artisan(['action' => 'baseline', 'args' => ['apply', 'hipaa'], '--mode' => 'on']);
        $this->assertSame(1, $code);
        $this->assertStringContainsString('Scan your databases before turning masking on.', $out);
        $this->assertSame('off', Settings::mode());

        $this->assertSame(0, $this->artisan(['action' => 'scan'])[0]);
        [$code] = $this->artisan(['action' => 'mode', 'args' => ['on']]);
        $this->assertSame(0, $code);
        $this->assertSame('on', Settings::mode());
        [$code] = $this->artisan(['action' => 'mode', 'args' => ['off']]);
        $this->assertSame(0, $code, 'the command line may always lower the mode');
        $this->assertSame('off', Settings::mode());
    }

    /** Without Gold the command keeps status, help, revoke and mode off, and refuses the rest. */
    public function testOtherLicenseLevelsKeepStatusAndTheWaysDown(): void
    {
        $this->addCrm();
        $this->assertSame(0, $this->artisan(['action' => 'scan'])[0]);
        $this->assertSame(0, $this->artisan(['action' => 'mode', 'args' => ['on']])[0]);

        License::resolveUsing(static fn () => LicenseLevel::OPEN_SOURCE);
        try {
            foreach ([['action' => 'scan'], ['action' => 'mode', 'args' => ['preview']], ['action' => 'grant', 'args' => ['k@example.com']],
                      ['action' => 'baseline', 'args' => ['apply', 'hipaa']], ['action' => 'setup']] as $args) {
                [$code, $out] = $this->artisan($args);
                $this->assertSame(1, $code, json_encode($args));
                $this->assertStringContainsString(License::MESSAGE, $out);
            }
            $this->assertSame('on', Settings::mode(), 'refused actions change nothing');
            $this->assertSame(0, $this->artisan(['action' => 'status'])[0]);
            $this->assertSame(0, $this->artisan(['action' => 'mode', 'args' => ['off']])[0]);
            $this->assertSame('off', Settings::mode(), 'masking can always be turned off');
        } finally {
            License::resolveUsing(static fn () => LicenseLevel::GOLD);
        }
    }

    public function testSetupNeverLowersTheMode(): void
    {
        $this->addCrm();
        $this->assertSame(0, $this->artisan(['action' => 'scan'])[0]);
        Settings::set(Settings::MODE, 'on');

        [$code, $out] = $this->artisan(['action' => 'setup', '--mode' => 'preview']);

        $this->assertSame(0, $code);
        $this->assertSame('on', Settings::mode(), 'still On');
        $this->assertStringContainsString('Masking is already On; leaving it On (use df:masking mode preview to lower it).', $out);
        $this->assertStringContainsString('4/4 Masking mode: On.', $out);
        $this->assertStringNotContainsString('Next:', $out, 'nothing to review and already On: no next step');
        $this->assertSame(0, DB::table(Tables::ACTIVITY)->where('kind', 'mode')->where('text', 'like', '%Preview%')->where('actor', 'Command line')->count());
    }

    public function testSetupRaisesTheModeAndPointsToTheRealNextStep(): void
    {
        $this->addCrm();
        [$code, $out] = $this->artisan(['action' => 'setup']);
        $this->assertSame(0, $code);
        $this->assertSame('preview', Settings::mode(), 'the first scan chose Preview');
        $this->assertStringContainsString('Next: switch the mode to On (admin app > Data Masking, or php artisan df:masking mode on).', $out,
            'nothing to review: no "review the to review columns" line');

        [$code, $out] = $this->artisan(['action' => 'setup', '--mode' => 'on']);
        $this->assertSame(0, $code);
        $this->assertSame('on', Settings::mode());
        $this->assertStringNotContainsString('Next:', $out);
    }

    /**
     * The only covered database is empty. The scan finds no column, so
     * setup does not recommend On, and On stays refused (exit 1) until a scan finds columns.
     */
    public function testEmptyDatabasesOnlyPointToAddingADatabase(): void
    {
        Harness::addService('db', Harness::sqlite([]));
        Coverage::forget();

        [$code, $out] = $this->artisan(['action' => 'setup']);
        $this->assertSame(0, $code);
        $this->assertSame('off', Settings::mode());
        $this->assertStringContainsString('Next: add a SQL database service, then run php artisan df:masking scan.', $out);
        $this->assertStringNotContainsString('turn masking on', $out);

        [$code, $out] = $this->artisan(['action' => 'mode', 'args' => ['on']]);
        $this->assertSame(1, $code);
        $this->assertStringContainsString('Scan your databases before turning masking on.', $out);
        $this->assertStringContainsString('Next: add a SQL database service, then run php artisan df:masking scan.', $out);
        $this->assertSame('off', Settings::mode());

        [$code] = $this->artisan(['action' => 'setup', '--mode' => 'on']);
        $this->assertSame(1, $code);
        $this->assertSame('off', Settings::mode());

        [$code, $out] = $this->artisan(['action' => 'setup', '--mode' => 'preview']);
        $this->assertSame(0, $code);
        $this->assertSame('preview', Settings::mode());
        $this->assertStringContainsString('Next: add a SQL database service, then run php artisan df:masking scan.', $out);
        $this->assertStringNotContainsString('switch the mode to On', $out);

        // data arrives: the next scan finds columns and On is allowed
        $this->addCrm();
        $this->assertSame(0, $this->artisan(['action' => 'scan'])[0]);
        $this->assertSame(0, $this->artisan(['action' => 'mode', 'args' => ['on']])[0]);
    }

    /** baseline apply on a never-scanned instance says the first scan started. */
    public function testApplyReportNamesTheFirstScan(): void
    {
        $started = MaskingCommand::applyReport('hipaa', ['name' => 'HIPAA', 'applied' => [], 'score' => ['pass' => 3, 'fail' => 1, 'manual' => 2], 'scan_started' => true]);
        $this->assertSame([
            ['info', 'HIPAA baseline adopted.'],
            ['line', '  Nothing needed changing.'],
            ['line', '  Checks: 3 pass, 1 fail, 2 manual'],
            ['line', 'First scan started: php artisan df:masking status'],
        ], $started);
        $later = MaskingCommand::applyReport('hipaa', ['name' => 'HIPAA', 'applied' => [['text' => 'Turn on masking Preview']], 'scan_started' => false]);
        $this->assertSame([['info', 'HIPAA baseline adopted.'], ['line', '  - Turn on masking Preview']], $later);
    }

    public function testNextStepNamesTheReviewQueue(): void
    {
        $this->addCrm(true);
        [, $out] = $this->artisan(['action' => 'setup']);
        $this->assertSame('review', DB::table(Tables::COLUMN)->where('column_name', 'ssn')->value('verdict'));
        $this->assertStringContainsString('Next: open the admin app > Data Masking, decide the 1 column to review, then switch the mode to On.', $out);
    }
}

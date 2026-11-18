<?php

declare(strict_types=1);

namespace DreamFactory\Core\Masking\Tests\Unit\Enforcement;

use DreamFactory\Core\Masking\Enforcement\ErrorScrubber;
use PHPUnit\Framework\TestCase;

/**
 * Database errors that can carry row data are reduced
 * to a fixed, language-independent text keeping the SQLSTATE and the operation, whatever the
 * server language. Messages below are the real templates captured from PostgreSQL 16
 * (lc_messages de_DE / fr_FR) and SQL Server 2022 (SET LANGUAGE Deutsch / Français), with
 * synthetic values, as DreamFactory delivers them (html-encoded).
 */
final class LocalizedErrorsTest extends TestCase
{
    private const VALUES = ['staff2@example.org', '602-12-6002', 'cust1@example.org', 'guest.person3@example.org', 'new.person@example.org'];

    /** @return array<string,array{0:string,1:string}> message, expected SQLSTATE */
    public static function localized(): array
    {
        return [
            'pgsql de check violation (row of another record)' => [
                "SQLSTATE[23514]: Check violation: 7 FEHLER:  neue Zeile f&uuml;r Relation &raquo;staff&laquo; verletzt Check-Constraint &raquo;staff_salary_check&laquo;\nDETAIL:  Fehlgeschlagene Zeile enth&auml;lt (2, staff2@example.org, 602-12-6002, -5, team2). (Connection: service.pgde, Host: pg, Port: 5432, Database: dm_de, SQL: \u{2022}\u{2022}\u{2022})",
                '23514',
            ],
            'pgsql de unique violation' => [
                "SQLSTATE[23505]: Unique violation: 7 FEHLER:  doppelter Schl&uuml;sselwert verletzt Unique-Constraint &raquo;staff_work_email_key&laquo;\nDETAIL:  Schl&uuml;ssel &raquo;(work_email)=(staff2@example.org)&laquo; existiert bereits. (Connection: service.pgde)",
                '23505',
            ],
            'pgsql fr check violation' => [
                "SQLSTATE[23514]: Check violation: 7 ERREUR:  la nouvelle ligne de la relation &laquo; staff &raquo; viole la contrainte de v&eacute;rification &laquo; staff_salary_check &raquo;\nD&Eacute;TAIL&nbsp;: La ligne en &eacute;chec contient (2, staff2@example.org, 602-12-6002, -5, team2).",
                '23514',
            ],
            'pgsql fr raw (not html-encoded)' => [
                "SQLSTATE[23514]: Check violation: 7 ERREUR:  la nouvelle ligne de la relation « staff » viole la contrainte de vérification « staff_salary_check »\nDÉTAIL : La ligne en échec contient (2, staff2@example.org, 602-12-6002, -5, team2).",
                '23514',
            ],
            'sqlsrv de duplicate key' => [
                'SQLSTATE[23000]: [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Verletzung der UNIQUE KEY-Einschr&auml;nkung &quot;UQ_x&quot;. Ein doppelter Schl&uuml;ssel kann in das sales.Customers-Objekt nicht eingef&uuml;gt werden. Der doppelte Schl&uuml;sselwert ist (cust1@example.org).',
                '23000',
            ],
            'sqlsrv fr duplicate key' => [
                "SQLSTATE[23000]: [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Violation de la contrainte UNIQUE KEY &laquo; UQ_sales_Customers_Email &raquo;. Impossible d'ins&eacute;rer une cl&eacute; en double dans l'objet &laquo; sales.Customers &raquo;. Valeur de cl&eacute; dupliqu&eacute;e : (cust1@example.org).",
                '23000',
            ],
            'pgsql en exclusion' => [
                "SQLSTATE[23P01]: &lt;&lt;Unknown error&gt;&gt;: 7 ERROR:  conflicting key value violates exclusion constraint &quot;one_active_email&quot;\nDETAIL:  Key (lower(guest_email::text))=(new.person@example.org) conflicts with existing key (lower(guest_email::text))=(guest.person3@example.org).",
                '23P01',
            ],
            'pgsql invalid input (data exception)' => [
                'SQLSTATE[22P02]: Invalid text representation: 7 FEHLER:  ung&uuml;ltige Eingabesyntax f&uuml;r Typ integer: &raquo;602-12-6002&laquo;',
                '22P02',
            ],
            'mysql de duplicate entry' => [
                "SQLSTATE[23000]: Integrity constraint violation: 1062 Doppelter Eintrag 'cust1@example.org' f&uuml;r Schl&uuml;ssel 'customers_email_unique'",
                '23000',
            ],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('localized')]
    public function testLocalizedDataErrorsAreReduced(string $message, string $state): void
    {
        $out = ErrorScrubber::scrubText($message, ['staff', 'work_email', 'ssn']);
        foreach (self::VALUES as $value) {
            $this->assertStringNotContainsString($value, $out);
        }
        $this->assertSame(sprintf(ErrorScrubber::REDUCED, 'request', $state), $out);
    }

    public function testReductionKeepsTheOperationThroughTheListenerPath(): void
    {
        $content = ['error' => ['code' => '23514', 'context' => null, 'message' => self::localized()['pgsql de check violation (row of another record)'][0]]];
        $out = ErrorScrubber::scrub($content, ['staff'], null, 'resource', 'update');
        $this->assertSame('Database error during update (SQLSTATE 23514). Data Masking removed the details.', $out['error']['message']);
        $this->assertSame('23514', $out['error']['code']);
    }

    public function testBatchEntriesAreReducedByTheirCode(): void
    {
        // A batch entry whose message lost its SQLSTATE prefix still carries the code.
        $content = ['error' => ['code' => 1000, 'message' => 'Batch Error: Not all requested records could be created.', 'context' => [
            'error' => [0],
            'resource' => [['code' => '23505', 'message' => 'doppelter Schl&uuml;sselwert verletzt Unique-Constraint &raquo;staff_work_email_key&laquo;']],
        ]]];
        $out = ErrorScrubber::scrub($content, [], fn (array $r) => $r, 'resource', 'insert');
        $this->assertSame('Batch Error: Not all requested records could be created.', $out['error']['message'], "DreamFactory's own text stays");
        $this->assertSame('Database error during insert (SQLSTATE 23505). Data Masking removed the details.', $out['error']['context']['resource'][0]['message']);
    }

    public function testDetailLinesInAnyLanguageAreReducedWithoutSqlstate(): void
    {
        foreach ([
            "fel\nDETAIL:  Key (a)=(staff2@example.org)",
            "Fehler\nKONTEXT:  SQL-Anweisung &raquo;x&laquo; 602-12-6002",
            "erreur\nD&Eacute;TAIL : 602-12-6002",
            "ошибка\nПОДРОБНОСТИ:  602-12-6002",
            "エラー\n詳細: 602-12-6002",
            "error\nDETALLE:  La fila que falla contiene (602-12-6002)",
        ] as $message) {
            $out = ErrorScrubber::scrubText($message);
            $this->assertStringNotContainsString('602-12-6002', $out, $message);
            $this->assertStringNotContainsString('staff2@example.org', $out, $message);
        }
    }

    public function testOtherErrorsKeepTheirTextAndApostrophes(): void
    {
        $fr = ErrorScrubber::scrubText("SQLSTATE[42S02]: Impossible d'acc&eacute;der &agrave; l'objet &laquo; dbo.missing &raquo;.", ['dbo.missing']);
        $this->assertStringContainsString("Impossible d'acc&eacute;der &agrave; l'objet", $fr, 'apostrophes are not quotes');
        $this->assertStringContainsString('dbo.missing', $fr, 'identifier kept');
        $own = ErrorScrubber::scrubText("Required field 'email' can not be NULL.", ['email']);
        $this->assertSame("Required field 'email' can not be NULL.", $own, "DreamFactory's own validation stays readable");
        $value = ErrorScrubber::scrubText('Valeur invalide : (602-12-6002) pour &laquo; ssn2 &raquo;', ['ssn']);
        $this->assertStringNotContainsString('602-12-6002', $value);
        $this->assertStringNotContainsString('ssn2', $value, 'typographic quotes are quotes');
    }
    /**
     * DreamFactory's own validation messages keep the field names the
     * caller sent, which are not row data; database text never does.
     */
    public function testDreamFactoryMessagesKeepFieldNamesTheCallerSent(): void
    {
        $order = "Invalid field '1' in order by clause.";
        $this->assertSame($order, ErrorScrubber::scrubText($order, [], null, ['1']));
        $filter = "Invalid or unparsable field in filter request: 'nosuchcol'";
        $this->assertSame($filter, ErrorScrubber::scrubText($filter, ['staff'], null, ['NoSuchCol']));
        $group = "Invalid or unknown field 'zz' in group by clause.";
        $this->assertSame($group, ErrorScrubber::scrubText($group, [], null, ['zz']));
        // ... only those names: other quoted text is still removed
        $this->assertSame("Invalid field '" . ErrorScrubber::REPLACEMENT . "' in order by clause.", ErrorScrubber::scrubText($order, [], null, ['2']));
        $this->assertSame("Record with identifier '" . ErrorScrubber::REPLACEMENT . "' not found.", ErrorScrubber::scrubText("Record with identifier '602-12-6002' not found.", ['id'], null, ['id', 'email']));
        // database text (SQLSTATE, SQL, driver tags, an SQLSTATE code) never keeps them
        $db = "Failed to retrieve records from 'staff'.\nSQLSTATE[42S22]: Column not found: 1054 Unknown column 'nosuchcol' in 'where clause'";
        $this->assertStringNotContainsString('nosuchcol', ErrorScrubber::scrubText($db, ['staff'], null, ['nosuchcol']));
        $this->assertStringNotContainsString('602-12-6002', ErrorScrubber::scrubText("[Microsoft][ODBC Driver 18 for SQL Server]Invalid column name '602-12-6002'.", [], null, ['602-12-6002']));
        $this->assertStringNotContainsString('nosuchcol', ErrorScrubber::scrubText("column 'nosuchcol' does not exist", [], '42703', ['nosuchcol']));
        // through scrub(): the identifiers apply to every message of the body
        $out = ErrorScrubber::scrub(['error' => ['code' => 400, 'context' => null, 'message' => $filter]], ['staff'], null, 'resource', 'read', ['nosuchcol']);
        $this->assertSame($filter, $out['error']['message']);
        $this->assertStringNotContainsString('nosuchcol', ErrorScrubber::scrub(['error' => ['code' => 400, 'context' => null, 'message' => $filter]])['error']['message']);
    }
}

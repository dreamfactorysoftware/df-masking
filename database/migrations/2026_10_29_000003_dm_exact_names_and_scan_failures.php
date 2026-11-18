<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Additive upgrade of the df-masking tables (running instances get it with `php artisan migrate`,
 * fresh installs run it right after the create migration):
 *
 *  1. dm_column.table_name / column_name compare exactly (byte for byte), whatever the system
 *     database's default collation. DreamFactory's MySQL default (utf8mb4_unicode_ci) and SQL
 *     Server's usual *_CI_AS collations treat "ÉMAIL" and "émail", "straße" and "strasse", or
 *     "Clients" and "clients" as equal, so the unique (service, table, column) key made two real
 *     columns overwrite each other. MySQL/MariaDB get the column charset's *_bin collation, SQL
 *     Server Latin1_General_100_BIN2 (code point order for nvarchar). PostgreSQL (deterministic
 *     collations) and SQLite (BINARY) already compare exactly: nothing to do there.
 *  2. dm_scan.failed_services: JSON list of the services a scan could not read
 *     ([{service_id, service, label, reason}], reasons carry SQLSTATEs, never data values).
 *
 * down() restores the table's default collation (rows whose names then compare equal keep one row
 * each: an admin decision first, else the oldest) and drops the column.
 */
return new class extends Migration {
    private const COLUMN = 'dm_column';
    private const SCAN = 'dm_scan';
    private const UNIQUE = 'dm_column_svc_tbl_col_unique';

    public function up(): void
    {
        if (Schema::hasTable(self::SCAN) && !Schema::hasColumn(self::SCAN, 'failed_services')) {
            Schema::table(self::SCAN, function (Blueprint $t) {
                $t->text('failed_services')->nullable();
            });
        }
        $this->collateNames(true);
    }

    public function down(): void
    {
        $this->collateNames(false);
        if (Schema::hasTable(self::SCAN) && Schema::hasColumn(self::SCAN, 'failed_services')) {
            Schema::table(self::SCAN, function (Blueprint $t) {
                $t->dropColumn('failed_services');
            });
        }
    }

    private function collateNames(bool $exact): void
    {
        if (!Schema::hasTable(self::COLUMN)) {
            return;
        }
        $conn = Schema::getConnection();
        $driver = $conn->getDriverName();
        if (!in_array($driver, ['mysql', 'mariadb', 'sqlsrv'], true)) {
            return; // pgsql, sqlite: equality is already exact
        }
        // MySQL/MariaDB: the column's character set (utf8mb4 on DreamFactory installs) with its
        // *_bin collation. SQL Server: code point order for nvarchar. Without a collation (down)
        // the column falls back to the table / database default.
        $charset = $exact && $driver !== 'sqlsrv' ? $this->mysqlCharset($conn) : null;
        $collation = !$exact ? null : ($driver === 'sqlsrv' ? 'Latin1_General_100_BIN2' : $charset . '_bin');

        // The unique key is dropped around the change: SQL Server cannot change the collation of an
        // indexed column, and going back to a case-insensitive collation can make rows collide.
        if ($this->hasUnique()) {
            Schema::table(self::COLUMN, function (Blueprint $t) {
                $t->dropUnique(self::UNIQUE);
            });
        }
        Schema::table(self::COLUMN, function (Blueprint $t) use ($charset, $collation) {
            foreach (['table_name', 'column_name'] as $name) {
                $column = $t->string($name, 255);
                if ($charset !== null) {
                    $column->charset($charset);
                }
                if ($collation !== null) {
                    $column->collation($collation);
                }
                $column->change();
            }
        });
        if (!$exact) {
            $this->dropCollationDuplicates();
        }
        Schema::table(self::COLUMN, function (Blueprint $t) {
            $t->unique(['service_id', 'table_name', 'column_name'], self::UNIQUE);
        });
    }

    private function hasUnique(): bool
    {
        try {
            return Schema::hasIndex(self::COLUMN, self::UNIQUE);
        } catch (\Throwable $e) {
            return true;
        }
    }

    /**
     * Rolling back to a case-insensitive collation: rows whose names now compare equal (for
     * example "Email" and "email") keep one row each, an admin decision first, else the oldest.
     * The database groups by its own collation, so this matches exactly what the unique key
     * will reject.
     */
    private function dropCollationDuplicates(): void
    {
        $groups = DB::table(self::COLUMN)
            ->select(['service_id', 'table_name', 'column_name'])
            ->groupBy('service_id', 'table_name', 'column_name')
            ->havingRaw('COUNT(*) > 1')
            ->get();
        foreach ($groups as $g) {
            $same = fn () => DB::table(self::COLUMN)->where('service_id', $g->service_id)
                ->where('table_name', $g->table_name)->where('column_name', $g->column_name);
            $keep = $same()->orderByRaw("CASE WHEN source = 'admin' THEN 0 ELSE 1 END")->orderBy('id')->value('id');
            $same()->where('id', '<>', $keep)->delete();
        }
    }

    private function mysqlCharset(\Illuminate\Database\Connection $conn): string
    {
        try {
            $row = $conn->selectOne(
                'SELECT CHARACTER_SET_NAME AS cs FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?',
                [$conn->getTablePrefix() . self::COLUMN, 'table_name']
            );
            $charset = $row->cs ?? null;
        } catch (\Throwable $e) {
            $charset = null;
        }

        return is_string($charset) && preg_match('/^[a-z0-9]+$/i', $charset) ? strtolower($charset) : 'utf8mb4';
    }
};

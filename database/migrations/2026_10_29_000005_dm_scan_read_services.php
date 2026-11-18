<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Additive: dm_scan.read_services is the JSON list of the ids of every service a finished scan
 * actually read ([12, 15]), including services a running scan picked up as extras (requests that
 * came due while it ran). Before, a scan row named only the service it was started for, so an
 * empty database read as an extra never counted as scanned (it has no dm_column rows to show it).
 *
 * Plain nullable text, no default and no index, so up() and down() are the same on MySQL
 * 5.7+/MariaDB, PostgreSQL, SQL Server and SQLite. Rows written before this migration have NULL
 * (their service_id / scope and the stored columns keep telling what they read).
 */
return new class extends Migration {
    private const SCAN = 'dm_scan';
    private const COLUMN = 'read_services';

    public function up(): void
    {
        if (!Schema::hasTable(self::SCAN) || Schema::hasColumn(self::SCAN, self::COLUMN)) {
            return;
        }
        Schema::table(self::SCAN, function (Blueprint $t) {
            $t->text(self::COLUMN)->nullable();
        });
    }

    public function down(): void
    {
        if (Schema::hasTable(self::SCAN) && Schema::hasColumn(self::SCAN, self::COLUMN)) {
            Schema::table(self::SCAN, function (Blueprint $t) {
                $t->dropColumn(self::COLUMN);
            });
        }
    }
};

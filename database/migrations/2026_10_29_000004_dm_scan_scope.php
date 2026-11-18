<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Additive: dm_scan.scope says what a scan covered, 'full' (every covered service) or 'service'
 * (one service), instead of inferring it from service_id NULL. Deleting a service sets the
 * service_id of its scans to NULL (DreamFactory may hand the id to a new service later), and its
 * single-service scans must never look like full scans then.
 *
 * Existing rows are backfilled from service_id (rows of services deleted before this migration
 * cannot be told apart from full scans; they keep the old reading). Plain nullable string, no
 * default and no index, so up() and down() are the same on MySQL 5.7+/MariaDB, PostgreSQL, SQL
 * Server and SQLite.
 */
return new class extends Migration {
    private const SCAN = 'dm_scan';
    private const COLUMN = 'scope';

    public function up(): void
    {
        if (!Schema::hasTable(self::SCAN) || Schema::hasColumn(self::SCAN, self::COLUMN)) {
            return;
        }
        Schema::table(self::SCAN, function (Blueprint $t) {
            $t->string(self::COLUMN, 16)->nullable();
        });
        DB::table(self::SCAN)->whereNotNull('service_id')->update([self::COLUMN => 'service']);
        DB::table(self::SCAN)->whereNull('service_id')->update([self::COLUMN => 'full']);
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

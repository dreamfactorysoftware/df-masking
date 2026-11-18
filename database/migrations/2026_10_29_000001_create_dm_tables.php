<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * df-masking system tables (everything except dm_baseline, which has its own migration).
 *
 * Portable across the system databases DreamFactory supports (MySQL/MariaDB, PostgreSQL,
 * SQLite, SQL Server): no engine-specific SQL, JSON kept in text columns. Rows reference
 * service/user/role with ON DELETE CASCADE where DreamFactory's own tables do; the package's
 * ServiceDeletedEvent/RoleDeletedEvent/UserDeletedEvent listeners clean up as well (SQLite
 * system databases may run without foreign key enforcement).
 *
 * No table ever holds a raw data value.
 *
 * up() and down() drop the cached df-masking settings (mode, first-scan marker, last-mode
 * fallback) and bump the policy version: cached state must never outlive the tables it was read
 * from (a reinstall within the cache lifetime would otherwise start with the old mode on empty
 * tables).
 */
return new class extends Migration {
    public function up(): void
    {
        $this->createTables();
        $this->invalidateCache();
    }

    private function createTables(): void
    {
        if (!Schema::hasTable('dm_setting')) {
            Schema::create('dm_setting', function (Blueprint $t) {
                $t->string('name', 64)->primary();
                $t->text('value')->nullable();
                $t->timestamp('updated_at')->nullable();
            });
        }

        if (!Schema::hasTable('dm_column')) {
            Schema::create('dm_column', function (Blueprint $t) {
                $t->bigIncrements('id');
                $t->unsignedInteger('service_id');
                $t->string('table_name', 255);
                $t->string('column_name', 255);
                $t->string('db_type', 100)->nullable();
                $t->string('verdict', 16);
                $t->string('class', 40)->nullable();
                $t->string('tier', 16)->nullable();
                $t->smallInteger('score')->default(0);
                $t->string('source', 16)->default('detected');
                $t->string('detected_class', 40)->nullable();
                $t->smallInteger('detected_score')->nullable();
                $t->text('evidence')->nullable();
                $t->text('examples')->nullable();
                $t->unsignedInteger('decided_by_id')->nullable();
                $t->string('decided_by', 255)->nullable();
                $t->timestamp('decided_at')->nullable();
                $t->timestamp('scanned_at')->nullable();
                $t->string('ruleset_version', 32)->nullable();
                $t->string('fingerprint', 64)->nullable();
                $t->integer('ordinal')->nullable();
                $t->timestamps();

                $t->unique(['service_id', 'table_name', 'column_name'], 'dm_column_svc_tbl_col_unique');
                $t->index(['service_id', 'verdict'], 'dm_column_svc_verdict_index');
                $t->foreign('service_id', 'dm_column_service_fk')->references('id')->on('service')->onDelete('cascade');
            });
        }

        if (!Schema::hasTable('dm_mask_format')) {
            Schema::create('dm_mask_format', function (Blueprint $t) {
                $t->string('class', 40)->primary();
                $t->string('format', 16);
                $t->string('updated_by', 255)->nullable();
                $t->timestamp('updated_at')->nullable();
            });
        }

        if (!Schema::hasTable('dm_rule')) {
            Schema::create('dm_rule', function (Blueprint $t) {
                $t->increments('id');
                $t->string('match', 8);
                $t->string('pattern', 500);
                $t->string('class', 40);
                $t->string('source', 40)->default('admin');
                $t->string('created_by', 255)->nullable();
                $t->timestamps();

                $t->index('source', 'dm_rule_source_index');
            });
        }

        if (!Schema::hasTable('dm_admin_grant')) {
            Schema::create('dm_admin_grant', function (Blueprint $t) {
                $t->increments('id');
                $t->unsignedInteger('admin_id');
                $t->timestamp('expires_at')->nullable();
                $t->unsignedInteger('granted_by_id')->nullable();
                $t->timestamps();

                $t->unique('admin_id', 'dm_admin_grant_admin_unique');
                $t->foreign('admin_id', 'dm_admin_grant_user_fk')->references('id')->on('user')->onDelete('cascade');
            });
        }

        if (!Schema::hasTable('dm_role_access')) {
            Schema::create('dm_role_access', function (Blueprint $t) {
                $t->unsignedInteger('role_id')->primary();
                $t->boolean('enabled')->default(false);
                $t->string('scope', 24)->default('except_restricted');
                $t->string('updated_by', 255)->nullable();
                $t->timestamp('updated_at')->nullable();

                $t->foreign('role_id', 'dm_role_access_role_fk')->references('id')->on('role')->onDelete('cascade');
            });
        }

        if (!Schema::hasTable('dm_activity')) {
            Schema::create('dm_activity', function (Blueprint $t) {
                $t->bigIncrements('id');
                $t->timestamp('created_at')->nullable()->index('dm_activity_created_index');
                $t->string('actor', 255);
                $t->unsignedInteger('actor_id')->nullable();
                $t->string('kind', 16)->index('dm_activity_kind_index');
                $t->string('text', 500);
                $t->string('target', 255)->nullable();
                $t->text('meta')->nullable();
            });
        }

        if (!Schema::hasTable('dm_scan')) {
            Schema::create('dm_scan', function (Blueprint $t) {
                $t->increments('id');
                // No foreign key: scan history outlives the service (SQL Server also rejects a
                // second SET NULL path onto service).
                $t->unsignedInteger('service_id')->nullable();
                $t->string('status', 16);
                $t->smallInteger('progress')->default(0);
                $t->integer('columns_total')->default(0);
                $t->integer('columns_done')->default(0);
                $t->timestamp('started_at')->nullable();
                $t->timestamp('finished_at')->nullable();
                $t->string('error', 1000)->nullable();
                $t->integer('pid')->nullable();
                $t->string('triggered_by', 255)->nullable();
                $t->timestamps();

                $t->index('status', 'dm_scan_status_index');
            });
        }
    }

    public function down(): void
    {
        foreach (['dm_scan', 'dm_activity', 'dm_role_access', 'dm_admin_grant', 'dm_rule', 'dm_mask_format', 'dm_column', 'dm_setting'] as $table) {
            Schema::dropIfExists($table);
        }
        $this->invalidateCache();
    }

    /** Settings::invalidateCache() when the package classes are loadable (never fails a migration). */
    private function invalidateCache(): void
    {
        $settings = 'DreamFactory\\Core\\Masking\\Support\\Settings';
        try {
            if (class_exists($settings) && method_exists($settings, 'invalidateCache')) {
                $settings::invalidateCache();
            }
        } catch (\Throwable $e) {
            // no cache store: nothing cached
        }
    }
};

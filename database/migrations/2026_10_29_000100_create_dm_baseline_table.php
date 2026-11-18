<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * dm_baseline: which Compliance baselines an instance has adopted (tracks them on the
 * Compliance page and in evidence reports). One row per adopted baseline; deleting a row only
 * stops tracking, the settings a baseline applied stay as they are.
 *
 * Portable across the system databases DreamFactory supports; `last_status` holds JSON text
 * (score and change ids of the last Apply), never data values.
 */
return new class extends Migration {
    public function up(): void
    {
        if (Schema::hasTable('dm_baseline')) {
            return;
        }

        Schema::create('dm_baseline', function (Blueprint $t) {
            $t->string('baseline_id', 40)->primary();
            $t->timestamp('adopted_at')->nullable();
            $t->string('adopted_by', 255)->nullable();
            $t->timestamp('applied_at')->nullable();
            $t->text('last_status')->nullable();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('dm_baseline');
        // The first migration a rollback runs: drop the cached df-masking settings and bump the
        // policy version before the other tables go (the create migration does it again after).
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

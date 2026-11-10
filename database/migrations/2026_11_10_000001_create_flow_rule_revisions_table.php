<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Every rules script WireTier applies to a network, so a bad change can
        // be reviewed and rolled back. The controller keeps no history.
        Schema::create('flow_rule_revisions', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignUuid('zerotier_network_id')->index();
            $table->uuid('user_id')->nullable();
            $table->text('source');
            $table->json('meta')->nullable();
            $table->string('hash', 64);
            $table->unsignedSmallInteger('rule_count');
            $table->unsignedSmallInteger('capability_count');
            $table->unsignedSmallInteger('tag_count');
            $table->timestamp('created_at')->nullable();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('flow_rule_revisions');
    }
};

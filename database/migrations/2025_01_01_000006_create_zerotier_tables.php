<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('zerotier_tokens', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignUuid('team_id');
            $table->string('name');
            $table->text('token');
            $table->string('host')->default('http://localhost:9993');
            $table->boolean('is_active')->default(true);
            $table->string('node_address')->nullable();
            $table->timestamps();

            $table->index('team_id');
        });

        Schema::create('zerotier_networks', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignUuid('team_id');
            $table->foreignUuid('zerotier_token_id');
            $table->string('network_id');
            $table->string('name')->nullable();
            $table->text('description')->nullable();
            $table->boolean('private')->default(true);
            $table->json('config')->nullable();
            $table->timestamps();

            $table->index('team_id');
            $table->index('zerotier_token_id');
            $table->unique(['zerotier_token_id', 'network_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('zerotier_networks');
        Schema::dropIfExists('zerotier_tokens');
    }
};

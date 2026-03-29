<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('zerotier_members', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignUuid('zerotier_network_id');
            $table->string('node_id', 10);
            $table->string('name')->nullable();
            $table->boolean('authorised')->default(false);
            $table->boolean('active_bridge')->default(false);
            $table->boolean('no_auto_assign_ips')->default(false);
            $table->json('ip_assignments')->nullable();
            $table->timestamp('last_seen')->nullable();
            $table->string('client_version')->nullable();
            $table->boolean('is_online')->default(false);
            $table->integer('latency')->default(-1);
            $table->string('physical_address')->nullable();
            $table->timestamp('synced_at')->nullable();
            $table->timestamps();

            $table->unique(['zerotier_network_id', 'node_id']);
            $table->index('zerotier_network_id');
        });

        Schema::table('zerotier_networks', function (Blueprint $table) {
            $table->timestamp('synced_at')->nullable()->after('config');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('zerotier_members');

        Schema::table('zerotier_networks', function (Blueprint $table) {
            $table->dropColumn('synced_at');
        });
    }
};

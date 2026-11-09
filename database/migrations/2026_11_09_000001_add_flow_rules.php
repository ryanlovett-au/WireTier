<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('zerotier_networks', function (Blueprint $table) {
            // The controller only stores compiled rules, so the human-readable
            // script and the names it defines (capabilities, tags, enums,
            // flags) are kept here.
            $table->text('rules_source')->nullable()->after('config');
            $table->json('rules_meta')->nullable()->after('rules_source');
            // Fingerprint of the compiled rules the controller returned when
            // WireTier last applied them; a mismatch with the live config
            // means the rules were changed outside WireTier.
            $table->string('rules_hash', 64)->nullable()->after('rules_meta');
            $table->timestamp('rules_updated_at')->nullable()->after('rules_hash');
        });

        Schema::table('zerotier_members', function (Blueprint $table) {
            $table->json('capabilities')->nullable()->after('ip_assignments');
            $table->json('tags')->nullable()->after('capabilities');
        });

        // Force the next sync to re-fetch every member's full config so the new
        // capabilities/tags columns are populated (unchanged revisions skip it).
        DB::table('zerotier_members')->update(['revision' => null]);
    }

    public function down(): void
    {
        Schema::table('zerotier_members', function (Blueprint $table) {
            $table->dropColumn(['capabilities', 'tags']);
        });

        Schema::table('zerotier_networks', function (Blueprint $table) {
            $table->dropColumn(['rules_source', 'rules_meta', 'rules_hash', 'rules_updated_at']);
        });
    }
};

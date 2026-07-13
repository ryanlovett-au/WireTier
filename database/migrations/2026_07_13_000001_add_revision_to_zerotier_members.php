<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('zerotier_members', function (Blueprint $table) {
            // Controller config revision for this member. Lets the sync skip the
            // per-member detail fetch when a member's config is unchanged.
            $table->unsignedBigInteger('revision')->nullable()->after('client_version');
        });
    }

    public function down(): void
    {
        Schema::table('zerotier_members', function (Blueprint $table) {
            $table->dropColumn('revision');
        });
    }
};

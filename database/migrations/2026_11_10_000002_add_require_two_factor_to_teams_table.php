<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('teams', function (Blueprint $table) {
            // Set by a team admin: members must have two-factor
            // authentication enabled before they can use the team.
            $table->boolean('require_two_factor')->default(false)->after('colour');
        });
    }

    public function down(): void
    {
        Schema::table('teams', function (Blueprint $table) {
            $table->dropColumn('require_two_factor');
        });
    }
};

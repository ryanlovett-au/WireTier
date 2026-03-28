<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('team_users', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignUuid('team_id');
            $table->foreignUuid('user_id');
            $table->string('role')->default('member');
            $table->date('expires')->nullable();
            $table->timestamps();

            $table->unique(['team_id', 'user_id']);
            $table->index('team_id');
            $table->index('user_id');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('team_users');
    }
};

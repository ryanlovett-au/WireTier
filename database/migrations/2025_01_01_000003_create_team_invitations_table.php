<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('team_invitations', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignUuid('team_id');
            $table->string('email');
            $table->string('role')->default('member');
            $table->date('expires')->nullable();
            $table->foreignId('referer')->nullable();
            $table->timestamps();

            $table->index('email');
            $table->index('team_id');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('team_invitations');
    }
};

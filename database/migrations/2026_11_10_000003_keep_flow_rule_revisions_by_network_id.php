<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // History follows the ZeroTier network ID, so a network released by a
        // deleted team gets its scripts back when it is imported again. While
        // released, zerotier_network_id is null.
        Schema::table('flow_rule_revisions', function (Blueprint $table) {
            $table->string('network_id', 16)->nullable()->after('zerotier_network_id')->index();
            $table->uuid('zerotier_network_id')->nullable()->change();
        });

        foreach (DB::table('zerotier_networks')->whereIn('id', DB::table('flow_rule_revisions')->select('zerotier_network_id'))->get(['id', 'network_id']) as $network) {
            DB::table('flow_rule_revisions')->where('zerotier_network_id', $network->id)->update(['network_id' => $network->network_id]);
        }
    }

    public function down(): void
    {
        DB::table('flow_rule_revisions')->whereNull('zerotier_network_id')->delete();

        Schema::table('flow_rule_revisions', function (Blueprint $table) {
            $table->uuid('zerotier_network_id')->nullable(false)->change();
            $table->dropIndex(['network_id']);
            $table->dropColumn('network_id');
        });
    }
};

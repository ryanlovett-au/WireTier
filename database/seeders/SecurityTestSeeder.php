<?php

namespace Database\Seeders;

use App\Models\Team;
use App\Models\TeamPermission;
use App\Models\TeamUser;
use App\Models\User;
use App\Models\ZerotierNetwork;
use App\Models\ZerotierToken;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;

class SecurityTestSeeder extends Seeder
{
    // Deterministic UUIDs for test references
    const ALPHA_TEAM_ID = '01961111-aaaa-7000-aaaa-aaaaaaaaaaaa';
    const BETA_TEAM_ID = '01961111-bbbb-7000-bbbb-bbbbbbbbbbbb';
    const ADMIN_TEAM_ID = '01961111-0000-7000-0000-000000000000';

    const ALPHA_TOKEN_ID = '01962222-aaaa-7000-aaaa-aaaaaaaaaaaa';
    const BETA_TOKEN_ID = '01962222-bbbb-7000-bbbb-bbbbbbbbbbbb';

    const ALPHA_NETWORK_ID = 'aaaa000001______';
    const BETA_NETWORK_ID = 'bbbb000001______';

    public function run(): void
    {
        // Use raw DB inserts for models with deterministic UUIDs
        // (their creating() hooks auto-generate UUIDs, overriding what we set)

        $now = now();

        // ─── Admin Team ───────────────────────────────────────────────
        DB::table('teams')->insert([
            'id' => self::ADMIN_TEAM_ID,
            'name' => 'Security Test Admin Team',
            'icon' => 'shield-check',
            'colour' => 'red',
            'created_at' => $now,
            'updated_at' => $now,
        ]);

        config(['laratier.admin_team' => self::ADMIN_TEAM_ID]);

        $superAdmin = User::factory()->create([
            'name' => 'Super Admin',
            'email' => 'superadmin@security-test.local',
            'current_team' => self::ADMIN_TEAM_ID,
        ]);

        TeamUser::create([
            'team_id' => self::ADMIN_TEAM_ID,
            'user_id' => $superAdmin->id,
            'role' => 'admin',
        ]);

        // ─── Team Alpha ──────────────────────────────────────────────
        DB::table('teams')->insert([
            'id' => self::ALPHA_TEAM_ID,
            'name' => 'Team Alpha',
            'icon' => 'users',
            'colour' => 'blue',
            'created_at' => $now,
            'updated_at' => $now,
        ]);

        $alphaAdmin = User::factory()->create([
            'name' => 'Alpha Admin',
            'email' => 'alpha-admin@security-test.local',
            'current_team' => self::ALPHA_TEAM_ID,
        ]);
        TeamUser::create(['team_id' => self::ALPHA_TEAM_ID, 'user_id' => $alphaAdmin->id, 'role' => 'admin']);

        $alphaMember = User::factory()->create([
            'name' => 'Alpha Member',
            'email' => 'alpha-member@security-test.local',
            'current_team' => self::ALPHA_TEAM_ID,
        ]);
        TeamUser::create(['team_id' => self::ALPHA_TEAM_ID, 'user_id' => $alphaMember->id, 'role' => 'member']);

        $alphaViewer = User::factory()->create([
            'name' => 'Alpha Viewer',
            'email' => 'alpha-viewer@security-test.local',
            'current_team' => self::ALPHA_TEAM_ID,
        ]);
        TeamUser::create(['team_id' => self::ALPHA_TEAM_ID, 'user_id' => $alphaViewer->id, 'role' => 'viewer']);

        // Alpha permissions
        foreach (['manage_networks', 'create_networks', 'delete_networks', 'manage_members', 'manage_tokens', 'view_peers'] as $perm) {
            TeamPermission::create(['team_id' => self::ALPHA_TEAM_ID, 'permission' => $perm]);
        }

        // Alpha ZeroTier token (needs deterministic ID — use raw insert)
        DB::table('zerotier_tokens')->insert([
            'id' => self::ALPHA_TOKEN_ID,
            'team_id' => self::ALPHA_TEAM_ID,
            'name' => 'Alpha Controller',
            'token' => encrypt('fake-alpha-token-for-security-testing'),
            'host' => 'http://localhost:9993',
            'is_active' => true,
            'node_address' => 'aaaa000001',
            'created_at' => $now,
            'updated_at' => $now,
        ]);

        // Alpha ZeroTier network
        ZerotierNetwork::create([
            'team_id' => self::ALPHA_TEAM_ID,
            'zerotier_token_id' => self::ALPHA_TOKEN_ID,
            'network_id' => self::ALPHA_NETWORK_ID,
            'name' => 'Alpha Private Net',
            'private' => true,
        ]);

        // ─── Team Beta ───────────────────────────────────────────────
        DB::table('teams')->insert([
            'id' => self::BETA_TEAM_ID,
            'name' => 'Team Beta',
            'icon' => 'users',
            'colour' => 'green',
            'created_at' => $now,
            'updated_at' => $now,
        ]);

        $betaAdmin = User::factory()->create([
            'name' => 'Beta Admin',
            'email' => 'beta-admin@security-test.local',
            'current_team' => self::BETA_TEAM_ID,
        ]);
        TeamUser::create(['team_id' => self::BETA_TEAM_ID, 'user_id' => $betaAdmin->id, 'role' => 'admin']);

        $betaMember = User::factory()->create([
            'name' => 'Beta Member',
            'email' => 'beta-member@security-test.local',
            'current_team' => self::BETA_TEAM_ID,
        ]);
        TeamUser::create(['team_id' => self::BETA_TEAM_ID, 'user_id' => $betaMember->id, 'role' => 'member']);

        // Beta permissions (limited — no delete_networks or manage_tokens)
        foreach (['manage_networks', 'create_networks', 'manage_members', 'view_peers'] as $perm) {
            TeamPermission::create(['team_id' => self::BETA_TEAM_ID, 'permission' => $perm]);
        }

        // Beta ZeroTier token (needs deterministic ID — use raw insert)
        DB::table('zerotier_tokens')->insert([
            'id' => self::BETA_TOKEN_ID,
            'team_id' => self::BETA_TEAM_ID,
            'name' => 'Beta Controller',
            'token' => encrypt('fake-beta-token-for-security-testing'),
            'host' => 'http://localhost:9994',
            'is_active' => true,
            'node_address' => 'bbbb000001',
            'created_at' => $now,
            'updated_at' => $now,
        ]);

        // Beta ZeroTier network
        ZerotierNetwork::create([
            'team_id' => self::BETA_TEAM_ID,
            'zerotier_token_id' => self::BETA_TOKEN_ID,
            'network_id' => self::BETA_NETWORK_ID,
            'name' => 'Beta Private Net',
            'private' => true,
        ]);

        // ─── Orphan User (no team) ──────────────────────────────────
        User::factory()->create([
            'name' => 'Orphan User',
            'email' => 'orphan@security-test.local',
            'current_team' => null,
        ]);
    }
}

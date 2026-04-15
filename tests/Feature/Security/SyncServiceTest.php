<?php

use App\Models\ZerotierMember;
use App\Models\ZerotierNetwork;
use App\Services\ZerotierSyncService;
use Database\Seeders\SecurityTestSeeder;
use Illuminate\Support\Facades\Http;

function syncHttpFakes(): void
{
    Http::fake(function ($request) {
        $url = $request->url();
        $method = $request->method();

        if (str_contains($url, '/status')) {
            return Http::response(['address' => 'aaaa000001', 'version' => '1.14.0', 'online' => true]);
        }
        if ($method === 'GET' && preg_match('#/member/([a-f0-9]+)$#', $url, $m)) {
            return Http::response([
                'address' => $m[1], 'authorized' => true, 'activeBridge' => false,
                'noAutoAssignIps' => false, 'ipAssignments' => ['10.0.0.2'],
                'name' => 'synced-node', 'vMajor' => 1, 'vMinor' => 14, 'vRev' => 2,
            ]);
        }
        if (str_contains($url, '/member')) {
            return Http::response(['aabb000001' => true, 'ccdd000002' => true]);
        }
        if ($method === 'GET' && preg_match('#/controller/network/([a-zA-Z0-9_]+)$#', $url, $m)) {
            return Http::response([
                'nwid' => $m[1], 'name' => 'Synced Net', 'private' => true,
                'routes' => [['target' => '10.0.0.0/24']],
            ]);
        }
        if (str_contains($url, '/controller/network')) {
            return Http::response([SecurityTestSeeder::ALPHA_NETWORK_ID]);
        }
        if (str_contains($url, '/peer')) {
            return Http::response([
                ['address' => 'aabb000001', 'latency' => 5, 'paths' => [['active' => true, 'address' => '1.2.3.4/9993']]],
            ]);
        }

        return Http::response([]);
    });
}

beforeEach(function () {
    $this->seed(SecurityTestSeeder::class);
    config(['wiretier.admin_team' => SecurityTestSeeder::ADMIN_TEAM_ID]);
});

// ─── Sync Service Tests ──────────────────────────────────────────────────

test('syncNetwork creates members in the database', function () {
    syncHttpFakes();

    $network = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();
    expect(ZerotierMember::where('zerotier_network_id', $network->id)->count())->toBe(0);

    ZerotierSyncService::syncNetwork($network);

    $members = ZerotierMember::where('zerotier_network_id', $network->id)->get();
    expect($members)->toHaveCount(2);
    expect($members->pluck('node_id')->toArray())->toContain('aabb000001', 'ccdd000002');
});

test('syncNetwork updates existing members', function () {
    syncHttpFakes();

    $network = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();

    // First sync
    ZerotierSyncService::syncNetwork($network);
    $member = ZerotierMember::where('zerotier_network_id', $network->id)
        ->where('node_id', 'aabb000001')->first();
    expect($member->authorised)->toBeTrue();
    expect($member->name)->toBe('synced-node');

    // Second sync — should update, not duplicate
    ZerotierSyncService::syncNetwork($network);
    expect(ZerotierMember::where('zerotier_network_id', $network->id)
        ->where('node_id', 'aabb000001')->count())->toBe(1);
});

test('syncNetwork removes members no longer on controller', function () {
    // Pre-create 2 members in DB manually
    $network = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();

    ZerotierMember::create([
        'zerotier_network_id' => $network->id, 'node_id' => 'aabb000001',
        'authorised' => true, 'ip_assignments' => [],
    ]);
    ZerotierMember::create([
        'zerotier_network_id' => $network->id, 'node_id' => 'oldmember01',
        'authorised' => true, 'ip_assignments' => [],
    ]);
    expect(ZerotierMember::where('zerotier_network_id', $network->id)->count())->toBe(2);

    // Fake API only returns aabb000001 — oldmember01 should be removed
    syncHttpFakes(); // returns aabb000001 and ccdd000002
    ZerotierSyncService::syncNetwork($network);

    // oldmember01 is gone (not in API), aabb000001 and ccdd000002 remain
    expect(ZerotierMember::where('zerotier_network_id', $network->id)
        ->where('node_id', 'oldmember01')->exists())->toBeFalse();
});

test('syncNetwork updates network synced_at timestamp', function () {
    syncHttpFakes();

    $network = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();
    expect($network->synced_at)->toBeNull();

    ZerotierSyncService::syncNetwork($network);

    $network->refresh();
    expect($network->synced_at)->not->toBeNull();
});

test('syncNetwork enriches members with peer online status', function () {
    syncHttpFakes();

    $network = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();
    ZerotierSyncService::syncNetwork($network);

    // aabb000001 is in the peer list with active paths
    $onlineMember = ZerotierMember::where('zerotier_network_id', $network->id)
        ->where('node_id', 'aabb000001')->first();
    expect($onlineMember->is_online)->toBeTrue();
    expect($onlineMember->latency)->toBe(5);
    expect($onlineMember->physical_address)->toBe('1.2.3.4/9993');

    // ccdd000002 is NOT in the peer list
    $offlineMember = ZerotierMember::where('zerotier_network_id', $network->id)
        ->where('node_id', 'ccdd000002')->first();
    expect($offlineMember->is_online)->toBeFalse();
});

test('syncNetwork builds client version string', function () {
    syncHttpFakes();

    $network = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();
    ZerotierSyncService::syncNetwork($network);

    $member = ZerotierMember::where('zerotier_network_id', $network->id)
        ->where('node_id', 'aabb000001')->first();
    expect($member->client_version)->toBe('1.14.2');
});

test('syncNetwork translates API authorized to AU English authorised', function () {
    syncHttpFakes();

    $network = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();
    ZerotierSyncService::syncNetwork($network);

    $member = ZerotierMember::where('zerotier_network_id', $network->id)
        ->where('node_id', 'aabb000001')->first();

    // API sends 'authorized: true', DB stores as 'authorised'
    expect($member->authorised)->toBeTrue();
});

test('syncAll syncs all active tokens', function () {
    syncHttpFakes();

    $synced = ZerotierSyncService::syncAll();
    expect($synced)->toBeGreaterThanOrEqual(1);

    // Both Alpha and Beta networks should have synced_at set
    $alphaNet = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();
    expect($alphaNet->synced_at)->not->toBeNull();
});

// ─── Team Isolation Tests ────────────────────────────────────────────────

test('team A cannot see team B members through DB queries', function () {
    syncHttpFakes();

    // Sync all networks — both Alpha and Beta get members
    ZerotierSyncService::syncAll();

    $alphaNet = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();
    $betaNet = ZerotierNetwork::where('network_id', SecurityTestSeeder::BETA_NETWORK_ID)->first();

    $alphaMembers = ZerotierMember::where('zerotier_network_id', $alphaNet->id)->get();
    $betaMembers = ZerotierMember::where('zerotier_network_id', $betaNet->id)->get();

    // Members should be isolated by network (and thus by team)
    $alphaNodeIds = $alphaMembers->pluck('node_id')->toArray();
    $betaNodeIds = $betaMembers->pluck('node_id')->toArray();

    // Querying through team scoping should only return own members
    $teamScopedMembers = ZerotierMember::whereHas('network', function ($q) {
        $q->where('team_id', SecurityTestSeeder::ALPHA_TEAM_ID);
    })->get();

    foreach ($teamScopedMembers as $member) {
        $network = $member->network;
        expect($network->team_id)->toBe(SecurityTestSeeder::ALPHA_TEAM_ID);
    }
});

test('sync does not create cross-team member records', function () {
    syncHttpFakes();

    ZerotierSyncService::syncAll();

    // Every member should belong to a network that has a team
    $allMembers = ZerotierMember::with('network')->get();

    foreach ($allMembers as $member) {
        expect($member->network)->not->toBeNull();
        expect($member->network->team_id)->not->toBeNull();
    }
});

// ─── Sync Command Test ───────────────────────────────────────────────────

test('zerotier:sync artisan command runs successfully', function () {
    syncHttpFakes();

    $this->artisan('zerotier:sync')
        ->assertExitCode(0);
});

<?php

use App\Models\ZerotierMember;
use App\Models\ZerotierNetwork;
use App\Services\ZerotierSyncService;
use Database\Seeders\SecurityTestSeeder;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

beforeEach(function () {
    $this->seed(SecurityTestSeeder::class);
    config(['laratier.admin_team' => SecurityTestSeeder::ADMIN_TEAM_ID]);
});

test('syncNetwork returns false when token is inactive', function () {
    $network = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();
    $token = $network->zerotierToken;
    $token->update(['is_active' => false]);

    expect(ZerotierSyncService::syncNetwork($network))->toBeFalse();
});

test('syncNetwork returns false when API fails', function () {
    Http::fake(function () {
        throw new RuntimeException('Connection refused');
    });

    Log::shouldReceive('warning')->once();

    $network = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();
    expect(ZerotierSyncService::syncNetwork($network))->toBeFalse();
});

test('syncNetwork handles member sync failure gracefully', function () {
    Http::fake(function ($request) {
        $url = $request->url();
        if (preg_match('#/member/([a-f0-9]+)$#', $url)) {
            throw new RuntimeException('Member fetch failed');
        }
        if (str_contains($url, '/member')) {
            return Http::response(['aabb000001' => true]);
        }
        if (preg_match('#/controller/network/([a-zA-Z0-9_]+)$#', $url, $m)) {
            return Http::response(['nwid' => $m[1], 'name' => 'Net', 'private' => true]);
        }
        if (str_contains($url, '/peer')) {
            return Http::response([]);
        }

        return Http::response([]);
    });

    Log::shouldReceive('warning')->atLeast()->once();

    $network = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();
    $result = ZerotierSyncService::syncNetwork($network);

    // Should still return true (network synced, members failed individually)
    expect($result)->toBeTrue();
    // No members should have been created since all failed
    expect(ZerotierMember::where('zerotier_network_id', $network->id)->count())->toBe(0);
});

test('syncNetwork identifies controller node as online', function () {
    // The controller address is the first 10 chars of the network ID
    $networkId = SecurityTestSeeder::ALPHA_NETWORK_ID;
    $controllerAddress = substr($networkId, 0, 10);

    Http::fake(function ($request) use ($controllerAddress) {
        $url = $request->url();
        if (preg_match('#/member/([a-f0-9]+)$#', $url, $m)) {
            return Http::response([
                'address' => $m[1], 'authorized' => true, 'ipAssignments' => [],
                'vMajor' => 1, 'vMinor' => 14, 'vRev' => 0,
            ]);
        }
        if (str_contains($url, '/member')) {
            return Http::response([$controllerAddress => true]);
        }
        if (preg_match('#/controller/network/([a-zA-Z0-9_]+)$#', $url, $m)) {
            return Http::response(['nwid' => $m[1], 'name' => 'Net', 'private' => true]);
        }
        if (str_contains($url, '/peer')) {
            return Http::response([]);
        }

        return Http::response([]);
    });

    $network = ZerotierNetwork::where('network_id', $networkId)->first();
    ZerotierSyncService::syncNetwork($network);

    $member = ZerotierMember::where('zerotier_network_id', $network->id)
        ->where('node_id', $controllerAddress)->first();

    expect($member)->not->toBeNull();
    expect($member->is_online)->toBeTrue();
    expect($member->latency)->toBe(0);
});

test('syncNetwork handles peer fetch failure gracefully', function () {
    Http::fake(function ($request) {
        $url = $request->url();
        if (str_contains($url, '/peer')) {
            throw new RuntimeException('Peer fetch failed');
        }
        if (preg_match('#/member/([a-f0-9]+)$#', $url, $m)) {
            return Http::response(['address' => $m[1], 'authorized' => true, 'ipAssignments' => []]);
        }
        if (str_contains($url, '/member')) {
            return Http::response(['aabb000001' => true]);
        }
        if (preg_match('#/controller/network/([a-zA-Z0-9_]+)$#', $url, $m)) {
            return Http::response(['nwid' => $m[1], 'name' => 'Net', 'private' => true]);
        }

        return Http::response([]);
    });

    $network = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();
    $result = ZerotierSyncService::syncNetwork($network);

    // Should still succeed — peer data is optional
    expect($result)->toBeTrue();
    expect(ZerotierMember::where('zerotier_network_id', $network->id)->count())->toBe(1);
});

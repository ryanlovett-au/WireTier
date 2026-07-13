<?php

use App\Models\ZerotierMember;
use App\Models\ZerotierNetwork;
use App\Services\ZerotierSyncService;
use Database\Seeders\SecurityTestSeeder;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;

beforeEach(function () {
    $this->seed(SecurityTestSeeder::class);
    config(['wiretier.admin_team' => SecurityTestSeeder::ADMIN_TEAM_ID]);
});

/** Fake responses for a healthy single-member sync of the given network. */
function fakeHealthyController(): void
{
    Http::fake(function ($request) {
        $url = $request->url();
        if (preg_match('#/member/([a-f0-9]+)$#', $url, $m)) {
            return Http::response(['address' => $m[1], 'authorized' => true, 'ipAssignments' => []]);
        }
        if (str_contains($url, '/member')) {
            return Http::response(['dddd000001' => true]);
        }
        if (preg_match('#/controller/network/([a-zA-Z0-9_]+)$#', $url, $m)) {
            return Http::response(['nwid' => $m[1], 'name' => 'Net', 'private' => true]);
        }

        return Http::response([]);
    });
}

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

test('syncNetwork does not wipe members when the member list fetch fails', function () {
    $network = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();

    // Two members from a previous good sync already in the DB.
    ZerotierMember::create(['zerotier_network_id' => $network->id, 'node_id' => 'dddd000001', 'authorised' => true]);
    ZerotierMember::create(['zerotier_network_id' => $network->id, 'node_id' => 'eeee000001', 'authorised' => true]);

    Http::fake(function ($request) {
        $url = $request->url();
        // The member list endpoint fails (transient error / rate limit).
        if (str_contains($url, '/member')) {
            return Http::response('error', 500);
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

    $result = ZerotierSyncService::syncNetwork($network);

    // A failed list fetch must abort without touching existing members.
    expect($result)->toBeFalse();
    expect(ZerotierMember::where('zerotier_network_id', $network->id)->count())->toBe(2);
});

test('syncNetwork preserves a member whose detail fetch fails but is still listed', function () {
    $network = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();

    ZerotierMember::create([
        'zerotier_network_id' => $network->id,
        'node_id' => 'dddd000001',
        'name' => 'Existing Device',
        'authorised' => true,
    ]);

    Http::fake(function ($request) {
        $url = $request->url();
        // The controller still lists the member, but its detail fetch is rate limited.
        if (preg_match('#/member/([a-f0-9]+)$#', $url)) {
            return Http::response('rate limited', 429);
        }
        if (str_contains($url, '/member')) {
            return Http::response(['dddd000001' => true]);
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

    $result = ZerotierSyncService::syncNetwork($network);

    expect($result)->toBeTrue();

    // The member is still on the controller, so it must survive even though we
    // couldn't refresh its details — the stale row stays intact.
    $member = ZerotierMember::where('zerotier_network_id', $network->id)
        ->where('node_id', 'dddd000001')->first();
    expect($member)->not->toBeNull();
    expect($member->name)->toBe('Existing Device');
});

test('syncNetwork removes members the controller no longer lists', function () {
    $network = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();

    ZerotierMember::create(['zerotier_network_id' => $network->id, 'node_id' => 'dddd000001', 'authorised' => true]);
    ZerotierMember::create(['zerotier_network_id' => $network->id, 'node_id' => 'eeee000001', 'authorised' => true]);

    Http::fake(function ($request) {
        $url = $request->url();
        if (preg_match('#/member/([a-f0-9]+)$#', $url, $m)) {
            return Http::response(['address' => $m[1], 'authorized' => true, 'ipAssignments' => []]);
        }
        // Controller now reports only dddd000001 — eeee000001 has genuinely left.
        if (str_contains($url, '/member')) {
            return Http::response(['dddd000001' => true]);
        }
        if (preg_match('#/controller/network/([a-zA-Z0-9_]+)$#', $url, $m)) {
            return Http::response(['nwid' => $m[1], 'name' => 'Net', 'private' => true]);
        }
        if (str_contains($url, '/peer')) {
            return Http::response([]);
        }

        return Http::response([]);
    });

    ZerotierSyncService::syncNetwork($network);

    // Legitimate reconciliation still prunes departed members.
    expect(ZerotierMember::where('zerotier_network_id', $network->id)->where('node_id', 'eeee000001')->exists())->toBeFalse();
    expect(ZerotierMember::where('zerotier_network_id', $network->id)->where('node_id', 'dddd000001')->exists())->toBeTrue();
});

test('syncNetwork skips the detail fetch when a member revision is unchanged', function () {
    $network = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();

    // Member already synced at revision 7.
    ZerotierMember::create([
        'zerotier_network_id' => $network->id,
        'node_id' => 'dddd000001',
        'name' => 'Cached Name',
        'authorised' => true,
        'revision' => 7,
    ]);

    $detailCalls = 0;
    Http::fake(function ($request) use (&$detailCalls) {
        $url = $request->url();
        if (preg_match('#/member/([a-f0-9]+)$#', $url, $m)) {
            $detailCalls++;

            return Http::response(['address' => $m[1], 'authorized' => true, 'name' => 'CHANGED', 'revision' => 7]);
        }
        if (str_contains($url, '/member')) {
            return Http::response(['dddd000001' => 7]); // unchanged revision
        }
        if (preg_match('#/controller/network/([a-zA-Z0-9_]+)$#', $url, $m)) {
            return Http::response(['nwid' => $m[1], 'name' => 'Net', 'private' => true]);
        }
        if (str_contains($url, '/peer')) {
            return Http::response([
                ['address' => 'dddd000001', 'latency' => 12, 'paths' => [['active' => true, 'address' => '9.9.9.9/1']]],
            ]);
        }

        return Http::response([]);
    });

    ZerotierSyncService::syncNetwork($network);

    // No per-member detail request was made...
    expect($detailCalls)->toBe(0);

    $member = ZerotierMember::where('zerotier_network_id', $network->id)->where('node_id', 'dddd000001')->first();
    // ...so config is left as-is...
    expect($member->name)->toBe('Cached Name');
    // ...but volatile runtime state is still refreshed from the single peer call.
    expect($member->is_online)->toBeTrue();
    expect($member->latency)->toBe(12);
});

test('syncNetwork re-fetches a member when its revision changes', function () {
    $network = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();

    ZerotierMember::create([
        'zerotier_network_id' => $network->id,
        'node_id' => 'dddd000001',
        'name' => 'Old Name',
        'authorised' => false,
        'revision' => 7,
    ]);

    Http::fake(function ($request) {
        $url = $request->url();
        if (preg_match('#/member/([a-f0-9]+)$#', $url, $m)) {
            return Http::response(['address' => $m[1], 'authorized' => true, 'name' => 'New Name', 'revision' => 8]);
        }
        if (str_contains($url, '/member')) {
            return Http::response(['dddd000001' => 8]); // bumped revision
        }
        if (preg_match('#/controller/network/([a-zA-Z0-9_]+)$#', $url, $m)) {
            return Http::response(['nwid' => $m[1], 'name' => 'Net', 'private' => true]);
        }

        return Http::response([]);
    });

    ZerotierSyncService::syncNetwork($network);

    $member = ZerotierMember::where('zerotier_network_id', $network->id)->where('node_id', 'dddd000001')->first();
    expect($member->name)->toBe('New Name');
    expect($member->authorised)->toBeTrue();
    expect($member->revision)->toBe(8);
});

test('syncNetwork debounces an interactive sync within the window', function () {
    config(['wiretier.sync_debounce_seconds' => 30]);

    $network = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();
    $network->update(['synced_at' => now()]);

    Http::fake();

    // A recently-synced network is a no-op — the controller is never touched.
    $result = ZerotierSyncService::syncNetwork($network);

    expect($result)->toBeTrue();
    Http::assertNothingSent();
});

test('syncNetwork force bypasses the debounce', function () {
    config(['wiretier.sync_debounce_seconds' => 30]);

    $network = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();
    $network->update(['synced_at' => now()]);

    fakeHealthyController();

    ZerotierSyncService::syncNetwork($network, force: true);

    // A forced sync (e.g. after a member mutation) runs despite the debounce.
    expect(ZerotierMember::where('zerotier_network_id', $network->id)->where('node_id', 'dddd000001')->exists())->toBeTrue();
});

test('system sync is not throttled by the interactive rate limiter', function () {
    // Saturate the interactive bucket so an interactive call would be rejected.
    for ($i = 0; $i < 120; $i++) {
        RateLimiter::hit('zt_api:system', 60);
    }

    $network = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();

    fakeHealthyController();

    $result = ZerotierSyncService::syncNetwork($network, system: true);

    // The trusted background sync bypasses the limiter and completes.
    expect($result)->toBeTrue();
    expect(ZerotierMember::where('zerotier_network_id', $network->id)->where('node_id', 'dddd000001')->exists())->toBeTrue();
});

test('interactive sync is still throttled by the rate limiter', function () {
    // Saturate the bucket (no authenticated user in this context => zt_api:system).
    for ($i = 0; $i < 120; $i++) {
        RateLimiter::hit('zt_api:system', 60);
    }

    $network = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();
    ZerotierMember::create(['zerotier_network_id' => $network->id, 'node_id' => 'dddd000001', 'authorised' => true]);

    fakeHealthyController();

    Log::shouldReceive('warning')->atLeast()->once();

    // force:true to get past the debounce and actually attempt the throttled call.
    $result = ZerotierSyncService::syncNetwork($network, force: true);

    // The limiter trips inside client(); reconciliation must not wipe the member.
    expect($result)->toBeFalse();
    expect(ZerotierMember::where('zerotier_network_id', $network->id)->count())->toBe(1);
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

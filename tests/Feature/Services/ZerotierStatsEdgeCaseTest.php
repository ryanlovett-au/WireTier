<?php

use App\Services\ZerotierStatsService;
use Database\Seeders\SecurityTestSeeder;
use Illuminate\Support\Facades\Http;

beforeEach(function () {
    $this->seed(SecurityTestSeeder::class);
    config(['wiretier.admin_team' => SecurityTestSeeder::ADMIN_TEAM_ID]);
});

test('untrackedNetworks counts networks not in database', function () {
    Http::fake(function ($request) {
        $url = $request->url();
        if (str_contains($url, '/controller/network')) {
            // API returns 3 networks, but only 2 are tracked in DB (from seeder)
            return Http::response([
                SecurityTestSeeder::ALPHA_NETWORK_ID,
                SecurityTestSeeder::BETA_NETWORK_ID,
                'untracked0000001',
            ]);
        }

        return Http::response([]);
    });

    $result = ZerotierStatsService::untrackedNetworks();
    // untracked0000001 should be counted once even if multiple tokens report it
    expect($result['count'])->toBe(1);
    expect($result['last_updated'])->not->toBeNull();
});

test('untrackedNetworks handles API failure gracefully', function () {
    Http::fake(function () {
        throw new RuntimeException('Connection refused');
    });

    $result = ZerotierStatsService::untrackedNetworks();
    expect($result['count'])->toBe(0);
    expect($result['failed'])->not->toBeEmpty();
});

test('a failed controller call is reported and retried rather than cached as zero', function () {
    $calls = 0;
    $down = true;
    Http::fake(function ($request) use (&$calls, &$down) {
        if (! str_contains($request->url(), '/controller/network')) {
            return Http::response([]);
        }
        $calls++;

        return $down
            ? Http::response('controller down', 500)
            : Http::response(['untracked0000001']);
    });

    $first = ZerotierStatsService::untrackedNetworks();
    expect($first['failed'])->not->toBeEmpty();
    expect($first['count'])->toBe(0);

    // Within the failure window the dead controller is not hit again.
    $callsAfterFirst = $calls;
    ZerotierStatsService::untrackedNetworks();
    expect($calls)->toBe($callsAfterFirst);

    // Once the failure entry expires, a recovered controller is counted.
    $down = false;
    $this->travel(31)->seconds();
    $recovered = ZerotierStatsService::untrackedNetworks();
    expect($recovered['failed'])->toBe([]);
    expect($recovered['count'])->toBe(1);
});

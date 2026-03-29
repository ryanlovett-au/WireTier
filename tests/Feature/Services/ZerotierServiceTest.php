<?php

use App\Models\ZerotierToken;
use App\Services\ZerotierService;
use Database\Seeders\SecurityTestSeeder;
use Illuminate\Support\Facades\Http;

beforeEach(function () {
    $this->seed(SecurityTestSeeder::class);
    config(['laratier.admin_team' => SecurityTestSeeder::ADMIN_TEAM_ID]);
});

test('getPeer validates address', function () {
    $token = ZerotierToken::find(SecurityTestSeeder::ALPHA_TOKEN_ID);
    $service = new ZerotierService($token);

    expect(fn () => $service->getPeer('../etc/passwd'))
        ->toThrow(InvalidArgumentException::class);
});

test('joinNetwork validates networkId', function () {
    $token = ZerotierToken::find(SecurityTestSeeder::ALPHA_TOKEN_ID);
    $service = new ZerotierService($token);

    expect(fn () => $service->joinNetwork('evil;rm -rf /'))
        ->toThrow(InvalidArgumentException::class);
});

test('leaveNetwork validates networkId', function () {
    $token = ZerotierToken::find(SecurityTestSeeder::ALPHA_TOKEN_ID);
    $service = new ZerotierService($token);

    expect(fn () => $service->leaveNetwork('../../../etc'))
        ->toThrow(InvalidArgumentException::class);
});

test('getPeers returns array', function () {
    Http::fake(['*/peer' => Http::response([])]);
    $service = new ZerotierService(ZerotierToken::find(SecurityTestSeeder::ALPHA_TOKEN_ID));
    expect($service->getPeers())->toBeArray();
});

test('getNetworks returns array', function () {
    Http::fake(['*/network' => Http::response([])]);
    $service = new ZerotierService(ZerotierToken::find(SecurityTestSeeder::ALPHA_TOKEN_ID));
    expect($service->getNetworks())->toBeArray();
});

test('zerotier:sync with --token option syncs specific token', function () {
    Http::fake(function ($request) {
        $url = $request->url();
        if (str_contains($url, '/status')) {
            return Http::response(['address' => 'aaaa000001', 'version' => '1.14.0', 'online' => true]);
        }
        if (preg_match('#/member/([a-f0-9]+)$#', $url, $m)) {
            return Http::response(['address' => $m[1], 'authorized' => true, 'ipAssignments' => []]);
        }
        if (str_contains($url, '/member')) {
            return Http::response([]);
        }
        if (preg_match('#/controller/network/([a-zA-Z0-9_]+)$#', $url, $m)) {
            return Http::response(['nwid' => $m[1], 'name' => 'Net', 'private' => true]);
        }
        if (str_contains($url, '/peer')) {
            return Http::response([]);
        }

        return Http::response([]);
    });

    $this->artisan('zerotier:sync', ['--token' => SecurityTestSeeder::ALPHA_TOKEN_ID])
        ->assertExitCode(0);
});

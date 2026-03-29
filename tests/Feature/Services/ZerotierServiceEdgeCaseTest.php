<?php

use App\Models\User;
use App\Models\ZerotierToken;
use App\Services\ZerotierService;
use Database\Seeders\SecurityTestSeeder;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\RateLimiter;

beforeEach(function () {
    $this->seed(SecurityTestSeeder::class);
    config(['laratier.admin_team' => SecurityTestSeeder::ADMIN_TEAM_ID]);
});

test('rate limiter throws when too many attempts', function () {
    $this->actingAs(User::where('email', 'alpha-admin@security-test.local')->first());

    // Exhaust the rate limiter
    $key = 'zt_api:'.auth()->id();
    for ($i = 0; $i < 120; $i++) {
        RateLimiter::hit($key, 60);
    }

    Http::fake(['*' => Http::response([])]);
    $token = ZerotierToken::find(SecurityTestSeeder::ALPHA_TOKEN_ID);
    $service = new ZerotierService($token);

    expect(fn () => $service->getStatus())
        ->toThrow(RuntimeException::class, 'Too many API requests');
});

test('getController returns json response', function () {
    Http::fake(['*/controller' => Http::response(['address' => 'aaaa000001'])]);
    $token = ZerotierToken::find(SecurityTestSeeder::ALPHA_TOKEN_ID);
    $service = new ZerotierService($token);

    expect($service->getController())->toBe(['address' => 'aaaa000001']);
});

test('getPeer returns json for valid address', function () {
    Http::fake(['*/peer/*' => Http::response(['address' => 'aabb000001', 'latency' => 5])]);
    $token = ZerotierToken::find(SecurityTestSeeder::ALPHA_TOKEN_ID);
    $service = new ZerotierService($token);

    $peer = $service->getPeer('aabb000001');
    expect($peer['address'])->toBe('aabb000001');
});

test('joinNetwork posts to network endpoint', function () {
    Http::fake(['*/network/*' => Http::response(['nwid' => 'aabbccdd11000001'])]);
    $token = ZerotierToken::find(SecurityTestSeeder::ALPHA_TOKEN_ID);
    $service = new ZerotierService($token);

    $result = $service->joinNetwork('aabbccdd11000001');
    expect($result['nwid'])->toBe('aabbccdd11000001');
});

test('leaveNetwork returns success', function () {
    Http::fake(['*/network/*' => Http::response([], 200)]);
    $token = ZerotierToken::find(SecurityTestSeeder::ALPHA_TOKEN_ID);
    $service = new ZerotierService($token);

    expect($service->leaveNetwork('aabbccdd11000001'))->toBeTrue();
});

test('createNetwork throws when node address is missing', function () {
    Http::fake(['*/status' => Http::response([])]);
    $token = ZerotierToken::find(SecurityTestSeeder::ALPHA_TOKEN_ID);
    $service = new ZerotierService($token);

    expect(fn () => $service->createNetwork())
        ->toThrow(RuntimeException::class, 'Could not determine controller node address');
});

test('testConnection catches generic exception', function () {
    Http::fake(function () {
        throw new RuntimeException('Unexpected error');
    });

    $token = ZerotierToken::find(SecurityTestSeeder::ALPHA_TOKEN_ID);
    $service = new ZerotierService($token);
    $result = $service->testConnection();

    expect($result['success'])->toBeFalse();
    expect($result['error'])->toBe('Unexpected error');
});

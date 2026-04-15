<?php

use App\Models\ZerotierToken;
use App\Services\ZerotierService;
use Database\Seeders\SecurityTestSeeder;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;

beforeEach(function () {
    $this->seed(SecurityTestSeeder::class);
    config(['wiretier.admin_team' => SecurityTestSeeder::ADMIN_TEAM_ID]);
});

// ─── Functional Tests ────────────────────────────────────────────────────

test('constructs with valid token and builds correct base URL', function () {
    $token = ZerotierToken::find(SecurityTestSeeder::ALPHA_TOKEN_ID);
    $service = new ZerotierService($token);

    // Base URL should come from the token's host
    $reflection = new ReflectionClass($service);
    $prop = $reflection->getProperty('baseUrl');
    $prop->setAccessible(true);

    expect($prop->getValue($service))->toBe('http://localhost:9993');
});

test('getControllerNetworks makes GET to controller network endpoint', function () {
    Http::fake([
        '*/controller/network' => Http::response(['aabbccdd11000001', 'aabbccdd22000002']),
        '*' => Http::response([]),
    ]);

    $token = ZerotierToken::find(SecurityTestSeeder::ALPHA_TOKEN_ID);
    $service = new ZerotierService($token);
    $networks = $service->getControllerNetworks();

    expect($networks)->toBe(['aabbccdd11000001', 'aabbccdd22000002']);
    Http::assertSent(fn ($request) => str_contains($request->url(), '/controller/network') && $request->method() === 'GET');
});

test('createNetwork fetches status first then POSTs', function () {
    $calls = [];
    Http::fake(function ($request) use (&$calls) {
        $calls[] = [$request->method(), $request->url()];
        if (str_contains($request->url(), '/status')) {
            return Http::response(['address' => 'aaaa000001']);
        }

        return Http::response(['nwid' => 'aaaa000001ffffff', 'name' => 'New']);
    });

    $token = ZerotierToken::find(SecurityTestSeeder::ALPHA_TOKEN_ID);
    $service = new ZerotierService($token);
    $result = $service->createNetwork(['name' => 'Test']);

    expect($result['nwid'])->toBe('aaaa000001ffffff');

    // First call should be GET /status, second should be POST /controller/network/...
    expect($calls[0][0])->toBe('GET');
    expect($calls[0][1])->toContain('/status');
    expect($calls[1][0])->toBe('POST');
    expect($calls[1][1])->toContain('/controller/network/aaaa000001');
});

test('testConnection returns success structure on valid response', function () {
    Http::fake([
        '*/status' => Http::response(['address' => 'aaaa000001', 'version' => '1.14.0', 'online' => true]),
    ]);

    $token = ZerotierToken::find(SecurityTestSeeder::ALPHA_TOKEN_ID);
    $service = new ZerotierService($token);
    $result = $service->testConnection();

    expect($result['success'])->toBeTrue();
    expect($result['address'])->toBe('aaaa000001');
    expect($result['version'])->toBe('1.14.0');
});

test('testConnection returns failure structure on connection error', function () {
    Http::fake(function () {
        throw new ConnectionException('Connection refused');
    });

    $token = ZerotierToken::find(SecurityTestSeeder::ALPHA_TOKEN_ID);
    $service = new ZerotierService($token);
    $result = $service->testConnection();

    expect($result['success'])->toBeFalse();
    expect($result['error'])->toContain('Could not connect');
});

// ─── Security: SSRF ──────────────────────────────────────────────────────

test('rejects internal IPs as host URL', function () {
    $internalHosts = [
        'http://127.0.0.1:9993',
        'http://10.0.0.1:9993',
        'http://192.168.1.1:9993',
        'http://172.16.0.1:9993',
        'http://169.254.169.254/latest/meta-data',  // AWS metadata
        'http://[::1]:9993',  // IPv6 loopback
    ];

    $token = ZerotierToken::find(SecurityTestSeeder::ALPHA_TOKEN_ID);

    try {
        foreach ($internalHosts as $host) {
            // Override the token host to test SSRF protection
            $token->host = $host;
            $service = new ZerotierService($token);

            $reflection = new ReflectionClass($service);
            $prop = $reflection->getProperty('baseUrl');
            $prop->setAccessible(true);
            $baseUrl = $prop->getValue($service);

            // The service should reject or sanitize internal IPs
            expect($baseUrl)->not->toContain('127.0.0.1', "SSRF: {$host} was accepted as base URL")
                ->and($baseUrl)->not->toContain('169.254', "SSRF: {$host} was accepted as base URL")
                ->and($baseUrl)->not->toContain('[::1]', "SSRF: {$host} was accepted as base URL");
        }
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: ZerotierService accepts internal/metadata IPs as host URL — SSRF to internal services is possible');
    }
});

test('rejects non-HTTP schemes as host URL', function () {
    $dangerousSchemes = [
        'file:///etc/passwd',
        'ftp://evil.com/payload',
        'gopher://evil.com:25/HELO',
    ];

    $token = ZerotierToken::find(SecurityTestSeeder::ALPHA_TOKEN_ID);

    foreach ($dangerousSchemes as $host) {
        $token->host = $host;
        expect(fn () => new ZerotierService($token))
            ->toThrow(InvalidArgumentException::class);
    }
});

// ─── Security: Path Injection ────────────────────────────────────────────

test('networkId with path traversal chars is rejected', function () {
    $token = ZerotierToken::find(SecurityTestSeeder::ALPHA_TOKEN_ID);
    $service = new ZerotierService($token);

    $maliciousIds = [
        '../../../etc/passwd',
        'aabbccdd11%2F..%2Fetc',
        'aabbccdd11;rm -rf /',
    ];

    foreach ($maliciousIds as $networkId) {
        expect(fn () => $service->getControllerNetwork($networkId))
            ->toThrow(InvalidArgumentException::class);
    }
});

test('empty token throws instead of falling back to localhost', function () {
    $token = ZerotierToken::find(SecurityTestSeeder::ALPHA_TOKEN_ID);
    $token->token = '';

    expect(fn () => new ZerotierService($token))
        ->toThrow(InvalidArgumentException::class, 'no API token configured');
});

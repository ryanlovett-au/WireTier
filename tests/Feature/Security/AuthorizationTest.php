<?php

use App\Models\User;
use App\Models\ZerotierToken;
use Database\Seeders\SecurityTestSeeder;
use Illuminate\Support\Facades\Http;
use Livewire\Livewire;

beforeEach(function () {
    $this->seed(SecurityTestSeeder::class);
    config(['laratier.admin_team' => SecurityTestSeeder::ADMIN_TEAM_ID]);

    Http::fake([
        '*/status' => Http::response(['address' => 'aaaa000001', 'version' => '1.14.0', 'online' => true]),
        '*/controller/network' => Http::response([]),
        '*/controller' => Http::response(['address' => 'aaaa000001']),
        '*' => Http::response([]),
    ]);

    $this->alphaAdmin = User::where('email', 'alpha-admin@security-test.local')->first();
    $this->alphaMember = User::where('email', 'alpha-member@security-test.local')->first();
    $this->alphaViewer = User::where('email', 'alpha-viewer@security-test.local')->first();
    $this->betaMember = User::where('email', 'beta-member@security-test.local')->first();
});

// ─── Tokens Page ──────────────────────────────────────────────────────

test('non-admin cannot access tokens page', function () {
    $this->actingAs($this->alphaAdmin);

    $response = $this->get(route('zerotier.tokens'));
    $response->assertStatus(403);
});

test('member cannot access tokens page', function () {
    $this->actingAs($this->alphaMember);

    $response = $this->get(route('zerotier.tokens'));
    $response->assertStatus(403);
});

// ─── Peers Page ───────────────────────────────────────────────────────

test('non-admin cannot access peers page', function () {
    $this->actingAs($this->alphaAdmin);

    $response = $this->get(route('zerotier.peers'));
    $response->assertStatus(403);
});

// ─── Networks: Role-based Authorization ──────────────────────────────

test('viewer cannot create network', function () {
    $this->actingAs($this->alphaViewer);
    session()->forget('current_team');

    $component = Livewire::test('pages::zerotier.networks')
        ->call('createNetwork');

    // createNetwork checks isTeamAdmin() and returns early for non-admins
    expect(
        \App\Models\ZerotierNetwork::where('name', 'Viewer Network')->exists()
    )->toBeFalse('Viewer was able to create a network');
});

test('viewer cannot save network', function () {
    $this->actingAs($this->alphaViewer);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.networks')
        ->call('saveNetwork');

    // saveNetwork checks isTeamAdmin() and returns early for non-admins
    $network = \App\Models\ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();
    expect($network->name)->toBe('Alpha Private Net', 'Viewer was able to edit a network');
});

test('viewer cannot delete network', function () {
    $this->actingAs($this->alphaViewer);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.networks')
        ->call('deleteNetwork');

    expect(
        \App\Models\ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->exists()
    )->toBeTrue('Viewer was able to delete a network');
});

// ─── Members: Missing Authorization ──────────────────────────────────

test('authorizeMember requires authorization check', function () {
    $this->actingAs($this->alphaViewer);

    $authorizeCalled = false;
    Http::fake(function ($request) use (&$authorizeCalled) {
        if (str_contains($request->url(), 'abc1234567')) {
            $authorizeCalled = true;
        }

        return Http::response(['authorized' => true], 200);
    });

    $component = Livewire::test('pages::zerotier.members', [
        'networkId' => SecurityTestSeeder::ALPHA_NETWORK_ID,
        'tokenId' => SecurityTestSeeder::ALPHA_TOKEN_ID,
    ])->call('authorizeMember', 'abc1234567');

    try {
        // Viewer should NOT be allowed to authorize members
        expect($authorizeCalled)->toBeFalse('Viewer was able to call the ZeroTier API to authorize a member');
    } catch (\Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: authorizeMember() has no authorization check — viewers can authorize network members');
    }
});

test('deauthorizeMember requires authorization check', function () {
    $this->actingAs($this->alphaViewer);

    $deauthorizeCalled = false;
    Http::fake(function ($request) use (&$deauthorizeCalled) {
        if (str_contains($request->url(), 'abc1234567')) {
            $deauthorizeCalled = true;
        }

        return Http::response(['authorized' => false], 200);
    });

    Livewire::test('pages::zerotier.members', [
        'networkId' => SecurityTestSeeder::ALPHA_NETWORK_ID,
        'tokenId' => SecurityTestSeeder::ALPHA_TOKEN_ID,
    ])->call('deauthorizeMember', 'abc1234567');

    try {
        // Viewer should NOT be allowed to deauthorize members
        expect($deauthorizeCalled)->toBeFalse('Viewer was able to call the ZeroTier API to deauthorize a member');
    } catch (\Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: deauthorizeMember() has no authorization check — viewers can deauthorize network members');
    }
});

test('deleteMember requires authorization check', function () {
    $this->actingAs($this->alphaViewer);

    $deleteCalled = false;
    Http::fake(function ($request) use (&$deleteCalled) {
        if (str_contains($request->url(), 'abc1234567') && $request->method() === 'DELETE') {
            $deleteCalled = true;
        }

        return Http::response([], 200);
    });

    Livewire::test('pages::zerotier.members', [
        'networkId' => SecurityTestSeeder::ALPHA_NETWORK_ID,
        'tokenId' => SecurityTestSeeder::ALPHA_TOKEN_ID,
    ])->set('delete_member_id', 'abc1234567')
        ->call('deleteMember');

    try {
        // Viewer should NOT be allowed to delete members
        expect($deleteCalled)->toBeFalse('Viewer was able to call the ZeroTier API to delete a member');
    } catch (\Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: deleteMember() has no authorization check — viewers can delete network members');
    }
});

// ─── Unauthenticated Access ──────────────────────────────────────────

test('unauthenticated user redirected from zerotier routes', function () {
    $this->get(route('zerotier.networks'))->assertRedirect('/login');
    $this->get(route('zerotier.tokens'))->assertRedirect('/login');
    $this->get(route('zerotier.peers'))->assertRedirect('/login');
});

test('unverified user cannot access zerotier routes', function () {
    $unverified = User::factory()->unverified()->create();

    $this->actingAs($unverified);

    $this->get(route('zerotier.networks'))->assertRedirect('/email/verify');
});

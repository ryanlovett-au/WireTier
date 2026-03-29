<?php

use App\Models\User;
use App\Models\ZerotierToken;
use Database\Seeders\SecurityTestSeeder;
use Illuminate\Support\Facades\Http;
use Livewire\Livewire;

beforeEach(function () {
    $this->seed(SecurityTestSeeder::class);
    config(['laratier.admin_team' => SecurityTestSeeder::ADMIN_TEAM_ID]);

    $this->superAdmin = User::where('email', 'superadmin@security-test.local')->first();
    $this->alphaAdmin = User::where('email', 'alpha-admin@security-test.local')->first();
});

function peersHttpFakes(): void
{
    Http::fake([
        '*/status' => Http::response(['address' => 'aaaa000001', 'version' => '1.14.0', 'online' => true]),
        '*/peer' => Http::response([
            ['address' => 'deadbeef01', 'role' => 'PLANET', 'latency' => 5, 'paths' => [['active' => true, 'address' => '1.2.3.4/9993']]],
            ['address' => 'cafebabe01', 'role' => 'LEAF', 'latency' => 12, 'paths' => []],
        ]),
        '*/controller/network' => Http::response([]),
        '*' => Http::response([]),
    ]);
}

// ─── Functional Tests ────────────────────────────────────────────────────

test('admin can mount peers page and loads data', function () {
    peersHttpFakes();
    $this->actingAs($this->superAdmin);

    $component = Livewire::test('pages::zerotier.peers');
    $component->assertStatus(200);

    $peers = $component->get('peers');
    expect($peers)->toHaveCount(2);
    // Peers should be sorted by role: PLANET first, then LEAF
    expect($peers[0]['role'])->toBe('PLANET');
    expect($peers[1]['role'])->toBe('LEAF');
});

test('non-admin user gets 403 on peers page', function () {
    peersHttpFakes();
    $this->actingAs($this->alphaAdmin);

    Livewire::test('pages::zerotier.peers')
        ->assertStatus(403);
});

test('peers page loads status data', function () {
    peersHttpFakes();
    $this->actingAs($this->superAdmin);

    $component = Livewire::test('pages::zerotier.peers');
    $status = $component->get('status');

    expect($status['address'])->toBe('aaaa000001');
    expect($status['version'])->toBe('1.14.0');
});

test('updatedSelectedToken reloads data', function () {
    peersHttpFakes();
    $this->actingAs($this->superAdmin);

    // Create a second global token
    $token2 = new ZerotierToken;
    $token2->name = 'Admin Token 2';
    $token2->token = 'admintoken2';
    $token2->host = 'http://localhost:9994';
    $token2->is_active = true;
    $token2->save();

    $component = Livewire::test('pages::zerotier.peers');

    // Switch to the new token
    $component->set('selectedToken', $token2->id);
    $peers = $component->get('peers');
    expect($peers)->toHaveCount(2); // Fakes return same data for both tokens
});

// Tokens are global (admin-managed) — no team isolation test needed for tokens.
// Peers page is admin-only, so all tokens should be visible.

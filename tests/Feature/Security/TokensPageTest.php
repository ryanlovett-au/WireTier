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
        '*/peer' => Http::response([]),
        '*' => Http::response([]),
    ]);

    $this->superAdmin = User::where('email', 'superadmin@security-test.local')->first();
    $this->alphaAdmin = User::where('email', 'alpha-admin@security-test.local')->first();
    $this->alphaMember = User::where('email', 'alpha-member@security-test.local')->first();
});

// ─── Functional Tests ────────────────────────────────────────────────────

test('admin can mount the tokens page', function () {
    $this->actingAs($this->superAdmin);

    $component = Livewire::test('pages::zerotier.tokens');

    $component->assertStatus(200);
    $component->assertSet('new_host', 'http://localhost:9993');
});

test('non-admin user gets 403 on tokens page', function () {
    $this->actingAs($this->alphaAdmin);

    Livewire::test('pages::zerotier.tokens')
        ->assertStatus(403);
});

test('addToken validates required fields', function () {
    $this->actingAs($this->superAdmin);

    Livewire::test('pages::zerotier.tokens')
        ->set('new_name', '')
        ->set('new_token', '')
        ->set('new_host', '')
        ->call('addToken')
        ->assertHasErrors(['new_name', 'new_token', 'new_host']);
});

test('addToken creates a global token', function () {
    $this->actingAs($this->superAdmin);

    Livewire::test('pages::zerotier.tokens')
        ->set('new_name', 'Test Controller')
        ->set('new_token', 'abc123secret')
        ->set('new_host', 'http://10.0.0.1:9993')
        ->call('addToken')
        ->assertHasNoErrors();

    $token = ZerotierToken::where('name', 'Test Controller')->first();
    expect($token)->not->toBeNull();
    expect($token->host)->toBe('http://10.0.0.1:9993');
    expect($token->node_address)->toBe('aaaa000001');
});

test('admin can see all tokens', function () {
    $this->actingAs($this->superAdmin);

    $component = Livewire::test('pages::zerotier.tokens');
    $tokens = $component->get('tokens');

    // Seeder creates 2 global tokens (Alpha Controller, Beta Controller)
    expect($tokens->count())->toBeGreaterThanOrEqual(2);
});

test('editTokenModal populates edit fields', function () {
    $this->actingAs($this->superAdmin);

    $token = ZerotierToken::first();

    $component = Livewire::test('pages::zerotier.tokens')
        ->call('editTokenModal', $token->id);

    $component->assertSet('edit_id', $token->id);
    $component->assertSet('edit_name', $token->name);
    $component->assertSet('edit_host', $token->host);
});

test('updateToken updates name and host', function () {
    $this->actingAs($this->superAdmin);

    $token = new ZerotierToken;
    $token->name = 'Original';
    $token->token = 'admintoken';
    $token->host = 'http://localhost:9993';
    $token->save();

    Livewire::test('pages::zerotier.tokens')
        ->set('edit_id', $token->id)
        ->set('edit_name', 'Renamed Controller')
        ->set('edit_host', 'http://10.0.0.2:9993')
        ->call('updateToken')
        ->assertHasNoErrors();

    $token->refresh();
    expect($token->name)->toBe('Renamed Controller');
    expect($token->host)->toBe('http://10.0.0.2:9993');
});

test('deleteToken removes the token from database', function () {
    $this->actingAs($this->superAdmin);

    // Create a token with no associated networks
    $token = new ZerotierToken;
    $token->name = 'To Delete';
    $token->token = 'deleteme';
    $token->host = 'http://localhost:9993';
    $token->save();
    $tokenId = $token->id;

    Livewire::test('pages::zerotier.tokens')
        ->set('delete_id', $tokenId)
        ->call('deleteToken');

    expect(ZerotierToken::find($tokenId))->toBeNull();
});

test('deleteToken blocked when token has active networks', function () {
    $this->actingAs($this->superAdmin);

    // ALPHA_TOKEN_ID has an associated network from the seeder
    $component = Livewire::test('pages::zerotier.tokens')
        ->set('delete_id', SecurityTestSeeder::ALPHA_TOKEN_ID)
        ->call('deleteToken');

    // Token should NOT be deleted
    expect(ZerotierToken::find(SecurityTestSeeder::ALPHA_TOKEN_ID))->not->toBeNull();
});

test('testToken updates node address on success', function () {
    $this->actingAs($this->superAdmin);

    $token = new ZerotierToken;
    $token->name = 'Test Me';
    $token->token = 'testtoken';
    $token->host = 'http://localhost:9993';
    $token->node_address = null;
    $token->save();

    Livewire::test('pages::zerotier.tokens')
        ->call('testToken', $token->id);

    $token->refresh();
    expect($token->node_address)->toBe('aaaa000001');
    expect($token->is_active)->toBeTrue();
});

test('toggleToken flips is_active', function () {
    $this->actingAs($this->superAdmin);

    $token = new ZerotierToken;
    $token->name = 'Toggle Me';
    $token->token = 'toggletoken';
    $token->host = 'http://localhost:9993';
    $token->is_active = true;
    $token->save();

    Livewire::test('pages::zerotier.tokens')
        ->call('toggleToken', $token->id);

    $token->refresh();
    expect($token->is_active)->toBeFalse();
});

// ─── Security: Token Data Exposure ───────────────────────────────────────

test('ZerotierToken hides sensitive fields from serialization', function () {
    $token = new ZerotierToken;
    $hidden = $token->getHidden();

    expect($hidden)->toContain('token');
    expect($hidden)->toContain('host');
    expect($hidden)->toContain('node_address');
});

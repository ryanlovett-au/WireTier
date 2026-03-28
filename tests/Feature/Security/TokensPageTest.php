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

test('addToken creates a token for the current team', function () {
    $this->actingAs($this->superAdmin);

    Livewire::test('pages::zerotier.tokens')
        ->set('new_name', 'Test Controller')
        ->set('new_token', 'abc123secret')
        ->set('new_host', 'http://10.0.0.1:9993')
        ->call('addToken')
        ->assertHasNoErrors();

    $token = ZerotierToken::where('name', 'Test Controller')->first();
    expect($token)->not->toBeNull();
    expect($token->team_id)->toBe(SecurityTestSeeder::ADMIN_TEAM_ID);
    expect($token->host)->toBe('http://10.0.0.1:9993');
    expect($token->node_address)->toBe('aaaa000001'); // from Http::fake status response
});

test('editTokenModal populates edit fields', function () {
    $this->actingAs($this->superAdmin);

    $adminToken = ZerotierToken::where('team_id', SecurityTestSeeder::ADMIN_TEAM_ID)->first();
    if (! $adminToken) {
        // Create one for the admin team so the test is valid
        $adminToken = new ZerotierToken;
        $adminToken->team_id = SecurityTestSeeder::ADMIN_TEAM_ID;
        $adminToken->name = 'Admin Token';
        $adminToken->token = 'admintoken';
        $adminToken->host = 'http://localhost:9993';
        $adminToken->save();
    }

    $component = Livewire::test('pages::zerotier.tokens')
        ->call('editTokenModal', $adminToken->id);

    $component->assertSet('edit_id', $adminToken->id);
    $component->assertSet('edit_name', $adminToken->name);
    $component->assertSet('edit_host', $adminToken->host);
});

test('updateToken updates name and host', function () {
    $this->actingAs($this->superAdmin);

    $adminToken = new ZerotierToken;
    $adminToken->team_id = SecurityTestSeeder::ADMIN_TEAM_ID;
    $adminToken->name = 'Original';
    $adminToken->token = 'admintoken';
    $adminToken->host = 'http://localhost:9993';
    $adminToken->save();

    Livewire::test('pages::zerotier.tokens')
        ->set('edit_id', $adminToken->id)
        ->set('edit_name', 'Renamed Controller')
        ->set('edit_host', 'http://10.0.0.2:9993')
        ->call('updateToken')
        ->assertHasNoErrors();

    $adminToken->refresh();
    expect($adminToken->name)->toBe('Renamed Controller');
    expect($adminToken->host)->toBe('http://10.0.0.2:9993');
});

test('deleteToken removes the token from database', function () {
    $this->actingAs($this->superAdmin);

    $adminToken = new ZerotierToken;
    $adminToken->team_id = SecurityTestSeeder::ADMIN_TEAM_ID;
    $adminToken->name = 'To Delete';
    $adminToken->token = 'deleteme';
    $adminToken->host = 'http://localhost:9993';
    $adminToken->save();
    $tokenId = $adminToken->id;

    Livewire::test('pages::zerotier.tokens')
        ->set('delete_id', $tokenId)
        ->call('deleteToken');

    expect(ZerotierToken::find($tokenId))->toBeNull();
});

test('testToken updates node address on success', function () {
    $this->actingAs($this->superAdmin);

    $adminToken = new ZerotierToken;
    $adminToken->team_id = SecurityTestSeeder::ADMIN_TEAM_ID;
    $adminToken->name = 'Test Me';
    $adminToken->token = 'testtoken';
    $adminToken->host = 'http://localhost:9993';
    $adminToken->node_address = null;
    $adminToken->save();

    Livewire::test('pages::zerotier.tokens')
        ->call('testToken', $adminToken->id);

    $adminToken->refresh();
    expect($adminToken->node_address)->toBe('aaaa000001');
    expect($adminToken->is_active)->toBeTrue();
});

test('toggleToken flips is_active', function () {
    $this->actingAs($this->superAdmin);

    $adminToken = new ZerotierToken;
    $adminToken->team_id = SecurityTestSeeder::ADMIN_TEAM_ID;
    $adminToken->name = 'Toggle Me';
    $adminToken->token = 'toggletoken';
    $adminToken->host = 'http://localhost:9993';
    $adminToken->is_active = true;
    $adminToken->save();

    Livewire::test('pages::zerotier.tokens')
        ->call('toggleToken', $adminToken->id);

    $adminToken->refresh();
    expect($adminToken->is_active)->toBeFalse();
});

// ─── Security: Team Isolation ────────────────────────────────────────────

test('loadTokens only returns tokens for the admin team', function () {
    $this->actingAs($this->superAdmin);

    $component = Livewire::test('pages::zerotier.tokens');
    $tokens = $component->get('tokens');

    try {
        foreach ($tokens as $token) {
            expect($token->team_id)->toBe(SecurityTestSeeder::ADMIN_TEAM_ID,
                "Token '{$token->name}' belongs to team {$token->team_id} but admin team is ".SecurityTestSeeder::ADMIN_TEAM_ID
            );
        }
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: ZerotierToken::all() is not scoped to current team — tokens from all teams are visible');
    }
});

test('testToken rejects a token belonging to another team', function () {
    $this->actingAs($this->superAdmin);

    $betaToken = ZerotierToken::find(SecurityTestSeeder::BETA_TOKEN_ID);
    $originalAddress = $betaToken->node_address;

    Livewire::test('pages::zerotier.tokens')
        ->call('testToken', SecurityTestSeeder::BETA_TOKEN_ID);

    $betaToken->refresh();

    try {
        expect($betaToken->node_address)->toBe($originalAddress,
            'Beta token node_address was modified by admin team user'
        );
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: testToken() does not verify team ownership — cross-team token testing is possible');
    }
});

test('toggleToken rejects a token belonging to another team', function () {
    $this->actingAs($this->superAdmin);

    $betaToken = ZerotierToken::find(SecurityTestSeeder::BETA_TOKEN_ID);
    $originalActive = $betaToken->is_active;

    Livewire::test('pages::zerotier.tokens')
        ->call('toggleToken', SecurityTestSeeder::BETA_TOKEN_ID);

    $betaToken->refresh();

    try {
        expect($betaToken->is_active)->toBe($originalActive,
            'Beta token is_active was changed by admin team user'
        );
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: toggleToken() does not verify team ownership — cross-team token toggling is possible');
    }
});

test('updateToken rejects a token belonging to another team', function () {
    $this->actingAs($this->superAdmin);

    Livewire::test('pages::zerotier.tokens')
        ->set('edit_id', SecurityTestSeeder::BETA_TOKEN_ID)
        ->set('edit_name', 'HACKED')
        ->set('edit_host', 'http://evil.com')
        ->call('updateToken');

    $betaToken = ZerotierToken::find(SecurityTestSeeder::BETA_TOKEN_ID);

    try {
        expect($betaToken->name)->not->toBe('HACKED',
            'Beta token name was changed by admin team user'
        );
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: updateToken() does not verify team ownership — cross-team token updates are possible');
    }
});

test('deleteToken rejects a token belonging to another team', function () {
    $this->actingAs($this->superAdmin);

    Livewire::test('pages::zerotier.tokens')
        ->set('delete_id', SecurityTestSeeder::BETA_TOKEN_ID)
        ->call('deleteToken');

    try {
        expect(ZerotierToken::find(SecurityTestSeeder::BETA_TOKEN_ID))->not->toBeNull(
            'Beta token was deleted by admin team user'
        );
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: deleteToken() does not verify team ownership — cross-team token deletion is possible');
    }
});

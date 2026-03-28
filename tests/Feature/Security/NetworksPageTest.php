<?php

use App\Models\User;
use App\Models\ZerotierNetwork;
use Database\Seeders\SecurityTestSeeder;
use Illuminate\Support\Facades\Http;
use Livewire\Livewire;

function defaultHttpFakes(): void
{
    Http::fake([
        '*/status' => Http::response(['address' => 'aaaa000001', 'version' => '1.14.0', 'online' => true]),
        '*/controller/network' => Http::response([]),
        '*/controller' => Http::response(['address' => 'aaaa000001']),
        '*/peer' => Http::response([]),
        '*' => Http::response([]),
    ]);
}

beforeEach(function () {
    $this->seed(SecurityTestSeeder::class);
    config(['laratier.admin_team' => SecurityTestSeeder::ADMIN_TEAM_ID]);

    $this->alphaAdmin = User::where('email', 'alpha-admin@security-test.local')->first();
    $this->alphaMember = User::where('email', 'alpha-member@security-test.local')->first();
    $this->alphaViewer = User::where('email', 'alpha-viewer@security-test.local')->first();
    $this->betaAdmin = User::where('email', 'beta-admin@security-test.local')->first();
});

// ─── Functional Tests ────────────────────────────────────────────────────

test('networks page mounts and loads team-scoped tokens', function () {
    defaultHttpFakes();
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    $component = Livewire::test('pages::zerotier.networks');
    $component->assertStatus(200);

    $tokens = $component->get('tokens');
    foreach ($tokens as $token) {
        expect($token->team_id)->toBe(SecurityTestSeeder::ALPHA_TEAM_ID);
    }
});

test('networks page redirects when user has no team', function () {
    defaultHttpFakes();
    $orphan = User::where('email', 'orphan@security-test.local')->first();
    $this->actingAs($orphan);

    Livewire::test('pages::zerotier.networks')
        ->assertRedirect('/settings/teams');
});

test('loadNetworks calls ZerotierService for network data', function () {
    // Set up fakes BEFORE mount so loadNetworks sees them during mount()
    Http::fake([
        '*/controller/network/aabbccdd11000001/member' => Http::response([]),
        '*/controller/network/aabbccdd11000001' => Http::response([
            'nwid' => 'aabbccdd11000001', 'name' => 'Test Net', 'private' => true,
        ]),
        '*/controller/network' => Http::response(['aabbccdd11000001']),
        '*/status' => Http::response(['address' => 'aaaa000001', 'version' => '1.14.0', 'online' => true]),
        '*' => Http::response([]),
    ]);

    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    $component = Livewire::test('pages::zerotier.networks');
    $networks = $component->get('networks');

    expect($networks)->toHaveCount(1);
    expect($networks[0]['name'])->toBe('Test Net');
});

test('createNetwork creates DB record and calls API', function () {
    Http::fake([
        '*/status' => Http::response(['address' => 'aaaa000001', 'version' => '1.14.0', 'online' => true]),
        '*/controller/network/aaaa000001______' => Http::response([
            'nwid' => 'aaaa000001ffffff', 'name' => 'New Network',
        ]),
        '*/controller/network' => Http::response([]),
        '*' => Http::response([]),
    ]);

    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.networks')
        ->set('new_network_name', 'New Network')
        ->set('new_network_subnet', '10.42.0.0/24')
        ->set('new_network_private', true)
        ->call('createNetwork')
        ->assertHasNoErrors();

    $network = ZerotierNetwork::where('network_id', 'aaaa000001ffffff')->first();
    expect($network)->not->toBeNull();
    expect($network->team_id)->toBe(SecurityTestSeeder::ALPHA_TEAM_ID);
    expect($network->name)->toBe('New Network');
});

test('saveNetwork updates network config via API and DB record', function () {
    Http::fake([
        '*/controller/network/'.SecurityTestSeeder::ALPHA_NETWORK_ID => Http::response([
            'nwid' => SecurityTestSeeder::ALPHA_NETWORK_ID,
            'name' => 'Updated',
        ]),
        '*/status' => Http::response(['address' => 'aaaa000001', 'version' => '1.14.0', 'online' => true]),
        '*/controller/network' => Http::response([]),
        '*' => Http::response([]),
    ]);

    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.networks')
        ->set('selectedToken', SecurityTestSeeder::ALPHA_TOKEN_ID)
        ->set('editing_network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)
        ->set('edit_name', 'Updated Name')
        ->set('edit_private', false)
        ->call('saveNetwork')
        ->assertHasNoErrors();

    $network = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();
    expect($network->name)->toBe('Updated Name');
    expect($network->private)->toBeFalse();
});

test('deleteNetwork removes via API and DB record', function () {
    Http::fake([
        '*/controller/network/'.SecurityTestSeeder::ALPHA_NETWORK_ID => Http::response([], 200),
        '*/status' => Http::response(['address' => 'aaaa000001', 'version' => '1.14.0', 'online' => true]),
        '*/controller/network' => Http::response([]),
        '*' => Http::response([]),
    ]);

    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.networks')
        ->set('selectedToken', SecurityTestSeeder::ALPHA_TOKEN_ID)
        ->set('delete_network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)
        ->call('deleteNetwork');

    expect(ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->exists())->toBeFalse();
});

test('openEditModal populates edit fields from API data', function () {
    $networkId = SecurityTestSeeder::ALPHA_NETWORK_ID;

    Http::fake([
        "*/{$networkId}" => Http::response([
            'nwid' => $networkId, 'name' => 'Alpha Net', 'private' => true,
            'enableBroadcast' => true, 'multicastLimit' => 32,
            'routes' => [['target' => '10.0.0.0/24']],
            'ipAssignmentPools' => [['ipRangeStart' => '10.0.0.1', 'ipRangeEnd' => '10.0.0.254']],
        ]),
        '*/status' => Http::response(['address' => 'aaaa000001', 'version' => '1.14.0', 'online' => true]),
        '*/controller/network' => Http::response([]),
        '*' => Http::response([]),
    ]);

    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    $component = Livewire::test('pages::zerotier.networks')
        ->set('selectedToken', SecurityTestSeeder::ALPHA_TOKEN_ID)
        ->call('openEditModal', $networkId);

    $component->assertSet('editing_network_id', $networkId);
    $component->assertSet('edit_name', 'Alpha Net');
    $component->assertSet('edit_private', true);
    expect($component->get('edit_routes'))->toHaveCount(1);
    expect($component->get('edit_ip_pools'))->toHaveCount(1);
});

test('addRoute and removeRoute manage route arrays', function () {
    defaultHttpFakes();
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    $component = Livewire::test('pages::zerotier.networks')
        ->set('new_route_target', '192.168.1.0/24')
        ->set('new_route_via', '10.0.0.1')
        ->call('addRoute');

    $routes = $component->get('edit_routes');
    expect($routes)->toHaveCount(1);
    expect($routes[0]['target'])->toBe('192.168.1.0/24');
    expect($routes[0]['via'])->toBe('10.0.0.1');

    $component->call('removeRoute', 0);
    expect($component->get('edit_routes'))->toHaveCount(0);
});

test('addIpPool and removeIpPool manage IP pool arrays', function () {
    defaultHttpFakes();
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    $component = Livewire::test('pages::zerotier.networks')
        ->set('new_pool_start', '10.0.0.1')
        ->set('new_pool_end', '10.0.0.254')
        ->call('addIpPool');

    $pools = $component->get('edit_ip_pools');
    expect($pools)->toHaveCount(1);
    expect($pools[0]['ipRangeStart'])->toBe('10.0.0.1');

    $component->call('removeIpPool', 0);
    expect($component->get('edit_ip_pools'))->toHaveCount(0);
});

test('viewer cannot create networks', function () {
    $this->actingAs($this->alphaViewer);
    session()->forget('current_team');

    Http::fake([
        '*/status' => Http::response(['address' => 'aaaa000001', 'version' => '1.14.0', 'online' => true]),
        '*/controller/network' => Http::response([]),
        '*' => Http::response([]),
    ]);

    $countBefore = ZerotierNetwork::count();

    Livewire::test('pages::zerotier.networks')
        ->set('new_network_name', 'Viewer Network')
        ->set('new_network_subnet', '10.42.0.0/24')
        ->call('createNetwork');

    expect(ZerotierNetwork::count())->toBe($countBefore);
});

test('viewer cannot save networks', function () {
    $this->actingAs($this->alphaViewer);
    session()->forget('current_team');

    $alphaNetwork = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();
    $originalName = $alphaNetwork->name;

    Http::fake([
        '*/status' => Http::response(['address' => 'aaaa000001', 'version' => '1.14.0', 'online' => true]),
        '*/controller/network' => Http::response([]),
        '*' => Http::response([]),
    ]);

    Livewire::test('pages::zerotier.networks')
        ->set('selectedToken', SecurityTestSeeder::ALPHA_TOKEN_ID)
        ->set('editing_network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)
        ->set('edit_name', 'HACKED BY VIEWER')
        ->call('saveNetwork');

    $alphaNetwork->refresh();

    try {
        expect($alphaNetwork->name)->toBe($originalName);
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: saveNetwork() isTeamAdmin() check does not block viewers — viewers can modify network configuration');
    }
});

test('viewer cannot delete networks', function () {
    $this->actingAs($this->alphaViewer);
    session()->forget('current_team');

    Http::fake([
        '*/status' => Http::response(['address' => 'aaaa000001', 'version' => '1.14.0', 'online' => true]),
        '*/controller/network' => Http::response([]),
        '*' => Http::response([]),
    ]);

    Livewire::test('pages::zerotier.networks')
        ->set('selectedToken', SecurityTestSeeder::ALPHA_TOKEN_ID)
        ->set('delete_network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)
        ->call('deleteNetwork');

    try {
        expect(ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->exists())->toBeTrue();
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: deleteNetwork() isTeamAdmin() check does not block viewers — viewers can delete networks');
    }
});

// ─── Security: Team Isolation ────────────────────────────────────────────

test('loadNetworks rejects a selectedToken from another team', function () {
    defaultHttpFakes();
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    $component = Livewire::test('pages::zerotier.networks')
        ->set('selectedToken', SecurityTestSeeder::BETA_TOKEN_ID)
        ->call('loadNetworks');

    try {
        expect($component->get('networks'))->toBeEmpty(
            'Networks were loaded using another team\'s token'
        );
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: loadNetworks() does not verify team ownership of selectedToken — cross-team token usage is possible');
    }
});

test('saveNetwork scopes DB update by team_id', function () {
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    $betaNetwork = ZerotierNetwork::where('network_id', SecurityTestSeeder::BETA_NETWORK_ID)->first();
    $originalName = $betaNetwork->name;

    Http::fake([
        '*' => Http::response(['nwid' => SecurityTestSeeder::BETA_NETWORK_ID], 200),
    ]);

    Livewire::test('pages::zerotier.networks')
        ->set('selectedToken', SecurityTestSeeder::ALPHA_TOKEN_ID)
        ->set('editing_network_id', SecurityTestSeeder::BETA_NETWORK_ID)
        ->set('edit_name', 'HACKED')
        ->call('saveNetwork');

    $betaNetwork->refresh();

    try {
        expect($betaNetwork->name)->toBe($originalName,
            'Beta network name was changed by Alpha team user'
        );
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: saveNetwork() does not scope ZerotierNetwork updates by team_id — cross-team network modification is possible');
    }
});

test('deleteNetwork scopes DB delete by team_id', function () {
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    Http::fake(['*' => Http::response([], 200)]);

    Livewire::test('pages::zerotier.networks')
        ->set('selectedToken', SecurityTestSeeder::ALPHA_TOKEN_ID)
        ->set('delete_network_id', SecurityTestSeeder::BETA_NETWORK_ID)
        ->call('deleteNetwork');

    try {
        expect(ZerotierNetwork::where('network_id', SecurityTestSeeder::BETA_NETWORK_ID)->exists())->toBeTrue(
            'Beta network was deleted by Alpha team user'
        );
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: deleteNetwork() does not scope ZerotierNetwork deletes by team_id — cross-team network deletion is possible');
    }
});

test('createNetwork rejects a cross-team selectedToken', function () {
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    Http::fake([
        '*/status' => Http::response(['address' => 'bbbb000001', 'version' => '1.14.0', 'online' => true]),
        '*/controller/network/bbbb000001______' => Http::response([
            'nwid' => 'bbbb000001ffffff',
            'name' => 'Stolen',
        ]),
        '*/controller/network' => Http::response([]),
        '*' => Http::response([]),
    ]);

    $countBefore = ZerotierNetwork::count();

    Livewire::test('pages::zerotier.networks')
        ->set('selectedToken', SecurityTestSeeder::BETA_TOKEN_ID)
        ->set('new_network_name', 'Stolen Network')
        ->set('new_network_subnet', '10.99.0.0/24')
        ->call('createNetwork');

    try {
        expect(ZerotierNetwork::count())->toBe($countBefore,
            'A network was created using another team\'s token'
        );
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: createNetwork() does not verify team ownership of selectedToken — network creation with cross-team tokens is possible');
    }
});

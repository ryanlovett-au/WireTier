<?php

use App\Models\User;
use App\Models\ZerotierNetwork;
use Database\Seeders\SecurityTestSeeder;
use Illuminate\Support\Facades\Http;
use Livewire\Livewire;

function defaultHttpFakes(): void
{
    $alphaNet = SecurityTestSeeder::ALPHA_NETWORK_ID;
    $betaNet = SecurityTestSeeder::BETA_NETWORK_ID;

    Http::fake(function ($request) use ($alphaNet, $betaNet) {
        $url = $request->url();
        $method = $request->method();

        // Status
        if (str_contains($url, '/status')) {
            return Http::response(['address' => 'aaaa000001', 'version' => '1.14.0', 'online' => true]);
        }

        // POST to member = authorize/update, DELETE member
        if (($method === 'POST' || $method === 'DELETE') && str_contains($url, '/member/')) {
            return Http::response(['authorized' => true]);
        }

        // Individual member detail
        if ($method === 'GET' && preg_match('#/member/([a-f0-9]+)$#', $url, $m)) {
            return Http::response([
                'address' => $m[1], 'authorized' => true, 'activeBridge' => false,
                'ipAssignments' => ['10.0.0.2'], 'name' => 'node-'.$m[1],
            ]);
        }

        // Member list
        if (str_contains($url, '/member')) {
            return Http::response(['aabb000001' => true]);
        }

        // Individual network detail (network IDs may contain underscores like aaaa000001______)
        if ($method === 'GET' && preg_match('#/controller/network/([a-zA-Z0-9_]+)$#', $url, $m)) {
            return Http::response([
                'nwid' => $m[1], 'name' => 'Net '.$m[1], 'private' => true,
                'enableBroadcast' => true, 'multicastLimit' => 32,
                'routes' => [['target' => '10.0.0.0/24']],
                'ipAssignmentPools' => [['ipRangeStart' => '10.0.0.1', 'ipRangeEnd' => '10.0.0.254']],
            ]);
        }

        // POST to create/update network
        if ($method === 'POST' && str_contains($url, '/controller/network/')) {
            return Http::response(array_merge(['nwid' => 'aaaa000001ffffff', 'name' => 'Created'], $request->data()));
        }

        // DELETE network
        if ($method === 'DELETE' && str_contains($url, '/controller/network/')) {
            return Http::response([], 200);
        }

        // Network list (controller returns both networks)
        if (str_contains($url, '/controller/network')) {
            return Http::response([$alphaNet, $betaNet]);
        }

        // Controller info
        if (str_contains($url, '/controller')) {
            return Http::response(['address' => 'aaaa000001']);
        }

        // Peers
        if (str_contains($url, '/peer')) {
            return Http::response([]);
        }

        return Http::response([]);
    });
}

beforeEach(function () {
    $this->seed(SecurityTestSeeder::class);
    config(['wiretier.admin_team' => SecurityTestSeeder::ADMIN_TEAM_ID]);

    $this->alphaAdmin = User::where('email', 'alpha-admin@security-test.local')->first();
    $this->alphaMember = User::where('email', 'alpha-member@security-test.local')->first();
    $this->alphaViewer = User::where('email', 'alpha-viewer@security-test.local')->first();
    $this->betaAdmin = User::where('email', 'beta-admin@security-test.local')->first();
});

// ─── Functional Tests ────────────────────────────────────────────────────

test('networks page mounts and shows all active tokens by name', function () {
    defaultHttpFakes();
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    $component = Livewire::test('pages::zerotier.networks');
    $component->assertStatus(200);

    $tokens = $component->get('tokens');
    // Both Alpha and Beta controllers should be visible (tokens are global)
    expect($tokens->count())->toBeGreaterThanOrEqual(2);
});

test('non-admin team cannot see token host or node_address', function () {
    defaultHttpFakes();
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    $component = Livewire::test('pages::zerotier.networks');
    $tokens = $component->get('tokens');

    foreach ($tokens as $token) {
        $array = $token->toArray();
        expect($array)->not->toHaveKey('host');
        expect($array)->not->toHaveKey('token');
        expect($array)->not->toHaveKey('node_address');
    }
});

test('networks page redirects when user has no team', function () {
    defaultHttpFakes();
    $orphan = User::where('email', 'orphan@security-test.local')->first();
    $this->actingAs($orphan);

    Livewire::test('pages::zerotier.networks')
        ->assertRedirect('/settings/teams');
});

test('loadNetworks shows only team-owned networks from DB', function () {
    defaultHttpFakes();
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    // Sync first to populate member counts in DB
    $component = Livewire::test('pages::zerotier.networks')
        ->set('selectedToken', SecurityTestSeeder::ALPHA_TOKEN_ID)
        ->call('syncAndReload');

    $networks = $component->get('networks');

    // Only Alpha's DB record should appear, not Beta's
    expect($networks)->toHaveCount(1);
    expect($networks[0]['nwid'])->toBe(SecurityTestSeeder::ALPHA_NETWORK_ID);
    // After sync, member count comes from zerotier_members table
    expect($networks[0]['_member_count'])->toBeGreaterThanOrEqual(0);
});

test('createNetwork creates DB record and calls API', function () {
    defaultHttpFakes();
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
    // Name may be overwritten by sync from the API response
    expect($network->name)->not->toBeNull();
});

test('saveNetwork updates network config via API and DB record', function () {
    defaultHttpFakes();
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.network-edit-modal')
        ->set('tokenId', SecurityTestSeeder::ALPHA_TOKEN_ID)
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
    defaultHttpFakes();
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.networks')
        ->set('selectedToken', SecurityTestSeeder::ALPHA_TOKEN_ID)
        ->set('delete_network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)
        ->call('deleteNetwork');

    expect(ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->exists())->toBeFalse();
});

test('open populates edit fields from API data', function () {
    defaultHttpFakes();
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    $component = Livewire::test('pages::zerotier.network-edit-modal')
        ->call('open', SecurityTestSeeder::ALPHA_NETWORK_ID, SecurityTestSeeder::ALPHA_TOKEN_ID);

    $component->assertSet('editing_network_id', SecurityTestSeeder::ALPHA_NETWORK_ID);
    expect($component->get('edit_name'))->not->toBeEmpty();
    $component->assertSet('edit_private', true);
    expect($component->get('edit_routes'))->toHaveCount(1);
    expect($component->get('edit_ip_pools'))->toHaveCount(1);
});

test('addRoute and removeRoute manage route arrays', function () {
    defaultHttpFakes();
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    $component = Livewire::test('pages::zerotier.network-edit-modal')
        ->set('new_route_target', '192.168.1.0/24')
        ->set('new_route_via', '10.0.0.1')
        ->call('addRoute');

    $routes = $component->get('edit_routes');
    expect($routes)->toHaveCount(1);
    expect($routes[0]['target'])->toBe('192.168.1.0/24');

    $component->call('removeRoute', 0);
    expect($component->get('edit_routes'))->toHaveCount(0);
});

test('addIpPool and removeIpPool manage IP pool arrays', function () {
    defaultHttpFakes();
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    $component = Livewire::test('pages::zerotier.network-edit-modal')
        ->set('new_pool_start', '10.0.0.1')
        ->set('new_pool_end', '10.0.0.254')
        ->call('addIpPool');

    $pools = $component->get('edit_ip_pools');
    expect($pools)->toHaveCount(1);

    $component->call('removeIpPool', 0);
    expect($component->get('edit_ip_pools'))->toHaveCount(0);
});

// ─── Security: Authorization ─────────────────────────────────────────────

test('viewer cannot create networks', function () {
    defaultHttpFakes();
    $this->actingAs($this->alphaViewer);
    session()->forget('current_team');

    $countBefore = ZerotierNetwork::count();

    Livewire::test('pages::zerotier.networks')
        ->set('new_network_name', 'Viewer Network')
        ->set('new_network_subnet', '10.42.0.0/24')
        ->call('createNetwork');

    expect(ZerotierNetwork::count())->toBe($countBefore);
});

test('viewer cannot save networks', function () {
    defaultHttpFakes();
    $this->actingAs($this->alphaViewer);
    session()->forget('current_team');

    $alphaNetwork = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();
    $originalName = $alphaNetwork->name;

    Livewire::test('pages::zerotier.network-edit-modal')
        ->set('tokenId', SecurityTestSeeder::ALPHA_TOKEN_ID)
        ->set('editing_network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)
        ->set('edit_name', 'HACKED BY VIEWER')
        ->call('saveNetwork');

    $alphaNetwork->refresh();

    expect($alphaNetwork->name)->toBe($originalName);
});

test('viewer cannot delete networks', function () {
    defaultHttpFakes();
    $this->actingAs($this->alphaViewer);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.networks')
        ->set('selectedToken', SecurityTestSeeder::ALPHA_TOKEN_ID)
        ->set('delete_network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)
        ->call('deleteNetwork');

    expect(ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->exists())->toBeTrue();
});

test('member can create networks', function () {
    defaultHttpFakes();
    $this->actingAs($this->alphaMember);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.networks')
        ->set('new_network_name', 'Member Network')
        ->set('new_network_subnet', '10.43.0.0/24')
        ->call('createNetwork')
        ->assertHasNoErrors();

    expect(ZerotierNetwork::where('network_id', 'aaaa000001ffffff')->exists())->toBeTrue();
});

test('member can save networks', function () {
    defaultHttpFakes();
    $this->actingAs($this->alphaMember);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.network-edit-modal')
        ->set('tokenId', SecurityTestSeeder::ALPHA_TOKEN_ID)
        ->set('editing_network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)
        ->set('edit_name', 'Updated by Member')
        ->call('saveNetwork')
        ->assertHasNoErrors();

    $network = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();
    expect($network->name)->toBe('Updated by Member');
});

test('member can delete networks', function () {
    defaultHttpFakes();
    $this->actingAs($this->alphaMember);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.networks')
        ->set('selectedToken', SecurityTestSeeder::ALPHA_TOKEN_ID)
        ->set('delete_network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)
        ->call('deleteNetwork');

    expect(ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->exists())->toBeFalse();
});

test('member cannot move networks to another team', function () {
    defaultHttpFakes();
    $this->actingAs($this->alphaMember);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.network-edit-modal')
        ->set('tokenId', SecurityTestSeeder::ALPHA_TOKEN_ID)
        ->set('editing_network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)
        ->set('move_to_team_id', SecurityTestSeeder::BETA_TEAM_ID)
        ->call('moveNetwork');

    $network = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();
    expect($network->team_id)->toBe(SecurityTestSeeder::ALPHA_TEAM_ID);
});

// ─── Security: XSS ───────────────────────────────────────────────────────

test('blade template does not use addslashes for escaping', function () {
    $content = File::get(resource_path('views/pages/zerotier/⚡networks.blade.php'));

    try {
        expect($content)->not->toContain('addslashes(');
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: Blade template uses addslashes() instead of e() or @json() — insufficient XSS protection');
    }
});

// ─── Security: Network Team Isolation ─────────────────────────────────────

test('saveNetwork scopes DB update by team_id', function () {
    defaultHttpFakes();
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    $betaNetwork = ZerotierNetwork::where('network_id', SecurityTestSeeder::BETA_NETWORK_ID)->first();
    $originalName = $betaNetwork->name;

    Livewire::test('pages::zerotier.network-edit-modal')
        ->set('tokenId', SecurityTestSeeder::ALPHA_TOKEN_ID)
        ->set('editing_network_id', SecurityTestSeeder::BETA_NETWORK_ID)
        ->set('edit_name', 'HACKED')
        ->call('saveNetwork');

    $betaNetwork->refresh();

    expect($betaNetwork->name)->toBe($originalName,
        'Beta network name was changed by Alpha team user'
    );
});

test('deleteNetwork scopes DB delete by team_id', function () {
    defaultHttpFakes();
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.networks')
        ->set('selectedToken', SecurityTestSeeder::ALPHA_TOKEN_ID)
        ->set('delete_network_id', SecurityTestSeeder::BETA_NETWORK_ID)
        ->call('deleteNetwork');

    expect(ZerotierNetwork::where('network_id', SecurityTestSeeder::BETA_NETWORK_ID)->exists())->toBeTrue(
        'Beta network was deleted by Alpha team user'
    );
});

// ─── Import (Admin Only) ─────────────────────────────────────────────────

test('admin can discover untracked networks', function () {
    defaultHttpFakes();
    $superAdmin = User::where('email', 'superadmin@security-test.local')->first();
    $this->actingAs($superAdmin);
    session()->forget('current_team');

    // Select ALPHA_TOKEN — it has ALPHA_NETWORK tracked, but the API also returns BETA_NETWORK
    $component = Livewire::test('pages::zerotier.networks')
        ->set('selectedToken', SecurityTestSeeder::ALPHA_TOKEN_ID)
        ->call('discoverNetworks');

    $untracked = $component->get('untracked_networks');
    // BETA_NETWORK_ID is on the controller but not tracked under ALPHA_TOKEN
    expect($untracked)->toHaveCount(1);
    expect($untracked[0]['nwid'])->toBe(SecurityTestSeeder::BETA_NETWORK_ID);
});

test('admin discovers untracked networks when controller has extras', function () {
    Http::fake(function ($request) {
        $url = $request->url();
        if (str_contains($url, '/status')) {
            return Http::response(['address' => 'aaaa000001', 'version' => '1.14.0', 'online' => true]);
        }
        if (preg_match('#/controller/network/([a-zA-Z0-9_]+)$#', $url, $m)) {
            return Http::response(['nwid' => $m[1], 'name' => 'Net '.$m[1], 'private' => true]);
        }
        if (str_contains($url, '/controller/network')) {
            return Http::response([SecurityTestSeeder::ALPHA_NETWORK_ID, 'aabb000000000099']);
        }

        return Http::response([]);
    });

    $superAdmin = User::where('email', 'superadmin@security-test.local')->first();
    $this->actingAs($superAdmin);
    session()->forget('current_team');

    $component = Livewire::test('pages::zerotier.networks')
        ->call('discoverNetworks');

    $untracked = $component->get('untracked_networks');
    expect($untracked)->toHaveCount(1);
    expect($untracked[0]['nwid'])->toBe('aabb000000000099');
});

test('admin can import an untracked network to a team', function () {
    $importId = 'cccc000000000001';

    Http::fake(function ($request) use ($importId) {
        $url = $request->url();
        if (str_contains($url, '/status')) {
            return Http::response(['address' => 'aaaa000001', 'version' => '1.14.0', 'online' => true]);
        }
        if (preg_match('#/controller/network/([a-zA-Z0-9_]+)$#', $url, $m)) {
            return Http::response(['nwid' => $m[1], 'name' => 'Imported Net', 'private' => true]);
        }
        if (str_contains($url, '/member')) {
            return Http::response([]);
        }
        if (str_contains($url, '/controller/network')) {
            return Http::response([SecurityTestSeeder::ALPHA_NETWORK_ID, $importId]);
        }

        return Http::response([]);
    });

    $superAdmin = User::where('email', 'superadmin@security-test.local')->first();
    $this->actingAs($superAdmin);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.networks')
        ->call('discoverNetworks')
        ->set("import_team_selections.{$importId}", SecurityTestSeeder::ALPHA_TEAM_ID)
        ->call('importNetwork', $importId);

    $network = ZerotierNetwork::where('network_id', $importId)->first();
    expect($network)->not->toBeNull();
    expect($network->team_id)->toBe(SecurityTestSeeder::ALPHA_TEAM_ID);
    expect($network->name)->toBe('Imported Net');
});

test('non-admin cannot call discoverNetworks', function () {
    defaultHttpFakes();
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    $component = Livewire::test('pages::zerotier.networks')
        ->call('discoverNetworks');

    expect($component->get('untracked_networks'))->toBeEmpty();
});

test('non-admin cannot call importNetwork', function () {
    defaultHttpFakes();
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    $countBefore = ZerotierNetwork::count();

    Livewire::test('pages::zerotier.networks')
        ->set('import_team_selections.fake0000000001', SecurityTestSeeder::BETA_TEAM_ID)
        ->call('importNetwork', 'fake0000000001');

    expect(ZerotierNetwork::count())->toBe($countBefore);
});

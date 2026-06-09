<?php

use App\Models\User;
use App\Models\ZerotierMember;
use App\Models\ZerotierNetwork;
use Database\Seeders\SecurityTestSeeder;
use Illuminate\Support\Facades\Http;
use Livewire\Livewire;

function membersHttpFakes(?object $tracker = null): void
{
    $memberData = [
        'address' => 'aabb000001', 'authorized' => true, 'activeBridge' => false,
        'noAutoAssignIps' => false, 'ipAssignments' => ['10.0.0.2'], 'name' => 'test-node',
    ];

    Http::fake(function ($request) use ($memberData, $tracker) {
        $url = $request->url();
        $method = $request->method();

        // POST to member = authorize/deauthorize/update
        if ($method === 'POST' && str_contains($url, '/member/')) {
            if ($tracker) {
                $tracker->called = true;
            }

            return Http::response(array_merge($memberData, $request->data()));
        }
        // DELETE member
        if ($method === 'DELETE' && str_contains($url, '/member/')) {
            if ($tracker) {
                $tracker->called = true;
            }

            return Http::response([], 200);
        }
        // GET individual member (must come before generic /member check)
        if ($method === 'GET' && preg_match('#/member/[a-f0-9]+$#', $url)) {
            return Http::response($memberData);
        }
        // GET member list
        if (str_contains($url, '/member')) {
            return Http::response(['aabb000001' => true]);
        }
        // GET network detail
        if (str_contains($url, '/controller/network/')) {
            return Http::response([
                'nwid' => SecurityTestSeeder::ALPHA_NETWORK_ID, 'name' => 'Alpha Net', 'private' => true,
            ]);
        }
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

test('members page mounts with valid token and network', function () {
    membersHttpFakes();
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    $component = Livewire::test('pages::zerotier.members', [
        'networkId' => SecurityTestSeeder::ALPHA_NETWORK_ID,
        'tokenId' => SecurityTestSeeder::ALPHA_TOKEN_ID,
    ]);

    $component->assertStatus(200);
    $component->assertSet('networkId', SecurityTestSeeder::ALPHA_NETWORK_ID);
    $component->assertSet('tokenId', SecurityTestSeeder::ALPHA_TOKEN_ID);
});

test('members page redirects when user has no team', function () {
    membersHttpFakes();
    $orphan = User::where('email', 'orphan@security-test.local')->first();
    $this->actingAs($orphan);

    Livewire::test('pages::zerotier.members', [
        'networkId' => SecurityTestSeeder::ALPHA_NETWORK_ID,
        'tokenId' => SecurityTestSeeder::ALPHA_TOKEN_ID,
    ])->assertRedirect('/settings/teams');
});

test('loadMembers shows synced members from DB', function () {
    membersHttpFakes();
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    // Sync first to populate members in DB
    $component = Livewire::test('pages::zerotier.members', [
        'networkId' => SecurityTestSeeder::ALPHA_NETWORK_ID,
        'tokenId' => SecurityTestSeeder::ALPHA_TOKEN_ID,
    ])->call('syncAndReload');

    $members = $component->get('members');
    expect($members)->not->toBeEmpty();
    expect($members[0]['address'])->toBe('aabb000001');
});

test('authorizeMember calls API to authorize', function () {
    $tracker = (object) ['called' => false];
    membersHttpFakes($tracker);

    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.members', [
        'networkId' => SecurityTestSeeder::ALPHA_NETWORK_ID,
        'tokenId' => SecurityTestSeeder::ALPHA_TOKEN_ID,
    ])->call('authorizeMember', 'aabb000001');

    expect($tracker->called)->toBeTrue();
});

test('deauthorizeMember calls API to deauthorize', function () {
    $tracker = (object) ['called' => false];
    membersHttpFakes($tracker);

    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.members', [
        'networkId' => SecurityTestSeeder::ALPHA_NETWORK_ID,
        'tokenId' => SecurityTestSeeder::ALPHA_TOKEN_ID,
    ])->call('deauthorizeMember', 'aabb000001');

    expect($tracker->called)->toBeTrue();
});

test('deleteMember calls API to delete', function () {
    $tracker = (object) ['called' => false];
    membersHttpFakes($tracker);

    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.members', [
        'networkId' => SecurityTestSeeder::ALPHA_NETWORK_ID,
        'tokenId' => SecurityTestSeeder::ALPHA_TOKEN_ID,
    ])
        ->set('delete_member_id', 'aabb000001')
        ->call('deleteMember');

    expect($tracker->called)->toBeTrue();
});

test('editMemberModal populates edit fields from DB', function () {
    membersHttpFakes();
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    // Sync to populate members in DB first
    $component = Livewire::test('pages::zerotier.members', [
        'networkId' => SecurityTestSeeder::ALPHA_NETWORK_ID,
        'tokenId' => SecurityTestSeeder::ALPHA_TOKEN_ID,
    ])->call('syncAndReload')
        ->call('editMemberModal', 'aabb000001');

    $component->assertSet('edit_member_id', 'aabb000001');
    $component->assertSet('edit_member_description', '');
    expect($component->get('edit_ip_assignments'))->toBe(['10.0.0.2']);
});

test('saveMember updates name and description', function () {
    $tracker = (object) ['called' => false];
    membersHttpFakes($tracker);

    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    $component = Livewire::test('pages::zerotier.members', [
        'networkId' => SecurityTestSeeder::ALPHA_NETWORK_ID,
        'tokenId' => SecurityTestSeeder::ALPHA_TOKEN_ID,
    ])->call('syncAndReload')
        ->call('editMemberModal', 'aabb000001')
        ->set('edit_member_name', 'Ryans Laptop')
        ->set('edit_member_description', 'Primary dev machine')
        ->call('saveMember');

    // Name should be pushed to API
    expect($tracker->called)->toBeTrue();

    // Description should be saved locally in DB
    $dbNetwork = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();
    $member = ZerotierMember::where('zerotier_network_id', $dbNetwork->id)
        ->where('node_id', 'aabb000001')
        ->first();

    expect($member->description)->toBe('Primary dev machine');
});

test('addIpAssignment and removeIpAssignment manage IP arrays', function () {
    membersHttpFakes();
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    $component = Livewire::test('pages::zerotier.members', [
        'networkId' => SecurityTestSeeder::ALPHA_NETWORK_ID,
        'tokenId' => SecurityTestSeeder::ALPHA_TOKEN_ID,
    ]);

    $component->set('new_ip', '10.0.0.99')->call('addIpAssignment');
    expect($component->get('edit_ip_assignments'))->toContain('10.0.0.99');

    $index = array_search('10.0.0.99', $component->get('edit_ip_assignments'));
    $component->call('removeIpAssignment', $index);
    expect($component->get('edit_ip_assignments'))->not->toContain('10.0.0.99');
});

// ─── Security: Network Team Isolation ─────────────────────────────────────

test('members page mount rejects a network not owned by the team', function () {
    membersHttpFakes();
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    // Alpha admin tries to access Beta's network — should get 403
    Livewire::test('pages::zerotier.members', [
        'networkId' => SecurityTestSeeder::BETA_NETWORK_ID,
        'tokenId' => SecurityTestSeeder::BETA_TOKEN_ID,
    ])->assertStatus(403);
});

// ─── Security: Authorization ─────────────────────────────────────────────

test('viewer cannot authorize members', function () {
    $tracker = (object) ['called' => false];
    membersHttpFakes($tracker);

    $this->actingAs($this->alphaViewer);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.members', [
        'networkId' => SecurityTestSeeder::ALPHA_NETWORK_ID,
        'tokenId' => SecurityTestSeeder::ALPHA_TOKEN_ID,
    ])->call('authorizeMember', 'aabb000001');

    expect($tracker->called)->toBeFalse('Viewer was able to authorize a member');
});

test('viewer cannot deauthorize members', function () {
    $tracker = (object) ['called' => false];
    membersHttpFakes($tracker);

    $this->actingAs($this->alphaViewer);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.members', [
        'networkId' => SecurityTestSeeder::ALPHA_NETWORK_ID,
        'tokenId' => SecurityTestSeeder::ALPHA_TOKEN_ID,
    ])->call('deauthorizeMember', 'aabb000001');

    expect($tracker->called)->toBeFalse('Viewer was able to deauthorize a member');
});

test('viewer cannot delete members', function () {
    $tracker = (object) ['called' => false];
    membersHttpFakes($tracker);

    $this->actingAs($this->alphaViewer);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.members', [
        'networkId' => SecurityTestSeeder::ALPHA_NETWORK_ID,
        'tokenId' => SecurityTestSeeder::ALPHA_TOKEN_ID,
    ])
        ->set('delete_member_id', 'aabb000001')
        ->call('deleteMember');

    expect($tracker->called)->toBeFalse('Viewer was able to delete a member');
});

test('viewer cannot open edit member modal', function () {
    membersHttpFakes();
    $this->actingAs($this->alphaViewer);
    session()->forget('current_team');

    $component = Livewire::test('pages::zerotier.members', [
        'networkId' => SecurityTestSeeder::ALPHA_NETWORK_ID,
        'tokenId' => SecurityTestSeeder::ALPHA_TOKEN_ID,
    ])->call('syncAndReload')
        ->call('editMemberModal', 'aabb000001');

    $component->assertSet('edit_member_id', '');
});

test('viewer cannot open delete member modal', function () {
    membersHttpFakes();
    $this->actingAs($this->alphaViewer);
    session()->forget('current_team');

    $component = Livewire::test('pages::zerotier.members', [
        'networkId' => SecurityTestSeeder::ALPHA_NETWORK_ID,
        'tokenId' => SecurityTestSeeder::ALPHA_TOKEN_ID,
    ])->call('confirmDeleteMember', 'aabb000001');

    $component->assertSet('delete_member_id', '');
});

test('member can authorize members', function () {
    $tracker = (object) ['called' => false];
    membersHttpFakes($tracker);

    $this->actingAs($this->alphaMember);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.members', [
        'networkId' => SecurityTestSeeder::ALPHA_NETWORK_ID,
        'tokenId' => SecurityTestSeeder::ALPHA_TOKEN_ID,
    ])->call('authorizeMember', 'aabb000001');

    expect($tracker->called)->toBeTrue();
});

test('member can delete members', function () {
    $tracker = (object) ['called' => false];
    membersHttpFakes($tracker);

    $this->actingAs($this->alphaMember);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.members', [
        'networkId' => SecurityTestSeeder::ALPHA_NETWORK_ID,
        'tokenId' => SecurityTestSeeder::ALPHA_TOKEN_ID,
    ])
        ->set('delete_member_id', 'aabb000001')
        ->call('deleteMember');

    expect($tracker->called)->toBeTrue();
});

test('member can edit members', function () {
    $tracker = (object) ['called' => false];
    membersHttpFakes($tracker);

    $this->actingAs($this->alphaMember);
    session()->forget('current_team');

    $component = Livewire::test('pages::zerotier.members', [
        'networkId' => SecurityTestSeeder::ALPHA_NETWORK_ID,
        'tokenId' => SecurityTestSeeder::ALPHA_TOKEN_ID,
    ])->call('syncAndReload')
        ->call('editMemberModal', 'aabb000001')
        ->set('edit_member_name', 'Member-set name')
        ->call('saveMember');

    expect($tracker->called)->toBeTrue();
});

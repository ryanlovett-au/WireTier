<?php

use App\Models\AuditLog;
use App\Models\User;
use App\Models\ZerotierMember;
use App\Models\ZerotierNetwork;
use App\Services\ZerotierSyncService;
use Database\Seeders\SecurityTestSeeder;
use Illuminate\Support\Facades\Http;
use Livewire\Features\SupportTesting\Testable;
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

// ─── Payload validation ──────────────────────────────────────────────────

test('saveMember rejects IP assignments that are not IP addresses', function () {
    $tracker = new stdClass;
    $tracker->called = false;
    membersHttpFakes($tracker);
    $this->actingAs($this->alphaAdmin);
    ZerotierSyncService::syncNetwork(ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first(), force: true);

    Livewire::test('pages::zerotier.members', [
        'networkId' => SecurityTestSeeder::ALPHA_NETWORK_ID,
        'tokenId' => SecurityTestSeeder::ALPHA_TOKEN_ID,
    ])
        ->call('editMemberModal', 'aabb000001')
        // A client can set the public array directly, bypassing addIpAssignment().
        ->set('edit_ip_assignments', ['10.0.0.2', '10.0.0.999', 'evil"; drop'])
        ->call('saveMember')
        ->assertHasErrors(['edit_ip_assignments.1', 'edit_ip_assignments.2']);

    expect($tracker->called)->toBeFalse();
});

test('addIpAssignment only accepts IP addresses', function () {
    membersHttpFakes();
    $this->actingAs($this->alphaAdmin);

    Livewire::test('pages::zerotier.members', [
        'networkId' => SecurityTestSeeder::ALPHA_NETWORK_ID,
        'tokenId' => SecurityTestSeeder::ALPHA_TOKEN_ID,
    ])
        ->set('new_ip', 'not-an-ip')
        ->call('addIpAssignment')
        ->assertHasErrors('new_ip')
        ->assertSet('edit_ip_assignments', [])
        ->set('new_ip', '10.0.0.9')
        ->call('addIpAssignment')
        ->assertHasNoErrors()
        ->assertSet('edit_ip_assignments', ['10.0.0.9']);
});

// ─── Add (pre-authorise) member ──────────────────────────────────────────

/** A controller whose member list grows as members are posted; returns the posted payloads. */
function preauthControllerFake(): ArrayObject
{
    $members = new ArrayObject(['aabb000001' => ['address' => 'aabb000001', 'authorized' => true, 'ipAssignments' => ['10.0.0.2'], 'name' => 'test-node']]);
    $posts = new ArrayObject;

    Http::fake(function ($request) use ($members, $posts) {
        $url = $request->url();

        if ($request->method() === 'POST' && preg_match('#/member/([a-f0-9]+)$#', $url, $m)) {
            $posts[$m[1]] = $request->data();
            $members[$m[1]] = array_merge(['address' => $m[1], 'authorized' => false, 'ipAssignments' => [], 'name' => ''], $members[$m[1]] ?? [], $request->data());

            return Http::response($members[$m[1]]);
        }
        if (preg_match('#/member/([a-f0-9]+)$#', $url, $m)) {
            return Http::response($members[$m[1]] ?? [], isset($members[$m[1]]) ? 200 : 404);
        }
        if (str_contains($url, '/member')) {
            return Http::response(array_fill_keys(array_keys($members->getArrayCopy()), 1));
        }
        if (str_contains($url, '/controller/network/')) {
            return Http::response(['nwid' => SecurityTestSeeder::ALPHA_NETWORK_ID, 'name' => 'Alpha Net', 'private' => true]);
        }

        return Http::response([]);
    });

    return $posts;
}

function alphaMembersPage(): Testable
{
    return Livewire::test('pages::zerotier.members', [
        'networkId' => SecurityTestSeeder::ALPHA_NETWORK_ID,
        'tokenId' => SecurityTestSeeder::ALPHA_TOKEN_ID,
    ]);
}

test('a member can be authorised by node ID before the device joins', function () {
    $posts = preauthControllerFake();
    $this->actingAs($this->alphaMember);

    $page = alphaMembersPage()
        ->call('addMemberModal')
        ->set('add_member_id', ' A1B2C3D4E5 ')
        ->set('add_member_name', 'Field laptop')
        ->set('add_member_description', 'Issued to the night shift')
        ->set('add_member_ip', '10.0.0.50')
        ->call('addMember')
        ->assertHasNoErrors()
        ->assertSet('add_member_id', '');

    expect($posts['a1b2c3d4e5'])->toBe(['authorized' => true, 'name' => 'Field laptop', 'ipAssignments' => ['10.0.0.50']]);

    $network = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();
    $member = ZerotierMember::where('zerotier_network_id', $network->id)->where('node_id', 'a1b2c3d4e5')->first();
    expect($member->authorised)->toBeTrue();
    expect($member->description)->toBe('Issued to the night shift');
    expect(collect($page->get('members'))->pluck('address'))->toContain('a1b2c3d4e5');
    expect(AuditLog::where('action', 'member.preauthorised')->where('resource_id', 'a1b2c3d4e5')->exists())->toBeTrue();
});

test('the IP is optional so the controller can auto-assign one', function () {
    $posts = preauthControllerFake();
    $this->actingAs($this->alphaAdmin);

    alphaMembersPage()->set('add_member_id', 'a1b2c3d4e5')->call('addMember')->assertHasNoErrors();

    expect($posts['a1b2c3d4e5'])->toBe(['authorized' => true, 'name' => '']);
});

test('adding a member rejects invalid node IDs, IPs and existing members', function (string $field, string $value) {
    $posts = preauthControllerFake();
    $this->actingAs($this->alphaAdmin);
    ZerotierSyncService::syncNetwork(ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first(), force: true);

    alphaMembersPage()
        ->set('add_member_id', 'a1b2c3d4e5')
        ->set($field, $value)
        ->call('addMember')
        ->assertHasErrors($field);

    expect($posts->count())->toBe(0);
})->with([
    'too short' => ['add_member_id', 'a1b2c3'],
    'not hex' => ['add_member_id', 'a1b2c3d4zz'],
    'reserved prefix' => ['add_member_id', 'ff12345678'],
    'all zero' => ['add_member_id', '0000000000'],
    'path characters' => ['add_member_id', '../../../x'],
    'already a member' => ['add_member_id', 'aabb000001'],
    'bad IP' => ['add_member_ip', '10.0.0.999'],
]);

test('viewers cannot add members', function () {
    $posts = preauthControllerFake();
    $this->actingAs($this->alphaViewer);

    alphaMembersPage()->set('add_member_id', 'a1b2c3d4e5')->call('addMember');

    expect($posts->count())->toBe(0);
});

test('another team cannot add members to this network', function () {
    $posts = preauthControllerFake();
    $this->actingAs($this->betaAdmin);

    alphaMembersPage()->assertStatus(403);
    expect($posts->count())->toBe(0);
});

<?php

use App\Models\AuditLog;
use App\Models\Team;
use App\Models\TeamUser;
use App\Models\User;
use Database\Seeders\SecurityTestSeeder;
use Illuminate\Support\Facades\Http;
use Livewire\Livewire;

function auditHttpFakes(): void
{
    Http::fake(function ($request) {
        $url = $request->url();
        $method = $request->method();

        if (str_contains($url, '/status')) {
            return Http::response(['address' => 'aaaa000001', 'version' => '1.14.0', 'online' => true]);
        }
        if ($method === 'GET' && preg_match('#/member/([a-f0-9]+)$#', $url, $m)) {
            return Http::response(['address' => $m[1], 'authorized' => true, 'ipAssignments' => ['10.0.0.2']]);
        }
        if (str_contains($url, '/member')) {
            return Http::response(['aabb000001' => true]);
        }
        if ($method === 'GET' && preg_match('#/controller/network/([a-zA-Z0-9_]+)$#', $url, $m)) {
            return Http::response(['nwid' => $m[1], 'name' => 'Net', 'private' => true]);
        }
        if ($method === 'POST' && str_contains($url, '/controller/network/')) {
            return Http::response(['nwid' => 'aaaa000001ffffff', 'name' => 'New']);
        }
        if ($method === 'DELETE') {
            return Http::response([], 200);
        }
        if (str_contains($url, '/controller/network')) {
            return Http::response([]);
        }

        return Http::response([]);
    });
}

beforeEach(function () {
    $this->seed(SecurityTestSeeder::class);
    config(['wiretier.admin_team' => SecurityTestSeeder::ADMIN_TEAM_ID]);

    $this->superAdmin = User::where('email', 'superadmin@security-test.local')->first();
    $this->alphaAdmin = User::where('email', 'alpha-admin@security-test.local')->first();
    $this->alphaMember = User::where('email', 'alpha-member@security-test.local')->first();
});

// ─── Recording Tests ─────────────────────────────────────────────────────

test('AuditLog::record creates an entry with correct fields', function () {
    $this->actingAs($this->alphaAdmin);

    AuditLog::record('test.action', 'widget', 'widget-123', ['key' => 'value']);

    $log = AuditLog::where('action', 'test.action')->first();
    expect($log)->not->toBeNull();
    expect($log->user_id)->toBe($this->alphaAdmin->id);
    expect($log->team_id)->toBe($this->alphaAdmin->current_team);
    expect($log->resource_type)->toBe('widget');
    expect($log->resource_id)->toBe('widget-123');
    expect($log->details)->toBe(['key' => 'value']);
    expect($log->ip_address)->not->toBeNull();
});

test('token creation is logged', function () {
    auditHttpFakes();
    $this->actingAs($this->superAdmin);

    Livewire::test('pages::zerotier.tokens')
        ->set('new_name', 'Logged Token')
        ->set('new_token', 'secret')
        ->set('new_host', 'http://10.0.0.1:9993')
        ->call('addToken');

    $log = AuditLog::where('action', 'token.created')->first();
    expect($log)->not->toBeNull();
    expect($log->details['name'])->toBe('Logged Token');
});

test('network creation is logged', function () {
    auditHttpFakes();
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.networks')
        ->set('new_network_name', 'Logged Network')
        ->set('new_network_subnet', '10.50.0.0/24')
        ->call('createNetwork');

    $log = AuditLog::where('action', 'network.created')->first();
    expect($log)->not->toBeNull();
    expect($log->details['name'])->toBe('Logged Network');
    expect($log->team_id)->toBe(SecurityTestSeeder::ALPHA_TEAM_ID);
});

test('member authorization is logged', function () {
    auditHttpFakes();
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.members', [
        'networkId' => SecurityTestSeeder::ALPHA_NETWORK_ID,
        'tokenId' => SecurityTestSeeder::ALPHA_TOKEN_ID,
    ])->call('authorizeMember', 'aabb000001');

    $log = AuditLog::where('action', 'member.authorised')->first();
    expect($log)->not->toBeNull();
    expect($log->resource_id)->toBe('aabb000001');
    expect($log->details['network_id'])->toBe(SecurityTestSeeder::ALPHA_NETWORK_ID);
});

test('team role change is logged', function () {
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    $memberTu = TeamUser::where('user_id', $this->alphaMember->id)
        ->where('team_id', SecurityTestSeeder::ALPHA_TEAM_ID)->first();

    Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ALPHA_TEAM_ID])
        ->call('changeRoleModal', $memberTu->toArray())
        ->set('change_user_role', 'viewer')
        ->call('changeRole');

    $log = AuditLog::where('action', 'team.role_changed')->first();
    expect($log)->not->toBeNull();
    expect($log->details['new_role'])->toBe('viewer');
});

test('team settings view is logged', function () {
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ALPHA_TEAM_ID]);

    $log = AuditLog::where('action', 'team.settings_viewed')->first();
    expect($log)->not->toBeNull();
    expect($log->resource_id)->toBe(SecurityTestSeeder::ALPHA_TEAM_ID);
});

test('member list view is logged', function () {
    auditHttpFakes();
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.members', [
        'networkId' => SecurityTestSeeder::ALPHA_NETWORK_ID,
        'tokenId' => SecurityTestSeeder::ALPHA_TOKEN_ID,
    ]);

    $log = AuditLog::where('action', 'member.list_viewed')->first();
    expect($log)->not->toBeNull();
    expect($log->resource_id)->toBe(SecurityTestSeeder::ALPHA_NETWORK_ID);
});

// ─── Viewer Access Tests ─────────────────────────────────────────────────

test('team admin can access audit log page', function () {
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    Livewire::test('pages::settings.audit-log')
        ->assertStatus(200);
});

test('system admin can access audit log page', function () {
    $this->actingAs($this->superAdmin);

    Livewire::test('pages::settings.audit-log')
        ->assertStatus(200);
});

test('regular member cannot access audit log page', function () {
    $this->actingAs($this->alphaMember);
    session()->forget('current_team');

    Livewire::test('pages::settings.audit-log')
        ->assertStatus(403);
});

// ─── Viewer Scoping Tests ────────────────────────────────────────────────

test('team admin only sees their team logs', function () {
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    // Create logs for both teams
    AuditLog::record('test.alpha', teamId: SecurityTestSeeder::ALPHA_TEAM_ID);

    $this->actingAs($this->superAdmin);
    AuditLog::record('test.admin', teamId: SecurityTestSeeder::ADMIN_TEAM_ID);

    // Alpha admin should only see Alpha team logs
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    $component = Livewire::test('pages::settings.audit-log');
    $logs = $component->get('logs');

    foreach ($logs as $log) {
        expect($log->team_id)->toBe(SecurityTestSeeder::ALPHA_TEAM_ID);
    }
});

test('system admin sees all logs', function () {
    $this->actingAs($this->alphaAdmin);
    AuditLog::record('test.alpha', teamId: SecurityTestSeeder::ALPHA_TEAM_ID);

    $this->actingAs($this->superAdmin);
    AuditLog::record('test.admin', teamId: SecurityTestSeeder::ADMIN_TEAM_ID);

    $component = Livewire::test('pages::settings.audit-log');
    $logs = $component->get('logs');

    $teamIds = collect($logs->items())->pluck('team_id')->unique()->toArray();
    expect(count($teamIds))->toBeGreaterThanOrEqual(2);
});

// ─── Filter Tests ────────────────────────────────────────────────────────

test('action filter works', function () {
    $this->actingAs($this->superAdmin);
    AuditLog::record('network.created', teamId: SecurityTestSeeder::ADMIN_TEAM_ID);
    AuditLog::record('team.updated', teamId: SecurityTestSeeder::ADMIN_TEAM_ID);

    $component = Livewire::test('pages::settings.audit-log')
        ->set('filter_action', 'network');

    $logs = $component->get('logs');
    foreach ($logs as $log) {
        expect($log->action)->toStartWith('network');
    }
});

test('search filter works', function () {
    $this->actingAs($this->superAdmin);
    AuditLog::record('network.created', 'network', 'unique-search-id-xyz', teamId: SecurityTestSeeder::ADMIN_TEAM_ID);
    AuditLog::record('team.updated', teamId: SecurityTestSeeder::ADMIN_TEAM_ID);

    $component = Livewire::test('pages::settings.audit-log')
        ->set('filter_search', 'unique-search-id-xyz');

    $logs = $component->get('logs');
    expect($logs->total())->toBe(1);
});

test('clear filters resets all filters', function () {
    $this->actingAs($this->superAdmin);

    $component = Livewire::test('pages::settings.audit-log')
        ->set('filter_action', 'network')
        ->set('filter_search', 'something')
        ->call('clearFilters');

    $component->assertSet('filter_action', '');
    $component->assertSet('filter_search', '');
});

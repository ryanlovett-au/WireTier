<?php

use App\Models\User;
use Database\Seeders\SecurityTestSeeder;
use Illuminate\Support\Facades\Http;
use Livewire\Livewire;

beforeEach(function () {
    $this->seed(SecurityTestSeeder::class);
    config(['wiretier.admin_team' => SecurityTestSeeder::ADMIN_TEAM_ID]);

    Http::fake(function ($request) {
        $url = $request->url();
        if (str_contains($url, '/status')) {
            return Http::response(['address' => 'aaaa000001', 'version' => '1.14.0', 'online' => true]);
        }
        if (preg_match('#/member/([a-f0-9]+)$#', $url, $m)) {
            return Http::response([
                'address' => $m[1], 'authorized' => true, 'ipAssignments' => ['10.0.0.2'],
                'name' => 'node', 'activeBridge' => false, 'noAutoAssignIps' => false,
            ]);
        }
        if (str_contains($url, '/member')) {
            return Http::response(['aabb000001' => true]);
        }
        if (preg_match('#/controller/network/([a-zA-Z0-9_]+)$#', $url, $m)) {
            return Http::response(['nwid' => $m[1], 'name' => 'Net', 'private' => true, 'routes' => []]);
        }
        if (str_contains($url, '/controller/network')) {
            return Http::response([]);
        }
        if (str_contains($url, '/peer')) {
            return Http::response([]);
        }

        return Http::response([]);
    });

    $this->superAdmin = User::where('email', 'superadmin@security-test.local')->first();
    $this->alphaAdmin = User::where('email', 'alpha-admin@security-test.local')->first();
    $this->alphaMember = User::where('email', 'alpha-member@security-test.local')->first();
    $this->alphaViewer = User::where('email', 'alpha-viewer@security-test.local')->first();
    $this->orphan = User::where('email', 'orphan@security-test.local')->first();
});

// ─── Dashboard ───────────────────────────────────────────────────────────

test('dashboard renders for user with team', function () {
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    Livewire::test('pages::dashboard')->assertStatus(200);
});

test('dashboard renders for user without team', function () {
    $this->actingAs($this->orphan);

    Livewire::test('pages::dashboard')->assertStatus(200);
});

test('dashboard renders for admin with untracked networks', function () {
    $this->actingAs($this->superAdmin);

    Livewire::test('pages::dashboard')->assertStatus(200);
});

// ─── ZeroTier Pages ──────────────────────────────────────────────────────

test('tokens page renders for admin', function () {
    $this->actingAs($this->superAdmin);

    Livewire::test('pages::zerotier.tokens')->assertStatus(200);
});

test('networks page renders for team admin', function () {
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.networks')->assertStatus(200);
});

test('networks page renders for team member', function () {
    $this->actingAs($this->alphaMember);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.networks')->assertStatus(200);
});

test('networks page renders for team viewer', function () {
    $this->actingAs($this->alphaViewer);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.networks')->assertStatus(200);
});

test('members page renders for team admin', function () {
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    Livewire::test('pages::zerotier.members', [
        'networkId' => SecurityTestSeeder::ALPHA_NETWORK_ID,
        'tokenId' => SecurityTestSeeder::ALPHA_TOKEN_ID,
    ])->assertStatus(200);
});

test('peers page renders for admin', function () {
    $this->actingAs($this->superAdmin);

    Livewire::test('pages::zerotier.peers')->assertStatus(200);
});

// ─── Settings Pages ──────────────────────────────────────────────────────

test('profile page renders', function () {
    $this->actingAs($this->alphaAdmin);

    Livewire::test('pages::settings.profile')->assertStatus(200);
});

test('security page renders', function () {
    $this->actingAs($this->alphaAdmin);

    Livewire::test('pages::settings.security')->assertStatus(200);
});

test('appearance page renders', function () {
    $this->actingAs($this->alphaAdmin);

    Livewire::test('pages::settings.appearance')->assertStatus(200);
});

test('teams page renders', function () {
    $this->actingAs($this->alphaAdmin);

    Livewire::test('pages::settings.teams')->assertStatus(200);
});

test('team settings page renders for team admin', function () {
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ALPHA_TEAM_ID])
        ->assertStatus(200);
});

test('team settings page renders for team member', function () {
    $this->actingAs($this->alphaMember);
    session()->forget('current_team');

    Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ALPHA_TEAM_ID])
        ->assertStatus(200);
});

test('audit log page renders for team admin', function () {
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    Livewire::test('pages::settings.audit-log')->assertStatus(200);
});

test('audit log page renders for system admin', function () {
    $this->actingAs($this->superAdmin);

    Livewire::test('pages::settings.audit-log')->assertStatus(200);
});

// ─── Auth Pages (non-Livewire, HTTP requests) ────────────────────────────

test('login page renders', function () {
    $this->get('/login')->assertStatus(200);
});

test('register page renders', function () {
    $this->get('/register')->assertStatus(200);
});

test('forgot password page renders', function () {
    $this->get('/forgot-password')->assertStatus(200);
});

test('welcome page renders', function () {
    $this->get('/')->assertStatus(200);
});

// ─── Protected Routes (HTTP) ─────────────────────────────────────────────

test('dashboard route renders for authenticated user', function () {
    $this->actingAs($this->alphaAdmin);

    $this->get('/dashboard')->assertStatus(200);
});

test('networks route renders for authenticated user', function () {
    $this->actingAs($this->alphaAdmin);

    $this->get('/zerotier/networks')->assertStatus(200);
});

test('settings profile route renders', function () {
    $this->actingAs($this->alphaAdmin);

    $this->get('/settings/profile')->assertStatus(200);
});

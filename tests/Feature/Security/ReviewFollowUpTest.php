<?php

/*
 * Regression tests for review findings: the password-reset limit, controller
 * errors on network creation, membership resolved with the current team, and
 * network caches cleared after team deletion commits.
 */

use App\Models\TeamUser;
use App\Models\User;
use App\Models\ZerotierNetwork;
use Database\Seeders\SecurityTestSeeder as S;
use Illuminate\Http\Client\RequestException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Notification;
use Livewire\Livewire;

beforeEach(function () {
    $this->seed(S::class);
    config(['wiretier.admin_team' => S::ADMIN_TEAM_ID]);

    $this->alphaAdmin = User::where('email', 'alpha-admin@security-test.local')->first();
});

test('password reset requests are limited per email even from many IPs', function () {
    Notification::fake();

    foreach (range(1, 5) as $i) {
        $this->withServerVariables(['REMOTE_ADDR' => "203.0.113.{$i}"])
            ->post('/forgot-password', ['email' => 'Alpha-Admin@security-test.local'])
            ->assertStatus(302);
    }

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.99'])
        ->post('/forgot-password', ['email' => 'alpha-admin@security-test.local'])
        ->assertStatus(429);

    // Another inbox is unaffected.
    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.99'])
        ->post('/forgot-password', ['email' => 'alpha-member@security-test.local'])
        ->assertStatus(302);
});

test('password reset requests are limited per IP across many emails', function () {
    Notification::fake();

    foreach (range(1, 20) as $i) {
        $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.7'])
            ->post('/forgot-password', ['email' => "nobody{$i}@example.com"]);
    }

    $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.7'])
        ->post('/forgot-password', ['email' => 'nobody21@example.com'])
        ->assertStatus(429);
});

test('a controller error on network creation is reported as that error and stores nothing', function () {
    Exceptions::fake();
    Http::fake(function ($request) {
        if (str_contains($request->url(), '/status')) {
            return Http::response(['address' => 'aaaa000001']);
        }
        if ($request->method() === 'POST') {
            return Http::response(['error' => 'unauthorized'], 401);
        }

        return Http::response([]);
    });
    $this->actingAs($this->alphaAdmin);
    $before = ZerotierNetwork::count();

    Livewire::test('pages::zerotier.networks')
        ->set('selectedToken', S::ALPHA_TOKEN_ID)
        ->set('new_network_name', 'Should not exist')
        ->set('new_network_subnet', '10.42.0.0/24')
        ->call('createNetwork');

    Exceptions::assertReported(RequestException::class);
    expect(ZerotierNetwork::count())->toBe($before);
});

test('role checks follow the current team when it changes on the same user instance', function () {
    // Admin of Alpha, plain member of Beta.
    TeamUser::create(['team_id' => S::BETA_TEAM_ID, 'user_id' => $this->alphaAdmin->id, 'role' => 'viewer']);
    $user = $this->alphaAdmin->fresh();

    expect($user->isTeamAdmin())->toBeTrue();
    expect($user->currentMembership()->team_id)->toBe(S::ALPHA_TEAM_ID);

    $user->current_team = S::BETA_TEAM_ID;

    expect($user->team->id)->toBe(S::BETA_TEAM_ID);
    expect($user->currentMembership()->team_id)->toBe(S::BETA_TEAM_ID);
    expect($user->isTeamAdmin())->toBeFalse();
    expect($user->canManageNetworks())->toBeFalse();
});

test('deleting a team clears its cached network list once the deletion commits', function () {
    Http::fake(fn () => Http::response([]));
    $this->actingAs($this->alphaAdmin);
    $key = 'team_'.S::ALPHA_TEAM_ID.'_networks_'.S::ALPHA_TOKEN_ID;
    Cache::put($key, ['stale'], 60);
    Cache::put('zt_controller_networks_'.S::ALPHA_TOKEN_ID, ['ok' => true, 'ids' => [], 'at' => now()], 60);

    Livewire::test('pages::settings.team', ['id' => S::ALPHA_TEAM_ID])->call('deleteTeam');

    expect(Cache::has($key))->toBeFalse();
    expect(Cache::has('zt_controller_networks_'.S::ALPHA_TOKEN_ID))->toBeFalse();
});

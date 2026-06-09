<?php

use App\Models\AuditLog;
use App\Models\Team;
use App\Models\TeamInvitation;
use App\Models\ZerotierNetwork;
use App\Models\ZerotierToken;
use Database\Seeders\SecurityTestSeeder;
use Illuminate\Database\Eloquent\Collection;

beforeEach(fn () => $this->seed(SecurityTestSeeder::class));

test('AuditLog belongs to team', function () {
    $log = AuditLog::record('test', teamId: SecurityTestSeeder::ALPHA_TEAM_ID);
    expect($log->team)->toBeInstanceOf(Team::class);
    expect($log->team->id)->toBe(SecurityTestSeeder::ALPHA_TEAM_ID);
});

test('Team does not have zerotierTokens relationship (tokens are global)', function () {
    $team = Team::find(SecurityTestSeeder::ADMIN_TEAM_ID);
    expect(method_exists($team, 'zerotierTokens'))->toBeFalse();
});

test('TeamInvitation belongs to team', function () {
    $invitation = TeamInvitation::create([
        'team_id' => SecurityTestSeeder::ALPHA_TEAM_ID,
        'email' => 'rel-test@test.local',
        'role' => 'member',
    ]);
    expect($invitation->team)->toBeInstanceOf(Team::class);
    expect($invitation->team->id)->toBe(SecurityTestSeeder::ALPHA_TEAM_ID);
});

test('ZerotierNetwork belongs to team', function () {
    $network = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();
    expect($network->team)->toBeInstanceOf(Team::class);
    expect($network->team->id)->toBe(SecurityTestSeeder::ALPHA_TEAM_ID);
});

test('ZerotierToken has networks relationship', function () {
    $token = ZerotierToken::find(SecurityTestSeeder::ALPHA_TOKEN_ID);
    expect($token->networks)->toBeInstanceOf(Collection::class);
    expect($token->networks)->not->toBeEmpty();
});

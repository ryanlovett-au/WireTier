<?php

use App\Models\Team;
use App\Models\TeamInvitation;
use App\Models\TeamUser;
use App\Models\User;
use Database\Seeders\SecurityTestSeeder;

beforeEach(fn () => $this->seed(SecurityTestSeeder::class));

test('Team has users relationship', function () {
    $team = Team::find(SecurityTestSeeder::ALPHA_TEAM_ID);
    expect($team->users)->not->toBeEmpty();
});

test('Team has teamUsers relationship', function () {
    $team = Team::find(SecurityTestSeeder::ALPHA_TEAM_ID);
    expect($team->teamUsers)->not->toBeEmpty();
});

test('Team has zerotierNetworks relationship', function () {
    $team = Team::find(SecurityTestSeeder::ALPHA_TEAM_ID);
    expect($team->zerotierNetworks)->not->toBeEmpty();
});

test('Team countUsers returns correct count', function () {
    $team = Team::find(SecurityTestSeeder::ALPHA_TEAM_ID);
    expect($team->countUsers())->toBe(3);
});

test('User team returns null when membership is expired', function () {
    $user = User::where('email', 'alpha-member@security-test.local')->first();
    $this->actingAs($user);
    session()->forget('current_team');

    TeamUser::where('user_id', $user->id)
        ->where('team_id', SecurityTestSeeder::ALPHA_TEAM_ID)
        ->update(['expires' => now()->subDay()->format('Y-m-d')]);

    expect($user->team)->toBeNull();
});

test('User team extends grace period for last team member', function () {
    $team = Team::factory()->create();
    $user = User::factory()->create(['current_team' => $team->id]);
    $this->actingAs($user);
    session()->forget('current_team');

    TeamUser::create([
        'team_id' => $team->id,
        'user_id' => $user->id,
        'role' => 'admin',
        'expires' => now()->subDay()->format('Y-m-d'),
    ]);

    expect($user->team)->not->toBeNull();
});

test('TeamUser expired returns false when expires is null', function () {
    $tu = new TeamUser;
    $tu->expires = null;
    expect($tu->expired)->toBeFalse();
});

test('TeamUser expired returns true when past date', function () {
    $tu = new TeamUser;
    $tu->expires = now()->subDay()->format('Y-m-d');
    expect($tu->expired)->toBeTrue();
});

test('TeamUser expired returns false when future date', function () {
    $tu = new TeamUser;
    $tu->expires = now()->addYear()->format('Y-m-d');
    expect($tu->expired)->toBeFalse();
});

test('TeamInvitation expired returns false when expires is null', function () {
    $inv = new TeamInvitation;
    $inv->expires = null;
    expect($inv->expired)->toBeFalse();
});

test('TeamInvitation expired returns true when past date', function () {
    $inv = new TeamInvitation;
    $inv->expires = now()->subDay()->format('Y-m-d');
    expect($inv->expired)->toBeTrue();
});

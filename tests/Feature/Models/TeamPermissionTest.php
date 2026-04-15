<?php

use App\Models\TeamPermission;
use App\Models\User;
use Database\Seeders\SecurityTestSeeder;

beforeEach(fn () => $this->seed(SecurityTestSeeder::class));

test('permissions returns cached permissions array', function () {
    config(['wiretier.admin_team' => SecurityTestSeeder::ADMIN_TEAM_ID]);
    $perms = TeamPermission::permissions(SecurityTestSeeder::ALPHA_TEAM_ID);
    expect($perms)->toBeArray()->toContain('manage_networks');
});

test('check returns true for granted permission', function () {
    config(['wiretier.admin_team' => SecurityTestSeeder::ADMIN_TEAM_ID]);
    $this->actingAs(User::where('email', 'alpha-admin@security-test.local')->first());
    session()->forget('current_team');
    expect(TeamPermission::check('manage_networks'))->toBeTrue();
});

test('check returns false for missing permission', function () {
    config(['wiretier.admin_team' => SecurityTestSeeder::ADMIN_TEAM_ID]);
    $this->actingAs(User::where('email', 'beta-admin@security-test.local')->first());
    session()->forget('current_team');
    expect(TeamPermission::check('delete_networks'))->toBeFalse();
});

test('check returns false when user has no team', function () {
    config(['wiretier.admin_team' => SecurityTestSeeder::ADMIN_TEAM_ID]);
    $this->actingAs(User::where('email', 'orphan@security-test.local')->first());
    expect(TeamPermission::check('manage_networks'))->toBeFalse();
});

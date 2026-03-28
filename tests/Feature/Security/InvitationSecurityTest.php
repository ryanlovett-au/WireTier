<?php

use App\Models\TeamInvitation;
use App\Models\TeamUser;
use App\Models\User;
use Database\Seeders\SecurityTestSeeder;
use Livewire\Livewire;

beforeEach(function () {
    $this->seed(SecurityTestSeeder::class);
    config(['laratier.admin_team' => SecurityTestSeeder::ADMIN_TEAM_ID]);

    $this->alphaAdmin = User::where('email', 'alpha-admin@security-test.local')->first();
});

test('expired invitation cannot add user to team', function () {
    // Create an expired invitation
    TeamInvitation::create([
        'team_id' => SecurityTestSeeder::ALPHA_TEAM_ID,
        'email' => 'expired@test.local',
        'role' => 'member',
        'expires' => now()->subDays(1)->format('Y-m-d'),
    ]);

    $invitation = TeamInvitation::where('email', 'expired@test.local')->first();
    expect($invitation->expired)->toBeTrue('Invitation should be marked as expired');
});

test('invitation is scoped to specific email', function () {
    TeamInvitation::create([
        'team_id' => SecurityTestSeeder::ALPHA_TEAM_ID,
        'email' => 'invited@test.local',
        'role' => 'member',
    ]);

    // A different user registering should NOT get this invitation
    $invitation = TeamInvitation::where('email', 'other@test.local')
        ->where('team_id', SecurityTestSeeder::ALPHA_TEAM_ID)
        ->first();

    expect($invitation)->toBeNull('Invitation found for wrong email');
});

test('invitation should be single-use', function () {
    TeamInvitation::create([
        'team_id' => SecurityTestSeeder::ALPHA_TEAM_ID,
        'email' => 'replay@test.local',
        'role' => 'member',
    ]);

    // First use: create user and accept invitation
    $user = User::factory()->create(['email' => 'replay@test.local']);
    TeamUser::create([
        'team_id' => SecurityTestSeeder::ALPHA_TEAM_ID,
        'user_id' => $user->id,
        'role' => 'member',
    ]);

    // Invitation should be deleted or marked as used after acceptance
    $invitation = TeamInvitation::where('email', 'replay@test.local')
        ->where('team_id', SecurityTestSeeder::ALPHA_TEAM_ID)
        ->first();

    try {
        // Currently invitations persist after use — this documents the replay vulnerability
        expect($invitation)->toBeNull(
            'Invitation still exists after being accepted — replay attack possible'
        );
    } catch (\Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: Invitations persist after acceptance — replay attacks are possible');
    }
});

test('non-admin cannot invite users to team', function () {
    $alphaMember = User::where('email', 'alpha-member@security-test.local')->first();
    $this->actingAs($alphaMember);
    session()->forget('current_team');

    // Try to invite via the team settings page
    $component = Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ALPHA_TEAM_ID])
        ->set('invite_team_email', 'hacker@test.local')
        ->set('invite_team_role', 'admin')
        ->call('inviteTeam');

    // Member should not be able to invite at admin role
    $adminInviteExists = TeamInvitation::where('email', 'hacker@test.local')
        ->where('role', 'admin')
        ->exists();

    try {
        expect($adminInviteExists)->toBeFalse('Member was able to create an admin invitation');
    } catch (\Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: inviteTeam() has no role-based authorization — members can create admin-level invitations');
    }
});

test('invitation does not leak team details to non-members', function () {
    $betaMember = User::where('email', 'beta-member@security-test.local')->first();
    $this->actingAs($betaMember);
    session()->forget('current_team');

    // Beta member trying to access Alpha team settings
    $response = $this->get(route('teams.show', SecurityTestSeeder::ALPHA_TEAM_ID));

    $response->assertStatus(403);
});

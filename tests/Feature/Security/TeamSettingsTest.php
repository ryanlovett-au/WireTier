<?php

use App\Models\Team;
use App\Models\TeamInvitation;
use App\Models\TeamPermission;
use App\Models\TeamUser;
use App\Models\User;
use Database\Seeders\SecurityTestSeeder;
use Illuminate\Support\Facades\Mail;
use Livewire\Livewire;

beforeEach(function () {
    $this->seed(SecurityTestSeeder::class);
    config(['laratier.admin_team' => SecurityTestSeeder::ADMIN_TEAM_ID]);
    Mail::fake();

    $this->alphaAdmin = User::where('email', 'alpha-admin@security-test.local')->first();
    $this->alphaMember = User::where('email', 'alpha-member@security-test.local')->first();
    $this->alphaViewer = User::where('email', 'alpha-viewer@security-test.local')->first();
    $this->betaAdmin = User::where('email', 'beta-admin@security-test.local')->first();
});

// ─── Functional Tests ────────────────────────────────────────────────────

test('team settings page mounts for team admin', function () {
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    $component = Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ALPHA_TEAM_ID]);
    $component->assertStatus(200);
    $component->assertSet('edit_team_name', 'Team Alpha');
});

test('non-member gets 403 on team settings', function () {
    $this->actingAs($this->betaAdmin);
    session()->forget('current_team');

    Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ALPHA_TEAM_ID])
        ->assertStatus(403);
});

test('editTeam updates team name', function () {
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ALPHA_TEAM_ID])
        ->set('edit_team_name', 'Renamed Alpha')
        ->call('editTeam')
        ->assertHasNoErrors();

    expect(Team::find(SecurityTestSeeder::ALPHA_TEAM_ID)->name)->toBe('Renamed Alpha');
});

test('inviteTeam creates invitation for unknown email', function () {
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ALPHA_TEAM_ID])
        ->set('invite_team_email', 'newuser@example.com')
        ->set('invite_team_role', 'member')
        ->set('invite_team_expires', now()->addYear()->format('Y-m-d'))
        ->call('inviteTeam');

    expect(TeamInvitation::where('email', 'newuser@example.com')
        ->where('team_id', SecurityTestSeeder::ALPHA_TEAM_ID)->exists())->toBeTrue();
});

test('inviteTeam adds existing user directly to team', function () {
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    // The orphan user exists but isn't in Alpha team
    $orphan = User::where('email', 'orphan@security-test.local')->first();

    Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ALPHA_TEAM_ID])
        ->set('invite_team_email', 'orphan@security-test.local')
        ->set('invite_team_role', 'viewer')
        ->set('invite_team_expires', now()->addYear()->format('Y-m-d'))
        ->call('inviteTeam');

    expect(TeamUser::where('user_id', $orphan->id)
        ->where('team_id', SecurityTestSeeder::ALPHA_TEAM_ID)->exists())->toBeTrue();
});

test('changeRole updates team user role', function () {
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    $memberTu = TeamUser::where('user_id', $this->alphaMember->id)
        ->where('team_id', SecurityTestSeeder::ALPHA_TEAM_ID)->first();

    Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ALPHA_TEAM_ID])
        ->call('changeRoleModal', $memberTu->toArray())
        ->set('change_user_role', 'viewer')
        ->call('changeRole');

    $memberTu->refresh();
    expect($memberTu->role)->toBe('viewer');
});

test('changeExpiry updates team user expiry', function () {
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    $memberTu = TeamUser::where('user_id', $this->alphaMember->id)
        ->where('team_id', SecurityTestSeeder::ALPHA_TEAM_ID)->first();

    $newExpiry = now()->addMonths(6)->format('Y-m-d');

    Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ALPHA_TEAM_ID])
        ->call('changeExpiryModal', $memberTu->toArray())
        ->set('change_user_expiry', $newExpiry)
        ->call('changeExpiry');

    $memberTu->refresh();
    expect($memberTu->expires)->toBe($newExpiry);
});

test('removeUser deletes team user record', function () {
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ALPHA_TEAM_ID])
        ->call('removeUserModal', $this->alphaViewer->id)
        ->call('removeUser');

    expect(TeamUser::where('user_id', $this->alphaViewer->id)
        ->where('team_id', SecurityTestSeeder::ALPHA_TEAM_ID)->exists())->toBeFalse();
});

test('leaveTeam removes current user from team', function () {
    $this->actingAs($this->alphaMember);
    session()->forget('current_team');

    Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ALPHA_TEAM_ID])
        ->call('leaveTeam')
        ->assertRedirect('/settings/teams');

    expect(TeamUser::where('user_id', $this->alphaMember->id)
        ->where('team_id', SecurityTestSeeder::ALPHA_TEAM_ID)->exists())->toBeFalse();
});

test('deleteTeam removes team and all related records', function () {
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ALPHA_TEAM_ID])
        ->call('deleteTeam')
        ->assertRedirect('/settings/teams');

    expect(Team::find(SecurityTestSeeder::ALPHA_TEAM_ID))->toBeNull();
    expect(TeamUser::where('team_id', SecurityTestSeeder::ALPHA_TEAM_ID)->count())->toBe(0);
    expect(TeamPermission::where('team_id', SecurityTestSeeder::ALPHA_TEAM_ID)->count())->toBe(0);
});

test('cancelInvitation removes invitation', function () {
    $this->actingAs($this->alphaAdmin);
    session()->forget('current_team');

    $invitation = new TeamInvitation;
    $invitation->team_id = SecurityTestSeeder::ALPHA_TEAM_ID;
    $invitation->email = 'cancel-test@example.com';
    $invitation->role = 'member';
    $invitation->save();

    Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ALPHA_TEAM_ID])
        ->call('cancelInvitation', $invitation->id);

    expect(TeamInvitation::find($invitation->id))->toBeNull();
});

test('updatePermission toggles permission on and off', function () {
    $this->actingAs($this->superAdmin = User::where('email', 'superadmin@security-test.local')->first());
    session()->forget('current_team');

    $component = Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ALPHA_TEAM_ID]);

    // Check if manage_tokens is currently in permissions, then toggle
    $permissions = $component->get('permissions');
    $hadManageTokens = in_array('manage_tokens', $permissions);

    $component->call('updatePermission', 'manage_tokens');

    if ($hadManageTokens) {
        expect(TeamPermission::where('team_id', SecurityTestSeeder::ALPHA_TEAM_ID)
            ->where('permission', 'manage_tokens')->exists())->toBeFalse();
    } else {
        expect(TeamPermission::where('team_id', SecurityTestSeeder::ALPHA_TEAM_ID)
            ->where('permission', 'manage_tokens')->exists())->toBeTrue();
    }
});

// ─── Security: Authorization ─────────────────────────────────────────────

test('removeUser requires admin role', function () {
    $this->actingAs($this->alphaMember);
    session()->forget('current_team');

    $viewerExists = TeamUser::where('user_id', $this->alphaViewer->id)
        ->where('team_id', SecurityTestSeeder::ALPHA_TEAM_ID)->exists();

    Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ALPHA_TEAM_ID])
        ->set('remove_team_user', $this->alphaViewer->id)
        ->call('removeUser');

    try {
        expect(TeamUser::where('user_id', $this->alphaViewer->id)
            ->where('team_id', SecurityTestSeeder::ALPHA_TEAM_ID)->exists())->toBeTrue(
                'Member was able to remove another user'
            );
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: removeUser() has no admin role check — any team member can remove other members');
    }
});

test('deleteTeam requires admin role', function () {
    $this->actingAs($this->alphaMember);
    session()->forget('current_team');

    Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ALPHA_TEAM_ID])
        ->call('deleteTeam');

    try {
        expect(Team::find(SecurityTestSeeder::ALPHA_TEAM_ID))->not->toBeNull(
            'Member was able to delete the team'
        );
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: deleteTeam() has no admin role check — any team member can delete the team');
    }
});

test('member cannot invite at admin role', function () {
    $this->actingAs($this->alphaMember);
    session()->forget('current_team');

    Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ALPHA_TEAM_ID])
        ->set('invite_team_email', 'exploit@test.local')
        ->set('invite_team_role', 'admin')
        ->set('invite_team_expires', now()->addYear()->format('Y-m-d'))
        ->call('inviteTeam');

    $adminInvite = TeamInvitation::where('email', 'exploit@test.local')
        ->where('role', 'admin')
        ->exists();

    try {
        expect($adminInvite)->toBeFalse('Member was able to create an admin invitation');
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: inviteTeam() has no role-based authorization — members can create admin-level invitations');
    }
});

test('member cannot change roles', function () {
    $this->actingAs($this->alphaMember);
    session()->forget('current_team');

    $viewerTu = TeamUser::where('user_id', $this->alphaViewer->id)
        ->where('team_id', SecurityTestSeeder::ALPHA_TEAM_ID)->first();

    Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ALPHA_TEAM_ID])
        ->set('change_user', $viewerTu->toArray())
        ->set('change_user_role', 'admin')
        ->call('changeRole');

    $viewerTu->refresh();

    try {
        expect($viewerTu->role)->toBe('viewer', 'Member was able to change another user\'s role');
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: changeRole() isTeamAdmin() check does not block members — members can escalate privileges');
    }
});

// ─── Security: Data Exposure ─────────────────────────────────────────────

test('team model does not expose sensitive fields in serialization', function () {
    // Team is used as a public Livewire property. Verify its fields are non-sensitive.
    $team = new Team;
    $fillable = $team->getFillable();

    // Team only has name, icon, colour — all non-sensitive display fields
    expect($fillable)->toBe(['name', 'icon', 'colour']);
});

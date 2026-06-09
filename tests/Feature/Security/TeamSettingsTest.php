<?php

use App\Models\Team;
use App\Models\TeamInvitation;
use App\Models\TeamUser;
use App\Models\User;
use Database\Seeders\SecurityTestSeeder;
use Illuminate\Support\Facades\Mail;
use Livewire\Livewire;

beforeEach(function () {
    $this->seed(SecurityTestSeeder::class);
    config(['wiretier.admin_team' => SecurityTestSeeder::ADMIN_TEAM_ID]);
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

// ─── Security: Authorization ─────────────────────────────────────────────

test('removeUser requires admin role', function () {
    $this->actingAs($this->alphaMember);
    session()->forget('current_team');

    Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ALPHA_TEAM_ID])
        ->set('remove_team_user', $this->alphaViewer->id)
        ->call('removeUser');

    expect(TeamUser::where('user_id', $this->alphaViewer->id)
        ->where('team_id', SecurityTestSeeder::ALPHA_TEAM_ID)->exists())->toBeTrue(
            'Member was able to remove another user'
        );
});

test('removeUserModal requires admin role', function () {
    $this->actingAs($this->alphaViewer);
    session()->forget('current_team');

    $component = Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ALPHA_TEAM_ID])
        ->call('removeUserModal', $this->alphaMember->id);

    $component->assertSet('remove_team_user', '');
});

test('deleteTeam requires admin role', function () {
    $this->actingAs($this->alphaMember);
    session()->forget('current_team');

    Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ALPHA_TEAM_ID])
        ->call('deleteTeam');

    expect(Team::find(SecurityTestSeeder::ALPHA_TEAM_ID))->not->toBeNull(
        'Member was able to delete the team'
    );
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

    expect($adminInvite)->toBeFalse('Member was able to create an admin invitation');
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

    expect($viewerTu->role)->toBe('viewer', 'Member was able to change another user\'s role');
});

test('viewer cannot cancel invitations', function () {
    $this->actingAs($this->alphaViewer);
    session()->forget('current_team');

    $invitation = new TeamInvitation;
    $invitation->team_id = SecurityTestSeeder::ALPHA_TEAM_ID;
    $invitation->email = 'should-stay@example.com';
    $invitation->role = 'member';
    $invitation->save();

    Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ALPHA_TEAM_ID])
        ->call('cancelInvitation', $invitation->id);

    expect(TeamInvitation::find($invitation->id))->not->toBeNull(
        'Viewer was able to cancel an invitation'
    );
});

test('member cannot cancel invitations', function () {
    $this->actingAs($this->alphaMember);
    session()->forget('current_team');

    $invitation = new TeamInvitation;
    $invitation->team_id = SecurityTestSeeder::ALPHA_TEAM_ID;
    $invitation->email = 'should-stay@example.com';
    $invitation->role = 'member';
    $invitation->save();

    Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ALPHA_TEAM_ID])
        ->call('cancelInvitation', $invitation->id);

    expect(TeamInvitation::find($invitation->id))->not->toBeNull(
        'Member was able to cancel an invitation'
    );
});

// ─── Security: Admin Team Role Constraint ────────────────────────────────

test('TeamUser save rejects non-admin role on admin team', function () {
    $orphan = User::where('email', 'orphan@security-test.local')->first();

    expect(fn () => TeamUser::create([
        'team_id' => SecurityTestSeeder::ADMIN_TEAM_ID,
        'user_id' => $orphan->id,
        'role' => 'viewer',
    ]))->toThrow(DomainException::class);
});

test('TeamUser save allows admin role on admin team', function () {
    $orphan = User::where('email', 'orphan@security-test.local')->first();

    $tu = TeamUser::create([
        'team_id' => SecurityTestSeeder::ADMIN_TEAM_ID,
        'user_id' => $orphan->id,
        'role' => 'admin',
    ]);

    expect($tu->exists)->toBeTrue();
});

test('changeRole rejects non-admin role on admin team', function () {
    $superAdmin = User::where('email', 'superadmin@security-test.local')->first();
    $this->actingAs($superAdmin);
    session()->forget('current_team');

    $adminTu = TeamUser::where('user_id', $superAdmin->id)
        ->where('team_id', SecurityTestSeeder::ADMIN_TEAM_ID)->first();

    Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ADMIN_TEAM_ID])
        ->call('changeRoleModal', $adminTu->toArray())
        ->set('change_user_role', 'viewer')
        ->call('changeRole');

    $adminTu->refresh();
    expect($adminTu->role)->toBe('admin');
});

test('inviteTeam rejects non-admin role on admin team', function () {
    $superAdmin = User::where('email', 'superadmin@security-test.local')->first();
    $this->actingAs($superAdmin);
    session()->forget('current_team');

    Livewire::test('pages::settings.team', ['id' => SecurityTestSeeder::ADMIN_TEAM_ID])
        ->set('invite_team_email', 'newuser@example.com')
        ->set('invite_team_role', 'viewer')
        ->set('invite_team_expires', now()->addYear()->format('Y-m-d'))
        ->call('inviteTeam');

    expect(TeamInvitation::where('email', 'newuser@example.com')
        ->where('team_id', SecurityTestSeeder::ADMIN_TEAM_ID)->exists())->toBeFalse();
});

// ─── Security: Data Exposure ─────────────────────────────────────────────

test('team model does not expose sensitive fields in serialization', function () {
    // Team is used as a public Livewire property. Verify its fields are non-sensitive.
    $team = new Team;
    $fillable = $team->getFillable();

    // Team only has name, icon, colour — all non-sensitive display fields
    expect($fillable)->toBe(['name', 'icon', 'colour']);
});

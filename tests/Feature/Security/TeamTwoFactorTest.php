<?php

/*
 * A team admin can require two-factor authentication for their team. Members
 * without it lose access to the team (not just its pages) until they set it up.
 */

use App\Models\AuditLog;
use App\Models\Team;
use App\Models\User;
use Database\Seeders\SecurityTestSeeder as S;
use Illuminate\Support\Facades\Http;
use Livewire\Features\SupportLockedProperties\CannotUpdateLockedPropertyException;
use Livewire\Livewire;

function withTwoFactor(User $user): User
{
    $user->forceFill([
        'two_factor_secret' => encrypt('JBSWY3DPEHPK3PXP'),
        'two_factor_recovery_codes' => encrypt(json_encode(['code-one'])),
        'two_factor_confirmed_at' => now(),
    ])->save();

    return $user->fresh();
}

function requireTwoFactor(string $teamId): void
{
    Team::where('id', $teamId)->update(['require_two_factor' => true]);
}

beforeEach(function () {
    $this->seed(S::class);
    config(['wiretier.admin_team' => S::ADMIN_TEAM_ID]);
    Http::fake(fn () => Http::response([]));

    $this->alphaAdmin = User::where('email', 'alpha-admin@security-test.local')->first();
    $this->alphaMember = User::where('email', 'alpha-member@security-test.local')->first();
    $this->superAdmin = User::where('email', 'superadmin@security-test.local')->first();
});

// ─── Enforcement ─────────────────────────────────────────────────────────

test('a member without 2FA is sent to set it up and loses access to the team', function () {
    requireTwoFactor(S::ALPHA_TEAM_ID);
    $this->actingAs($this->alphaMember);

    $this->get(route('dashboard'))->assertRedirect(route('security.edit'));
    $this->get(route('zerotier.networks'))->assertRedirect(route('security.edit'));
    $this->get(route('teams.show', S::ALPHA_TEAM_ID))->assertRedirect(route('security.edit'));

    // Not just a redirect: the team and its rights don't resolve at all, so
    // Livewire actions on an already-open page get nothing either.
    $member = $this->alphaMember->fresh();
    expect($member->team)->toBeNull();
    expect($member->canManageNetworks())->toBeFalse();

    Livewire::test('pages::zerotier.members', ['networkId' => S::ALPHA_NETWORK_ID, 'tokenId' => S::ALPHA_TOKEN_ID])
        ->assertRedirect('/settings/teams');
});

test('the pages needed to set up 2FA or change team stay reachable', function () {
    requireTwoFactor(S::ALPHA_TEAM_ID);
    $this->actingAs($this->alphaMember);

    $this->get(route('teams.index'))->assertOk();
    $this->get(route('profile.edit'))->assertOk();
    $this->withSession(['auth.password_confirmed_at' => time()])
        ->get(route('security.edit'))->assertOk()->assertSee('requires two-factor authentication');
});

test('a member with 2FA keeps full access', function () {
    requireTwoFactor(S::ALPHA_TEAM_ID);
    $member = withTwoFactor($this->alphaMember);
    $this->actingAs($member);

    $this->get(route('dashboard'))->assertOk();
    expect($member->team?->id)->toBe(S::ALPHA_TEAM_ID);
    expect($member->canManageNetworks())->toBeTrue();
});

test('teams that do not require 2FA are unaffected', function () {
    $this->actingAs($this->alphaMember);

    $this->get(route('dashboard'))->assertOk();
    expect($this->alphaMember->fresh()->team?->id)->toBe(S::ALPHA_TEAM_ID);
});

test('an admin without 2FA cannot administer a team that requires it', function () {
    requireTwoFactor(S::ALPHA_TEAM_ID);

    expect($this->alphaAdmin->fresh()->canAdministerTeam(S::ALPHA_TEAM_ID))->toBeFalse();
    expect(withTwoFactor($this->alphaAdmin)->canAdministerTeam(S::ALPHA_TEAM_ID))->toBeTrue();
});

test('requiring 2FA on the admin team applies to system admins', function () {
    requireTwoFactor(S::ADMIN_TEAM_ID);

    expect($this->superAdmin->fresh()->isAdmin())->toBeFalse();
    expect(withTwoFactor($this->superAdmin)->isAdmin())->toBeTrue();
});

// ─── The team setting ────────────────────────────────────────────────────

test('a team admin with 2FA can require it, listing members who lack it', function () {
    $admin = withTwoFactor($this->alphaAdmin);
    $this->actingAs($admin);

    $page = Livewire::test('pages::settings.team', ['id' => S::ALPHA_TEAM_ID])
        ->call('confirmTwoFactorRequirement', true)
        ->assertSet('pending_require_two_factor', true)
        ->assertSee($this->alphaMember->name);

    expect($page->instance()->membersWithoutTwoFactor)->not->toContain($admin->name);

    $page->call('setTwoFactorRequirement');

    expect(Team::find(S::ALPHA_TEAM_ID)->require_two_factor)->toBeTrue();
    expect(AuditLog::where('action', 'team.two_factor_required')->where('resource_id', S::ALPHA_TEAM_ID)->exists())->toBeTrue();
});

test('a team admin cannot require 2FA before setting it up themselves', function () {
    $this->actingAs($this->alphaAdmin);

    Livewire::test('pages::settings.team', ['id' => S::ALPHA_TEAM_ID])
        ->call('confirmTwoFactorRequirement', true)
        ->assertSet('pending_require_two_factor', false)
        ->call('setTwoFactorRequirement');

    expect(Team::find(S::ALPHA_TEAM_ID)->require_two_factor)->toBeFalse();
});

test('a team admin can make 2FA optional again', function () {
    requireTwoFactor(S::ALPHA_TEAM_ID);
    $this->actingAs(withTwoFactor($this->alphaAdmin));

    Livewire::test('pages::settings.team', ['id' => S::ALPHA_TEAM_ID])
        ->call('confirmTwoFactorRequirement', false)
        ->call('setTwoFactorRequirement');

    expect(Team::find(S::ALPHA_TEAM_ID)->require_two_factor)->toBeFalse();
    expect(AuditLog::where('action', 'team.two_factor_optional')->exists())->toBeTrue();
});

test('members who are not team admins cannot change the setting', function () {
    $this->actingAs(withTwoFactor($this->alphaMember));

    Livewire::test('pages::settings.team', ['id' => S::ALPHA_TEAM_ID])
        ->call('confirmTwoFactorRequirement', true)
        ->call('setTwoFactorRequirement');

    expect(Team::find(S::ALPHA_TEAM_ID)->require_two_factor)->toBeFalse();
});

test('the pending choice cannot be set from the browser', function () {
    $this->actingAs(withTwoFactor($this->alphaAdmin));

    expect(fn () => Livewire::test('pages::settings.team', ['id' => S::ALPHA_TEAM_ID])
        ->set('pending_require_two_factor', true))
        ->toThrow(CannotUpdateLockedPropertyException::class);
});

// ─── Turning 2FA off ─────────────────────────────────────────────────────

test('2FA cannot be turned off while a team requires it', function () {
    requireTwoFactor(S::ALPHA_TEAM_ID);
    $member = withTwoFactor($this->alphaMember);
    $this->actingAs($member);

    Livewire::test('pages::settings.security')
        ->assertSet('teamRequiresTwoFactor', true)
        ->call('disable');

    expect($member->fresh()->hasEnabledTwoFactorAuthentication())->toBeTrue();
});

test('2FA can be turned off when no team requires it', function () {
    $member = withTwoFactor($this->alphaMember);
    $this->actingAs($member);

    Livewire::test('pages::settings.security')->call('disable');

    expect($member->fresh()->hasEnabledTwoFactorAuthentication())->toBeFalse();
});

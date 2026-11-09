<?php

/*
 * Regression tests for cross-team access control. Each test reproduces an
 * attack that previously succeeded, and asserts it is now refused.
 */

use App\Models\Team;
use App\Models\TeamInvitation;
use App\Models\TeamUser;
use App\Models\User;
use App\Models\ZerotierNetwork;
use Database\Seeders\SecurityTestSeeder as S;
use Illuminate\Support\Facades\Http;
use Livewire\Features\SupportLockedProperties\CannotUpdateLockedPropertyException;
use Livewire\Livewire;

beforeEach(function () {
    $this->seed(S::class);
    config(['wiretier.admin_team' => S::ADMIN_TEAM_ID]);

    $this->alphaAdmin = User::where('email', 'alpha-admin@security-test.local')->first();
    $this->alphaMember = User::where('email', 'alpha-member@security-test.local')->first();
    $this->superAdmin = User::where('email', 'superadmin@security-test.local')->first();

    // Status code for controller DELETEs; tests override it to simulate failure.
    $this->deleteStatus = 200;

    Http::fake(function ($request) {
        if ($request->method() === 'DELETE') {
            return Http::response([], $this->deleteStatus);
        }

        if (str_ends_with($request->url(), '/controller/network')) {
            return Http::response([S::ALPHA_NETWORK_ID, S::BETA_NETWORK_ID]);
        }

        return Http::response([
            'nwid' => S::BETA_NETWORK_ID, 'name' => 'Beta', 'private' => true,
            'routes' => [], 'ipAssignmentPools' => [],
        ]);
    });
});

/** Whether any request with this method was sent to a URL containing $needle. */
function requestSentTo(string $method, string $needle): bool
{
    return Http::recorded()->contains(
        fn ($pair) => $pair[0]->method() === $method && str_contains($pair[0]->url(), $needle)
    );
}

// ─── Networks page ───────────────────────────────────────────────────────

test('deleting another team\'s network never reaches the controller', function () {
    $this->actingAs($this->alphaMember);

    Livewire::test('pages::zerotier.networks')
        ->set('selectedToken', S::BETA_TOKEN_ID)
        ->set('delete_network_id', S::BETA_NETWORK_ID)
        ->call('deleteNetwork');

    expect(requestSentTo('DELETE', S::BETA_NETWORK_ID))->toBeFalse();
    expect(ZerotierNetwork::where('network_id', S::BETA_NETWORK_ID)->exists())->toBeTrue();
});

test('a failed controller delete keeps the network in the database', function () {
    $this->deleteStatus = 500;

    $this->actingAs($this->alphaMember);

    Livewire::test('pages::zerotier.networks')
        ->set('selectedToken', S::ALPHA_TOKEN_ID)
        ->set('delete_network_id', S::ALPHA_NETWORK_ID)
        ->call('deleteNetwork');

    expect(ZerotierNetwork::where('network_id', S::ALPHA_NETWORK_ID)->exists())->toBeTrue();
});

test('the untracked-network delete refuses a network a team is tracking', function () {
    $this->actingAs($this->superAdmin);

    Livewire::test('pages::zerotier.networks')
        ->set('selectedToken', S::BETA_TOKEN_ID)
        ->set('delete_untracked_id', S::BETA_NETWORK_ID)
        ->call('deleteUntrackedNetwork');

    expect(requestSentTo('DELETE', S::BETA_NETWORK_ID))->toBeFalse();
});

// ─── Members page ────────────────────────────────────────────────────────

test('members page network and token ids are locked after mount', function () {
    $this->actingAs($this->alphaMember);

    Livewire::test('pages::zerotier.members', ['networkId' => S::ALPHA_NETWORK_ID, 'tokenId' => S::ALPHA_TOKEN_ID])
        ->set('networkId', S::BETA_NETWORK_ID);
})->throws(CannotUpdateLockedPropertyException::class);

test('members page rejects a token that does not match the network', function () {
    $this->actingAs($this->alphaMember);

    Livewire::test('pages::zerotier.members', ['networkId' => S::ALPHA_NETWORK_ID, 'tokenId' => S::BETA_TOKEN_ID])
        ->assertForbidden();
});

test('system admin can view members of any team\'s network', function () {
    $this->actingAs($this->superAdmin);

    Livewire::test('pages::zerotier.members', ['networkId' => S::BETA_NETWORK_ID, 'tokenId' => S::BETA_TOKEN_ID])
        ->assertOk()
        ->assertSet('network.nwid', S::BETA_NETWORK_ID);
});

test('member actions stop once the user loses access to the network', function () {
    $this->actingAs($this->alphaMember);

    $component = Livewire::test('pages::zerotier.members', ['networkId' => S::ALPHA_NETWORK_ID, 'tokenId' => S::ALPHA_TOKEN_ID]);

    // The network moves to another team between page load and the action.
    ZerotierNetwork::where('network_id', S::ALPHA_NETWORK_ID)->update(['team_id' => S::BETA_TEAM_ID]);

    $component->call('authorizeMember', 'deadbeef01')->assertForbidden();

    expect(requestSentTo('POST', '/member/deadbeef01'))->toBeFalse();
});

// ─── Network edit modal ──────────────────────────────────────────────────

test('edit modal will not open another team\'s network', function () {
    $this->actingAs($this->alphaMember);

    Livewire::test('pages::zerotier.network-edit-modal')
        ->call('open', S::BETA_NETWORK_ID, S::BETA_TOKEN_ID)
        ->assertSet('editing_network_id', '')
        ->call('saveNetwork');

    expect(requestSentTo('POST', S::BETA_NETWORK_ID))->toBeFalse();
    expect(requestSentTo('GET', S::BETA_NETWORK_ID))->toBeFalse();
});

test('edit modal target ids are locked', function () {
    $this->actingAs($this->alphaMember);

    Livewire::test('pages::zerotier.network-edit-modal')
        ->set('editing_network_id', S::BETA_NETWORK_ID);
})->throws(CannotUpdateLockedPropertyException::class);

test('team admin cannot move another team\'s network into a team they administer', function () {
    $other = Team::create(['name' => 'Other']);
    TeamUser::create(['team_id' => $other->id, 'user_id' => $this->alphaAdmin->id, 'role' => 'admin']);
    $this->actingAs($this->alphaAdmin);

    Livewire::test('pages::zerotier.network-edit-modal')
        ->call('open', S::BETA_NETWORK_ID, S::BETA_TOKEN_ID)
        ->set('move_to_team_id', (string) $other->id)
        ->call('moveNetwork');

    expect(ZerotierNetwork::where('network_id', S::BETA_NETWORK_ID)->value('team_id'))->toBe(S::BETA_TEAM_ID);
});

test('saveNetwork rejects malformed routes injected into the public property', function () {
    $this->actingAs($this->alphaAdmin);

    Livewire::test('pages::zerotier.network-edit-modal')
        ->call('open', S::ALPHA_NETWORK_ID, S::ALPHA_TOKEN_ID)
        ->set('edit_routes', [['target' => 'not-a-cidr', 'via' => null]])
        ->call('saveNetwork')
        ->assertHasErrors('edit_routes.0.target');

    expect(requestSentTo('POST', S::ALPHA_NETWORK_ID))->toBeFalse();
});

// ─── System admin status ─────────────────────────────────────────────────

test('removal from the admin team revokes system admin', function () {
    expect($this->superAdmin->isAdmin())->toBeTrue();

    TeamUser::where('team_id', S::ADMIN_TEAM_ID)->where('user_id', $this->superAdmin->id)->delete();

    expect($this->superAdmin->fresh()->isAdmin())->toBeFalse();
});

test('an expired admin team membership revokes system admin', function () {
    TeamUser::where('team_id', S::ADMIN_TEAM_ID)->where('user_id', $this->superAdmin->id)
        ->update(['expires' => now()->subDay()->format('Y-m-d')]);

    expect($this->superAdmin->fresh()->isAdmin())->toBeFalse();
});

// ─── Team settings ───────────────────────────────────────────────────────

test('admin of the current team cannot administer a team where they are only a viewer', function () {
    TeamUser::create(['team_id' => S::BETA_TEAM_ID, 'user_id' => $this->alphaAdmin->id, 'role' => 'viewer']);
    $this->actingAs($this->alphaAdmin);

    Livewire::test('pages::settings.team', ['id' => S::BETA_TEAM_ID])
        ->set('edit_team_name', 'Renamed')
        ->call('editTeam')
        ->set('invite_team_email', 'intruder@example.com')
        ->set('invite_team_role', 'admin')
        ->call('inviteTeam')
        ->call('deleteTeam');

    $beta = Team::find(S::BETA_TEAM_ID);
    expect($beta)->not->toBeNull();
    expect($beta->name)->not->toBe('Renamed');
    expect(TeamInvitation::where('email', 'intruder@example.com')->exists())->toBeFalse();
});

test('changeRole cannot target a membership row of another team', function () {
    $betaRow = TeamUser::create(['team_id' => S::BETA_TEAM_ID, 'user_id' => $this->alphaAdmin->id, 'role' => 'viewer']);
    $this->actingAs($this->alphaAdmin);

    Livewire::test('pages::settings.team', ['id' => S::ALPHA_TEAM_ID])
        ->call('changeRoleModal', (string) $betaRow->id)
        ->set('change_user_role', 'admin')
        ->call('changeRole');

    expect($betaRow->fresh()->role)->toBe('viewer');
});

test('changeExpiry cannot target a membership row of another team', function () {
    $betaRow = TeamUser::create(['team_id' => S::BETA_TEAM_ID, 'user_id' => $this->alphaAdmin->id, 'role' => 'viewer', 'expires' => '2026-01-01']);
    $this->actingAs($this->alphaAdmin);

    Livewire::test('pages::settings.team', ['id' => S::ALPHA_TEAM_ID])
        ->call('changeExpiryModal', (string) $betaRow->id)
        ->set('change_user_expiry', '2099-01-01')
        ->call('changeExpiry');

    expect($betaRow->fresh()->expires)->toBe('2026-01-01');
});

// ─── Current team resolution ─────────────────────────────────────────────

test('a user removed from a team loses access on the next request', function () {
    $this->actingAs($this->alphaMember);

    // Previously the team was cached in the session on first use and never
    // re-checked, so a removed member kept reading the team's data.
    session(['current_team' => Team::find(S::ALPHA_TEAM_ID)]);
    TeamUser::where('team_id', S::ALPHA_TEAM_ID)->where('user_id', $this->alphaMember->id)->delete();

    expect($this->alphaMember->fresh()->team)->toBeNull();

    Livewire::test('pages::zerotier.members', ['networkId' => S::ALPHA_NETWORK_ID, 'tokenId' => S::ALPHA_TOKEN_ID])
        ->assertRedirect('/settings/teams');
});

test('an expired membership no longer grants the team', function () {
    TeamUser::where('team_id', S::ALPHA_TEAM_ID)->where('user_id', $this->alphaMember->id)
        ->update(['expires' => now()->subDay()->format('Y-m-d')]);

    expect($this->alphaMember->fresh()->team)->toBeNull();
});

test('switching current_team on the same instance re-resolves the team', function () {
    TeamUser::create(['team_id' => S::BETA_TEAM_ID, 'user_id' => $this->alphaMember->id, 'role' => 'viewer']);
    $user = $this->alphaMember->fresh();

    expect($user->team->id)->toBe(S::ALPHA_TEAM_ID);

    $user->current_team = S::BETA_TEAM_ID;

    expect($user->team->id)->toBe(S::BETA_TEAM_ID);
});

test('the membership being edited cannot be swapped from the client', function () {
    $this->actingAs($this->alphaAdmin);

    Livewire::test('pages::settings.team', ['id' => S::ALPHA_TEAM_ID])
        ->set('change_user', ['id' => 'anything']);
})->throws(CannotUpdateLockedPropertyException::class);

test('team colour and icon allow-lists cannot be extended from the client', function () {
    $this->actingAs($this->alphaAdmin);

    Livewire::test('pages::settings.teams')
        ->set('icons', ['../../evil']);
})->throws(CannotUpdateLockedPropertyException::class);

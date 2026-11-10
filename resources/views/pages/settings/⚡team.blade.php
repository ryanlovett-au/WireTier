<?php

use App\Mail\TeamAddedUser;
use App\Mail\TeamInviteUser;
use App\Models\AuditLog;
use App\Models\Team;
use App\Models\TeamInvitation;
use App\Models\TeamUser;
use App\Models\User;
use App\Models\ZerotierNetwork;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Livewire\Attributes\Computed;
use Livewire\Attributes\Locked;
use Livewire\Attributes\Title;
use Livewire\Component;
use Livewire\WithPagination;

new #[Title('Team Settings')] class extends Component
{
    use WithPagination;

    public Team $current_team;

    public string $action = 'view';

    /** The membership being edited; set only by selectTeamUser(). */
    #[Locked]
    public array $change_user = [];

    public string $change_user_role = '';

    public string $change_user_expiry = '';

    public string $edit_team_name = '';

    public string $invite_team_email = '';

    public string $invite_team_role = 'member';

    public string $invite_team_expires = '';

    /**
     * Whether the user may administer the team shown on THIS page. This page
     * can show any team the user belongs to (/settings/team/{id}), so the
     * check must not use isTeamAdmin(), which reflects the current team.
     */
    public function canAdminister(): bool
    {
        return auth()->user()->canAdministerTeam($this->current_team->id);
    }

    /** A membership row of this team, by id; null for rows of other teams. */
    protected function teamUserOnThisTeam(mixed $id): ?TeamUser
    {
        if (! is_string($id) || $id === '') {
            return null;
        }

        return TeamUser::where('id', $id)->where('team_id', $this->current_team->id)->first();
    }

    #[Computed]
    public function isAdminTeam(): bool
    {
        return $this->current_team->id === config('wiretier.admin_team');
    }

    #[Computed]
    public function availableRoles(): array
    {
        $roles = config('wiretier.roles');

        if ($this->isAdminTeam()) {
            return ['admin' => $roles['admin']];
        }

        return $roles;
    }

    /** The two-factor requirement waiting on the confirm modal. */
    #[Locked]
    public bool $pending_require_two_factor = false;

    public string $remove_team_user = '';

    public string $remove_team_user_name = '';

    public function mount(?string $id = null)
    {
        $teamId = $id ?? auth()->user()->current_team;

        if (! $teamId) {
            abort(404);
        }

        // Check access
        if (! auth()->user()->belongsToTeam($teamId) && ! auth()->user()->isAdmin()) {
            abort(403);
        }

        $this->current_team = Team::findOrFail($teamId);

        // A team that requires two-factor authentication stays closed until
        // the user sets it up.
        if (! auth()->user()->isAdmin() && ! auth()->user()->meetsTwoFactorRequirementOf($this->current_team)) {
            session()->flash('two_factor_required', $this->current_team->name);
            $this->redirectRoute('security.edit');

            return;
        }
        $this->edit_team_name = $this->current_team->name;
        $this->invite_team_expires = now()->addYear()->format('Y-m-d');

        if ($this->current_team->id === config('wiretier.admin_team')) {
            $this->invite_team_role = 'admin';
        }

        if (request()->query('action') === 'admin') {
            $this->action = 'admin';
        }

        AuditLog::record('team.settings_viewed', 'team', $this->current_team->id);
    }

    #[Computed]
    public function teamMembers()
    {
        return TeamUser::where('team_id', $this->current_team->id)
            ->with('user')
            ->paginate(15);
    }

    #[Computed]
    public function pendingInvitations()
    {
        return TeamInvitation::where('team_id', $this->current_team->id)->get();
    }

    public function changeRoleModal(string $teamUserId): void
    {
        if (! $this->canAdminister()) {
            Flux::toast(variant: 'danger', heading: 'Permission Denied', text: 'You do not have permission to change roles.');

            return;
        }

        if (! $this->selectTeamUser($teamUserId)) {
            return;
        }

        $this->change_user_role = $this->change_user['role'];
        Flux::modal('change_role_modal')->show();
    }

    public function changeRole(): void
    {
        if (! $this->canAdminister()) {
            return;
        }

        if (! array_key_exists($this->change_user_role, config('wiretier.roles'))) {
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Invalid role selected.');
            Flux::modal('change_role_modal')->close();

            return;
        }

        if ($this->current_team->id === config('wiretier.admin_team') && $this->change_user_role !== 'admin') {
            Flux::toast(variant: 'danger', heading: 'Not Allowed', text: 'Only the admin role is allowed on the admin team.');
            Flux::modal('change_role_modal')->close();

            return;
        }

        $teamUser = $this->teamUserOnThisTeam($this->change_user['id'] ?? null);

        if (! $teamUser) {
            Flux::modal('change_role_modal')->close();

            return;
        }

        $teamUser->update(['role' => $this->change_user_role]);
        AuditLog::record('team.role_changed', 'team', $this->current_team->id, ['user_id' => $this->change_user['user_id'] ?? null, 'new_role' => $this->change_user_role]);

        $this->change_user = [];
        $this->change_user_role = '';
        Flux::modal('change_role_modal')->close();
        Flux::toast(variant: 'success', heading: 'Role Updated', text: 'The team member role has been updated.');
    }

    public function changeExpiryModal(string $teamUserId): void
    {
        if (! $this->canAdminister()) {
            return;
        }

        if (! $this->selectTeamUser($teamUserId)) {
            return;
        }

        $this->change_user_expiry = $this->change_user['expires'] ?? now()->addYear()->format('Y-m-d');
        Flux::modal('change_expiry_modal')->show();
    }

    /**
     * Load the membership being edited from the server (only this team's
     * rows), rather than trusting a model the page serialised to the client.
     */
    protected function selectTeamUser(string $teamUserId): bool
    {
        $teamUser = $this->teamUserOnThisTeam($teamUserId);

        if (! $teamUser) {
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Team member not found.');

            return false;
        }

        $this->change_user = $teamUser->only(['id', 'user_id', 'role', 'expires'])
            + ['name' => $teamUser->user?->name ?? ''];

        return true;
    }

    public function changeExpiry(): void
    {
        if (! $this->canAdminister()) {
            return;
        }

        $this->validate(['change_user_expiry' => 'required|date']);

        $teamUser = $this->teamUserOnThisTeam($this->change_user['id'] ?? null);

        if (! $teamUser) {
            Flux::modal('change_expiry_modal')->close();

            return;
        }

        $teamUser->update(['expires' => $this->change_user_expiry]);
        AuditLog::record('team.expiry_changed', 'team', $this->current_team->id, ['user_id' => $this->change_user['user_id'] ?? null, 'new_expiry' => $this->change_user_expiry]);

        $this->change_user = [];
        $this->change_user_expiry = '';
        Flux::modal('change_expiry_modal')->close();
        Flux::toast(variant: 'success', heading: 'Expiry Updated', text: 'The membership expiry has been updated.');
    }

    public function editTeam(): void
    {
        if (! $this->canAdminister()) {
            return;
        }

        $this->validate(['edit_team_name' => 'required|string|max:255']);

        $oldName = $this->current_team->name;
        Team::where('id', $this->current_team->id)->update(['name' => $this->edit_team_name]);
        $this->current_team = Team::find($this->current_team->id);

        AuditLog::record('team.updated', 'team', $this->current_team->id, ['old_name' => $oldName, 'new_name' => $this->edit_team_name]);

        Flux::toast(variant: 'success', heading: 'Saved', text: 'The team name has been changed.');
    }

    public function inviteTeam(): void
    {
        if (! $this->canAdminister()) {
            return;
        }

        $this->validate([
            'invite_team_email' => 'required|email',
            'invite_team_role' => 'required|in:'.implode(',', array_keys(config('wiretier.roles'))),
            'invite_team_expires' => 'required|date',
        ]);

        if ($this->current_team->id === config('wiretier.admin_team') && $this->invite_team_role !== 'admin') {
            Flux::toast(variant: 'danger', heading: 'Not Allowed', text: 'Only the admin role is allowed on the admin team.');

            return;
        }

        // Check if email belongs to existing user
        if ($invited = User::where('email', $this->invite_team_email)->first()) {
            // Check not already a member
            if (TeamUser::where('team_id', $this->current_team->id)->where('user_id', $invited->id)->exists()) {
                Flux::toast(variant: 'warning', heading: 'Already a Member', text: 'This user is already a member of this team.');

                return;
            }

            $teamUser = new TeamUser;
            $teamUser->user_id = $invited->id;
            $teamUser->team_id = $this->current_team->id;
            $teamUser->role = $this->invite_team_role;
            $teamUser->expires = $this->invite_team_expires;
            $teamUser->save();

            // Clean up any pending invitation for this email/team
            TeamInvitation::where('email', $this->invite_team_email)
                ->where('team_id', $this->current_team->id)
                ->delete();

            Mail::to($this->invite_team_email)->queue(new TeamAddedUser($this->current_team->name, config('wiretier.roles')[$this->invite_team_role]));
            AuditLog::record('team.member_added', 'team', $this->current_team->id, ['email' => $this->invite_team_email, 'role' => $this->invite_team_role]);

            Flux::toast(variant: 'success', heading: 'User Added', text: 'The user has been added to this team.');
            $this->invite_team_email = '';

            return;
        }

        // Create or update invitation
        $invitation = TeamInvitation::where('email', $this->invite_team_email)
            ->where('team_id', $this->current_team->id)
            ->first();

        if (! $invitation) {
            $invitation = new TeamInvitation;
        }

        $invitation->email = $this->invite_team_email;
        $invitation->team_id = $this->current_team->id;
        $invitation->role = $this->invite_team_role;
        $invitation->expires = $this->invite_team_expires;
        $invitation->referer = auth()->user()->id;
        $invitation->save();

        Mail::to($this->invite_team_email)->queue(new TeamInviteUser($this->current_team->name, config('wiretier.roles')[$this->invite_team_role]));
        AuditLog::record('team.member_invited', 'team', $this->current_team->id, ['email' => $this->invite_team_email, 'role' => $this->invite_team_role]);

        Flux::toast(variant: 'success', heading: 'Invitation Sent', text: 'An invitation email has been sent.');
        $this->invite_team_email = '';
    }

    public function removeUserModal($userId): void
    {
        if (! $this->canAdminister()) {
            return;
        }

        $this->remove_team_user = $userId;

        if ($userId == auth()->user()->id) {
            $this->remove_team_user_name = 'yourself';
        } else {
            $member = TeamUser::where('team_id', $this->current_team->id)->where('user_id', $userId)->with('user')->first();

            if (! $member?->user) {
                return;
            }

            $this->remove_team_user_name = $member->user->name;
        }

        Flux::modal('removeUserConfirm')->show();
    }

    public function removeUser(): void
    {
        if (! $this->canAdminister()) {
            return;
        }

        TeamUser::where('user_id', $this->remove_team_user)->where('team_id', $this->current_team->id)->delete();
        AuditLog::record('team.member_removed', 'team', $this->current_team->id, ['user_id' => $this->remove_team_user]);
        Flux::modal('removeUserConfirm')->close();
        Flux::toast(variant: 'success', heading: 'Removed', text: 'The user has been removed from the team.');
    }

    public function leaveTeam(): void
    {
        TeamUser::where('user_id', auth()->user()->id)->where('team_id', $this->current_team->id)->delete();
        AuditLog::record('team.member_left', 'team', $this->current_team->id);
        Flux::modal('leaveTeamConfirm')->close();
        $this->redirect('/settings/teams');
    }

    /**
     * Whether the team shown here may be deleted by this user: its admins (or
     * a system admin), but never the system admin team, whose deletion would
     * lock every system admin out.
     */
    public function canDeleteTeam(): bool
    {
        return $this->canAdminister()
            && $this->current_team->id !== config('wiretier.admin_team');
    }

    /** What deleting this team takes with it, shown in the confirm modal. */
    #[Computed]
    public function deletionImpact(): array
    {
        return [
            'users' => $this->current_team->countUsers(),
            'networks' => ZerotierNetwork::where('team_id', $this->current_team->id)->count(),
        ];
    }

    public function deleteTeamModal(): void
    {
        if (! $this->canDeleteTeam()) {
            return;
        }

        unset($this->deletionImpact);
        Flux::modal('deleteTeamConfirm')->show();
    }

    /** Members who haven't set up two-factor authentication, shown before requiring it. */
    #[Computed]
    public function membersWithoutTwoFactor(): array
    {
        return User::whereIn('id', TeamUser::where('team_id', $this->current_team->id)->select('user_id'))
            ->whereNull('two_factor_confirmed_at')
            ->orderBy('name')
            ->pluck('name')
            ->all();
    }

    public function confirmTwoFactorRequirement(bool $require): void
    {
        if (! $this->canAdminister()) {
            return;
        }

        // Requiring it without having it would lock the admin out of the team.
        if ($require && ! auth()->user()->hasEnabledTwoFactorAuthentication()) {
            Flux::toast(variant: 'danger', heading: 'Set up 2FA first', text: 'Turn on two-factor authentication for your own account before requiring it for the team.');

            return;
        }

        $this->pending_require_two_factor = $require;
        unset($this->membersWithoutTwoFactor);
        Flux::modal('twoFactorRequirementConfirm')->show();
    }

    public function setTwoFactorRequirement(): void
    {
        if (! $this->canAdminister()) {
            return;
        }

        $require = $this->pending_require_two_factor;

        if ($require && ! auth()->user()->hasEnabledTwoFactorAuthentication()) {
            return;
        }

        $this->current_team->forceFill(['require_two_factor' => $require])->save();

        AuditLog::record($require ? 'team.two_factor_required' : 'team.two_factor_optional', 'team', $this->current_team->id, [
            'team_name' => $this->current_team->name,
            'members_without_two_factor' => $require ? count($this->membersWithoutTwoFactor) : null,
        ]);

        Flux::modal('twoFactorRequirementConfirm')->close();
        Flux::toast(variant: 'success', heading: 'Saved', text: $require
            ? 'Members now need two-factor authentication to use this team.'
            : 'Two-factor authentication is now optional for this team.');
    }

    public function deleteTeam()
    {
        if (! $this->canDeleteTeam()) {
            return;
        }

        $teamId = $this->current_team->id;

        // Release the team's networks: drop WireTier's records (not the
        // networks on the controller) so they reappear as untracked for a
        // system admin to import into another team, instead of being orphaned
        // under a team that no longer exists.
        $networks = ZerotierNetwork::where('team_id', $teamId)->get();

        DB::transaction(function () use ($teamId, $networks) {
            foreach ($networks as $network) {
                $network->members()->delete();
                $network->delete();
            }

            TeamUser::where('team_id', $teamId)->delete();
            TeamInvitation::where('team_id', $teamId)->delete();
            User::where('current_team', $teamId)->update(['current_team' => null]);
            Team::where('id', $teamId)->delete();
        });

        foreach ($networks->pluck('zerotier_token_id')->unique() as $tokenId) {
            Cache::forget("team_{$teamId}_networks_{$tokenId}");
            Cache::forget("zt_controller_networks_{$tokenId}");
        }
        Cache::forget("zt_stats_authorised_{$teamId}");
        Cache::forget('zt_stats_authorised_all');

        AuditLog::record('team.deleted', 'team', $teamId, [
            'name' => $this->current_team->name,
            'released_networks' => $networks->pluck('network_id')->all(),
        ]);

        return $this->redirect('/settings/teams');
    }

    public function cancelInvitation($invitationId): void
    {
        if (! $this->canAdminister()) {
            return;
        }

        TeamInvitation::where('id', $invitationId)->where('team_id', $this->current_team->id)->delete();
        AuditLog::record('team.invitation_cancelled', 'team', $this->current_team->id, ['invitation_id' => $invitationId]);
        Flux::toast(variant: 'success', heading: 'Cancelled', text: 'The invitation has been cancelled.');
    }

}; ?>

<section class="w-full">
    @include('partials.settings-heading')

    <x-pages::settings.layout :heading="$current_team->name" :subheading="__('Manage team members, invitations, and settings.')">
    <div class="max-w-3xl">
        {{-- Current Team Info --}}
        <flux:card class="mb-6">
            <div class="flex items-center gap-3">
                @php
                    $teamColours = [
                        'blue'=>'#3b82f6','red'=>'#ef4444','green'=>'#22c55e','purple'=>'#a855f7',
                        'orange'=>'#f97316','yellow'=>'#eab308','pink'=>'#ec4899','indigo'=>'#6366f1',
                        'cyan'=>'#06b6d4','zinc'=>'#71717a','lime'=>'#84cc16','teal'=>'#14b8a6',
                    ];
                    $tc = $teamColours[$current_team->colour] ?? '#6366f1';
                @endphp
                <div style="width:3rem;height:3rem;border-radius:0.5rem;background:{{ $tc }};display:flex;align-items:center;justify-content:center;flex-shrink:0;">
                    <flux:icon name="{{ $current_team->icon }}" class="size-6 text-white" />
                </div>
                <div>
                    <flux:heading size="lg">{{ $current_team->name }}</flux:heading>
                    @if (auth()->user()->teamUser?->first())
                        <flux:badge :color="config('wiretier.roles.'.auth()->user()->teamUser->first()->role.'.colour')" size="sm" class="mt-1">
                            {{ config('wiretier.roles.'.auth()->user()->teamUser->first()->role.'.name') }}
                        </flux:badge>
                    @endif
                </div>
            </div>
        </flux:card>

        {{-- Team Members --}}
        @if ($this->canAdminister())
        <flux:card class="mb-6">
            <flux:heading class="mb-4">Team Members</flux:heading>

            <flux:table :paginate="$this->teamMembers">
                <flux:table.columns>
                    <flux:table.column>Name</flux:table.column>
                    <flux:table.column>Email</flux:table.column>
                    <flux:table.column>Role</flux:table.column>
                    <flux:table.column>Expires</flux:table.column>
                    <flux:table.column>2FA</flux:table.column>
                    <flux:table.column>Actions</flux:table.column>
                </flux:table.columns>

                <flux:table.rows>
                @foreach ($this->teamMembers as $member)
                    <flux:table.row :key="$member->id">
                        <flux:table.cell>{{ $member->user->name }}</flux:table.cell>
                        <flux:table.cell>{{ $member->user->email }}</flux:table.cell>
                        <flux:table.cell>
                            <flux:badge :color="config('wiretier.roles.'.$member->role.'.colour')" size="sm">
                                {{ config('wiretier.roles.'.$member->role.'.name') }}
                            </flux:badge>
                        </flux:table.cell>
                        <flux:table.cell>{{ $member->expires ? \Carbon\Carbon::parse($member->expires)->format('d M Y') : 'Never' }}</flux:table.cell>
                        <flux:table.cell>
                            @if ($member->user->two_factor_confirmed_at)
                                <flux:badge color="green" size="sm">On</flux:badge>
                            @else
                                <flux:badge color="zinc" size="sm">Off</flux:badge>
                            @endif
                        </flux:table.cell>
                        <flux:table.cell>
                            @if ($member->user->id != auth()->user()->id)
                                <div class="flex gap-1">
                                    <flux:button size="xs" icon="arrows-right-left" tooltip="Change Role" wire:click="changeRoleModal({{ Js::from($member->id) }})" />
                                    <flux:button size="xs" icon="clock" tooltip="Change Expiry" wire:click="changeExpiryModal({{ Js::from($member->id) }})" />
                                    <flux:button size="xs" icon="x-mark" tooltip="Remove" wire:click="removeUserModal({{ Js::from($member->user_id) }})" />
                                </div>
                            @endif
                        </flux:table.cell>
                    </flux:table.row>
                @endforeach
                </flux:table.rows>
            </flux:table>
        </flux:card>

        {{-- Pending Invitations --}}
        @if ($this->pendingInvitations->count() > 0)
        <flux:card class="mb-6">
            <flux:heading class="mb-4">Pending Invitations</flux:heading>

            <flux:table>
                <flux:table.columns>
                    <flux:table.column>Email</flux:table.column>
                    <flux:table.column>Role</flux:table.column>
                    <flux:table.column>Expires</flux:table.column>
                    <flux:table.column>Actions</flux:table.column>
                </flux:table.columns>
                <flux:table.rows>
                @foreach ($this->pendingInvitations as $invitation)
                    <flux:table.row :key="$invitation->id">
                        <flux:table.cell>{{ $invitation->email }}</flux:table.cell>
                        <flux:table.cell>
                            <flux:badge :color="config('wiretier.roles.'.$invitation->role.'.colour')" size="sm">
                                {{ config('wiretier.roles.'.$invitation->role.'.name') }}
                            </flux:badge>
                        </flux:table.cell>
                        <flux:table.cell>{{ $invitation->expires ? \Carbon\Carbon::parse($invitation->expires)->format('d M Y') : 'Never' }}</flux:table.cell>
                        <flux:table.cell>
                            <flux:button size="xs" icon="x-mark" variant="danger" wire:click="cancelInvitation('{{ $invitation->id }}')" />
                        </flux:table.cell>
                    </flux:table.row>
                @endforeach
                </flux:table.rows>
            </flux:table>
        </flux:card>
        @endif

        @if ($this->canAdminister())
        <flux:card class="mb-6">
            <div class="flex items-start justify-between gap-6">
                <div>
                    <flux:heading>Two-Factor Authentication</flux:heading>
                    <flux:text class="mt-1">
                        @if ($current_team->require_two_factor)
                            Required. Members without two-factor authentication are sent to set it up before they can use this team.
                        @else
                            Optional. Require it to make every member set up two-factor authentication before using this team.
                        @endif
                    </flux:text>
                </div>
                @if ($current_team->require_two_factor)
                    <flux:button wire:click="confirmTwoFactorRequirement(false)">Make Optional</flux:button>
                @else
                    <flux:button variant="primary" wire:click="confirmTwoFactorRequirement(true)">Require 2FA</flux:button>
                @endif
            </div>
        </flux:card>
        @endif

        {{-- Edit Team Name --}}
        <flux:card class="mb-6">
            <flux:heading class="mb-2">Edit Team</flux:heading>
            <flux:input wire:model="edit_team_name" label="Team Name" />
            <div class="flex mt-4">
                <flux:spacer />
                <flux:button variant="primary" wire:click="editTeam()">Save</flux:button>
            </div>
        </flux:card>

        {{-- Invite User --}}
        <flux:card class="mb-6">
            <flux:heading class="mb-4">Invite User</flux:heading>

            <flux:input wire:model="invite_team_email" type="email" label="Email Address" class="mb-4" />

            <flux:radio.group wire:model="invite_team_role" variant="cards" :indicator="false" class="flex-col mb-4 max-w-xs" label="Role">
                @foreach ($this->availableRoles as $key => $role)
                    <flux:radio :value="$key" :label="$role['name']" :description="$role['description']" />
                @endforeach
            </flux:radio.group>

            @if ($this->isAdminTeam)
                <div class="flex items-start gap-2 px-3 py-2.5 rounded-md border border-amber-300 bg-amber-50 dark:bg-amber-950/30 dark:border-amber-800 text-sm mb-4 max-w-xs">
                    <flux:icon name="shield-check" class="size-4 text-amber-500 shrink-0 mt-0.5" />
                    <div class="text-amber-900 dark:text-amber-200">
                        Only the <strong>Admin</strong> role can be assigned on the admin team.
                    </div>
                </div>
            @endif

            <flux:input wire:model="invite_team_expires" type="date" label="Membership Expires" class="mb-4 max-w-xs" />

            <div class="flex">
                <flux:spacer />
                <flux:button variant="primary" wire:click="inviteTeam()">Invite</flux:button>
            </div>
        </flux:card>

        @endif

        {{-- Leave Team --}}
        @if (auth()->user()->current_team == $current_team->id)
        <flux:card class="mb-6">
            <flux:heading>Leave Team</flux:heading>
            <flux:subheading>Remove yourself from this team.</flux:subheading>
            <div class="flex mt-4">
                <flux:spacer />
                <flux:button variant="danger" wire:click="leaveTeamModal">Leave</flux:button>
            </div>
        </flux:card>
        @endif

        {{-- Delete Team (team admins; never the system admin team) --}}
        @if ($this->canDeleteTeam())
        <flux:card class="mb-6">
            <flux:heading>Delete Team</flux:heading>
            <flux:subheading>Permanently delete this team, its memberships and invitations. Its networks are kept on the controller and become untracked.</flux:subheading>
            <div class="flex mt-4">
                <flux:spacer />
                <flux:button variant="danger" wire:click="deleteTeamModal">Delete</flux:button>
            </div>
        </flux:card>
        @endif
    </div>

    {{-- Modals --}}
    <flux:modal name="change_role_modal" focusable class="w-[350px]">
        <div>
            <flux:heading size="lg" class="mb-6">Change Role</flux:heading>
            <flux:subheading class="mb-4">
                Change the role for {{ $this->change_user['name'] ?? '' }} in the {{ $this->current_team->name }} team.
            </flux:subheading>
            <flux:radio.group wire:model="change_user_role" variant="cards" :indicator="false" class="flex-col mb-6">
                @foreach ($this->availableRoles as $key => $role)
                    <flux:radio :value="$key" :label="$role['name']" :description="$role['description']" />
                @endforeach
            </flux:radio.group>

            @if ($this->isAdminTeam)
                <div class="flex items-start gap-2 px-3 py-2.5 rounded-md border border-amber-300 bg-amber-50 dark:bg-amber-950/30 dark:border-amber-800 text-sm mb-6">
                    <flux:icon name="shield-check" class="size-4 text-amber-500 shrink-0 mt-0.5" />
                    <div class="text-amber-900 dark:text-amber-200">
                        Only the <strong>Admin</strong> role can be assigned on the admin team.
                    </div>
                </div>
            @endif
        </div>
        <div class="flex justify-end space-x-2">
            <flux:modal.close><flux:button variant="filled">Cancel</flux:button></flux:modal.close>
            <flux:button variant="primary" wire:click="changeRole()">Save</flux:button>
        </div>
    </flux:modal>

    <flux:modal name="change_expiry_modal" focusable class="w-[350px]">
        <div>
            <flux:heading size="lg" class="mb-6">Change Expiry</flux:heading>
            <flux:subheading class="mb-4">
                Change the membership expiry for {{ $this->change_user['name'] ?? '' }}.
            </flux:subheading>
            <flux:input wire:model="change_user_expiry" type="date" class="mb-6" />
        </div>
        <div class="flex justify-end space-x-2">
            <flux:modal.close><flux:button variant="filled">Cancel</flux:button></flux:modal.close>
            <flux:button variant="primary" wire:click="changeExpiry()">Save</flux:button>
        </div>
    </flux:modal>

    <flux:modal name="removeUserConfirm" focusable class="max-w-sm">
        <div class="text-center">
            <flux:heading size="lg">Remove User?</flux:heading>
            <flux:subheading class="mt-2">
                Are you sure you want to remove <strong>{{ $remove_team_user_name }}</strong> from the <strong>{{ $current_team->name }}</strong> team?
            </flux:subheading>
        </div>
        <div class="flex justify-end space-x-2 mt-4">
            <flux:modal.close><flux:button variant="filled">Cancel</flux:button></flux:modal.close>
            <flux:button variant="danger" wire:click="removeUser">Remove</flux:button>
        </div>
    </flux:modal>

    @if ($this->canAdminister())
    <flux:modal name="twoFactorRequirementConfirm" focusable class="max-w-md">
        <div class="text-center">
            <flux:heading size="lg">{{ $pending_require_two_factor ? 'Require Two-Factor Authentication?' : 'Make Two-Factor Optional?' }}</flux:heading>
            <flux:subheading class="mt-2">
                @if ($pending_require_two_factor)
                    @php $without = $this->membersWithoutTwoFactor; @endphp
                    @if (count($without) === 0)
                        Every member of <strong>{{ $current_team->name }}</strong> already has two-factor authentication.
                    @else
                        {{ count($without) }} {{ Str::plural('member', count($without)) }} of <strong>{{ $current_team->name }}</strong>
                        {{ count($without) === 1 ? 'does' : 'do' }} not have it yet: {{ implode(', ', array_slice($without, 0, 5)) }}{{ count($without) > 5 ? ' and '.(count($without) - 5).' more' : '' }}.
                        They will be sent to set it up before they can use the team again.
                    @endif
                @else
                    Members of <strong>{{ $current_team->name }}</strong> will be able to use the team without two-factor authentication.
                @endif
            </flux:subheading>
        </div>
        <div class="flex justify-end space-x-2 mt-4">
            <flux:modal.close><flux:button variant="filled">Cancel</flux:button></flux:modal.close>
            <flux:button :variant="$pending_require_two_factor ? 'primary' : 'danger'" wire:click="setTwoFactorRequirement">
                {{ $pending_require_two_factor ? 'Require 2FA' : 'Make Optional' }}
            </flux:button>
        </div>
    </flux:modal>
    @endif

    @if ($this->canDeleteTeam())
    <flux:modal name="deleteTeamConfirm" focusable class="max-w-sm">
        <div class="text-center">
            <flux:heading size="lg">Delete Team?</flux:heading>
            <flux:subheading class="mt-2">
                This permanently deletes the <strong>{{ $current_team->name }}</strong> team and removes its
                {{ $this->deletionImpact['users'] }} {{ Str::plural('member', $this->deletionImpact['users']) }}.
                @if ($this->deletionImpact['networks'] > 0)
                    {{ $this->deletionImpact['networks'] === 1 ? 'Its network stays' : 'Its '.$this->deletionImpact['networks'].' networks stay' }}
                    on the controller, but only a system admin can import {{ $this->deletionImpact['networks'] === 1 ? 'it' : 'them' }} into another team.
                @endif
                This cannot be undone.
            </flux:subheading>
        </div>
        <div class="flex justify-end space-x-2 mt-4">
            <flux:modal.close><flux:button variant="filled">Cancel</flux:button></flux:modal.close>
            <flux:button variant="danger" wire:click="deleteTeam">Delete Team</flux:button>
        </div>
    </flux:modal>
    @endif

    <flux:modal name="leaveTeamConfirm" focusable class="max-w-sm">
        <div class="text-center">
            <flux:heading size="lg">Leave Team?</flux:heading>
            <flux:subheading class="mt-2">
                Are you sure you want to leave the <strong>{{ $current_team->name }}</strong> team?
                You will not be able to re-join unless invited by a team admin.
            </flux:subheading>
        </div>
        <div class="flex justify-end space-x-2 mt-4">
            <flux:modal.close><flux:button variant="filled">Cancel</flux:button></flux:modal.close>
            <flux:button variant="danger" wire:click="leaveTeam">Leave</flux:button>
        </div>
    </flux:modal>
    </x-pages::settings.layout>
</section>

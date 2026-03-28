<?php

use Livewire\Attributes\Title;
use Livewire\Component;
use Livewire\WithPagination;

use App\Models\User;
use App\Models\Team;
use App\Models\TeamUser;
use App\Models\TeamInvitation;
use App\Models\TeamPermission;

use Illuminate\Support\Facades\Mail;
use App\Mail\TeamInviteUser;
use App\Mail\TeamAddedUser;

new #[Title('Team Settings')] class extends Component {
    use WithPagination;

    public Team $current_team;
    public string $action = 'view';

    public array $change_user = [];
    public string $change_user_role = '';
    public string $change_user_expiry = '';

    public string $edit_team_name = '';

    public string $invite_team_email = '';
    public string $invite_team_role = 'member';
    public string $invite_team_expires = '';

    public string $remove_team_user = '';
    public string $remove_team_user_name = '';

    public array $permissions = [];

    public function mount()
    {
        $teamId = request()->query('id', auth()->user()->current_team);

        if (! $teamId) {
            abort(404);
        }

        // Check access
        if (! auth()->user()->belongsToTeam($teamId) && ! auth()->user()->isAdmin()) {
            abort(403);
        }

        $this->current_team = Team::findOrFail($teamId);
        $this->edit_team_name = $this->current_team->name;
        $this->invite_team_expires = now()->addYear()->format('Y-m-d');

        if (request()->query('action') === 'admin') {
            $this->action = 'admin';
        }

        if (auth()->user()->isAdmin()) {
            $this->permissions = TeamPermission::where('team_id', $this->current_team->id)->pluck('permission')->toArray();
        }
    }

    #[\Livewire\Attributes\Computed]
    public function teamMembers()
    {
        return TeamUser::where('team_id', $this->current_team->id)
            ->with('user')
            ->paginate(15);
    }

    #[\Livewire\Attributes\Computed]
    public function pendingInvitations()
    {
        return TeamInvitation::where('team_id', $this->current_team->id)->get();
    }

    public function changeRoleModal($teamUser): void
    {
        if (! auth()->user()->isTeamAdmin()) {
            Flux::toast(variant: 'danger', heading: 'Permission Denied', text: 'You do not have permission to change roles.');
            return;
        }

        $this->change_user = $teamUser;
        $this->change_user_role = $teamUser['role'];
        Flux::modal('change_role_modal')->show();
    }

    public function changeRole(): void
    {
        if (! auth()->user()->isTeamAdmin()) {
            return;
        }

        if (! array_key_exists($this->change_user_role, config('laratier.roles'))) {
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Invalid role selected.');
            Flux::modal('change_role_modal')->close();
            return;
        }

        TeamUser::where('id', $this->change_user['id'])->update(['role' => $this->change_user_role]);

        $this->change_user = [];
        $this->change_user_role = '';
        Flux::modal('change_role_modal')->close();
        Flux::toast(variant: 'success', heading: 'Role Updated', text: 'The team member role has been updated.');
    }

    public function changeExpiryModal($teamUser): void
    {
        if (! auth()->user()->isTeamAdmin()) {
            return;
        }

        $this->change_user = $teamUser;
        $this->change_user_expiry = $teamUser['expires'] ?? now()->addYear()->format('Y-m-d');
        Flux::modal('change_expiry_modal')->show();
    }

    public function changeExpiry(): void
    {
        if (! auth()->user()->isTeamAdmin()) {
            return;
        }

        TeamUser::where('id', $this->change_user['id'])->update(['expires' => $this->change_user_expiry]);

        $this->change_user = [];
        $this->change_user_expiry = '';
        Flux::modal('change_expiry_modal')->close();
        Flux::toast(variant: 'success', heading: 'Expiry Updated', text: 'The membership expiry has been updated.');
    }

    public function editTeam(): void
    {
        if (! auth()->user()->isTeamAdmin()) {
            return;
        }

        $this->validate(['edit_team_name' => 'required|string|max:255']);

        Team::where('id', $this->current_team->id)->update(['name' => $this->edit_team_name]);
        $this->current_team = Team::find($this->current_team->id);

        if (auth()->user()->current_team == $this->current_team->id) {
            session(['current_team' => $this->current_team]);
        }

        Flux::toast(variant: 'success', heading: 'Saved', text: 'The team name has been changed.');
    }

    public function inviteTeam(): void
    {
        if (! auth()->user()->isTeamAdmin()) {
            return;
        }

        $this->validate([
            'invite_team_email' => 'required|email',
            'invite_team_role' => 'required|in:'.implode(',', array_keys(config('laratier.roles'))),
            'invite_team_expires' => 'required|date',
        ]);

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

            Mail::to($this->invite_team_email)->queue(new TeamAddedUser($this->current_team->name, config('laratier.roles')[$this->invite_team_role]));

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

        Mail::to($this->invite_team_email)->queue(new TeamInviteUser($this->current_team->name, config('laratier.roles')[$this->invite_team_role]));

        Flux::toast(variant: 'success', heading: 'Invitation Sent', text: 'An invitation email has been sent.');
        $this->invite_team_email = '';
    }

    public function removeUserModal($userId): void
    {
        $this->remove_team_user = $userId;

        if ($userId == auth()->user()->id) {
            $this->remove_team_user_name = 'yourself';
        } else {
            $this->remove_team_user_name = User::findOrFail($userId)->name;
        }

        Flux::modal('removeUserConfirm')->show();
    }

    public function removeUser(): void
    {
        TeamUser::where('user_id', $this->remove_team_user)->where('team_id', $this->current_team->id)->delete();
        Flux::modal('removeUserConfirm')->close();
        Flux::toast(variant: 'success', heading: 'Removed', text: 'The user has been removed from the team.');
    }

    public function leaveTeam(): void
    {
        TeamUser::where('user_id', auth()->user()->id)->where('team_id', $this->current_team->id)->delete();
        session()->forget('current_team');
        Flux::modal('leaveTeamConfirm')->close();
        $this->redirect('/settings/teams');
    }

    public function deleteTeam()
    {
        TeamUser::where('team_id', $this->current_team->id)->delete();
        TeamInvitation::where('team_id', $this->current_team->id)->delete();
        TeamPermission::where('team_id', $this->current_team->id)->delete();
        Team::where('id', $this->current_team->id)->delete();

        return $this->redirect('/settings/teams');
    }

    public function cancelInvitation($invitationId): void
    {
        TeamInvitation::where('id', $invitationId)->where('team_id', $this->current_team->id)->delete();
        Flux::toast(variant: 'success', heading: 'Cancelled', text: 'The invitation has been cancelled.');
    }

    public function updatePermission($permission): void
    {
        if (in_array($permission, $this->permissions)) {
            TeamPermission::where('team_id', $this->current_team->id)->where('permission', $permission)->delete();
        } else {
            $perm = new TeamPermission;
            $perm->team_id = $this->current_team->id;
            $perm->permission = $permission;
            $perm->save();
        }

        $this->permissions = TeamPermission::where('team_id', $this->current_team->id)->pluck('permission')->toArray();
        \Illuminate\Support\Facades\Cache::forget('team_'.$this->current_team->id.'_permissions');
    }
}; ?>

<x-settings-layout>
    <x-slot:heading>{{ $current_team->name }}</x-slot:heading>
    <x-slot:subheading>Manage team members, invitations, and settings.</x-slot:subheading>

    <div class="max-w-2xl">
        {{-- Current Team Info --}}
        <flux:card class="mb-6">
            <div class="flex items-center gap-3">
                <div class="relative w-12 h-12 rounded-full bg-{{ $current_team->colour }}-400/20 text-{{ $current_team->colour }}-600 flex items-center justify-center">
                    <flux:icon variant="solid" name="{{ $current_team->icon }}" class="size-5" />
                </div>
                <div>
                    <flux:heading size="lg">{{ $current_team->name }}</flux:heading>
                    @if (auth()->user()->teamUser?->first())
                        <flux:badge :color="config('laratier.roles.'.auth()->user()->teamUser->first()->role.'.colour')" size="sm" class="mt-1">
                            {{ config('laratier.roles.'.auth()->user()->teamUser->first()->role.'.name') }}
                        </flux:badge>
                    @endif
                </div>
            </div>
        </flux:card>

        {{-- Team Members --}}
        @if (auth()->user()->isTeamAdmin())
        <flux:card class="mb-6">
            <flux:heading class="mb-4">Team Members</flux:heading>

            <flux:table :paginate="$this->teamMembers">
                <flux:table.columns>
                    <flux:table.column>Name</flux:table.column>
                    <flux:table.column>Email</flux:table.column>
                    <flux:table.column>Role</flux:table.column>
                    <flux:table.column>Expires</flux:table.column>
                    <flux:table.column>Actions</flux:table.column>
                </flux:table.columns>

                <flux:table.rows>
                @foreach ($this->teamMembers as $member)
                    <flux:table.row :key="$member->id">
                        <flux:table.cell>{{ $member->user->name }}</flux:table.cell>
                        <flux:table.cell>{{ $member->user->email }}</flux:table.cell>
                        <flux:table.cell>
                            <flux:badge :color="config('laratier.roles.'.$member->role.'.colour')" size="sm">
                                {{ config('laratier.roles.'.$member->role.'.name') }}
                            </flux:badge>
                        </flux:table.cell>
                        <flux:table.cell>{{ $member->expires ? \Carbon\Carbon::parse($member->expires)->format('d M Y') : 'Never' }}</flux:table.cell>
                        <flux:table.cell>
                            @if ($member->user->id != auth()->user()->id)
                                <div class="flex gap-1">
                                    <flux:button size="xs" icon="arrows-right-left" tooltip="Change Role" wire:click="changeRoleModal({{ $member }})" />
                                    <flux:button size="xs" icon="clock" tooltip="Change Expiry" wire:click="changeExpiryModal({{ $member }})" />
                                    <flux:button size="xs" icon="x-mark" tooltip="Remove" wire:click="removeUserModal('{{ $member->user_id }}')" />
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
                            <flux:badge :color="config('laratier.roles.'.$invitation->role.'.colour')" size="sm">
                                {{ config('laratier.roles.'.$invitation->role.'.name') }}
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
                @foreach (config('laratier.roles') as $key => $role)
                    <flux:radio :value="$key" :label="$role['name']" :description="$role['description']" />
                @endforeach
            </flux:radio.group>

            <flux:input wire:model="invite_team_expires" type="date" label="Membership Expires" class="mb-4 max-w-xs" />

            <div class="flex">
                <flux:spacer />
                <flux:button variant="primary" wire:click="inviteTeam()">Invite</flux:button>
            </div>
        </flux:card>

        {{-- Permissions (Admin only) --}}
        @if (auth()->user()->isAdmin())
        <flux:card class="mb-6">
            <flux:heading class="mb-4">Team Permissions</flux:heading>
            <flux:subheading class="mb-4">Manage the permissions for this team.</flux:subheading>

            <flux:fieldset>
                <div class="space-y-3">
                @foreach (config('laratier.permissions') as $permission)
                    <flux:separator variant="subtle" />
                    <flux:switch
                        label="{{ ucwords(str_replace('_', ' ', $permission)) }}"
                        :checked="in_array($permission, $this->permissions)"
                        wire:change="updatePermission('{{ $permission }}')"
                    />
                    @if ($loop->last)
                        <flux:separator variant="subtle" />
                    @endif
                @endforeach
                </div>
            </flux:fieldset>
        </flux:card>
        @endif
        @endif

        {{-- Leave Team --}}
        @if (auth()->user()->current_team == $current_team->id)
        <flux:card class="mb-6">
            <flux:heading>Leave Team</flux:heading>
            <flux:subheading>Remove yourself from this team.</flux:subheading>
            <div class="flex mt-4">
                <flux:spacer />
                <flux:button variant="danger" wire:click="$dispatch('open-modal', { name: 'leaveTeamConfirm' })">Leave</flux:button>
            </div>
        </flux:card>
        @endif

        {{-- Delete Team (Admin only, empty team only) --}}
        @if (auth()->user()->isAdmin() && $current_team->id != auth()->user()->current_team && $current_team->countUsers() === 0)
        <flux:card class="mb-6">
            <flux:heading>Delete Team</flux:heading>
            <flux:subheading>Permanently delete this team and all associated records.</flux:subheading>
            <div class="flex mt-4">
                <flux:spacer />
                <flux:button variant="danger" wire:click="deleteTeam">Delete</flux:button>
            </div>
        </flux:card>
        @endif
    </div>

    {{-- Modals --}}
    <flux:modal name="change_role_modal" focusable class="w-[350px]">
        <div>
            <flux:heading size="lg" class="mb-6">Change Role</flux:heading>
            <flux:subheading class="mb-4">
                Change the role for {{ $this->change_user['user']['name'] ?? '' }} in the {{ $this->current_team->name }} team.
            </flux:subheading>
            <flux:radio.group wire:model="change_user_role" variant="cards" :indicator="false" class="flex-col mb-6">
                @foreach (config('laratier.roles') as $key => $role)
                    <flux:radio :value="$key" :label="$role['name']" :description="$role['description']" />
                @endforeach
            </flux:radio.group>
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
                Change the membership expiry for {{ $this->change_user['user']['name'] ?? '' }}.
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
</x-settings-layout>

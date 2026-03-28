<?php

use Livewire\Attributes\Title;
use Livewire\Component;
use App\Models\Team;
use App\Models\TeamUser;

new #[Title('Teams')] class extends Component {
    public $teams;

    public string $new_team_name = '';
    public string $new_team_colour = 'blue';
    public string $new_team_icon = 'users';

    public array $colours = ['red', 'orange', 'yellow', 'green', 'cyan', 'blue', 'purple', 'pink', 'zinc'];
    public array $icons = ['users', 'building-office', 'server', 'globe-alt', 'shield-check', 'cloud', 'cpu-chip', 'signal', 'wifi', 'key', 'lock-closed', 'command-line', 'circle-stack', 'cube', 'squares-2x2', 'wrench', 'cog-6-tooth', 'beaker', 'academic-cap', 'rocket-launch'];

    public function mount()
    {
        if (auth()->user()->isAdmin()) {
            $this->teams = Team::all();
        } else {
            $this->teams = auth()->user()->teams->map(fn ($tu) => $tu->team);
        }
    }

    public function selectTeam($id)
    {
        return $this->redirect('/settings/team?id='.$id);
    }

    public function switchTeam($id)
    {
        $team = Team::findOrFail($id);
        $teamUser = TeamUser::where('team_id', $team->id)->where('user_id', auth()->user()->id)->firstOrFail();

        if ($teamUser->expired) {
            Flux::toast(variant: 'danger', heading: 'Expired', text: 'Your membership of this team has expired.');
            return;
        }

        session(['current_team' => $team]);
        auth()->user()->current_team = $id;
        auth()->user()->save();

        Flux::toast(variant: 'success', heading: 'Switched', text: 'You are now working in the '.$team->name.' team.');
        $this->redirect('/dashboard');
    }

    public function createTeam(): void
    {
        if (! auth()->user()->isAdmin()) {
            return;
        }

        $this->validate([
            'new_team_name' => 'required|string|max:255',
            'new_team_colour' => 'required|in:'.implode(',', $this->colours),
            'new_team_icon' => 'required|in:'.implode(',', $this->icons),
        ]);

        $team = new Team;
        $team->name = $this->new_team_name;
        $team->colour = $this->new_team_colour;
        $team->icon = $this->new_team_icon;
        $team->save();

        // Add creator as admin
        $teamUser = new TeamUser;
        $teamUser->user_id = auth()->user()->id;
        $teamUser->team_id = $team->id;
        $teamUser->role = 'admin';
        $teamUser->expires = now()->addYears(10)->format('Y-m-d');
        $teamUser->save();

        $this->teams = auth()->user()->isAdmin() ? Team::all() : auth()->user()->teams->map(fn ($tu) => $tu->team);
        $this->new_team_name = '';

        Flux::toast(variant: 'success', heading: 'Team Created', text: 'The team has been created.');
    }
}; ?>

<x-settings-layout>
    <x-slot:heading>Teams</x-slot:heading>
    <x-slot:subheading>Manage your teams and switch between them.</x-slot:subheading>

    <div class="max-w-2xl">
        {{-- Team List --}}
        <flux:card class="mb-6">
            <flux:heading class="mb-4">Your Teams</flux:heading>

            @if ($teams->count() > 0)
            <flux:table>
                <flux:table.columns>
                    <flux:table.column></flux:table.column>
                    <flux:table.column>Name</flux:table.column>
                    <flux:table.column>Members</flux:table.column>
                    <flux:table.column>Actions</flux:table.column>
                </flux:table.columns>
                <flux:table.rows>
                @foreach ($teams as $team)
                    <flux:table.row :key="$team->id">
                        <flux:table.cell>
                            <div class="relative w-10 h-10 rounded-full bg-{{ $team->colour }}-400/20 text-{{ $team->colour }}-600 flex items-center justify-center">
                                <flux:icon variant="solid" name="{{ $team->icon }}" class="size-4" />
                            </div>
                        </flux:table.cell>
                        <flux:table.cell class="font-medium">
                            {{ $team->name }}
                            @if (auth()->user()->current_team == $team->id)
                                <flux:badge color="green" size="sm" class="ml-2">Current</flux:badge>
                            @endif
                        </flux:table.cell>
                        <flux:table.cell>{{ $team->countUsers() }}</flux:table.cell>
                        <flux:table.cell>
                            <div class="flex gap-1">
                                @if (auth()->user()->current_team != $team->id)
                                    <flux:button size="xs" icon="arrows-right-left" tooltip="Switch to this team" wire:click="switchTeam('{{ $team->id }}')" />
                                @endif
                                <flux:button size="xs" icon="cog-6-tooth" tooltip="Manage" wire:click="selectTeam('{{ $team->id }}')" />
                            </div>
                        </flux:table.cell>
                    </flux:table.row>
                @endforeach
                </flux:table.rows>
            </flux:table>
            @else
                <flux:subheading>You are not a member of any teams yet.</flux:subheading>
            @endif
        </flux:card>

        {{-- Create Team (Admin Only) --}}
        @if (auth()->user()->isAdmin())
        <flux:card>
            <flux:heading class="mb-4">Create Team</flux:heading>

            <flux:input wire:model="new_team_name" label="Team Name" class="mb-4" />

            <div class="mb-4">
                <flux:label>Colour</flux:label>
                <div class="flex flex-wrap gap-2 mt-2">
                    @foreach ($colours as $colour)
                        <button
                            wire:click="$set('new_team_colour', '{{ $colour }}')"
                            class="w-8 h-8 rounded-full bg-{{ $colour }}-500 ring-2 {{ $new_team_colour === $colour ? 'ring-offset-2 ring-'.$colour.'-500' : 'ring-transparent' }}"
                        ></button>
                    @endforeach
                </div>
            </div>

            <div class="mb-4">
                <flux:label>Icon</flux:label>
                <div class="flex flex-wrap gap-2 mt-2">
                    @foreach ($icons as $icon)
                        <button
                            wire:click="$set('new_team_icon', '{{ $icon }}')"
                            class="w-10 h-10 rounded-lg flex items-center justify-center {{ $new_team_icon === $icon ? 'bg-zinc-200 dark:bg-zinc-700' : 'hover:bg-zinc-100 dark:hover:bg-zinc-800' }}"
                        >
                            <flux:icon name="{{ $icon }}" class="size-5" />
                        </button>
                    @endforeach
                </div>
            </div>

            <div class="flex">
                <flux:spacer />
                <flux:button variant="primary" wire:click="createTeam()">Create Team</flux:button>
            </div>
        </flux:card>
        @endif
    </div>
</x-settings-layout>

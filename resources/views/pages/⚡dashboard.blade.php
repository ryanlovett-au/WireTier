<?php

use App\Models\ZerotierNetwork;
use App\Services\ZerotierStatsService;
use Livewire\Attributes\Computed;
use Livewire\Attributes\Title;
use Livewire\Component;

new #[Title('Dashboard')] class extends Component
{
    #[Computed]
    public function ztStats()
    {
        if (! auth()->user()->team) {
            return ['total' => 0, 'by_network' => [], 'last_updated' => null];
        }

        return ZerotierStatsService::authorisedMembers(auth()->user()->team->id);
    }

    #[Computed]
    public function untrackedStats()
    {
        if (! auth()->user()->isAdmin()) {
            return ['count' => 0, 'last_updated' => null];
        }

        return ZerotierStatsService::untrackedNetworks();
    }

    #[Computed]
    public function recentNetworks()
    {
        if (! auth()->user()->team) {
            return collect();
        }

        return ZerotierNetwork::where('team_id', auth()->user()->team->id)
            ->latest()
            ->take(5)
            ->get();
    }

    #[Computed]
    public function networkCount()
    {
        if (! auth()->user()->team) {
            return 0;
        }

        return ZerotierNetwork::where('team_id', auth()->user()->team->id)->count();
    }
}; ?>

<div class="flex h-full w-full flex-1 flex-col gap-4 rounded-xl p-6" wire:poll.30s>
        <div class="mb-4">
            <flux:heading size="xl">Dashboard</flux:heading>
            <flux:subheading>
                @if (auth()->user()->team)
                    Working in <strong>{{ auth()->user()->team->name }}</strong>
                @else
                    <flux:badge color="amber">No team selected</flux:badge>
                @endif
            </flux:subheading>
        </div>

        @if (auth()->user()->team)
        <div class="grid auto-rows-min gap-4 md:grid-cols-3">
            {{-- Networks Count --}}
            <flux:card>
                <div class="flex items-center gap-3">
                    <div class="w-10 h-10 rounded-full bg-blue-400/20 text-blue-600 flex items-center justify-center">
                        <flux:icon name="globe-alt" class="size-5" />
                    </div>
                    <div>
                        <flux:heading size="lg">{{ $this->networkCount }}</flux:heading>
                        <flux:subheading>Networks</flux:subheading>
                    </div>
                </div>
            </flux:card>

            {{-- Team Members Count --}}
            <flux:card>
                <div class="flex items-center gap-3">
                    <div class="w-10 h-10 rounded-full bg-purple-400/20 text-purple-600 flex items-center justify-center">
                        <flux:icon name="users" class="size-5" />
                    </div>
                    <div>
                        <flux:heading size="lg">{{ auth()->user()->team->countUsers() }}</flux:heading>
                        <flux:subheading>Team Members</flux:subheading>
                    </div>
                </div>
            </flux:card>

            {{-- Authorised Devices --}}
            <flux:card>
                <div class="flex items-center gap-3">
                    <div class="w-10 h-10 rounded-full bg-emerald-400/20 text-emerald-600 flex items-center justify-center">
                        <flux:icon name="cpu-chip" class="size-5" />
                    </div>
                    <div>
                        <flux:heading size="lg">{{ $this->ztStats['total'] }}</flux:heading>
                        <flux:subheading>Authorised Devices</flux:subheading>
                    </div>
                </div>
                <div
                    x-data="{ label: '' }"
                    x-init="setInterval(() => {
                        let ts = {{ $this->ztStats['last_updated'] ?? 0 }};
                        if (!ts) { label = 'pending'; return; }
                        let s = Math.floor(Date.now()/1000) - ts;
                        if (s < 5) label = 'just now';
                        else if (s < 60) label = s + 's ago';
                        else if (s < 3600) label = Math.floor(s/60) + 'm ago';
                        else label = Math.floor(s/3600) + 'h ago';
                    }, 1000)"
                    class="text-xs text-zinc-400 mt-2"
                >
                    Last updated &middot; <span x-text="label"></span>
                </div>
            </flux:card>
        </div>

        @if (auth()->user()->isAdmin() && $this->untrackedStats['count'] > 0)
        <flux:card class="border-amber-500/30 bg-amber-50/50 dark:bg-amber-950/20">
            <div class="flex items-center justify-between">
                <div class="flex items-center gap-3">
                    <div class="w-10 h-10 rounded-full bg-amber-400/20 text-amber-600 flex items-center justify-center">
                        <flux:icon name="exclamation-triangle" class="size-5" />
                    </div>
                    <div>
                        <flux:heading size="lg">{{ $this->untrackedStats['count'] }}</flux:heading>
                        <flux:subheading>Untracked Network(s)</flux:subheading>
                    </div>
                </div>
                <flux:button size="sm" icon="arrow-down-tray" :href="route('zerotier.networks')" wire:navigate>Import</flux:button>
            </div>
            <div
                x-data="{ label: '' }"
                x-init="setInterval(() => {
                    let ts = {{ $this->untrackedStats['last_updated'] ?? 0 }};
                    if (!ts) { label = 'pending'; return; }
                    let s = Math.floor(Date.now()/1000) - ts;
                    if (s < 5) label = 'just now';
                    else if (s < 60) label = s + 's ago';
                    else if (s < 3600) label = Math.floor(s/60) + 'm ago';
                    else label = Math.floor(s/3600) + 'h ago';
                }, 1000)"
                class="text-xs text-zinc-400 mt-2"
            >
                Last checked &middot; <span x-text="label"></span>
            </div>
        </flux:card>
        @endif

        <div class="grid gap-4 md:grid-cols-2">
            {{-- Quick Actions --}}
            <flux:card>
                <flux:heading class="mb-4">Quick Actions</flux:heading>
                <div class="space-y-2">
                    <flux:button variant="ghost" icon="globe-alt" :href="route('zerotier.networks')" wire:navigate class="w-full justify-start">
                        Manage Networks
                    </flux:button>
                    @if (auth()->user()->isAdmin())
                    <flux:button variant="ghost" icon="signal" :href="route('zerotier.peers')" wire:navigate class="w-full justify-start">
                        View Peers & Status
                    </flux:button>
                    <flux:button variant="ghost" icon="key" :href="route('zerotier.tokens')" wire:navigate class="w-full justify-start">
                        Manage Controllers
                    </flux:button>
                    @endif
                    <flux:button variant="ghost" icon="users" :href="route('teams.show', auth()->user()->current_team)" wire:navigate class="w-full justify-start">
                        Team Settings
                    </flux:button>
                </div>
            </flux:card>

            {{-- Recent Networks --}}
            <flux:card>
                <flux:heading class="mb-4">Tracked Networks</flux:heading>
                @if ($this->recentNetworks->count() > 0)
                    <div class="space-y-3">
                        @foreach ($this->recentNetworks as $network)
                            <div class="flex items-center justify-between">
                                <div>
                                    <div class="font-medium text-sm">{{ $network->name ?? 'Unnamed' }}</div>
                                    <div class="text-xs text-zinc-500 font-mono flex items-center gap-1">
                                        {{ $network->network_id }}
                                        <span
                                            x-data="{ copied: false }"
                                            x-on:click.stop="navigator.clipboard.writeText('{{ $network->network_id }}'); copied = true; setTimeout(() => copied = false, 2000)"
                                            class="cursor-pointer"
                                        >
                                            <flux:icon x-show="!copied" name="clipboard" class="size-3 hover:text-zinc-700 dark:hover:text-zinc-300 transition-colors" />
                                            <flux:icon x-show="copied" name="clipboard-document-check" class="size-3 text-green-500" />
                                        </span>
                                    </div>
                                </div>
                                <div class="flex items-center gap-2">
                                    <flux:badge color="zinc" size="sm">
                                        {{ $this->ztStats['by_network'][$network->network_id] ?? 0 }} members
                                    </flux:badge>
                                    @if ($network->private)
                                        <flux:badge color="green" size="sm">Private</flux:badge>
                                    @else
                                        <flux:badge color="red" size="sm">Public</flux:badge>
                                    @endif
                                </div>
                            </div>
                        @endforeach
                    </div>
                @else
                    <flux:subheading>No networks tracked yet.</flux:subheading>
                @endif
            </flux:card>
        </div>
        @else
            <flux:card>
                <div class="text-center py-12">
                    <flux:icon name="users" class="mx-auto size-16 text-zinc-300 mb-4" />
                    <flux:heading size="lg">Get Started</flux:heading>
                    <flux:subheading class="mt-2 mb-6">Join or create a team to start managing ZeroTier networks.</flux:subheading>
                    <flux:button variant="primary" :href="route('teams.index')" wire:navigate>Go to Teams</flux:button>
                </div>
            </flux:card>
        @endif
    </div>
</div>

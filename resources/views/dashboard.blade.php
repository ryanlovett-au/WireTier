<x-layouts::app :title="__('Dashboard')">
    <div class="flex h-full w-full flex-1 flex-col gap-4 rounded-xl p-6">
        <div class="mb-4">
            <flux:heading size="xl">Dashboard</flux:heading>
            <flux:subheading>
                @if (auth()->user()->team)
                    Working in <strong>{{ auth()->user()->team->name }}</strong>
                @else
                    <flux:badge color="amber">No team selected</flux:badge>
                    <a href="{{ route('teams.index') }}" class="text-blue-500 hover:underline ml-2" wire:navigate>Join or create a team</a>
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
                        <flux:heading size="lg">
                            {{ \App\Models\ZerotierNetwork::where('team_id', auth()->user()->team->id)->count() }}
                        </flux:heading>
                        <flux:subheading>Networks</flux:subheading>
                    </div>
                </div>
            </flux:card>

            {{-- Connections Count --}}
            <flux:card>
                <div class="flex items-center gap-3">
                    <div class="w-10 h-10 rounded-full bg-green-400/20 text-green-600 flex items-center justify-center">
                        <flux:icon name="signal" class="size-5" />
                    </div>
                    <div>
                        <flux:heading size="lg">
                            {{ \App\Models\ZerotierToken::where('team_id', auth()->user()->team->id)->where('is_active', true)->count() }}
                        </flux:heading>
                        <flux:subheading>Active Connections</flux:subheading>
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
                        <flux:heading size="lg">
                            {{ auth()->user()->team->countUsers() }}
                        </flux:heading>
                        <flux:subheading>Team Members</flux:subheading>
                    </div>
                </div>
            </flux:card>
        </div>

        <div class="grid gap-4 md:grid-cols-2">
            {{-- Quick Actions --}}
            <flux:card>
                <flux:heading class="mb-4">Quick Actions</flux:heading>
                <div class="space-y-2">
                    <flux:button variant="ghost" icon="globe-alt" :href="route('zerotier.networks')" wire:navigate class="w-full justify-start">
                        Manage Networks
                    </flux:button>
                    <flux:button variant="ghost" icon="signal" :href="route('zerotier.peers')" wire:navigate class="w-full justify-start">
                        View Peers & Status
                    </flux:button>
                    <flux:button variant="ghost" icon="key" :href="route('zerotier.tokens')" wire:navigate class="w-full justify-start">
                        Manage Connections
                    </flux:button>
                    <flux:button variant="ghost" icon="users" :href="route('teams.show', ['id' => auth()->user()->current_team])" wire:navigate class="w-full justify-start">
                        Team Settings
                    </flux:button>
                </div>
            </flux:card>

            {{-- Recent Networks --}}
            <flux:card>
                <flux:heading class="mb-4">Tracked Networks</flux:heading>
                @php
                    $recentNetworks = \App\Models\ZerotierNetwork::where('team_id', auth()->user()->team->id)
                        ->latest()
                        ->take(5)
                        ->get();
                @endphp

                @if ($recentNetworks->count() > 0)
                    <div class="space-y-3">
                        @foreach ($recentNetworks as $network)
                            <div class="flex items-center justify-between">
                                <div>
                                    <div class="font-medium text-sm">{{ $network->name ?? 'Unnamed' }}</div>
                                    <div class="text-xs text-zinc-500 font-mono">{{ $network->network_id }}</div>
                                </div>
                                @if ($network->private)
                                    <flux:badge color="amber" size="sm">Private</flux:badge>
                                @else
                                    <flux:badge color="green" size="sm">Public</flux:badge>
                                @endif
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
</x-layouts::app>

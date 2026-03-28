<?php

use Livewire\Attributes\Title;
use Livewire\Component;
use App\Models\ZerotierToken;
use App\Services\ZerotierService;

new #[Title('Node Status & Peers')] class extends Component {
    public $tokens;
    public string $selectedToken = '';
    public array $peers = [];
    public array $status = [];

    public function mount()
    {
        if (! auth()->user()->team) {
            $this->redirect('/settings/teams');
            return;
        }

        $this->tokens = ZerotierToken::where('team_id', auth()->user()->team->id)
            ->where('is_active', true)
            ->get();

        if ($this->tokens->count() > 0) {
            $this->selectedToken = $this->tokens->first()->id;
            $this->loadData();
        }
    }

    public function loadData(): void
    {
        if (empty($this->selectedToken)) {
            return;
        }

        $token = ZerotierToken::findOrFail($this->selectedToken);
        $service = new ZerotierService($token);

        try {
            $this->status = $service->getStatus();
            $this->peers = $service->getPeers();
        } catch (\Exception $e) {
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Failed to load peers: '.$e->getMessage());
        }
    }

    public function updatedSelectedToken(): void
    {
        $this->loadData();
    }
}; ?>

<x-layouts::app :title="__('ZeroTier Peers')">
    <div class="mx-auto max-w-5xl p-6">
        <div class="flex items-center justify-between mb-6">
            <div>
                <flux:heading size="xl">Node Status & Peers</flux:heading>
                <flux:subheading>View the local ZeroTier node status and connected peers.</flux:subheading>
            </div>
            <div class="flex items-center gap-3">
                @if ($tokens->count() > 1)
                    <flux:select wire:model.live="selectedToken" class="w-48">
                        @foreach ($tokens as $token)
                            <flux:select.option value="{{ $token->id }}">{{ $token->name }}</flux:select.option>
                        @endforeach
                    </flux:select>
                @endif
                <flux:button size="sm" icon="arrow-path" wire:click="loadData">Refresh</flux:button>
            </div>
        </div>

        @if ($tokens->count() === 0)
            <flux:card>
                <div class="text-center py-8">
                    <flux:icon name="signal-slash" class="mx-auto size-12 text-zinc-400 mb-4" />
                    <flux:heading>No Connections</flux:heading>
                    <flux:subheading class="mb-4">Add a ZeroTier connection first.</flux:subheading>
                    <flux:button variant="primary" :href="route('zerotier.tokens')" wire:navigate>Add Connection</flux:button>
                </div>
            </flux:card>
        @else
            {{-- Node Status --}}
            @if (! empty($status))
            <flux:card class="mb-6">
                <flux:heading class="mb-4">Node Status</flux:heading>
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div>
                        <flux:label>Address</flux:label>
                        <div class="font-mono text-sm mt-1">{{ $status['address'] ?? '—' }}</div>
                    </div>
                    <div>
                        <flux:label>Version</flux:label>
                        <div class="text-sm mt-1">{{ $status['version'] ?? '—' }}</div>
                    </div>
                    <div>
                        <flux:label>Online</flux:label>
                        <div class="mt-1">
                            @if ($status['online'] ?? false)
                                <flux:badge color="green" size="sm">Online</flux:badge>
                            @else
                                <flux:badge color="red" size="sm">Offline</flux:badge>
                            @endif
                        </div>
                    </div>
                    <div>
                        <flux:label>TCP Fallback</flux:label>
                        <div class="text-sm mt-1">{{ ($status['tcpFallbackActive'] ?? false) ? 'Active' : 'Inactive' }}</div>
                    </div>
                </div>
            </flux:card>
            @endif

            {{-- Peers --}}
            <flux:card>
                <flux:heading class="mb-4">Peers ({{ count($peers) }})</flux:heading>

                @if (count($peers) === 0)
                    <flux:subheading>No peers connected.</flux:subheading>
                @else
                    <flux:table>
                        <flux:table.columns>
                            <flux:table.column>Address</flux:table.column>
                            <flux:table.column>Role</flux:table.column>
                            <flux:table.column>Latency</flux:table.column>
                            <flux:table.column>Version</flux:table.column>
                            <flux:table.column>Paths</flux:table.column>
                        </flux:table.columns>
                        <flux:table.rows>
                        @foreach ($peers as $peer)
                            <flux:table.row :key="$peer['address'] ?? $loop->index">
                                <flux:table.cell class="font-mono text-xs">{{ $peer['address'] ?? '—' }}</flux:table.cell>
                                <flux:table.cell>
                                    <flux:badge :color="($peer['role'] ?? '') === 'LEAF' ? 'blue' : 'amber'" size="sm">
                                        {{ $peer['role'] ?? '—' }}
                                    </flux:badge>
                                </flux:table.cell>
                                <flux:table.cell>{{ ($peer['latency'] ?? -1) >= 0 ? ($peer['latency'].'ms') : '—' }}</flux:table.cell>
                                <flux:table.cell class="text-xs">{{ ($peer['versionMajor'] ?? '').'.'.($peer['versionMinor'] ?? '').'.'.($peer['versionRev'] ?? '') }}</flux:table.cell>
                                <flux:table.cell class="text-xs font-mono">
                                    @foreach (($peer['paths'] ?? []) as $path)
                                        <div>{{ $path['address'] ?? '' }} {{ ($path['active'] ?? false) ? '(active)' : '' }}</div>
                                    @endforeach
                                </flux:table.cell>
                            </flux:table.row>
                        @endforeach
                        </flux:table.rows>
                    </flux:table>
                @endif
            </flux:card>
        @endif
    </div>
</x-layouts::app>

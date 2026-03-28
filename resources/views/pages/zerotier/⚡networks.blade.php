<?php

use Livewire\Attributes\Title;
use Livewire\Component;
use App\Models\ZerotierToken;
use App\Models\ZerotierNetwork;
use App\Services\ZerotierService;

new #[Title('ZeroTier Networks')] class extends Component {
    public $tokens;
    public array $networks = [];
    public string $selectedToken = '';

    // Create network form
    public string $new_network_name = '';
    public bool $new_network_private = true;
    public string $new_network_subnet = '10.147.17.0/24';

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
            $this->loadNetworks();
        }
    }

    public function loadNetworks(): void
    {
        if (empty($this->selectedToken)) {
            return;
        }

        $token = ZerotierToken::findOrFail($this->selectedToken);
        $service = new ZerotierService($token);

        try {
            $networkIds = $service->getControllerNetworks();
            $this->networks = [];

            foreach ($networkIds as $networkId) {
                try {
                    $network = $service->getControllerNetwork($networkId);
                    $members = $service->getNetworkMembers($networkId);
                    $network['_member_count'] = count($members);
                    $this->networks[] = $network;
                } catch (\Exception $e) {
                    // Skip networks that error
                }
            }
        } catch (\Exception $e) {
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Failed to load networks: '.$e->getMessage());
        }
    }

    public function updatedSelectedToken(): void
    {
        $this->loadNetworks();
    }

    public function createNetwork(): void
    {
        if (! auth()->user()->isTeamAdmin()) {
            return;
        }

        $this->validate([
            'new_network_name' => 'required|string|max:255',
            'new_network_subnet' => 'required|string',
        ]);

        $token = ZerotierToken::findOrFail($this->selectedToken);
        $service = new ZerotierService($token);

        try {
            // Parse subnet
            $parts = explode('/', $this->new_network_subnet);
            $ip = $parts[0];
            $bits = $parts[1] ?? '24';

            $network = $service->createNetwork([
                'name' => $this->new_network_name,
                'private' => $this->new_network_private,
                'ipAssignmentPools' => [
                    [
                        'ipRangeStart' => long2ip(ip2long($ip) + 1),
                        'ipRangeEnd' => long2ip(ip2long($ip) + (pow(2, 32 - (int) $bits) - 2)),
                    ],
                ],
                'routes' => [
                    ['target' => $this->new_network_subnet],
                ],
                'v4AssignMode' => ['zt' => true],
            ]);

            // Track in database
            $dbNetwork = new ZerotierNetwork;
            $dbNetwork->team_id = auth()->user()->team->id;
            $dbNetwork->zerotier_token_id = $token->id;
            $dbNetwork->network_id = $network['nwid'] ?? $network['id'];
            $dbNetwork->name = $this->new_network_name;
            $dbNetwork->private = $this->new_network_private;
            $dbNetwork->config = $network;
            $dbNetwork->save();

            Flux::toast(variant: 'success', heading: 'Network Created', text: 'Network '.$dbNetwork->network_id.' has been created.');
            Flux::modal('createNetworkModal')->close();
            $this->new_network_name = '';
            $this->loadNetworks();
        } catch (\Exception $e) {
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Failed to create network: '.$e->getMessage());
        }
    }

    public function deleteNetwork($networkId): void
    {
        if (! auth()->user()->isTeamAdmin()) {
            return;
        }

        $token = ZerotierToken::findOrFail($this->selectedToken);
        $service = new ZerotierService($token);

        try {
            $service->deleteNetwork($networkId);
            ZerotierNetwork::where('network_id', $networkId)->delete();
            Flux::toast(variant: 'success', heading: 'Deleted', text: 'Network has been deleted.');
            $this->loadNetworks();
        } catch (\Exception $e) {
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Failed to delete network: '.$e->getMessage());
        }
    }
}; ?>

<x-layouts::app :title="__('ZeroTier Networks')">
    <div class="mx-auto max-w-5xl p-6">
        <div class="flex items-center justify-between mb-6">
            <div>
                <flux:heading size="xl">Networks</flux:heading>
                <flux:subheading>Manage ZeroTier networks on your controller.</flux:subheading>
            </div>
            <div class="flex items-center gap-3">
                @if ($tokens->count() > 1)
                    <flux:select wire:model.live="selectedToken" class="w-48">
                        @foreach ($tokens as $token)
                            <flux:select.option value="{{ $token->id }}">{{ $token->name }}</flux:select.option>
                        @endforeach
                    </flux:select>
                @endif

                @if (auth()->user()->isTeamAdmin() && $tokens->count() > 0)
                    <flux:button variant="primary" icon="plus" wire:click="$dispatch('open-modal', { name: 'createNetworkModal' })">Create Network</flux:button>
                @endif
            </div>
        </div>

        @if ($tokens->count() === 0)
            <flux:card>
                <div class="text-center py-8">
                    <flux:icon name="signal-slash" class="mx-auto size-12 text-zinc-400 mb-4" />
                    <flux:heading>No Connections</flux:heading>
                    <flux:subheading class="mb-4">Add a ZeroTier connection first to manage networks.</flux:subheading>
                    <flux:button variant="primary" :href="route('zerotier.tokens')" wire:navigate>Add Connection</flux:button>
                </div>
            </flux:card>
        @elseif (count($networks) === 0)
            <flux:card>
                <div class="text-center py-8">
                    <flux:icon name="globe-alt" class="mx-auto size-12 text-zinc-400 mb-4" />
                    <flux:heading>No Networks</flux:heading>
                    <flux:subheading>No networks found on this controller. Create one to get started.</flux:subheading>
                </div>
            </flux:card>
        @else
            <div class="grid gap-4">
                @foreach ($networks as $network)
                <flux:card>
                    <div class="flex items-center justify-between">
                        <div>
                            <div class="flex items-center gap-3">
                                <flux:heading size="lg">{{ $network['name'] ?? 'Unnamed' }}</flux:heading>
                                @if ($network['private'] ?? true)
                                    <flux:badge color="amber" size="sm">Private</flux:badge>
                                @else
                                    <flux:badge color="green" size="sm">Public</flux:badge>
                                @endif
                            </div>
                            <div class="flex items-center gap-4 mt-2 text-sm text-zinc-500">
                                <span class="font-mono">{{ $network['nwid'] ?? $network['id'] ?? '—' }}</span>
                                <span>{{ $network['_member_count'] ?? 0 }} members</span>
                                @if (! empty($network['routes']))
                                    @foreach ($network['routes'] as $route)
                                        <span class="font-mono">{{ $route['target'] ?? '' }}</span>
                                    @endforeach
                                @endif
                            </div>
                        </div>
                        <div class="flex gap-2">
                            <flux:button size="sm" icon="users" :href="route('zerotier.members', ['networkId' => $network['nwid'] ?? $network['id'], 'tokenId' => $selectedToken])" wire:navigate>
                                Members
                            </flux:button>
                            @if (auth()->user()->isTeamAdmin())
                                <flux:button size="sm" icon="trash" variant="danger" wire:click="deleteNetwork('{{ $network['nwid'] ?? $network['id'] }}')" wire:confirm="Are you sure you want to delete this network?">
                                    Delete
                                </flux:button>
                            @endif
                        </div>
                    </div>
                </flux:card>
                @endforeach
            </div>
        @endif

        {{-- Create Network Modal --}}
        <flux:modal name="createNetworkModal" focusable class="w-[450px]">
            <flux:heading size="lg" class="mb-4">Create Network</flux:heading>

            <flux:input wire:model="new_network_name" label="Network Name" class="mb-4" />
            <flux:input wire:model="new_network_subnet" label="IPv4 Subnet" description="e.g. 10.147.17.0/24" class="mb-4" />

            <flux:switch wire:model="new_network_private" label="Private Network" description="Members must be authorized to join" class="mb-4" />

            <div class="flex justify-end space-x-2">
                <flux:modal.close><flux:button variant="filled">Cancel</flux:button></flux:modal.close>
                <flux:button variant="primary" wire:click="createNetwork()">Create</flux:button>
            </div>
        </flux:modal>
    </div>
</x-layouts::app>

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

    // Delete confirmation
    public string $delete_network_id = '';
    public string $delete_network_name = '';

    // Create network form
    public string $new_network_name = '';
    public bool $new_network_private = true;
    public string $new_network_subnet = '';
    public array $subnet_suggestions = [];

    public function generateSubnetSuggestions(): void
    {
        $suggestions = [];
        $used = [];

        while (count($suggestions) < 6) {
            // Alternate between 10.x.x.0/24 and 172.x.x.0/24
            if (count($suggestions) % 2 === 0) {
                // 10.x.x.0/24 — avoid .0.x and .1.x (too common)
                $second = rand(2, 254);
                $third  = rand(0, 254);
                $subnet = "10.{$second}.{$third}.0/24";
            } else {
                // 172.16.x.0/24 through 172.31.x.0/24
                $second = rand(16, 31);
                $third  = rand(0, 254);
                $subnet = "172.{$second}.{$third}.0/24";
            }

            if (! in_array($subnet, $used)) {
                $used[]        = $subnet;
                $suggestions[] = $subnet;
            }
        }

        $this->subnet_suggestions = $suggestions;
        if (empty($this->new_network_subnet)) {
            $this->new_network_subnet = $suggestions[0];
        }
    }

    public function mount()
    {
        if (! auth()->user()->team) {
            $this->redirect('/settings/teams');
            return;
        }

        $this->generateSubnetSuggestions();

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
                    $network['_member_count']        = collect($members)->where('authorized', true)->count();
                    $network['_pending_count']        = collect($members)->where('authorized', false)->count();
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

    public function openCreateModal(): void
    {
        $this->new_network_name   = '';
        $this->new_network_subnet = '';
        $this->generateSubnetSuggestions();
        Flux::modal('createNetworkModal')->show();
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

    public function confirmDeleteNetwork(string $networkId, string $networkName): void
    {
        if (! auth()->user()->isTeamAdmin()) {
            return;
        }

        $this->delete_network_id   = $networkId;
        $this->delete_network_name = $networkName ?: $networkId;
        Flux::modal('deleteNetworkModal')->show();
    }

    public function deleteNetwork(): void
    {
        if (! auth()->user()->isTeamAdmin()) {
            return;
        }

        $token = ZerotierToken::findOrFail($this->selectedToken);
        $service = new ZerotierService($token);

        try {
            $service->deleteNetwork($this->delete_network_id);
            ZerotierNetwork::where('network_id', $this->delete_network_id)->delete();
            Flux::modal('deleteNetworkModal')->close();
            Flux::toast(variant: 'success', heading: 'Deleted', text: 'Network has been deleted.');
            $this->delete_network_id   = '';
            $this->delete_network_name = '';
            $this->loadNetworks();
        } catch (\Exception $e) {
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Failed to delete network: '.$e->getMessage());
        }
    }
}; ?>

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
                    <flux:button variant="primary" icon="plus" wire:click="openCreateModal">Create Network</flux:button>
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
                    <div class="flex items-end justify-between">
                        <div>
                            <div class="flex items-center gap-3">
                                <flux:heading size="lg">{{ $network['name'] ?? 'Unnamed' }}</flux:heading>
                                @if ($network['private'] ?? true)
                                    <flux:badge color="green" size="sm">Private</flux:badge>
                                @else
                                    <flux:badge color="red" size="sm">Public</flux:badge>
                                @endif
                            </div>
                            <div class="flex items-center gap-4 mt-2 text-sm text-zinc-500">
                                <span class="font-mono flex items-center gap-1">
                                    {{ $network['nwid'] ?? $network['id'] ?? '—' }}
                                    <span
                                        x-data="{ copied: false }"
                                        x-on:click.stop="navigator.clipboard.writeText('{{ $network['nwid'] ?? $network['id'] ?? '' }}'); copied = true; setTimeout(() => copied = false, 2000)"
                                        class="cursor-pointer"
                                    >
                                        <flux:icon x-show="!copied" name="clipboard" class="size-3.5 hover:text-zinc-700 dark:hover:text-zinc-300 transition-colors" />
                                        <flux:icon x-show="copied" name="clipboard-document-check" class="size-3.5 text-green-500" />
                                    </span>
                                </span>
                                <flux:badge color="zinc" size="sm">{{ $network['_member_count'] ?? 0 }} members</flux:badge>
                                @if (($network['_pending_count'] ?? 0) > 0)
                                    <flux:badge color="orange" size="sm">{{ $network['_pending_count'] }} pending</flux:badge>
                                @endif
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
                                <flux:button size="sm" icon="trash" variant="danger" wire:click="confirmDeleteNetwork('{{ $network['nwid'] ?? $network['id'] }}', '{{ addslashes($network['name'] ?? '') }}')" />
                            @endif
                        </div>
                    </div>
                </flux:card>
                @endforeach
            </div>
        @endif

        {{-- Delete Network Modal --}}
        <flux:modal name="deleteNetworkModal" focusable class="max-w-sm">
            <div class="w-14 h-14 rounded-full bg-red-100 p-4 mt-4 mb-4 mx-auto flex items-center justify-center">
                <flux:icon name="trash" class="size-6 text-red-600" />
            </div>

            <flux:heading size="lg" class="text-center">Delete Network?</flux:heading>
            <flux:subheading class="text-center mt-2 mb-6">
                Are you sure you want to delete <strong>{{ $delete_network_name }}</strong>?
                This cannot be undone.
            </flux:subheading>

            <div class="flex justify-end gap-2">
                <flux:modal.close>
                    <flux:button variant="filled">Cancel</flux:button>
                </flux:modal.close>
                <flux:button variant="danger" wire:click="deleteNetwork">Delete</flux:button>
            </div>
        </flux:modal>

        {{-- Create Network Modal --}}
        <flux:modal name="createNetworkModal" focusable class="w-[480px]">
            <flux:heading size="lg" class="mb-4">Create Network</flux:heading>

            <flux:input wire:model="new_network_name" label="Network Name" class="mb-5" />

            <flux:label class="mb-2">IPv4 Subnet</flux:label>
            <div class="flex flex-wrap gap-2 mb-6">
                @foreach ($subnet_suggestions as $suggestion)
                    <button
                        type="button"
                        wire:click="$set('new_network_subnet', '{{ $suggestion }}')"
                        class="px-2.5 py-1 rounded-md text-xs font-mono border border-zinc-300 text-zinc-600 bg-white hover:border-zinc-500 dark:bg-zinc-800 dark:text-zinc-300 dark:border-zinc-600 transition-colors"
                        :style="$wire.new_network_subnet === '{{ $suggestion }}' ? 'background:#18181b;color:#fff;border-color:#18181b;' : ''"
                    >{{ $suggestion }}</button>
                @endforeach
                <button
                    type="button"
                    wire:click="generateSubnetSuggestions"
                    class="px-2.5 py-1 rounded-md text-xs border border-dashed border-zinc-300 text-zinc-400 hover:border-zinc-500 hover:text-zinc-600 dark:border-zinc-600 dark:text-zinc-500 dark:hover:border-zinc-400 transition-colors"
                >↺ New</button>
            </div>
            <flux:input wire:model="new_network_subnet" placeholder="or type your own…" class="mb-5" />

            <flux:switch wire:model="new_network_private" label="Private Network" description="Members must be authorized to join" class="mb-6" />

            <div class="flex justify-end space-x-2 mt-4">
                <flux:modal.close><flux:button variant="filled">Cancel</flux:button></flux:modal.close>
                <flux:button variant="primary" wire:click="createNetwork()">Create</flux:button>
            </div>
        </flux:modal>
</div>

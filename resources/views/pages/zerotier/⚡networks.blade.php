<?php

use App\Models\AuditLog;
use App\Models\Team;
use App\Models\ZerotierNetwork;
use App\Models\ZerotierToken;
use App\Services\ZerotierService;
use Livewire\Attributes\Title;
use Livewire\Component;

new #[Title('ZeroTier Networks')] class extends Component
{
    public $tokens;

    public array $networks = [];

    public string $selectedToken = '';

    // Delete confirmation
    public string $delete_network_id = '';

    public string $delete_network_name = '';

    // Edit network modal
    public string $editing_network_id = '';

    public string $edit_tab = 'settings';

    public string $edit_name = '';

    public bool $edit_private = true;

    public bool $edit_broadcast = true;

    public int $edit_multicast_limit = 32;

    public array $edit_routes = [];

    public array $edit_ip_pools = [];

    public string $new_route_target = '';

    public string $new_route_via = '';

    public string $new_pool_start = '';

    public string $new_pool_end = '';

    // Create network form
    public string $new_network_name = '';

    public bool $new_network_private = true;

    public string $new_network_subnet = '';

    public array $subnet_suggestions = [];

    // Import (admin-only)
    public array $untracked_networks = [];

    public array $teams = [];

    public array $import_team_selections = [];

    // Delete untracked network
    public string $delete_untracked_id = '';

    public string $delete_untracked_name = '';

    public function generateSubnetSuggestions(): void
    {
        $suggestions = [];
        $used = [];

        while (count($suggestions) < 6) {
            // Alternate between 10.x.x.0/24 and 172.x.x.0/24
            if (count($suggestions) % 2 === 0) {
                // 10.x.x.0/24 — avoid .0.x and .1.x (too common)
                $second = rand(2, 254);
                $third = rand(0, 254);
                $subnet = "10.{$second}.{$third}.0/24";
            } else {
                // 172.16.x.0/24 through 172.31.x.0/24
                $second = rand(16, 31);
                $third = rand(0, 254);
                $subnet = "172.{$second}.{$third}.0/24";
            }

            if (! in_array($subnet, $used)) {
                $used[] = $subnet;
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

        $this->tokens = ZerotierToken::where('is_active', true)
            ->select('id', 'name')
            ->get();

        if ($this->tokens->count() > 0) {
            $this->selectedToken = $this->tokens->first()->id;
            $this->loadNetworks();

            if (auth()->user()->isAdmin()) {
                $this->discoverNetworks();
            }
        }
    }

    public function loadNetworks(): void
    {
        if (empty($this->selectedToken)) {
            return;
        }

        // DB-first: only show networks this team owns for the selected controller
        $dbNetworks = ZerotierNetwork::where('team_id', auth()->user()->team->id)
            ->where('zerotier_token_id', $this->selectedToken)
            ->get();

        $token = ZerotierToken::findOrFail($this->selectedToken);
        $service = new ZerotierService($token);

        $this->networks = [];

        foreach ($dbNetworks as $dbNetwork) {
            $offline = [
                'id' => $dbNetwork->network_id,
                'nwid' => $dbNetwork->network_id,
                'name' => $dbNetwork->name ?? 'Unknown',
                'private' => $dbNetwork->private,
                'routes' => [],
                '_member_count' => 0,
                '_pending_count' => 0,
                '_offline' => true,
            ];

            try {
                $network = $service->getControllerNetwork($dbNetwork->network_id);

                // If API returned empty/invalid data, use offline fallback
                if (empty($network) || ! isset($network['nwid'])) {
                    $this->networks[] = $offline;

                    continue;
                }

                $memberIds = array_keys($service->getNetworkMembers($dbNetwork->network_id));
                $authorized = 0;
                $pending = 0;
                foreach ($memberIds as $nodeId) {
                    try {
                        $m = $service->getNetworkMember($dbNetwork->network_id, $nodeId);
                        ($m['authorized'] ?? false) ? $authorized++ : $pending++;
                    } catch (Exception) {
                    }
                }
                $network['_member_count'] = $authorized;
                $network['_pending_count'] = $pending;
                $this->networks[] = $network;
            } catch (Exception) {
                $this->networks[] = $offline;
            }
        }
    }

    public function updatedSelectedToken(): void
    {
        $this->loadNetworks();

        if (auth()->user()->isAdmin()) {
            $this->discoverNetworks();
        } else {
            $this->untracked_networks = [];
        }
    }

    // ─── Import (Admin Only) ──────────────────────────────────────────

    public function discoverNetworks(): void
    {
        if (! auth()->user()->isAdmin()) {
            return;
        }

        if (empty($this->selectedToken)) {
            return;
        }

        $token = ZerotierToken::findOrFail($this->selectedToken);
        $service = new ZerotierService($token);

        try {
            $allNetworkIds = $service->getControllerNetworks();
            $trackedIds = ZerotierNetwork::where('zerotier_token_id', $this->selectedToken)
                ->pluck('network_id')
                ->toArray();

            $this->untracked_networks = [];

            foreach ($allNetworkIds as $networkId) {
                if (in_array($networkId, $trackedIds)) {
                    continue;
                }

                try {
                    $network = $service->getControllerNetwork($networkId);
                    $this->untracked_networks[] = [
                        'nwid' => $networkId,
                        'name' => $network['name'] ?? '',
                        'private' => $network['private'] ?? true,
                    ];
                } catch (Exception) {
                    $this->untracked_networks[] = [
                        'nwid' => $networkId,
                        'name' => '',
                        'private' => true,
                    ];
                }
            }

            $this->teams = Team::all()->map(fn ($t) => ['id' => $t->id, 'name' => $t->name])->toArray();

            // Pre-select the first team for each untracked network
            $defaultTeamId = ! empty($this->teams) ? $this->teams[0]['id'] : null;
            $this->import_team_selections = [];
            foreach ($this->untracked_networks as $net) {
                $this->import_team_selections[$net['nwid']] = $defaultTeamId;
            }

            if (empty($this->untracked_networks)) {
                Flux::toast(variant: 'success', heading: 'All Synced', text: 'All networks on this controller are already tracked.');
            }
        } catch (Exception $e) {
            report($e);
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Failed to discover networks.');
        }
    }

    public function importNetwork(string $networkId): void
    {
        if (! auth()->user()->isAdmin()) {
            return;
        }

        $teamId = $this->import_team_selections[$networkId] ?? null;

        if (! $teamId) {
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Please select a team for this network.');

            return;
        }

        $token = ZerotierToken::findOrFail($this->selectedToken);
        $service = new ZerotierService($token);

        try {
            $network = $service->getControllerNetwork($networkId);

            ZerotierNetwork::create([
                'team_id' => $teamId,
                'zerotier_token_id' => $this->selectedToken,
                'network_id' => $networkId,
                'name' => $network['name'] ?? null,
                'private' => $network['private'] ?? true,
                'config' => $network,
            ]);

            AuditLog::record('network.imported', 'network', $networkId, ['name' => $network['name'] ?? null, 'assigned_team' => $teamId]);

            $this->untracked_networks = array_values(
                array_filter($this->untracked_networks, fn ($n) => $n['nwid'] !== $networkId)
            );

            Flux::toast(variant: 'success', heading: 'Imported', text: "Network {$networkId} has been assigned.");
            $this->loadNetworks();
        } catch (Exception $e) {
            report($e);
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Failed to import network.');
        }
    }

    public function confirmDeleteUntracked(string $networkId, string $networkName): void
    {
        if (! auth()->user()->isAdmin()) {
            return;
        }

        $this->delete_untracked_id = $networkId;
        $this->delete_untracked_name = $networkName ?: $networkId;
        Flux::modal('deleteUntrackedModal')->show();
    }

    public function deleteUntrackedNetwork(): void
    {
        if (! auth()->user()->isAdmin()) {
            return;
        }

        $token = ZerotierToken::findOrFail($this->selectedToken);
        $service = new ZerotierService($token);

        try {
            $service->deleteNetwork($this->delete_untracked_id);
            Flux::modal('deleteUntrackedModal')->close();
            Flux::toast(variant: 'success', heading: 'Deleted', text: 'Untracked network has been removed from the controller.');

            $this->untracked_networks = array_values(
                array_filter($this->untracked_networks, fn ($n) => $n['nwid'] !== $this->delete_untracked_id)
            );
            AuditLog::record('network.untracked_deleted', 'network', $this->delete_untracked_id);
            $this->delete_untracked_id = '';
            $this->delete_untracked_name = '';
        } catch (Exception $e) {
            report($e);
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Failed to delete network from controller.');
        }
    }

    public function openCreateModal(): void
    {
        $this->new_network_name = '';
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

            AuditLog::record('network.created', 'network', $dbNetwork->network_id, ['name' => $this->new_network_name, 'token' => $token->name]);

            Flux::toast(variant: 'success', heading: 'Network Created', text: 'Network '.$dbNetwork->network_id.' has been created.');
            Flux::modal('createNetworkModal')->close();
            $this->new_network_name = '';
            $this->loadNetworks();
        } catch (Exception $e) {
            report($e);
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Failed to create network. Please try again.');
        }
    }

    // ─── Edit Network ────────────────────────────────────────────────

    public function openEditModal(string $networkId): void
    {
        $token = ZerotierToken::findOrFail($this->selectedToken);
        $service = new ZerotierService($token);

        try {
            $network = $service->getControllerNetwork($networkId);

            $this->editing_network_id = $networkId;
            $this->edit_tab = 'settings';
            $this->edit_name = $network['name'] ?? '';
            $this->edit_private = $network['private'] ?? true;
            $this->edit_broadcast = $network['enableBroadcast'] ?? true;
            $this->edit_multicast_limit = $network['multicastLimit'] ?? 32;
            $this->edit_routes = array_values($network['routes'] ?? []);
            $this->edit_ip_pools = array_values($network['ipAssignmentPools'] ?? []);
            $this->new_route_target = '';
            $this->new_route_via = '';
            $this->new_pool_start = '';
            $this->new_pool_end = '';

            Flux::modal('editNetworkModal')->show();
        } catch (Exception $e) {
            report($e);
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Failed to load network. Please try again.');
        }
    }

    public function addRoute(): void
    {
        $this->validate(['new_route_target' => 'required|string|regex:/^[\d\.\/\:a-fA-F]+$/']);

        $this->edit_routes[] = [
            'target' => $this->new_route_target,
            'via' => $this->new_route_via ?: null,
            'flags' => 0,
            'metric' => 0,
        ];

        $this->new_route_target = '';
        $this->new_route_via = '';
    }

    public function removeRoute(int $index): void
    {
        array_splice($this->edit_routes, $index, 1);
        $this->edit_routes = array_values($this->edit_routes);
    }

    public function addIpPool(): void
    {
        $this->validate([
            'new_pool_start' => 'required|ip',
            'new_pool_end' => 'required|ip',
        ]);

        $this->edit_ip_pools[] = [
            'ipRangeStart' => $this->new_pool_start,
            'ipRangeEnd' => $this->new_pool_end,
        ];

        $this->new_pool_start = '';
        $this->new_pool_end = '';
    }

    public function removeIpPool(int $index): void
    {
        array_splice($this->edit_ip_pools, $index, 1);
        $this->edit_ip_pools = array_values($this->edit_ip_pools);
    }

    public function saveNetwork(): void
    {
        if (! auth()->user()->isTeamAdmin()) {
            return;
        }

        $this->validate(['edit_name' => 'required|string|max:255']);

        $token = ZerotierToken::findOrFail($this->selectedToken);
        $service = new ZerotierService($token);

        try {
            $service->updateNetwork($this->editing_network_id, [
                'name' => $this->edit_name,
                'private' => $this->edit_private,
                'enableBroadcast' => $this->edit_broadcast,
                'multicastLimit' => $this->edit_multicast_limit,
                'routes' => $this->edit_routes,
                'ipAssignmentPools' => $this->edit_ip_pools,
                'v4AssignMode' => ['zt' => count($this->edit_ip_pools) > 0],
            ]);

            // Sync local DB record if tracked (scoped to current team)
            ZerotierNetwork::where('network_id', $this->editing_network_id)
                ->where('team_id', auth()->user()->team->id)
                ->update([
                    'name' => $this->edit_name,
                    'private' => $this->edit_private,
                ]);

            AuditLog::record('network.updated', 'network', $this->editing_network_id, ['name' => $this->edit_name]);

            Flux::toast(variant: 'success', heading: 'Saved', text: 'Network settings updated.');
            Flux::modal('editNetworkModal')->close();
            $this->loadNetworks();
        } catch (Exception $e) {
            report($e);
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Failed to save network. Please try again.');
        }
    }

    // ─── Delete Network ──────────────────────────────────────────────

    public function confirmDeleteNetwork(string $networkId, string $networkName): void
    {
        if (! auth()->user()->isTeamAdmin()) {
            return;
        }

        $this->delete_network_id = $networkId;
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
            ZerotierNetwork::where('network_id', $this->delete_network_id)
                ->where('team_id', auth()->user()->team->id)
                ->delete();
            Flux::modal('deleteNetworkModal')->close();
            Flux::toast(variant: 'success', heading: 'Deleted', text: 'Network has been deleted.');
            AuditLog::record('network.deleted', 'network', $this->delete_network_id, ['name' => $this->delete_network_name]);
            $this->delete_network_id = '';
            $this->delete_network_name = '';
            $this->loadNetworks();
        } catch (Exception $e) {
            report($e);
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Failed to delete network. Please try again.');
        }
    }
}; ?>

<div class="mx-auto max-w-5xl p-6" wire:poll.60s="loadNetworks">
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

                <flux:button size="sm" icon="arrow-path" wire:click="loadNetworks">Refresh</flux:button>
                @if (auth()->user()->isTeamAdmin() && $tokens->count() > 0)
                    <flux:button icon="plus" variant="filled" wire:click="openCreateModal">Create Network</flux:button>
                @endif
            </div>
        </div>

        @if (count($untracked_networks) > 0 && auth()->user()->isAdmin())
            <flux:card class="mb-4 border-amber-500/30 bg-amber-50/50 dark:bg-amber-950/20">
                <div class="flex items-center gap-2 mb-3">
                    <flux:icon name="exclamation-triangle" class="size-5 text-amber-500" />
                    <flux:heading size="sm">{{ count($untracked_networks) }} Untracked Network(s)</flux:heading>
                </div>
                <flux:subheading class="mb-4">These networks exist on the controller but are not assigned to any team.</flux:subheading>

                <flux:table>
                    <flux:table.columns>
                        <flux:table.column>Network ID</flux:table.column>
                        <flux:table.column>Name</flux:table.column>
                        <flux:table.column>Type</flux:table.column>
                        <flux:table.column>Assign to Team</flux:table.column>
                        <flux:table.column></flux:table.column>
                    </flux:table.columns>
                    <flux:table.rows>
                        @foreach ($untracked_networks as $uNetwork)
                        <flux:table.row>
                            <flux:table.cell class="font-mono text-xs">{{ $uNetwork['nwid'] }}</flux:table.cell>
                            <flux:table.cell>{{ $uNetwork['name'] ?: '—' }}</flux:table.cell>
                            <flux:table.cell>
                                @if ($uNetwork['private'])
                                    <flux:badge color="green" size="sm">Private</flux:badge>
                                @else
                                    <flux:badge color="red" size="sm">Public</flux:badge>
                                @endif
                            </flux:table.cell>
                            <flux:table.cell>
                                <flux:select wire:model="import_team_selections.{{ $uNetwork['nwid'] }}" class="w-48" placeholder="Select team...">
                                    @foreach ($teams as $team)
                                        <flux:select.option value="{{ $team['id'] }}">{{ $team['name'] }}</flux:select.option>
                                    @endforeach
                                </flux:select>
                            </flux:table.cell>
                            <flux:table.cell>
                                <div class="flex gap-1">
                                    <flux:button size="xs" icon="arrow-down-tray" wire:click="importNetwork('{{ $uNetwork['nwid'] }}')">Import</flux:button>
                                    <flux:button size="xs" icon="trash" variant="danger" wire:click="confirmDeleteUntracked('{{ $uNetwork['nwid'] }}', '{{ e($uNetwork['name'] ?? '') }}')" tooltip="Delete from controller" />
                                </div>
                            </flux:table.cell>
                        </flux:table.row>
                        @endforeach
                    </flux:table.rows>
                </flux:table>
            </flux:card>
        @endif

        @if ($tokens->count() === 0)
            <flux:card>
                <div class="text-center py-8">
                    <flux:icon name="signal-slash" class="mx-auto size-12 text-zinc-400 mb-4" />
                    <flux:heading>No Controllers</flux:heading>
                    <flux:subheading class="mb-4">Add a ZeroTier controller first to manage networks.</flux:subheading>
                    <flux:button variant="primary" :href="route('zerotier.tokens')" wire:navigate>Add Controller</flux:button>
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
                                <flux:button size="sm" icon="cog-6-tooth" wire:click="openEditModal('{{ $network['nwid'] ?? $network['id'] }}')" tooltip="Network Settings" />
                                <flux:button size="sm" icon="trash" variant="danger" wire:click="confirmDeleteNetwork('{{ $network['nwid'] ?? $network['id'] }}', {{ Js::from($network['name'] ?? '') }})" tooltip="Delete Network" />
                            @endif
                        </div>
                    </div>
                </flux:card>
                @endforeach
            </div>
        @endif

        {{-- Edit Network Modal --}}
        <flux:modal name="editNetworkModal" focusable class="w-full max-w-2xl">
            <flux:heading size="lg" class="mb-1">Network Settings</flux:heading>
            <flux:subheading class="mb-5 font-mono text-xs">{{ $editing_network_id }}</flux:subheading>

            <flux:tabs wire:model="edit_tab" class="mb-4">
                <flux:tab name="settings">Settings</flux:tab>
                <flux:tab name="ip_ranges">IP Ranges</flux:tab>
                <flux:tab name="routes">Managed Routes</flux:tab>
            </flux:tabs>

            {{-- Settings Panel --}}
            <div x-show="$wire.edit_tab === 'settings'" class="space-y-5 min-h-[220px]">
                <flux:input wire:model="edit_name" label="Network Name" />
                <div class="grid grid-cols-2 gap-4">
                    <flux:switch wire:model="edit_private" label="Private Network" description="Members must be authorised to join" />
                    <flux:switch wire:model="edit_broadcast" label="Enable Broadcast" description="Allow broadcast traffic on this network" />
                </div>
                <div>
                    <flux:label>Multicast Recipient Limit</flux:label>
                    <flux:description class="mb-2">Maximum recipients for a multicast/broadcast packet (0 = disabled)</flux:description>
                    <flux:input wire:model="edit_multicast_limit" type="number" min="0" max="1000" style="width:120px;" />
                </div>
            </div>

            {{-- IP Ranges Panel --}}
            <div x-show="$wire.edit_tab === 'ip_ranges'" class="min-h-[220px]">
                @if (count($edit_ip_pools) > 0)
                    <div class="space-y-2 mb-5">
                        @foreach ($edit_ip_pools as $i => $pool)
                            <div class="flex items-center gap-3 px-4 py-2.5 rounded-lg bg-zinc-50 dark:bg-zinc-800 border border-zinc-200 dark:border-zinc-700">
                                <flux:icon name="circle-stack" class="size-4 text-zinc-400 shrink-0" />
                                <span class="font-mono text-sm flex-1">{{ $pool['ipRangeStart'] }} &rarr; {{ $pool['ipRangeEnd'] }}</span>
                                <flux:button size="xs" icon="x-mark" variant="ghost" wire:click="removeIpPool({{ $i }})" />
                            </div>
                        @endforeach
                    </div>
                @else
                    <p class="text-sm text-zinc-400 italic mb-5">No IP ranges configured. Add one below to enable auto-assignment.</p>
                @endif

                <p class="text-xs font-semibold uppercase tracking-wide text-zinc-400 dark:text-zinc-500 mb-3">Add Range</p>
                <div class="grid grid-cols-2 gap-3">
                    <flux:input wire:model="new_pool_start" label="Range Start" placeholder="10.147.17.1" />
                    <flux:input wire:model="new_pool_end" label="Range End" placeholder="10.147.17.254" />
                </div>
                <div class="mt-6">
                    <flux:button size="sm" icon="plus" wire:click="addIpPool">Add Range</flux:button>
                </div>
            </div>

            {{-- Routes Panel --}}
            <div x-show="$wire.edit_tab === 'routes'" class="min-h-[220px]">

                @if (count($edit_routes) > 0)
                    <table class="w-full text-sm mb-5">
                        <thead>
                            <tr class="border-b border-zinc-200 dark:border-zinc-700">
                                <th class="text-left py-2 px-2 text-xs font-semibold text-zinc-400 uppercase tracking-wide w-8"></th>
                                <th class="text-left py-2 px-2 text-xs font-semibold text-zinc-400 uppercase tracking-wide">Target</th>
                                <th class="text-left py-2 px-2 text-xs font-semibold text-zinc-400 uppercase tracking-wide">Via</th>
                                <th class="w-8"></th>
                            </tr>
                        </thead>
                        <tbody>
                            @foreach ($edit_routes as $i => $route)
                                <tr class="border-b border-zinc-100 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-800/50">
                                    <td class="py-2.5 px-2">
                                        <flux:icon name="arrow-right-circle" class="size-4 text-zinc-400" />
                                    </td>
                                    <td class="py-2.5 px-2 font-mono">{{ $route['target'] }}</td>
                                    <td class="py-2.5 px-2 font-mono">
                                        @if (! empty($route['via']))
                                            {{ $route['via'] }}
                                        @else
                                            <span class="text-zinc-400 italic">(LAN)</span>
                                        @endif
                                    </td>
                                    <td class="py-2.5 px-2 text-right">
                                        <flux:button size="xs" icon="trash" variant="ghost" class="text-red-400 hover:text-red-600" wire:click="removeRoute({{ $i }})" />
                                    </td>
                                </tr>
                            @endforeach
                        </tbody>
                    </table>
                @else
                    <p class="text-sm text-zinc-400 italic mb-5">No managed routes configured.</p>
                @endif

                <p class="text-xs font-semibold uppercase tracking-wide text-zinc-400 dark:text-zinc-500 mb-3">Add Route</p>
                <div class="flex items-end gap-2">
                    <div class="flex-1">
                        <flux:input wire:model="new_route_target" label="Destination (CIDR)" placeholder="10.0.0.0/8" />
                    </div>
                    <div class="flex-1">
                        <flux:input wire:model="new_route_via" label="Via (leave blank for LAN)" placeholder="10.147.17.1" />
                    </div>
                    <div class="pb-0.5">
                        <flux:button icon="plus" wire:click="addRoute" tooltip="Add Route" />
                    </div>
                </div>
            </div>

            <div class="flex justify-end gap-2" style="margin-top: 3rem;">
                <flux:modal.close><flux:button variant="filled">Cancel</flux:button></flux:modal.close>
                <flux:button variant="primary" wire:click="saveNetwork">Save Changes</flux:button>
            </div>
        </flux:modal>

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

        {{-- Delete Untracked Network Modal --}}
        <flux:modal name="deleteUntrackedModal" focusable class="max-w-sm">
            <div class="w-14 h-14 rounded-full bg-red-100 p-4 mt-4 mb-4 mx-auto flex items-center justify-center">
                <flux:icon name="trash" class="size-6 text-red-600" />
            </div>

            <flux:heading size="lg" class="text-center">Delete Untracked Network?</flux:heading>
            <flux:subheading class="text-center mt-2 mb-6">
                Are you sure you want to delete <strong>{{ $delete_untracked_name }}</strong> from the controller?
                This will permanently remove the network and cannot be undone.
            </flux:subheading>

            <div class="flex justify-end gap-2">
                <flux:modal.close>
                    <flux:button variant="filled">Cancel</flux:button>
                </flux:modal.close>
                <flux:button variant="danger" wire:click="deleteUntrackedNetwork">Delete</flux:button>
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

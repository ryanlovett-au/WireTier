<?php

use App\Models\AuditLog;
use App\Models\Team;
use App\Models\ZerotierNetwork;
use App\Models\ZerotierToken;
use App\Services\ZerotierService;
use App\Services\ZerotierSyncService;
use Illuminate\Support\Facades\Cache;
use Livewire\Attributes\On;
use Livewire\Attributes\Title;
use Livewire\Component;

new #[Title('ZeroTier Networks')] class extends Component
{
    public $tokens;

    public array $networks = [];

    public string $selectedToken = '';

    public int $lastRefreshedAt = 0;

    // Delete confirmation
    public string $delete_network_id = '';

    public string $delete_network_name = '';

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

        // DB-only: read from synced data, no API calls
        $teamId = auth()->user()->team->id;
        $tokenId = $this->selectedToken;

        $this->networks = Cache::flexible("team_{$teamId}_networks_{$tokenId}", [30, 60], function () use ($teamId, $tokenId) {
            return ZerotierNetwork::where('team_id', $teamId)
                ->where('zerotier_token_id', $tokenId)
                ->withCount([
                    'members as authorised_count' => fn ($q) => $q->where('authorised', true),
                    'members as pending_count' => fn ($q) => $q->where('authorised', false),
                ])
                ->get()
                ->map(function ($n) {
                    $config = $n->config ?? [];

                    return [
                        'id' => $n->network_id,
                        'nwid' => $n->network_id,
                        'name' => $n->name ?? 'Unknown',
                        'private' => $n->private,
                        'routes' => $config['routes'] ?? [],
                        'ipAssignmentPools' => $config['ipAssignmentPools'] ?? [],
                        '_member_count' => $n->authorised_count ?? 0,
                        '_pending_count' => $n->pending_count ?? 0,
                        '_synced_at' => $n->synced_at?->diffForHumans(),
                    ];
                })
                ->toArray();
        });

        // Use the most recent synced_at from the DB, not "now"
        $latestSync = ZerotierNetwork::where('team_id', $teamId)
            ->where('zerotier_token_id', $tokenId)
            ->max('synced_at');
        $this->lastRefreshedAt = $latestSync ? strtotime($latestSync) : 0;
    }

    public function syncAndReload(): void
    {
        if (! empty($this->selectedToken)) {
            ZerotierSyncService::syncToken($this->selectedToken);

            $teamId = auth()->user()->team->id;
            Cache::forget("team_{$teamId}_networks_{$this->selectedToken}");
        }

        $this->loadNetworks();

        if (auth()->user()->isAdmin()) {
            $this->discoverNetworks();
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

            ZerotierSyncService::syncNetwork($dbNetwork);

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

    // ─── Edit / Move (handled by <livewire:pages::zerotier.network-edit-modal />) ───

    #[On('network-updated')]
    #[On('network-moved')]
    public function refreshAfterEdit(): void
    {
        $this->loadNetworks();
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

<div class="mx-auto max-w-5xl p-6" wire:poll.30s="loadNetworks">
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

                <flux:button size="sm" icon="arrow-path" wire:click="syncAndReload">Refresh</flux:button>
                @if (auth()->user()->isTeamAdmin() && $tokens->count() > 0)
                    <flux:button size="sm" icon="plus" variant="primary" wire:click="openCreateModal">Create Network</flux:button>
                @endif
            </div>
        </div>
        @if ($lastRefreshedAt)
        <div
            x-data="{ label: '' }"
            x-init="setInterval(() => {
                let s = Math.floor(Date.now()/1000) - $wire.lastRefreshedAt;
                if (s < 5) label = 'just now';
                else if (s < 60) label = s + 's ago';
                else if (s < 3600) label = Math.floor(s/60) + 'm ago';
                else label = Math.floor(s/3600) + 'h ago';
            }, 1000)"
            class="text-xs text-zinc-400 text-right -mt-4 mb-4"
        >
            Last refreshed &middot; <span x-text="label"></span>
        </div>
        @endif

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
                        <flux:table.row wire:key="untracked-{{ $uNetwork['nwid'] }}">
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
                <flux:card wire:key="network-{{ $network['nwid'] ?? $network['id'] }}">
                    <div class="flex items-end justify-between">
                        <div>
                            <div class="flex items-center gap-3">
                                <a href="{{ route('zerotier.members', ['networkId' => $network['nwid'] ?? $network['id'], 'tokenId' => $selectedToken]) }}" class="underline underline-offset-4 decoration-zinc-300 hover:decoration-zinc-500 dark:decoration-zinc-600 dark:hover:decoration-zinc-400" wire:navigate>
                                    <flux:heading size="lg">{{ $network['name'] ?? 'Unnamed' }}</flux:heading>
                                </a>
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
                                @foreach (($network['routes'] ?? []) as $route)
                                    @if (empty($route['via']))
                                        <span class="font-mono">{{ $route['target'] }}</span>
                                    @endif
                                @endforeach
                            </div>
                        </div>
                        <div class="flex gap-2">
                            <flux:button size="sm" icon="users" :href="route('zerotier.members', ['networkId' => $network['nwid'] ?? $network['id'], 'tokenId' => $selectedToken])" wire:navigate>
                                Members
                            </flux:button>
                            @if (auth()->user()->isTeamAdmin())
                                <flux:button size="sm" icon="cog-6-tooth" wire:click="$dispatch('open-network-edit', { networkId: '{{ $network['nwid'] ?? $network['id'] }}', tokenId: '{{ $selectedToken }}' })" tooltip="Network Settings" />
                                <flux:button size="sm" icon="trash" variant="danger" wire:click="confirmDeleteNetwork('{{ $network['nwid'] ?? $network['id'] }}', {{ Js::from($network['name'] ?? '') }})" tooltip="Delete Network" />
                            @endif
                        </div>
                    </div>
                </flux:card>
                @endforeach
            </div>
        @endif

        {{-- Network Edit / Move Modal (shared component) --}}
        <livewire:pages::zerotier.network-edit-modal />

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

            <flux:switch wire:model="new_network_private" label="Private Network" description="Members must be authorised to join" class="mb-6" />

            <div class="flex justify-end space-x-2 mt-4">
                <flux:modal.close><flux:button variant="filled">Cancel</flux:button></flux:modal.close>
                <flux:button variant="primary" wire:click="createNetwork()">Create</flux:button>
            </div>
        </flux:modal>
</div>

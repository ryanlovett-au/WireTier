<?php

use App\Models\AuditLog;
use App\Models\Team;
use App\Models\TeamUser;
use App\Models\ZerotierNetwork;
use App\Models\ZerotierToken;
use App\Services\ZerotierService;
use Illuminate\Support\Facades\Cache;
use Livewire\Attributes\On;
use Livewire\Component;

new class extends Component
{
    public string $editing_network_id = '';

    public string $tokenId = '';

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

    public string $move_to_team_id = '';

    public array $movable_teams = [];

    #[On('open-network-edit')]
    public function open(string $networkId, string $tokenId): void
    {
        $token = ZerotierToken::findOrFail($tokenId);
        $service = new ZerotierService($token);

        try {
            $network = $service->getControllerNetwork($networkId);

            $this->editing_network_id = $networkId;
            $this->tokenId = $tokenId;
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

            $this->move_to_team_id = '';
            $this->movable_teams = $this->loadMovableTeams();

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

        $token = ZerotierToken::findOrFail($this->tokenId);
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
                ->where('team_id', auth()->user()->team?->id)
                ->update([
                    'name' => $this->edit_name,
                    'private' => $this->edit_private,
                ]);

            // Bust the parent page's network list cache (whichever team it belongs to).
            if ($teamId = $this->resolveNetworkTeamId()) {
                Cache::forget("team_{$teamId}_networks_{$this->tokenId}");
            }

            AuditLog::record('network.updated', 'network', $this->editing_network_id, ['name' => $this->edit_name]);

            Flux::toast(variant: 'success', heading: 'Saved', text: 'Network settings updated.');
            Flux::modal('editNetworkModal')->close();

            $this->dispatch('network-updated', networkId: $this->editing_network_id);
        } catch (Exception $e) {
            report($e);
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Failed to save network. Please try again.');
        }
    }

    // ─── Move Network ────────────────────────────────────────────────

    protected function loadMovableTeams(): array
    {
        $currentTeamId = auth()->user()->team?->id;

        $query = Team::query()->orderBy('name');

        if ($currentTeamId) {
            $query->where('id', '!=', $currentTeamId);
        }

        if (! auth()->user()->isAdmin()) {
            $query->whereIn('id', TeamUser::query()
                ->select('team_id')
                ->where('user_id', auth()->id())
                ->where('role', 'admin'));
        }

        return $query->get(['id', 'name'])
            ->map(fn ($t) => ['id' => $t->id, 'name' => $t->name])
            ->toArray();
    }

    protected function resolveNetworkTeamId(): ?string
    {
        return ZerotierNetwork::where('network_id', $this->editing_network_id)
            ->where('zerotier_token_id', $this->tokenId)
            ->value('team_id');
    }

    public function confirmMoveNetwork(): void
    {
        if (! auth()->user()->isTeamAdmin()) {
            return;
        }

        if (empty($this->move_to_team_id)) {
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Please select a destination team.');

            return;
        }

        Flux::modal('moveNetworkConfirm')->show();
    }

    public function moveNetwork(): void
    {
        if (! auth()->user()->isTeamAdmin()) {
            return;
        }

        if (empty($this->move_to_team_id)) {
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Please select a destination team.');

            return;
        }

        $sourceTeamId = $this->resolveNetworkTeamId();

        if (! $sourceTeamId) {
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Network not found.');

            return;
        }

        if ($this->move_to_team_id === $sourceTeamId) {
            Flux::toast(variant: 'warning', heading: 'No Change', text: 'This network is already on that team.');

            return;
        }

        // Re-verify the user is admin of the destination team (system admin bypasses this).
        if (! auth()->user()->isAdmin()) {
            $isAdminOfDestination = TeamUser::where('user_id', auth()->id())
                ->where('team_id', $this->move_to_team_id)
                ->where('role', 'admin')
                ->exists();

            if (! $isAdminOfDestination) {
                Flux::toast(variant: 'danger', heading: 'Permission Denied', text: 'You must be an admin of the destination team.');

                return;
            }
        }

        $destinationTeam = Team::find($this->move_to_team_id);

        if (! $destinationTeam) {
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Destination team not found.');

            return;
        }

        $network = ZerotierNetwork::where('network_id', $this->editing_network_id)
            ->where('team_id', $sourceTeamId)
            ->where('zerotier_token_id', $this->tokenId)
            ->first();

        if (! $network) {
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Network not found.');

            return;
        }

        $networkName = $network->name;
        $network->team_id = $destinationTeam->id;
        $network->save();

        AuditLog::record('network.moved', 'network', $this->editing_network_id, [
            'name' => $networkName,
            'from_team_id' => $sourceTeamId,
            'to_team_id' => $destinationTeam->id,
            'to_team_name' => $destinationTeam->name,
        ]);

        AuditLog::record('network.received', 'network', $this->editing_network_id, [
            'name' => $networkName,
            'from_team_id' => $sourceTeamId,
        ], teamId: $destinationTeam->id);

        Cache::forget("team_{$sourceTeamId}_networks_{$this->tokenId}");
        Cache::forget("team_{$destinationTeam->id}_networks_{$this->tokenId}");

        Flux::toast(variant: 'success', heading: 'Moved', text: "Network has been moved to {$destinationTeam->name}.");
        Flux::modal('moveNetworkConfirm')->close();
        Flux::modal('editNetworkModal')->close();

        $this->move_to_team_id = '';

        $this->dispatch('network-moved', networkId: $this->editing_network_id, toTeamId: $destinationTeam->id);
    }
}; ?>

<div>
    {{-- Edit Network Modal --}}
    <flux:modal name="editNetworkModal" focusable class="w-full max-w-2xl">
        <flux:heading size="lg" class="mb-1">Network Settings</flux:heading>
        <flux:subheading class="mb-5 font-mono text-xs">{{ $editing_network_id }}</flux:subheading>

        <flux:tabs wire:model="edit_tab" class="mb-4">
            <flux:tab name="settings">Settings</flux:tab>
            <flux:tab name="ip_ranges">IP Ranges</flux:tab>
            <flux:tab name="routes">Managed Routes</flux:tab>
            <flux:tab name="move">Move Team</flux:tab>
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
                        <div wire:key="pool-{{ $i }}" class="flex items-center gap-3 px-4 py-2.5 rounded-lg bg-zinc-50 dark:bg-zinc-800 border border-zinc-200 dark:border-zinc-700">
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
                            <tr wire:key="route-{{ $i }}" class="border-b border-zinc-100 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-800/50">
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

        {{-- Move Panel --}}
        <div x-show="$wire.edit_tab === 'move'" class="space-y-5 min-h-[220px]">
            <div>
                <flux:label>Current Team</flux:label>
                <div class="mt-1 px-3 py-2 rounded-md border border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-800 text-sm">
                    {{ auth()->user()->team?->name ?? '—' }}
                </div>
            </div>

            @if (count($movable_teams) > 0)
                <flux:select wire:model="move_to_team_id" label="Move to Team" placeholder="Select destination team…">
                    @foreach ($movable_teams as $team)
                        <flux:select.option value="{{ $team['id'] }}">{{ $team['name'] }}</flux:select.option>
                    @endforeach
                </flux:select>

                <div class="flex items-start gap-2 px-3 py-2.5 rounded-md border border-amber-300 bg-amber-50 dark:bg-amber-950/30 dark:border-amber-800 text-sm">
                    <flux:icon name="exclamation-triangle" class="size-4 text-amber-500 shrink-0 mt-0.5" />
                    <div class="text-amber-900 dark:text-amber-200">
                        Moving this network will transfer it (and all its members) to the destination team. Members of the source team will lose access.
                    </div>
                </div>

                <div class="flex justify-end">
                    <flux:button variant="primary" wire:click="confirmMoveNetwork">Move Network</flux:button>
                </div>
            @else
                <div class="flex items-start gap-2 px-3 py-2.5 rounded-md border border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-800 text-sm text-zinc-500">
                    <flux:icon name="information-circle" class="size-4 shrink-0 mt-0.5" />
                    <div>You are not an admin of any other team, so there is nowhere to move this network.</div>
                </div>
            @endif
        </div>

        <div x-show="$wire.edit_tab !== 'move'" class="flex justify-end gap-2" style="margin-top: 3rem;">
            <flux:modal.close><flux:button variant="filled">Cancel</flux:button></flux:modal.close>
            <flux:button variant="primary" wire:click="saveNetwork">Save Changes</flux:button>
        </div>
    </flux:modal>

    {{-- Move Network Confirm Modal --}}
    <flux:modal name="moveNetworkConfirm" focusable class="max-w-sm">
        <div class="w-14 h-14 rounded-full bg-amber-100 dark:bg-amber-900/40 p-4 mt-4 mb-4 mx-auto flex items-center justify-center">
            <flux:icon name="arrow-right-circle" class="size-6 text-amber-600 dark:text-amber-400" />
        </div>

        <flux:heading size="lg" class="text-center">Move Network?</flux:heading>
        <flux:subheading class="text-center mt-2 mb-6">
            @php
                $destTeamName = collect($movable_teams)->firstWhere('id', $move_to_team_id)['name'] ?? '';
            @endphp
            This will transfer the network and all its members to <strong>{{ $destTeamName }}</strong>.
            Members of <strong>{{ auth()->user()->team?->name }}</strong> will lose access.
        </flux:subheading>

        <div class="flex justify-end gap-2">
            <flux:modal.close>
                <flux:button variant="filled">Cancel</flux:button>
            </flux:modal.close>
            <flux:button variant="primary" wire:click="moveNetwork">Move</flux:button>
        </div>
    </flux:modal>
</div>

<?php

use App\Models\AuditLog;
use App\Models\ZerotierMember;
use App\Models\ZerotierNetwork;
use App\Models\ZerotierToken;
use App\Services\ZerotierService;
use App\Services\ZerotierSyncService;
use Illuminate\Support\Facades\Cache;
use Livewire\Attributes\On;
use Livewire\Attributes\Title;
use Livewire\Component;

new #[Title('Network Members')] class extends Component
{
    public string $networkId;

    public string $tokenId;

    public array $network = [];

    public array $members = [];

    public int $lastRefreshedAt = 0;

    // Delete confirmation
    public string $delete_member_id = '';

    // Edit member
    public string $edit_member_id = '';

    public string $edit_member_name = '';

    public string $edit_member_description = '';

    public array $edit_ip_assignments = [];

    public bool $edit_active_bridge = false;

    public bool $edit_no_auto_assign = false;

    public string $new_ip = '';

    public string $sortBy = '';

    public string $sortDirection = 'asc';

    public function sort(string $column): void
    {
        if ($this->sortBy === $column) {
            $this->sortDirection = $this->sortDirection === 'asc' ? 'desc' : 'asc';
        } else {
            $this->sortBy = $column;
            $this->sortDirection = 'asc';
        }
    }

    public function getSortedMembers(): array
    {
        if (empty($this->sortBy)) {
            return $this->members;
        }

        $sorted = collect($this->members)->sortBy(function ($member) {
            return match ($this->sortBy) {
                'name' => strtolower($member['name'] ?? ''),
                'ip' => ip2long($member['ipAssignments'][0] ?? '0.0.0.0'),
                'authorised' => $member['authorized'] ?? false,
                'last_seen' => $member['_online'] ?? false ? PHP_INT_MAX : ($member['lastOnline'] ?? 0),
                default => '',
            };
        }, descending: $this->sortDirection === 'desc');

        return $sorted->values()->toArray();
    }

    public function mount(string $networkId, string $tokenId)
    {
        if (! auth()->user()->team) {
            $this->redirect('/settings/teams');

            return;
        }

        // Verify the user's team owns this network
        $ownsNetwork = ZerotierNetwork::where('network_id', $networkId)
            ->where('team_id', auth()->user()->team->id)
            ->exists();

        if (! $ownsNetwork && ! auth()->user()->isAdmin()) {
            abort(403);
        }

        $this->networkId = $networkId;
        $this->tokenId = $tokenId;
        $this->loadNetwork();
        $this->loadMembers();
        AuditLog::record('member.list_viewed', 'network', $this->networkId);
    }

    protected function getService(): ZerotierService
    {
        $token = ZerotierToken::findOrFail($this->tokenId);

        return new ZerotierService($token);
    }

    protected function getDbNetwork(): ?ZerotierNetwork
    {
        return ZerotierNetwork::where('network_id', $this->networkId)
            ->where('team_id', auth()->user()->team?->id)
            ->first();
    }

    public function loadNetwork(): void
    {
        $dbNetwork = $this->getDbNetwork();

        if ($dbNetwork) {
            $config = $dbNetwork->config ?? [];
            $this->network = array_merge($config, [
                'nwid' => $dbNetwork->network_id,
                'name' => $dbNetwork->name ?? ($config['name'] ?? 'Unknown'),
                'private' => $dbNetwork->private,
                '_synced_at' => $dbNetwork->synced_at?->diffForHumans(),
            ]);
        }
    }

    public function loadMembers(): void
    {
        $dbNetwork = $this->getDbNetwork();

        if (! $dbNetwork) {
            $this->members = [];

            return;
        }

        $this->members = Cache::flexible("network_{$dbNetwork->id}_members", [30, 60], function () use ($dbNetwork) {
            return ZerotierMember::where('zerotier_network_id', $dbNetwork->id)
                ->orderByDesc('is_online')
                ->orderBy('node_id')
                ->get()
                ->map(fn ($m) => [
                    'address' => $m->node_id,
                    'name' => $m->name,
                    'description' => $m->description,
                    'authorized' => $m->authorised,
                    'activeBridge' => $m->active_bridge,
                    'noAutoAssignIps' => $m->no_auto_assign_ips,
                    'ipAssignments' => $m->ip_assignments ?? [],
                    '_version' => $m->client_version,
                    '_online' => $m->is_online,
                    '_latency' => $m->latency,
                    '_physicalAddr' => $m->physical_address,
                    '_synced_at' => $m->synced_at?->diffForHumans(),
                ])
                ->toArray();
        });

        $this->lastRefreshedAt = $dbNetwork->synced_at ? $dbNetwork->synced_at->timestamp : 0;
    }

    public function syncAndReload(bool $force = false): void
    {
        $dbNetwork = $this->getDbNetwork();

        if ($dbNetwork) {
            ZerotierSyncService::syncNetwork($dbNetwork, force: $force);
            Cache::forget("network_{$dbNetwork->id}_members");
        }

        $this->loadNetwork();
        $this->loadMembers();
    }

    #[On('network-updated')]
    public function reloadAfterNetworkUpdated(): void
    {
        $this->loadNetwork();
        $this->loadMembers();
    }

    #[On('network-moved')]
    public function reloadAfterNetworkMoved(): void
    {
        // The network is no longer on the user's current team — bounce back to the list.
        $this->redirect(route('zerotier.networks'), navigate: true);
    }

    public function authorizeMember($nodeId): void
    {
        if (! auth()->user()->canManageNetworks()) {
            return;
        }

        try {
            $this->getService()->authorizeMember($this->networkId, $nodeId);
            Flux::toast(variant: 'success', heading: 'Authorised', text: 'Member '.$nodeId.' has been authorised.');
            AuditLog::record('member.authorised', 'member', $nodeId, ['network_id' => $this->networkId]);
            $this->syncAndReload(force: true);
        } catch (Exception $e) {
            report($e);
            Flux::toast(variant: 'danger', heading: 'Error', text: 'An unexpected error occurred. Please try again.');
        }
    }

    public function deauthorizeMember($nodeId): void
    {
        if (! auth()->user()->canManageNetworks()) {
            return;
        }

        try {
            $this->getService()->deauthorizeMember($this->networkId, $nodeId);
            Flux::toast(variant: 'warning', heading: 'Deauthorised', text: 'Member '.$nodeId.' has been deauthorised.');
            AuditLog::record('member.deauthorised', 'member', $nodeId, ['network_id' => $this->networkId]);
            $this->syncAndReload(force: true);
        } catch (Exception $e) {
            report($e);
            Flux::toast(variant: 'danger', heading: 'Error', text: 'An unexpected error occurred. Please try again.');
        }
    }

    public function confirmDeleteMember(string $nodeId): void
    {
        if (! auth()->user()->canManageNetworks()) {
            return;
        }

        $this->delete_member_id = $nodeId;
        Flux::modal('deleteMemberModal')->show();
    }

    public function deleteMember(): void
    {
        if (! auth()->user()->canManageNetworks()) {
            return;
        }

        try {
            $this->getService()->deleteMember($this->networkId, $this->delete_member_id);
            Flux::modal('deleteMemberModal')->close();
            Flux::toast(variant: 'success', heading: 'Deleted', text: 'Member has been removed.');
            AuditLog::record('member.deleted', 'member', $this->delete_member_id, ['network_id' => $this->networkId]);
            $this->delete_member_id = '';
            $this->syncAndReload(force: true);
        } catch (Exception $e) {
            report($e);
            Flux::toast(variant: 'danger', heading: 'Error', text: 'An unexpected error occurred. Please try again.');
        }
    }

    public function editMemberModal($nodeId): void
    {
        if (! auth()->user()->canManageNetworks()) {
            return;
        }

        $dbNetwork = $this->getDbNetwork();
        $member = ZerotierMember::where('zerotier_network_id', $dbNetwork?->id)
            ->where('node_id', $nodeId)
            ->first();

        if (! $member) {
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Member not found.');

            return;
        }

        $this->edit_member_id = $nodeId;
        $this->edit_member_name = $member->name ?? '';
        $this->edit_member_description = $member->description ?? '';
        $this->edit_ip_assignments = $member->ip_assignments ?? [];
        $this->edit_active_bridge = $member->active_bridge;
        $this->edit_no_auto_assign = $member->no_auto_assign_ips;
        $this->new_ip = '';
        Flux::modal('editMemberModal')->show();
    }

    public function addIpAssignment(): void
    {
        if (! empty($this->new_ip) && ! in_array($this->new_ip, $this->edit_ip_assignments)) {
            $this->edit_ip_assignments[] = $this->new_ip;
            $this->new_ip = '';
        }
    }

    public function removeIpAssignment($index): void
    {
        unset($this->edit_ip_assignments[$index]);
        $this->edit_ip_assignments = array_values($this->edit_ip_assignments);
    }

    public function saveMember(): void
    {
        if (! auth()->user()->canManageNetworks()) {
            return;
        }

        try {
            $this->getService()->updateNetworkMember($this->networkId, $this->edit_member_id, [
                'name' => $this->edit_member_name,
                'ipAssignments' => $this->edit_ip_assignments,
                'activeBridge' => $this->edit_active_bridge,
                'noAutoAssignIps' => $this->edit_no_auto_assign,
            ]);

            // Save description locally (not supported by ZT API)
            $dbNetwork = $this->getDbNetwork();
            if ($dbNetwork) {
                ZerotierMember::where('zerotier_network_id', $dbNetwork->id)
                    ->where('node_id', $this->edit_member_id)
                    ->update(['description' => $this->edit_member_description]);
            }

            Flux::modal('editMemberModal')->close();
            Flux::toast(variant: 'success', heading: 'Updated', text: 'Member settings have been updated.');
            AuditLog::record('member.updated', 'member', $this->edit_member_id, ['network_id' => $this->networkId, 'name' => $this->edit_member_name]);
            $this->syncAndReload(force: true);
        } catch (Exception $e) {
            report($e);
            Flux::toast(variant: 'danger', heading: 'Error', text: 'An unexpected error occurred. Please try again.');
        }
    }
}; ?>

<div class="mx-auto max-w-5xl p-6" wire:poll.10s="loadMembers">
        <div class="flex items-center justify-between mb-6">
            <div>
                <div class="flex items-center gap-2 mb-1">
                    <flux:button size="sm" icon="arrow-left" variant="ghost" :href="route('zerotier.networks')" wire:navigate />
                    <flux:heading size="xl">{{ $network['name'] ?? 'Network' }}</flux:heading>
                </div>
                <div class="flex items-center gap-2 flex-wrap mt-1">
                    <x-copy-pill :value="$networkId" class="font-mono text-sm text-zinc-500" />
                    <flux:badge color="zinc" size="sm">
                        {{ collect($members)->where('authorized', true)->count() }} members
                    </flux:badge>
                    @php $pending = collect($members)->where('authorized', false)->count(); @endphp
                    @if ($pending > 0)
                        <flux:badge color="orange" size="sm">{{ $pending }} pending</flux:badge>
                    @endif
                    @foreach (($network['routes'] ?? []) as $route)
                        @if (empty($route['via']))
                            <span class="font-mono text-sm text-zinc-400">{{ $route['target'] }}</span>
                        @endif
                    @endforeach
                </div>
            </div>
            <div class="flex items-center gap-2">
                @if (auth()->user()->canManageNetworks())
                    <flux:button size="sm" icon="cog-6-tooth" wire:click="$dispatch('open-network-edit', { networkId: '{{ $networkId }}', tokenId: '{{ $tokenId }}' })">Settings</flux:button>
                @endif
                <flux:button size="sm" icon="arrow-path" wire:click="syncAndReload">Refresh</flux:button>
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

        @if (count($members) === 0)
            <flux:card>
                <div class="text-center py-8">
                    <flux:icon name="users" class="mx-auto size-12 text-zinc-400 mb-4" />
                    <flux:heading>No Members</flux:heading>
                    <flux:subheading>No devices have joined this network yet. Have a device join using the network ID above.</flux:subheading>
                </div>
            </flux:card>
        @else
            <flux:card>
                <flux:table>
                    <flux:table.columns>
                        <flux:table.column sortable :sorted="$sortBy === 'name'" :direction="$sortDirection" wire:click="sort('name')">Member</flux:table.column>
                        <flux:table.column sortable :sorted="$sortBy === 'ip'" :direction="$sortDirection" wire:click="sort('ip')">IP Assignments</flux:table.column>
                        <flux:table.column sortable :sorted="$sortBy === 'authorised'" :direction="$sortDirection" wire:click="sort('authorised')">Authorised</flux:table.column>
                        <flux:table.column>Bridge</flux:table.column>
                        <flux:table.column sortable :sorted="$sortBy === 'last_seen'" :direction="$sortDirection" wire:click="sort('last_seen')">Last Seen</flux:table.column>
                        <flux:table.column>Version / IP / Latency</flux:table.column>
                        @if (auth()->user()->canManageNetworks())
                            <flux:table.column>Actions</flux:table.column>
                        @endif
                    </flux:table.columns>
                    <flux:table.rows>
                    @foreach ($this->getSortedMembers() as $member)
                        <flux:table.row :key="$member['address'] ?? $member['id'] ?? $loop->index">
                            <flux:table.cell>
                                @if (! empty($member['name']))
                                    <div class="text-sm font-medium">{{ $member['name'] }}</div>
                                @endif
                                @if (! empty($member['description']))
                                    <div class="text-xs text-zinc-400">{{ $member['description'] }}</div>
                                @endif
                                <div class="font-mono text-xs text-zinc-400">{{ $member['address'] ?? '—' }}</div>
                            </flux:table.cell>
                            <flux:table.cell class="font-mono text-xs">
                                @foreach (($member['ipAssignments'] ?? []) as $ip)
                                    <div><x-copy-pill :value="$ip" /></div>
                                @endforeach
                            </flux:table.cell>
                            <flux:table.cell>
                                @if ($member['authorized'] ?? false)
                                    <flux:badge color="green" size="sm">Yes</flux:badge>
                                @else
                                    <flux:badge color="red" size="sm">No</flux:badge>
                                @endif
                            </flux:table.cell>
                            <flux:table.cell>
                                @if ($member['activeBridge'] ?? false)
                                    <flux:badge color="blue" size="sm">Yes</flux:badge>
                                @else
                                    <span class="text-zinc-400">No</span>
                                @endif
                            </flux:table.cell>
                            <flux:table.cell>
                                @if ($member['_online'] ?? false)
                                    <flux:badge color="green" size="sm">Online</flux:badge>
                                @else
                                    @php
                                        $lastOnlineSec = ($member['lastOnline'] ?? 0) / 1000;
                                    @endphp
                                    @if ($lastOnlineSec > 0)
                                        <span class="text-zinc-400">{{ \Carbon\Carbon::createFromTimestamp($lastOnlineSec)->diffForHumans() }}</span>
                                    @else
                                        <span class="text-zinc-400">Never</span>
                                    @endif
                                @endif
                            </flux:table.cell>
                            <flux:table.cell class="text-xs text-zinc-500">
                                @if (! empty($member['_version']))
                                    <div>v{{ $member['_version'] }}</div>
                                @endif
                                @if (! empty($member['_physicalAddr']))
                                    <div class="font-mono">{{ $member['_physicalAddr'] }}</div>
                                @endif
                                @php $latency = $member['_latency'] ?? -1; @endphp
                                @if ($latency > 0)
                                    <div>{{ $latency }} ms</div>
                                @endif
                            </flux:table.cell>
                            @if (auth()->user()->canManageNetworks())
                                <flux:table.cell>
                                    <div class="flex gap-1">
                                        @if (! ($member['authorized'] ?? false))
                                            <flux:button size="xs" icon="check" style="background:#16a34a;color:#fff;border-color:#16a34a;" tooltip="Authorise" wire:click="authorizeMember('{{ $member['address'] ?? $member['id'] }}')" />
                                        @else
                                            <flux:button size="xs" icon="x-mark" style="background:#dc2626;color:#fff;border-color:#dc2626;" tooltip="Deauthorise" wire:click="deauthorizeMember('{{ $member['address'] ?? $member['id'] }}')" />
                                        @endif
                                        <flux:button size="xs" icon="pencil" tooltip="Edit Member" wire:click="editMemberModal('{{ $member['address'] ?? $member['id'] }}')" />
                                        <flux:button size="xs" icon="trash" style="background:#18181b;color:#fff;border-color:#18181b;" tooltip="Delete" wire:click="confirmDeleteMember('{{ $member['address'] ?? $member['id'] }}')" />
                                    </div>
                                </flux:table.cell>
                            @endif
                        </flux:table.row>
                    @endforeach
                    </flux:table.rows>
                </flux:table>
            </flux:card>
        @endif

        {{-- Network Edit / Move Modal (shared component) --}}
        <livewire:pages::zerotier.network-edit-modal />

        {{-- Delete Member Modal --}}
        <flux:modal name="deleteMemberModal" focusable class="max-w-sm">
            <div class="w-14 h-14 rounded-full bg-red-100 p-4 mt-4 mb-4 mx-auto flex items-center justify-center">
                <flux:icon name="trash" class="size-6 text-red-600" />
            </div>
            <flux:heading size="lg" class="text-center">Remove Member?</flux:heading>
            <flux:subheading class="text-center mt-2 mb-6">
                Are you sure you want to remove <span class="font-mono">{{ $delete_member_id }}</span> from this network? This cannot be undone.
            </flux:subheading>
            <div class="flex justify-end gap-2">
                <flux:modal.close><flux:button variant="filled">Cancel</flux:button></flux:modal.close>
                <flux:button variant="danger" wire:click="deleteMember">Remove</flux:button>
            </div>
        </flux:modal>

        {{-- Edit Member Modal --}}
        <flux:modal name="editMemberModal" focusable class="w-[450px]">
            <flux:heading size="lg" class="mb-4">Edit Member</flux:heading>
            <flux:subheading class="mb-4">Node: <span class="font-mono">{{ $edit_member_id }}</span></flux:subheading>

            <div class="space-y-4 mb-4">
                <flux:input wire:model="edit_member_name" label="Name" placeholder="e.g. Ryan's Laptop" />
                <flux:textarea wire:model="edit_member_description" label="Description" placeholder="Optional notes about this device..." rows="2" />
            </div>

            <div class="mb-4">
                <flux:label>IP Assignments</flux:label>
                <div class="space-y-2 mt-2">
                    @foreach ($edit_ip_assignments as $index => $ip)
                        <div wire:key="ip-{{ $index }}" class="flex items-center gap-2">
                            <span class="font-mono text-sm flex-1">{{ $ip }}</span>
                            <flux:button size="xs" icon="x-mark" variant="danger" wire:click="removeIpAssignment({{ $index }})" />
                        </div>
                    @endforeach
                </div>

                <div class="flex items-center gap-2 mt-2">
                    <flux:input wire:model="new_ip" placeholder="e.g. 10.147.17.50" class="flex-1" size="sm" wire:keydown.enter="addIpAssignment" />
                    <flux:button size="sm" icon="plus" wire:click="addIpAssignment">Add</flux:button>
                </div>
            </div>

            <div class="space-y-4 mt-5 pt-5 border-t border-zinc-100 dark:border-zinc-700">
                <flux:switch wire:model="edit_active_bridge"
                    label="Allow Ethernet Bridging"
                    description="Allow this member to bridge other Ethernet segments into the network" />
                <flux:switch wire:model="edit_no_auto_assign"
                    label="Do Not Auto-Assign IPs"
                    description="Prevent ZeroTier from automatically assigning an IP to this member" />
            </div>

            <div class="flex justify-end space-x-2 mt-6">
                <flux:modal.close><flux:button variant="filled">Cancel</flux:button></flux:modal.close>
                <flux:button variant="primary" wire:click="saveMember()">Save</flux:button>
            </div>
        </flux:modal>
</div>

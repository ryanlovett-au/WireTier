<?php

use Livewire\Attributes\Title;
use Livewire\Component;
use App\Models\ZerotierToken;
use App\Services\ZerotierService;

new #[Title('Network Members')] class extends Component {
    public string $networkId;
    public string $tokenId;
    public array $network = [];
    public array $members = [];

    // Delete confirmation
    public string $delete_member_id = '';

    // Edit member
    public string $edit_member_id = '';
    public string $edit_member_name = '';
    public array  $edit_ip_assignments = [];
    public bool   $edit_active_bridge = false;
    public bool   $edit_no_auto_assign = false;
    public string $new_ip = '';

    public function mount(string $networkId, string $tokenId)
    {
        if (! auth()->user()->team) {
            $this->redirect('/settings/teams');
            return;
        }

        $this->networkId = $networkId;
        $this->tokenId = $tokenId;
        $this->loadNetwork();
        $this->loadMembers();
    }

    protected function getService(): ZerotierService
    {
        $token = ZerotierToken::findOrFail($this->tokenId);
        return new ZerotierService($token);
    }

    public function loadNetwork(): void
    {
        try {
            $this->network = $this->getService()->getControllerNetwork($this->networkId);
        } catch (\Exception $e) {
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Failed to load network: '.$e->getMessage());
        }
    }

    public function loadMembers(): void
    {
        $service = $this->getService();

        try {
            $memberIds = $service->getNetworkMembers($this->networkId);
            $this->members = [];

            foreach (array_keys($memberIds) as $nodeId) {
                try {
                    $member = $service->getNetworkMember($this->networkId, $nodeId);
                    $this->members[] = $member;
                } catch (\Exception $e) {
                    // Skip members that error
                }
            }
        } catch (\Exception $e) {
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Failed to load members: '.$e->getMessage());
        }
    }

    public function authorizeMember($nodeId): void
    {
        try {
            $this->getService()->authorizeMember($this->networkId, $nodeId);
            Flux::toast(variant: 'success', heading: 'Authorized', text: 'Member '.$nodeId.' has been authorized.');
            $this->loadMembers();
        } catch (\Exception $e) {
            Flux::toast(variant: 'danger', heading: 'Error', text: $e->getMessage());
        }
    }

    public function deauthorizeMember($nodeId): void
    {
        try {
            $this->getService()->deauthorizeMember($this->networkId, $nodeId);
            Flux::toast(variant: 'warning', heading: 'Deauthorized', text: 'Member '.$nodeId.' has been deauthorized.');
            $this->loadMembers();
        } catch (\Exception $e) {
            Flux::toast(variant: 'danger', heading: 'Error', text: $e->getMessage());
        }
    }

    public function confirmDeleteMember(string $nodeId): void
    {
        $this->delete_member_id = $nodeId;
        Flux::modal('deleteMemberModal')->show();
    }

    public function deleteMember(): void
    {
        try {
            $this->getService()->deleteMember($this->networkId, $this->delete_member_id);
            Flux::modal('deleteMemberModal')->close();
            Flux::toast(variant: 'success', heading: 'Deleted', text: 'Member has been removed.');
            $this->delete_member_id = '';
            $this->loadMembers();
        } catch (\Exception $e) {
            Flux::toast(variant: 'danger', heading: 'Error', text: $e->getMessage());
        }
    }

    public function editMemberModal($nodeId): void
    {
        try {
            $member = $this->getService()->getNetworkMember($this->networkId, $nodeId);
            $this->edit_member_id       = $nodeId;
            $this->edit_member_name     = $member['name'] ?? '';
            $this->edit_ip_assignments  = $member['ipAssignments'] ?? [];
            $this->edit_active_bridge   = $member['activeBridge'] ?? false;
            $this->edit_no_auto_assign  = $member['noAutoAssignIps'] ?? false;
            $this->new_ip = '';
            Flux::modal('editMemberModal')->show();
        } catch (\Exception $e) {
            Flux::toast(variant: 'danger', heading: 'Error', text: $e->getMessage());
        }
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
        try {
            $this->getService()->updateNetworkMember($this->networkId, $this->edit_member_id, [
                'ipAssignments'   => $this->edit_ip_assignments,
                'activeBridge'    => $this->edit_active_bridge,
                'noAutoAssignIps' => $this->edit_no_auto_assign,
            ]);
            Flux::modal('editMemberModal')->close();
            Flux::toast(variant: 'success', heading: 'Updated', text: 'Member settings have been updated.');
            $this->loadMembers();
        } catch (\Exception $e) {
            Flux::toast(variant: 'danger', heading: 'Error', text: $e->getMessage());
        }
    }
}; ?>

<div class="mx-auto max-w-5xl p-6">
        <div class="flex items-center justify-between mb-6">
            <div>
                <div class="flex items-center gap-2 mb-1">
                    <flux:button size="sm" icon="arrow-left" variant="ghost" :href="route('zerotier.networks')" wire:navigate />
                    <flux:heading size="xl">{{ $network['name'] ?? 'Network' }}</flux:heading>
                </div>
                <div class="flex items-center gap-2 flex-wrap mt-1">
                    <span class="font-mono text-sm text-zinc-500">{{ $networkId }}</span>
                    <flux:badge color="zinc" size="sm">
                        {{ collect($members)->where('authorized', true)->count() }} members
                    </flux:badge>
                    @php $pending = collect($members)->where('authorized', false)->count(); @endphp
                    @if ($pending > 0)
                        <flux:badge color="orange" size="sm">{{ $pending }} pending</flux:badge>
                    @endif
                    @if (! empty($network['routes']))
                        @foreach ($network['routes'] as $route)
                            <span class="font-mono text-sm text-zinc-400">{{ $route['target'] ?? '' }}</span>
                        @endforeach
                    @endif
                </div>
            </div>
            <flux:button size="sm" icon="arrow-path" wire:click="loadMembers">Refresh</flux:button>
        </div>

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
                        <flux:table.column>Node ID</flux:table.column>
                        <flux:table.column>IP Assignments</flux:table.column>
                        <flux:table.column>Authorized</flux:table.column>
                        <flux:table.column>Bridge</flux:table.column>
                        <flux:table.column>Last Seen</flux:table.column>
                        <flux:table.column>Version</flux:table.column>
                        <flux:table.column>Actions</flux:table.column>
                    </flux:table.columns>
                    <flux:table.rows>
                    @foreach ($members as $member)
                        <flux:table.row :key="$member['address'] ?? $member['id'] ?? $loop->index">
                            <flux:table.cell class="font-mono text-xs">{{ $member['address'] ?? $member['id'] ?? '—' }}</flux:table.cell>
                            <flux:table.cell class="font-mono text-xs">
                                @foreach (($member['ipAssignments'] ?? []) as $ip)
                                    <div>{{ $ip }}</div>
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
                            <flux:table.cell class="text-xs">
                                @php
                                    $lastOnlineSec = ($member['lastOnline'] ?? 0) / 1000;
                                    $isOnline = $lastOnlineSec > 0 && (time() - $lastOnlineSec) < 300;
                                @endphp
                                @if ($isOnline)
                                    <span style="color:#16a34a;font-weight:600;">Online</span>
                                @elseif ($lastOnlineSec > 0)
                                    <span class="text-zinc-400">{{ \Carbon\Carbon::createFromTimestamp($lastOnlineSec)->diffForHumans() }}</span>
                                @else
                                    <span class="text-zinc-400">Never</span>
                                @endif
                            </flux:table.cell>
                            <flux:table.cell class="text-xs text-zinc-500">
                                <div>v{{ ($member['vMajor'] ?? '?') }}.{{ ($member['vMinor'] ?? '?') }}.{{ ($member['vRev'] ?? '?') }}</div>
                                @if (! empty($member['physicalAddr']))
                                    <div class="font-mono">{{ $member['physicalAddr'] }}</div>
                                @endif
                                @if (isset($member['latency']) && $member['latency'] >= 0)
                                    <div>({{ $member['latency'] }} ms)</div>
                                @endif
                            </flux:table.cell>
                            <flux:table.cell>
                                <div class="flex gap-1">
                                    @if (! ($member['authorized'] ?? false))
                                        <flux:button size="xs" icon="check" style="background:#16a34a;color:#fff;border-color:#16a34a;" tooltip="Authorize" wire:click="authorizeMember('{{ $member['address'] ?? $member['id'] }}')" />
                                    @else
                                        <flux:button size="xs" icon="x-mark" variant="outline" style="color:#dc2626;border-color:#dc2626;" tooltip="Deauthorize" wire:click="deauthorizeMember('{{ $member['address'] ?? $member['id'] }}')" />
                                    @endif
                                    <flux:button size="xs" icon="pencil" tooltip="Edit Member" wire:click="editMemberModal('{{ $member['address'] ?? $member['id'] }}')" />
                                    <flux:button size="xs" icon="trash" variant="danger" tooltip="Delete" wire:click="confirmDeleteMember('{{ $member['address'] ?? $member['id'] }}')" />
                                </div>
                            </flux:table.cell>
                        </flux:table.row>
                    @endforeach
                    </flux:table.rows>
                </flux:table>
            </flux:card>
        @endif

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

            <div class="mb-4">
                <flux:label>IP Assignments</flux:label>
                <div class="space-y-2 mt-2">
                    @foreach ($edit_ip_assignments as $index => $ip)
                        <div class="flex items-center gap-2">
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

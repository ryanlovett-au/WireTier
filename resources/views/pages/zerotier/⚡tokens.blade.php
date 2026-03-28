<?php

use Livewire\Attributes\Title;
use Livewire\Component;
use App\Models\ZerotierToken;
use App\Services\ZerotierService;

new #[Title('ZeroTier Connections')] class extends Component {
    public $tokens;

    public string $new_name = '';
    public string $new_token = '';
    public string $new_host = 'http://localhost:9993';

    public string $edit_id = '';
    public string $edit_name = '';
    public string $edit_host = '';

    public string $delete_id = '';
    public string $delete_name = '';

    public function mount()
    {
        if (! auth()->user()->team) {
            $this->redirect('/settings/teams');
            return;
        }

        $this->loadTokens();
    }

    public function loadTokens()
    {
        $this->tokens = ZerotierToken::where('team_id', auth()->user()->team->id)->get();
    }

    public function addToken(): void
    {
        if (! auth()->user()->isTeamAdmin()) {
            return;
        }

        $this->validate([
            'new_name' => 'required|string|max:255',
            'new_token' => 'required|string',
            'new_host' => 'required|url',
        ]);

        $token = new ZerotierToken;
        $token->team_id = auth()->user()->team->id;
        $token->name = $this->new_name;
        $token->token = $this->new_token;
        $token->host = $this->new_host;
        $token->save();

        // Test connection and store node address
        $service = new ZerotierService($token);
        $result = $service->testConnection();

        if ($result['success']) {
            $token->node_address = $result['address'];
            $token->save();
            Flux::toast(variant: 'success', heading: 'Token Added', text: 'Connected to ZeroTier node '.$result['address'].' (v'.$result['version'].')');
        } else {
            Flux::toast(variant: 'warning', heading: 'Token Saved', text: 'Token saved but could not connect: '.$result['error']);
        }

        $this->new_name = '';
        $this->new_token = '';
        $this->new_host = 'http://localhost:9993';
        $this->loadTokens();
    }

    public function testToken($tokenId): void
    {
        $token = ZerotierToken::findOrFail($tokenId);
        $service = new ZerotierService($token);
        $result = $service->testConnection();

        if ($result['success']) {
            $token->node_address = $result['address'];
            $token->is_active = true;
            $token->save();
            Flux::toast(variant: 'success', heading: 'Connected', text: 'Node '.$result['address'].' v'.$result['version'].' - '.($result['online'] ? 'Online' : 'Offline'));
        } else {
            Flux::toast(variant: 'danger', heading: 'Connection Failed', text: $result['error']);
        }

        $this->loadTokens();
    }

    public function toggleToken($tokenId): void
    {
        $token = ZerotierToken::findOrFail($tokenId);
        $token->is_active = ! $token->is_active;
        $token->save();
        $this->loadTokens();
    }

    public function editTokenModal($tokenId): void
    {
        $token = ZerotierToken::findOrFail($tokenId);
        $this->edit_id = $token->id;
        $this->edit_name = $token->name;
        $this->edit_host = $token->host;
        Flux::modal('editTokenModal')->show();
    }

    public function updateToken(): void
    {
        $this->validate([
            'edit_name' => 'required|string|max:255',
            'edit_host' => 'required|url',
        ]);

        ZerotierToken::where('id', $this->edit_id)->update([
            'name' => $this->edit_name,
            'host' => $this->edit_host,
        ]);

        Flux::modal('editTokenModal')->close();
        Flux::toast(variant: 'success', heading: 'Updated', text: 'Token settings updated.');
        $this->loadTokens();
    }

    public function deleteTokenModal($tokenId): void
    {
        $token = ZerotierToken::findOrFail($tokenId);
        $this->delete_id = $token->id;
        $this->delete_name = $token->name;
        Flux::modal('deleteTokenConfirm')->show();
    }

    public function deleteToken(): void
    {
        ZerotierToken::where('id', $this->delete_id)->delete();
        Flux::modal('deleteTokenConfirm')->close();
        Flux::toast(variant: 'success', heading: 'Deleted', text: 'The token has been removed.');
        $this->loadTokens();
    }
}; ?>

<x-layouts::app :title="__('ZeroTier Tokens')">
    <div class="mx-auto max-w-4xl p-6">
        <div class="mb-6">
            <flux:heading size="xl">ZeroTier Connections</flux:heading>
            <flux:subheading>Connect to your self-hosted ZeroTier instances by adding their API tokens.</flux:subheading>
        </div>

        {{-- Existing Tokens --}}
        @if ($tokens->count() > 0)
        <flux:card class="mb-6">
            <flux:table>
                <flux:table.columns>
                    <flux:table.column>Name</flux:table.column>
                    <flux:table.column>Host</flux:table.column>
                    <flux:table.column>Node Address</flux:table.column>
                    <flux:table.column>Status</flux:table.column>
                    <flux:table.column>Actions</flux:table.column>
                </flux:table.columns>
                <flux:table.rows>
                @foreach ($tokens as $token)
                    <flux:table.row :key="$token->id">
                        <flux:table.cell class="font-medium">{{ $token->name }}</flux:table.cell>
                        <flux:table.cell class="text-xs font-mono">{{ $token->host }}</flux:table.cell>
                        <flux:table.cell class="text-xs font-mono">{{ $token->node_address ?? '—' }}</flux:table.cell>
                        <flux:table.cell>
                            @if ($token->is_active)
                                <flux:badge color="green" size="sm">Active</flux:badge>
                            @else
                                <flux:badge color="zinc" size="sm">Disabled</flux:badge>
                            @endif
                        </flux:table.cell>
                        <flux:table.cell>
                            <div class="flex gap-1">
                                <flux:button size="xs" icon="signal" tooltip="Test Connection" wire:click="testToken('{{ $token->id }}')" />
                                <flux:button size="xs" icon="pencil" tooltip="Edit" wire:click="editTokenModal('{{ $token->id }}')" />
                                <flux:button size="xs" icon="{{ $token->is_active ? 'pause' : 'play' }}" tooltip="{{ $token->is_active ? 'Disable' : 'Enable' }}" wire:click="toggleToken('{{ $token->id }}')" />
                                <flux:button size="xs" icon="trash" tooltip="Delete" variant="danger" wire:click="deleteTokenModal('{{ $token->id }}')" />
                            </div>
                        </flux:table.cell>
                    </flux:table.row>
                @endforeach
                </flux:table.rows>
            </flux:table>
        </flux:card>
        @endif

        {{-- Add New Token --}}
        @if (auth()->user()->isTeamAdmin())
        <flux:card>
            <flux:heading class="mb-4">Add ZeroTier Connection</flux:heading>
            <flux:subheading class="mb-4">
                Enter the API token from your ZeroTier installation. On Linux, this is typically found at <code class="text-xs">/var/lib/zerotier-one/authtoken.secret</code>.
            </flux:subheading>

            <flux:input wire:model="new_name" label="Name" description="A friendly name for this connection" class="mb-4" />
            <flux:input wire:model="new_host" label="Host" description="The ZeroTier API endpoint" class="mb-4" />
            <flux:input wire:model="new_token" label="API Token" type="password" description="The authtoken.secret value" class="mb-4" />

            <div class="flex">
                <flux:spacer />
                <flux:button variant="primary" wire:click="addToken()">Add Connection</flux:button>
            </div>
        </flux:card>
        @endif

        {{-- Edit Modal --}}
        <flux:modal name="editTokenModal" focusable class="w-[400px]">
            <flux:heading size="lg" class="mb-4">Edit Connection</flux:heading>
            <flux:input wire:model="edit_name" label="Name" class="mb-4" />
            <flux:input wire:model="edit_host" label="Host" class="mb-4" />
            <div class="flex justify-end space-x-2">
                <flux:modal.close><flux:button variant="filled">Cancel</flux:button></flux:modal.close>
                <flux:button variant="primary" wire:click="updateToken()">Save</flux:button>
            </div>
        </flux:modal>

        {{-- Delete Confirm --}}
        <flux:modal name="deleteTokenConfirm" focusable class="max-w-sm">
            <div class="text-center">
                <flux:heading size="lg">Delete Connection?</flux:heading>
                <flux:subheading class="mt-2">
                    Are you sure you want to delete <strong>{{ $delete_name }}</strong>? This will also remove all tracked networks for this connection.
                </flux:subheading>
            </div>
            <div class="flex justify-end space-x-2 mt-4">
                <flux:modal.close><flux:button variant="filled">Cancel</flux:button></flux:modal.close>
                <flux:button variant="danger" wire:click="deleteToken">Delete</flux:button>
            </div>
        </flux:modal>
    </div>
</x-layouts::app>

<?php

use App\Models\AuditLog;
use App\Models\Team;
use App\Models\User;
use Livewire\Attributes\Computed;
use Livewire\Attributes\Title;
use Livewire\Component;
use Livewire\WithPagination;

new #[Title('Audit Log')] class extends Component
{
    use WithPagination;

    public string $filter_action = '';

    public string $filter_user = '';

    public string $filter_date_from = '';

    public string $filter_date_to = '';

    public string $filter_search = '';

    public function mount()
    {
        if (! auth()->user()->isTeamAdmin() && ! auth()->user()->isAdmin()) {
            abort(403);
        }
    }

    public function updatedFilterAction()
    {
        $this->resetPage();
    }

    public function updatedFilterUser()
    {
        $this->resetPage();
    }

    public function updatedFilterDateFrom()
    {
        $this->resetPage();
    }

    public function updatedFilterDateTo()
    {
        $this->resetPage();
    }

    public function updatedFilterSearch()
    {
        $this->resetPage();
    }

    #[Computed]
    public function logs()
    {
        $query = AuditLog::with('user');

        // System admins see all logs; team admins see only their team's logs
        if (! auth()->user()->isAdmin()) {
            $query->where('team_id', auth()->user()->current_team);
        }

        if ($this->filter_action) {
            $query->where('action', 'like', $this->filter_action.'%');
        }

        if ($this->filter_user) {
            $query->where('user_id', $this->filter_user);
        }

        if ($this->filter_date_from) {
            $query->whereDate('created_at', '>=', $this->filter_date_from);
        }

        if ($this->filter_date_to) {
            $query->whereDate('created_at', '<=', $this->filter_date_to);
        }

        if ($this->filter_search) {
            $search = $this->filter_search;
            $query->where(function ($q) use ($search) {
                $q->where('action', 'like', "%{$search}%")
                    ->orWhere('resource_id', 'like', "%{$search}%")
                    ->orWhere('details', 'like', "%{$search}%");
            });
        }

        return $query->latest('created_at')->paginate(25);
    }

    #[Computed]
    public function actionCategories()
    {
        return [
            'auth' => 'Authentication',
            'team' => 'Team',
            'token' => 'Controllers',
            'network' => 'Networks',
            'member' => 'Members',
        ];
    }

    #[Computed]
    public function users()
    {
        if (auth()->user()->isAdmin()) {
            return User::orderBy('name')->get(['id', 'name']);
        }

        return User::whereHas('teams', function ($q) {
            $q->where('team_id', auth()->user()->current_team);
        })->orderBy('name')->get(['id', 'name']);
    }

    public function clearFilters(): void
    {
        $this->filter_action = '';
        $this->filter_user = '';
        $this->filter_date_from = '';
        $this->filter_date_to = '';
        $this->filter_search = '';
        $this->resetPage();
    }

    public static function actionBadgeColor(string $action): string
    {
        $prefix = explode('.', $action)[0] ?? '';

        return match ($prefix) {
            'auth' => 'purple',
            'team' => 'blue',
            'token' => 'red',
            'network' => 'green',
            'member' => 'orange',
            default => 'zinc',
        };
    }
}; ?>

<x-pages::settings.layout :heading="__('Audit Log')" :subheading="__('View a history of actions performed in your organisation.')">
    <div class="max-w-4xl">
        {{-- Filters --}}
        <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
            <flux:select wire:model.live="filter_action" placeholder="All Actions">
                @foreach ($this->actionCategories as $prefix => $label)
                    <flux:select.option value="{{ $prefix }}">{{ $label }}</flux:select.option>
                @endforeach
            </flux:select>

            <flux:select wire:model.live="filter_user" placeholder="All Users">
                @foreach ($this->users as $user)
                    <flux:select.option value="{{ $user->id }}">{{ $user->name }}</flux:select.option>
                @endforeach
            </flux:select>

            <flux:input type="date" wire:model.live="filter_date_from" placeholder="From" />
            <flux:input type="date" wire:model.live="filter_date_to" placeholder="To" />
        </div>

        <div class="flex items-center gap-3 mb-6">
            <flux:input wire:model.live.debounce.300ms="filter_search" placeholder="Search actions, resources, details..." icon="magnifying-glass" class="flex-1" />
            @if ($filter_action || $filter_user || $filter_date_from || $filter_date_to || $filter_search)
                <flux:button size="sm" wire:click="clearFilters" icon="x-mark">Clear</flux:button>
            @endif
        </div>

        {{-- Log Table --}}
        @if ($this->logs->count() > 0)
            <flux:table>
                <flux:table.columns>
                    <flux:table.column>Date</flux:table.column>
                    <flux:table.column>User</flux:table.column>
                    <flux:table.column>Action</flux:table.column>
                    <flux:table.column>Details</flux:table.column>
                </flux:table.columns>
                <flux:table.rows>
                    @foreach ($this->logs as $log)
                        <flux:table.row>
                            <flux:table.cell class="text-xs text-zinc-500 whitespace-nowrap">
                                {{ $log->created_at->format('d M Y H:i') }}
                            </flux:table.cell>
                            <flux:table.cell class="text-sm">
                                {{ $log->user?->name ?? 'System' }}
                            </flux:table.cell>
                            <flux:table.cell>
                                <flux:badge color="{{ self::actionBadgeColor($log->action) }}" size="sm">
                                    {{ $log->action }}
                                </flux:badge>
                                @if ($log->resource_id)
                                    <span class="text-xs font-mono text-zinc-400 ml-1">{{ Str::limit($log->resource_id, 16) }}</span>
                                @endif
                            </flux:table.cell>
                            <flux:table.cell class="text-xs text-zinc-500 max-w-xs truncate">
                                @if ($log->details)
                                    @foreach ($log->details as $key => $value)
                                        <span class="text-zinc-400">{{ $key }}:</span>
                                        {{ is_bool($value) ? ($value ? 'yes' : 'no') : Str::limit((string) $value, 30) }}{{ !$loop->last ? ', ' : '' }}
                                    @endforeach
                                @else
                                    —
                                @endif
                            </flux:table.cell>
                        </flux:table.row>
                    @endforeach
                </flux:table.rows>
            </flux:table>

            <div class="mt-4">
                {{ $this->logs->links() }}
            </div>
        @else
            <flux:card>
                <div class="text-center py-8">
                    <flux:icon name="clipboard-document-list" class="mx-auto size-12 text-zinc-400 mb-4" />
                    <flux:heading>No Logs Found</flux:heading>
                    <flux:subheading>No audit log entries match your filters.</flux:subheading>
                </div>
            </flux:card>
        @endif
    </div>
</x-pages::settings.layout>

<?php

use App\Models\AuditLog;
use App\Models\Team;
use App\Models\TeamUser;
use App\Models\ZerotierNetwork;
use App\Services\FlowRules\FlowRuleCompileException;
use App\Services\FlowRules\FlowRuleCompiler;
use App\Services\FlowRules\FlowRulesService;
use App\Services\ZerotierService;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use Livewire\Attributes\Locked;
use Livewire\Attributes\On;
use Livewire\Component;

new class extends Component
{
    // Locked: only open() may set these, after verifying the user can access
    // the network. Every action re-resolves the network from them.
    #[Locked]
    public string $editing_network_id = '';

    #[Locked]
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

    // ─── Flow rules (team admins only) ───────────────────────────────

    public string $rules_source = '';

    /** See ZerotierNetwork::rulesState(). Display-only. */
    #[Locked]
    public string $rules_state = 'default';

    #[Locked]
    public ?string $rules_error = null;

    #[Locked]
    public string $rules_summary = '';

    /** Compiled payload preview (JSON). */
    #[Locked]
    public string $rules_preview = '';

    /** The controller's live rules (JSON), shown when they are not WireTier's. */
    #[Locked]
    public string $live_rules_json = '';

    #[Locked]
    public string $rules_updated_label = '';

    #[On('open-network-edit')]
    public function open(string $networkId, string $tokenId): void
    {
        if (! auth()->user()->canManageNetworks()) {
            return;
        }

        $dbNetwork = $this->findAccessibleNetwork($networkId, $tokenId);

        if (! $dbNetwork) {
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Network not found.');

            return;
        }

        $service = new ZerotierService($dbNetwork->zerotierToken);

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
            $this->movable_teams = $this->loadMovableTeams($dbNetwork->team_id);

            $this->loadRulesEditor($dbNetwork, $network);

            Flux::modal('editNetworkModal')->show();
        } catch (Exception $e) {
            report($e);
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Failed to load network. Please try again.');
        }
    }

    public function addRoute(): void
    {
        $this->validate([
            'new_route_target' => ['required', 'string', $this->cidrRule()],
            'new_route_via' => 'nullable|ip',
        ]);

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
        if (! auth()->user()->canManageNetworks()) {
            return;
        }

        $dbNetwork = $this->findAccessibleNetwork($this->editing_network_id, $this->tokenId);

        if (! $dbNetwork) {
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Network not found.');

            return;
        }

        // Routes and pools are public properties, so they are validated here
        // rather than trusting the add* helpers to have been the only writers.
        $this->validate([
            'edit_name' => 'required|string|max:255',
            'edit_multicast_limit' => 'required|integer|min:0|max:1000000',
            'edit_routes' => 'array|max:128',
            'edit_routes.*.target' => ['required', 'string', $this->cidrRule()],
            'edit_routes.*.via' => 'nullable|ip',
            'edit_ip_pools' => 'array|max:128',
            'edit_ip_pools.*.ipRangeStart' => 'required|ip',
            'edit_ip_pools.*.ipRangeEnd' => 'required|ip',
        ]);

        $routes = array_map(fn ($r) => [
            'target' => $r['target'],
            'via' => ($r['via'] ?? null) ?: null,
        ], array_values($this->edit_routes));

        $pools = array_map(fn ($p) => [
            'ipRangeStart' => $p['ipRangeStart'],
            'ipRangeEnd' => $p['ipRangeEnd'],
        ], array_values($this->edit_ip_pools));

        $service = new ZerotierService($dbNetwork->zerotierToken);

        try {
            $service->updateNetwork($this->editing_network_id, [
                'name' => $this->edit_name,
                'private' => $this->edit_private,
                'enableBroadcast' => $this->edit_broadcast,
                'multicastLimit' => $this->edit_multicast_limit,
                'routes' => $routes,
                'ipAssignmentPools' => $pools,
                'v4AssignMode' => ['zt' => count($pools) > 0],
            ]);

            $dbNetwork->update([
                'name' => $this->edit_name,
                'private' => $this->edit_private,
            ]);

            // Bust the parent page's network list cache.
            Cache::forget("team_{$dbNetwork->team_id}_networks_{$this->tokenId}");

            AuditLog::record('network.updated', 'network', $this->editing_network_id, ['name' => $this->edit_name]);

            Flux::toast(variant: 'success', heading: 'Saved', text: 'Network settings updated.');
            Flux::modal('editNetworkModal')->close();

            $this->dispatch('network-updated', networkId: $this->editing_network_id);
        } catch (Exception $e) {
            report($e);
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Failed to save network. Please try again.');
        }
    }

    // ─── Flow Rules ──────────────────────────────────────────────────

    protected function loadRulesEditor(ZerotierNetwork $dbNetwork, array $liveConfig): void
    {
        $this->rules_source = '';
        $this->rules_error = null;
        $this->rules_summary = '';
        $this->rules_preview = '';
        $this->live_rules_json = '';
        $this->rules_updated_label = '';
        $this->rules_state = 'default';

        if (! auth()->user()->isTeamAdmin()) {
            return;
        }

        $this->rules_state = $dbNetwork->rulesState($liveConfig);
        $this->rules_source = $dbNetwork->rules_source
            ?? ($this->rules_state === 'default' ? FlowRulesService::DEFAULT_SOURCE : '');
        $this->rules_updated_label = $dbNetwork->rules_updated_at?->diffForHumans() ?? '';

        if (in_array($this->rules_state, ['drifted', 'unmanaged'], true)) {
            $this->live_rules_json = json_encode([
                'rules' => $liveConfig['rules'] ?? [],
                'capabilities' => $liveConfig['capabilities'] ?? [],
                'tags' => $liveConfig['tags'] ?? [],
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        }

        $this->compileRules();
    }

    /** Compile the editor contents for live feedback; never touches the controller. */
    protected function compileRules(): void
    {
        $this->rules_error = null;
        $this->rules_summary = '';
        $this->rules_preview = '';

        if (mb_strlen($this->rules_source) > FlowRulesService::MAX_SOURCE_LENGTH) {
            $this->rules_error = 'The rules script is longer than '.FlowRulesService::MAX_SOURCE_LENGTH.' characters.';

            return;
        }

        try {
            $compiled = FlowRuleCompiler::compile($this->rules_source);

            $rules = count($compiled->rules);
            $caps = count($compiled->capabilities);
            $tags = count($compiled->tags);
            $this->rules_summary = "{$rules} ".Str::plural('rule', $rules)
                .", {$caps} ".Str::plural('capability', $caps)
                .", {$tags} ".Str::plural('tag', $tags);
            $this->rules_preview = json_encode($compiled->toNetworkConfig(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        } catch (FlowRuleCompileException $e) {
            $this->rules_error = $e->describe();
        }
    }

    public function updatedRulesSource(): void
    {
        if (! auth()->user()->isTeamAdmin()) {
            return;
        }

        $this->compileRules();
    }

    public function confirmLoadExample(): void
    {
        if (! auth()->user()->isTeamAdmin()) {
            return;
        }

        // Nothing to lose when the editor is empty or untouched: load straight away.
        if (trim($this->rules_source) === '' || $this->rules_source === FlowRulesService::DEFAULT_SOURCE) {
            $this->loadExampleRules();

            return;
        }

        Flux::modal('loadExampleConfirm')->show();
    }

    public function loadExampleRules(): void
    {
        if (! auth()->user()->isTeamAdmin()) {
            return;
        }

        $this->rules_source = FlowRulesService::EXAMPLE_SOURCE;
        $this->compileRules();

        Flux::modal('loadExampleConfirm')->close();
    }

    public function confirmSaveRules(): void
    {
        if (! auth()->user()->isTeamAdmin()) {
            return;
        }

        $this->compileRules();

        if ($this->rules_error) {
            Flux::toast(variant: 'danger', heading: 'Rules Not Saved', text: 'Fix the errors in the rules script first.');

            return;
        }

        Flux::modal('saveRulesConfirm')->show();
    }

    public function saveRules(FlowRulesService $flowRules): void
    {
        if (! auth()->user()->isTeamAdmin()) {
            return;
        }

        $dbNetwork = $this->findAccessibleNetwork($this->editing_network_id, $this->tokenId);

        if (! $dbNetwork) {
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Network not found.');

            return;
        }

        Flux::modal('saveRulesConfirm')->close();

        try {
            $compiled = $flowRules->apply($dbNetwork, $this->rules_source);
        } catch (FlowRuleCompileException $e) {
            $this->rules_error = $e->describe();
            Flux::toast(variant: 'danger', heading: 'Rules Not Saved', text: 'Fix the errors in the rules script first.');

            return;
        } catch (Exception $e) {
            report($e);
            Flux::toast(variant: 'danger', heading: 'Error', text: 'The controller rejected the rules. Nothing was changed.');

            return;
        }

        AuditLog::record('network.rules_updated', 'network', $this->editing_network_id, [
            'name' => $dbNetwork->name,
            'rules' => count($compiled->rules),
            'capabilities' => array_keys($compiled->capabilities),
            'tags' => array_keys($compiled->tags),
            'hash' => $dbNetwork->rules_hash,
        ]);

        Cache::forget("team_{$dbNetwork->team_id}_networks_{$this->tokenId}");
        Cache::forget("network_{$dbNetwork->id}_members");

        $this->rules_state = 'managed';
        $this->live_rules_json = '';
        $this->rules_updated_label = $dbNetwork->rules_updated_at?->diffForHumans() ?? '';

        Flux::toast(variant: 'success', heading: 'Rules Applied', text: 'Flow rules are now active on the network.');
        $this->dispatch('network-updated', networkId: $this->editing_network_id);
    }

    // ─── Move Network ────────────────────────────────────────────────

    /**
     * Resolve a tracked network the current user may manage: one owned by their
     * current team on the given controller, or any tracked network for system
     * admins. Returns null otherwise, including for untracked network IDs.
     */
    protected function findAccessibleNetwork(string $networkId, string $tokenId): ?ZerotierNetwork
    {
        if ($networkId === '' || $tokenId === '') {
            return null;
        }

        $query = ZerotierNetwork::with('zerotierToken')
            ->where('network_id', $networkId)
            ->where('zerotier_token_id', $tokenId);

        if (! auth()->user()->isAdmin()) {
            $query->where('team_id', auth()->user()->team?->id);
        }

        $network = $query->first();

        // A disabled controller is off limits, like a missing one.
        return ($network && $network->zerotierToken?->is_active) ? $network : null;
    }

    /** Validation rule: an IPv4/IPv6 CIDR such as 10.0.0.0/24 or fd00::/8. */
    protected function cidrRule(): Closure
    {
        return function (string $attribute, mixed $value, Closure $fail) {
            $parts = explode('/', (string) $value);
            $ip = $parts[0];
            $bits = $parts[1] ?? null;
            $isV4 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
            $isV6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
            $max = $isV4 ? 32 : 128;

            if (count($parts) !== 2 || (! $isV4 && ! $isV6) || ! ctype_digit((string) $bits) || (int) $bits > $max) {
                $fail('The :attribute must be a valid CIDR (e.g. 10.0.0.0/24).');
            }
        };
    }

    protected function loadMovableTeams(?string $networkTeamId): array
    {
        $query = Team::query()->orderBy('name');

        if ($networkTeamId) {
            $query->where('id', '!=', $networkTeamId);
        }

        if (! auth()->user()->isAdmin()) {
            $query->whereIn('id', TeamUser::query()
                ->select('team_id')
                ->where('user_id', auth()->id())
                ->where('role', 'admin')
                ->active());
        }

        return $query->get(['id', 'name'])
            ->map(fn ($t) => ['id' => $t->id, 'name' => $t->name])
            ->toArray();
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

        // Only a network the user can access (their current team's, or any
        // for a system admin) can be moved out of its team.
        $network = $this->findAccessibleNetwork($this->editing_network_id, $this->tokenId);

        if (! $network) {
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Network not found.');

            return;
        }

        $sourceTeamId = $network->team_id;

        if ($this->move_to_team_id === $sourceTeamId) {
            Flux::toast(variant: 'warning', heading: 'No Change', text: 'This network is already on that team.');

            return;
        }

        // Re-verify the user is admin of the destination team (system admin bypasses this).
        if (! auth()->user()->canAdministerTeam($this->move_to_team_id)) {
            Flux::toast(variant: 'danger', heading: 'Permission Denied', text: 'You must be an admin of the destination team.');

            return;
        }

        $destinationTeam = Team::find($this->move_to_team_id);

        if (! $destinationTeam) {
            Flux::toast(variant: 'danger', heading: 'Error', text: 'Destination team not found.');

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
            @if (auth()->user()->isTeamAdmin())
                <flux:tab name="rules">Flow Rules</flux:tab>
                <flux:tab name="move">Move Team</flux:tab>
            @endif
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
                            <flux:button size="xs" icon="x-mark" variant="ghost" wire:click="removeIpPool({{ (int) $i }})" />
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
                                    <flux:button size="xs" icon="trash" variant="ghost" class="text-red-400 hover:text-red-600" wire:click="removeRoute({{ (int) $i }})" />
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

        {{-- Flow Rules Panel (team admins only) --}}
        @if (auth()->user()->isTeamAdmin())
            <div x-show="$wire.edit_tab === 'rules'" class="space-y-3 min-h-[220px]">
                @if ($rules_state === 'drifted' || $rules_state === 'unmanaged')
                    <div class="flex items-start gap-2 px-3 py-2.5 rounded-md border border-amber-300 bg-amber-50 dark:bg-amber-950/30 dark:border-amber-800 text-sm">
                        <flux:icon name="exclamation-triangle" class="size-4 text-amber-500 shrink-0 mt-0.5" />
                        <div class="text-amber-900 dark:text-amber-200 min-w-0 flex-1">
                            @if ($rules_state === 'drifted')
                                The live rules were changed outside WireTier after they were last saved here. The script below is the last version saved in WireTier; saving it will replace the live rules.
                            @else
                                This network has flow rules set by another tool, and WireTier doesn't have their source script. Saving a script here will replace them.
                            @endif
                            <details class="mt-2">
                                <summary class="cursor-pointer text-xs font-medium">View live compiled rules</summary>
                                <pre class="mt-2 max-h-48 overflow-auto rounded bg-white/70 dark:bg-zinc-900/60 p-2 text-xs font-mono text-zinc-700 dark:text-zinc-300">{{ $live_rules_json }}</pre>
                            </details>
                        </div>
                    </div>
                @endif

                <div class="flex items-center justify-between gap-2">
                    <div>
                        <flux:label>Rules script</flux:label>
                        <flux:description>Written in the ZeroTier rules language. Compiled and checked as you type.</flux:description>
                    </div>
                    <flux:button size="xs" variant="ghost" icon="document-text" wire:click="confirmLoadExample">Load example</flux:button>
                </div>

                <textarea
                    wire:model.live.debounce.600ms="rules_source"
                    x-on:keydown.tab="if (! $event.shiftKey) { $event.preventDefault(); $el.setRangeText('\t', $el.selectionStart, $el.selectionEnd, 'end'); $el.dispatchEvent(new Event('input')); }"
                    spellcheck="false"
                    autocapitalize="off"
                    autocomplete="off"
                    rows="16"
                    aria-label="Flow rules script"
                    class="block w-full rounded-lg border border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-900 px-3 py-2 font-mono text-xs leading-5 text-zinc-800 dark:text-zinc-200 focus:outline-none focus:ring-2 focus:ring-zinc-400 dark:focus:ring-zinc-500 [tab-size:4]"
                ></textarea>

                <div class="flex items-start justify-between gap-3 text-sm" aria-live="polite">
                    @if ($rules_error)
                        <div class="flex items-start gap-1.5 text-red-600 dark:text-red-400 min-w-0">
                            <flux:icon name="x-circle" class="size-4 shrink-0 mt-0.5" />
                            <span class="font-mono text-xs break-words">{{ $rules_error }}</span>
                        </div>
                    @elseif ($rules_summary)
                        <div class="flex items-center gap-1.5 text-green-700 dark:text-green-400">
                            <flux:icon name="check-circle" class="size-4 shrink-0" />
                            <span>Compiles to {{ $rules_summary }}</span>
                        </div>
                    @endif
                    @if ($rules_updated_label && $rules_state === 'managed')
                        <span class="text-xs text-zinc-400 shrink-0">Applied {{ $rules_updated_label }}</span>
                    @endif
                </div>

                @if ($rules_preview && ! $rules_error)
                    <details>
                        <summary class="cursor-pointer text-xs font-medium text-zinc-500">Preview compiled rules</summary>
                        <pre class="mt-2 max-h-48 overflow-auto rounded-lg bg-zinc-50 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-700 p-2 text-xs font-mono text-zinc-700 dark:text-zinc-300">{{ $rules_preview }}</pre>
                    </details>
                @endif

                <div class="flex items-center justify-between gap-3 pt-2">
                    <p class="text-xs text-zinc-500">Rules take effect on every member as soon as they are saved.</p>
                    <div class="flex gap-2 shrink-0">
                        <flux:modal.close><flux:button variant="filled">Cancel</flux:button></flux:modal.close>
                        <flux:button
                            variant="primary"
                            wire:click="confirmSaveRules"
                            :disabled="(bool) $rules_error"
                        >Save Rules</flux:button>
                    </div>
                </div>
            </div>
        @endif

        {{-- Move Panel --}}
        @if (auth()->user()->isTeamAdmin())
            <div x-show="$wire.edit_tab === 'move'" class="space-y-5 min-h-[220px]">
                <div>
                    <flux:label>Current Team</flux:label>
                    <div class="mt-1 px-3 py-2 rounded-md border border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-800 text-sm">
                        {{ auth()->user()->team?->name ?? '-' }}
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
        @endif

        <div x-show="! ['move', 'rules'].includes($wire.edit_tab)" class="flex justify-end gap-2" style="margin-top: 3rem;">
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

    {{-- Apply Flow Rules Confirm Modal --}}
    <flux:modal name="saveRulesConfirm" focusable class="max-w-sm">
        <div class="w-14 h-14 rounded-full bg-amber-100 dark:bg-amber-900/40 p-4 mt-4 mb-4 mx-auto flex items-center justify-center">
            <flux:icon name="shield-check" class="size-6 text-amber-600 dark:text-amber-400" />
        </div>

        <flux:heading size="lg" class="text-center">Apply Flow Rules?</flux:heading>
        <flux:subheading class="text-center mt-2 mb-6">
            The rules take effect immediately for every member of this network.
            Traffic that doesn't match an accept rule will be dropped.
        </flux:subheading>

        <div class="flex justify-end gap-2">
            <flux:modal.close>
                <flux:button variant="filled">Cancel</flux:button>
            </flux:modal.close>
            <flux:button variant="primary" wire:click="saveRules">Apply Rules</flux:button>
        </div>
    </flux:modal>

    {{-- Load Example Rules Confirm Modal --}}
    <flux:modal name="loadExampleConfirm" focusable class="max-w-sm">
        <div class="w-14 h-14 rounded-full bg-zinc-100 dark:bg-zinc-800 p-4 mt-4 mb-4 mx-auto flex items-center justify-center">
            <flux:icon name="document-text" class="size-6 text-zinc-600 dark:text-zinc-300" />
        </div>

        <flux:heading size="lg" class="text-center">Load Example Script?</flux:heading>
        <flux:subheading class="text-center mt-2 mb-6">
            This replaces the script in the editor with the example. Nothing is applied until you save.
        </flux:subheading>

        <div class="flex justify-end gap-2">
            <flux:modal.close>
                <flux:button variant="filled">Cancel</flux:button>
            </flux:modal.close>
            <flux:button variant="primary" wire:click="loadExampleRules">Replace Script</flux:button>
        </div>
    </flux:modal>
</div>

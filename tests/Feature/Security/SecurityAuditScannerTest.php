<?php

/*
 * Tests for the security:audit scanners. Each fixture reproduces a bug the
 * audit must catch (most are the cross-team bugs fixed in 8769624, as they
 * looked before the fix) or a false positive it must not raise.
 */

use App\Console\Commands\SecurityAudit;
use App\Tools\Security\Analysis\PhpSource;
use App\Tools\Security\Checks\ClientInputLookupCheck;
use App\Tools\Security\Checks\ControllerApiInputCheck;
use App\Tools\Security\Checks\CurrentTeamRoleCheck;
use App\Tools\Security\Checks\JsAttributeEchoCheck;
use Illuminate\Support\Facades\Artisan;

/** A ⚡ single-file component with $body as its class body. */
function component(string $body, string $name = '⚡fixture.blade.php'): PhpSource
{
    return new PhpSource(
        '/fixtures/resources/views/pages/'.$name,
        "<?php\n\nuse App\\Models\\Team;\nuse Livewire\\Attributes\\Locked;\nuse Livewire\\Component;\n\nnew class extends Component\n{\n{$body}\n}; ?>\n<div></div>\n",
    );
}

function descriptions(array $findings): array
{
    return array_column($findings, 'description');
}

// ─── Controller API Input ────────────────────────────────────────────────

test('flags a client-writable network id sent to a controller write', function () {
    $findings = (new ControllerApiInputCheck)->check(component(<<<'PHP'
        public string $delete_network_id = '';

        public function deleteNetwork(): void
        {
            if (! auth()->user()->canManageNetworks()) {
                return;
            }
            $service = new ZerotierService(ZerotierToken::findOrFail($this->selectedToken));
            $service->deleteNetwork($this->delete_network_id);
        }
    PHP));

    expect($findings)->toHaveCount(1);
    expect($findings[0]['severity'])->toBe('critical');
    expect($findings[0]['description'])->toContain('$this->delete_network_id')->toContain('deleteNetwork()');
});

test('flags an unlocked network id even when mount() checked ownership', function () {
    // The members page bug: mount() verified the network, but the property
    // could be changed afterwards.
    $findings = (new ControllerApiInputCheck)->check(component(<<<'PHP'
        public string $networkId;

        public function mount(string $networkId): void
        {
            abort_unless(ZerotierNetwork::where('network_id', $networkId)->where('team_id', auth()->user()->team->id)->exists(), 403);
            $this->networkId = $networkId;
        }

        public function authorizeMember($nodeId): void
        {
            $this->getService()->authorizeMember($this->networkId, $nodeId);
        }
    PHP));

    expect(descriptions($findings))->toHaveCount(1);
    expect($findings[0]['description'])->toContain('authorizeMember()');
});

test('accepts a locked network id', function () {
    $findings = (new ControllerApiInputCheck)->check(component(<<<'PHP'
        #[Locked]
        public string $networkId;

        public function authorizeMember($nodeId): void
        {
            $this->getService()->authorizeMember($this->networkId, $nodeId);
        }
    PHP));

    expect($findings)->toBe([]);
});

test('accepts a network resolved through a team-scoped helper first', function () {
    $findings = (new ControllerApiInputCheck)->check(component(<<<'PHP'
        public function open(string $networkId, string $tokenId): void
        {
            $dbNetwork = $this->findAccessibleNetwork($networkId, $tokenId);
            if (! $dbNetwork) {
                return;
            }
            $network = (new ZerotierService($dbNetwork->zerotierToken))->getControllerNetwork($networkId);
        }

        protected function findAccessibleNetwork(string $networkId, string $tokenId): ?ZerotierNetwork
        {
            return ZerotierNetwork::where('network_id', $networkId)->where('team_id', auth()->user()->team?->id)->first();
        }
    PHP));

    expect($findings)->toBe([]);
});

test('still flags when the scoped lookup result is never checked', function () {
    $findings = (new ControllerApiInputCheck)->check(component(<<<'PHP'
        public function open(string $networkId): void
        {
            $dbNetwork = $this->findAccessibleNetwork($networkId);
            $this->service->updateNetwork($networkId, []);
        }

        protected function findAccessibleNetwork(string $networkId): ?ZerotierNetwork
        {
            return ZerotierNetwork::where('network_id', $networkId)->where('team_id', 1)->first();
        }
    PHP));

    expect($findings)->toHaveCount(1);
});

test('accepts controller calls in system-admin-only actions', function () {
    $findings = (new ControllerApiInputCheck)->check(component(<<<'PHP'
        public string $delete_untracked_id = '';

        public function deleteUntrackedNetwork(): void
        {
            if (! auth()->user()->isAdmin()) {
                return;
            }
            $this->service->deleteNetwork($this->delete_untracked_id);
        }
    PHP));

    expect($findings)->toBe([]);
});

// ─── Livewire Client Input ───────────────────────────────────────────────

test('flags a membership row looked up by a client-writable array', function () {
    $findings = (new ClientInputLookupCheck)->check(component(<<<'PHP'
        public array $change_user = [];

        public function changeRole(): void
        {
            TeamUser::where('id', $this->change_user['id'])->update(['role' => 'admin']);
        }
    PHP));

    expect($findings)->toHaveCount(1);
    expect($findings[0]['description'])->toContain('$this->change_user');
});

test('reading team_id off the row is not a team constraint', function () {
    // The network-move bug: ->value('team_id') made the old check treat
    // the lookup as team-scoped.
    $findings = (new ClientInputLookupCheck)->check(component(<<<'PHP'
        public string $editing_network_id = '';

        protected function resolveNetworkTeamId(): ?string
        {
            return ZerotierNetwork::where('network_id', $this->editing_network_id)->value('team_id');
        }
    PHP));

    expect($findings)->toHaveCount(1);
    expect($findings[0]['description'])->toContain('resolveNetworkTeamId()');
});

test('a team constraint with a client-chosen value does not scope the lookup', function () {
    $findings = (new ClientInputLookupCheck)->check(component(<<<'PHP'
        public string $teamId = '';

        public function load(string $id): void
        {
            ZerotierNetwork::where('id', $id)->where('team_id', $this->teamId)->first();
        }
    PHP));

    // Both keys are client-chosen, so both are reported.
    expect(descriptions($findings))->toHaveCount(2);
    expect($findings[1]['description'])->toContain('$this->teamId');
});

test('accepts a lookup scoped by the current team', function () {
    $findings = (new ClientInputLookupCheck)->check(component(<<<'PHP'
        public function load(string $id): void
        {
            ZerotierNetwork::where('id', $id)->where('team_id', auth()->user()->team->id)->first();
        }
    PHP));

    expect($findings)->toBe([]);
});

test('accepts a team lookup followed by a membership check that fails for others', function () {
    $findings = (new ClientInputLookupCheck)->check(component(<<<'PHP'
        public function switchTeam($id): void
        {
            $team = Team::findOrFail($id);
            $teamUser = TeamUser::where('team_id', $team->id)->where('user_id', auth()->user()->id)->firstOrFail();
        }
    PHP));

    expect($findings)->toBe([]);
});

test('accepts lookups on models shared across teams by design', function () {
    $source = component(<<<'PHP'
        public string $selectedToken = '';

        public function createNetwork(): void
        {
            $token = ZerotierToken::findOrFail($this->selectedToken);
        }
    PHP);

    expect((new ClientInputLookupCheck)->check($source))->toHaveCount(1);
    expect((new ClientInputLookupCheck(SecurityAudit::SHARED_MODELS))->check($source))->toBe([]);
});

test('accepts a team lookup gated by canAdministerTeam on the same value', function () {
    $findings = (new ClientInputLookupCheck)->check(component(<<<'PHP'
        public string $move_to_team_id = '';

        public function moveNetwork(): void
        {
            if (! auth()->user()->canAdministerTeam($this->move_to_team_id)) {
                return;
            }
            $team = Team::find($this->move_to_team_id);
        }
    PHP));

    expect($findings)->toBe([]);
});

// ─── Current-Team Role Check ─────────────────────────────────────────────

test('flags a current-team role check on a page acting on another team', function () {
    $findings = (new CurrentTeamRoleCheck)->check(component(<<<'PHP'
        public Team $current_team;

        public function deleteTeam(): void
        {
            if (! auth()->user()->isTeamAdmin()) {
                return;
            }
            Team::where('id', $this->current_team->id)->delete();
        }
    PHP));

    expect($findings)->toHaveCount(1);
    expect($findings[0]['description'])->toContain('deleteTeam()')->toContain('isTeamAdmin()');
});

test('accepts a role check on the team being acted on, directly or via a helper', function () {
    $findings = (new CurrentTeamRoleCheck)->check(component(<<<'PHP'
        public Team $current_team;

        public function canAdminister(): bool
        {
            return auth()->user()->canAdministerTeam($this->current_team->id);
        }

        public function deleteTeam(): void
        {
            if (! $this->canAdminister()) {
                return;
            }
            Team::where('id', $this->current_team->id)->delete();
        }

        public function editTeam(): void
        {
            if (! auth()->user()->canAdministerTeam($this->current_team->id)) {
                return;
            }
            $this->current_team->save();
        }
    PHP));

    expect($findings)->toBe([]);
});

test('ignores current-team checks on pages that only use the current team', function () {
    $findings = (new CurrentTeamRoleCheck)->check(component(<<<'PHP'
        public function saveRules(): void
        {
            if (! auth()->user()->isTeamAdmin()) {
                return;
            }
        }
    PHP));

    expect($findings)->toBe([]);
});

// ─── Alpine/Livewire JS Injection ────────────────────────────────────────

test('flags a quoted echo inside wire:click and accepts Js::from in either spelling', function () {
    $check = new JsAttributeEchoCheck;
    $file = '/fixtures/resources/views/x.blade.php';

    expect($check->check($file, '<button wire:click="confirmDelete(\'{{ e($network[\'name\']) }}\')">'))->toHaveCount(1);
    expect($check->check($file, '<button wire:click="confirmDelete({{ Js::from($network[\'name\']) }})">'))->toBe([]);
    expect($check->check($file, '<button x-on:click="copy({{ \Illuminate\Support\Js::from($value) }})">'))->toBe([]);
});

// ─── Whole-codebase gates ────────────────────────────────────────────────

test('the codebase has no high or critical audit findings', function () {
    $exit = Artisan::call('security:audit', ['--output' => 'json']);
    $report = json_decode(Artisan::output(), true);

    $serious = array_values(array_filter(
        $report['findings'],
        fn ($f) => in_array($f['severity'], ['critical', 'high'], true),
    ));

    expect($serious)->toBe([]);
    expect($exit)->toBe(0);
});

test('every suppression still matches a finding and gives a reason', function () {
    $findings = [];
    foreach ((new SecurityAudit)->scanners() as $scan) {
        array_push($findings, ...$scan());
    }

    [, , $stale] = SecurityAudit::applySuppressions($findings, SecurityAudit::SUPPRESSIONS);

    expect($stale)->toBe([]);
    foreach (SecurityAudit::SUPPRESSIONS as $entry) {
        expect(trim($entry['reason']))->not->toBe('');
    }
});

test('the system admin check requires a current admin-team membership', function () {
    $findings = (new SecurityAudit)->scanners()['Admin Check Integrity']();

    expect($findings)->toBe([]);
});

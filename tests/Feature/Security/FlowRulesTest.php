<?php

use App\Models\AuditLog;
use App\Models\User;
use App\Models\ZerotierMember;
use App\Models\ZerotierNetwork;
use App\Services\FlowRules\FlowRulesService;
use App\Services\FlowRules\RulesFingerprint;
use App\Services\ZerotierSyncService;
use Database\Seeders\SecurityTestSeeder as S;
use Illuminate\Support\Facades\Http;
use Livewire\Livewire;

beforeEach(function () {
    $this->seed(S::class);
    config(['wiretier.admin_team' => S::ADMIN_TEAM_ID]);

    $this->alphaAdmin = User::where('email', 'alpha-admin@security-test.local')->first();
    $this->alphaMember = User::where('email', 'alpha-member@security-test.local')->first();
    $this->network = ZerotierNetwork::where('network_id', S::ALPHA_NETWORK_ID)->first();

    // A minimal stateful controller: POSTed network fields are kept and echoed
    // back, so tests see what a real controller would return after a write.
    $this->controller = [
        'nwid' => S::ALPHA_NETWORK_ID, 'name' => 'Alpha', 'private' => true,
        'routes' => [], 'ipAssignmentPools' => [],
        'rules' => [['type' => 'ACTION_ACCEPT']], 'capabilities' => [], 'tags' => [],
    ];
    $this->memberConfig = ['address' => 'aabb000001', 'authorized' => true, 'capabilities' => [], 'tags' => [], 'revision' => 1];
    $this->rejectWrites = false;

    Http::fake(function ($request) {
        $url = $request->url();

        if ($request->method() === 'POST' && $this->rejectWrites) {
            return Http::response(['error' => 'nope'], 500);
        }
        if (preg_match('#/member/([0-9a-f]{10})$#', $url)) {
            if ($request->method() === 'POST') {
                $this->memberConfig = array_merge($this->memberConfig, $request->data(), ['revision' => $this->memberConfig['revision'] + 1]);
            }

            return Http::response($this->memberConfig);
        }
        if (str_ends_with($url, '/member')) {
            return Http::response(['aabb000001' => $this->memberConfig['revision']]);
        }
        if (str_contains($url, '/peer')) {
            return Http::response([]);
        }
        if (str_contains($url, '/controller/network/'.S::ALPHA_NETWORK_ID)) {
            if ($request->method() === 'POST') {
                $this->controller = array_merge($this->controller, $request->data());
            }

            return Http::response($this->controller);
        }

        return Http::response([]);
    });
});

function openRulesEditor(User $user)
{
    test()->actingAs($user);

    return Livewire::test('pages::zerotier.network-edit-modal')
        ->call('open', S::ALPHA_NETWORK_ID, S::ALPHA_TOKEN_ID);
}

const SSH_RULES = "cap ssh\n id 1000\n accept ipprotocol tcp dport 22;\n;\ntag dept\n id 2000\n enum 1 eng\n enum 2 sales\n;\naccept tdiff dept 0;\ndrop;\n";

// ─── Editor ──────────────────────────────────────────────────────────────

test('a never-configured network opens with the default accept script', function () {
    openRulesEditor($this->alphaAdmin)
        ->assertSet('rules_state', 'default')
        ->assertSet('rules_source', FlowRulesService::DEFAULT_SOURCE)
        ->assertSet('rules_error', null)
        ->assertSet('rules_summary', '1 rule, 0 capabilities, 0 tags');
});

test('the editor reports compile errors as you type', function () {
    openRulesEditor($this->alphaAdmin)
        ->set('rules_source', "drop\n  nonsense 1\n;")
        ->assertSet('rules_error', 'Line 2, column 3: Unrecognized match type "nonsense".')
        ->assertSet('rules_summary', '');
});

test('the example script compiles', function () {
    openRulesEditor($this->alphaAdmin)
        ->call('loadExampleRules')
        ->assertSet('rules_error', null)
        ->assertSet('rules_summary', '5 rules, 0 capabilities, 0 tags');
});

// ─── Saving ──────────────────────────────────────────────────────────────

test('team admin saves rules to the controller and WireTier keeps the source', function () {
    openRulesEditor($this->alphaAdmin)
        ->set('rules_source', SSH_RULES)
        ->call('saveRules')
        ->assertSet('rules_state', 'managed');

    // Controller received the compiled payload.
    expect($this->controller['capabilities'])->toHaveCount(1);
    expect($this->controller['capabilities'][0]['id'])->toBe(1000);
    expect($this->controller['tags'])->toBe([['id' => 2000, 'default' => null]]);
    expect(collect($this->controller['rules'])->last())->toBe(['type' => 'ACTION_DROP']);

    $network = $this->network->fresh();
    expect($network->rules_source)->toBe(SSH_RULES);
    expect($network->rules_meta['capabilities'])->toBe(['ssh' => ['id' => 1000, 'default' => false]]);
    expect($network->rules_meta['tags']['dept']['enums'])->toBe(['eng' => 1, 'sales' => 2]);
    expect($network->rules_hash)->toBe(RulesFingerprint::of($this->controller));
    expect($network->rulesState())->toBe('managed');

    expect(AuditLog::where('action', 'network.rules_updated')->where('resource_id', S::ALPHA_NETWORK_ID)->exists())->toBeTrue();
});

test('a team member who is not an admin cannot save rules', function () {
    openRulesEditor($this->alphaMember)
        ->set('rules_source', 'drop;')
        ->call('saveRules');

    expect($this->controller['rules'])->toBe([['type' => 'ACTION_ACCEPT']]);
    expect($this->network->fresh()->rules_source)->toBeNull();
});

test('a non-admin does not get the rules source loaded into the editor', function () {
    $this->network->update(['rules_source' => SSH_RULES]);

    openRulesEditor($this->alphaMember)->assertSet('rules_source', '');
});

test('an invalid script is never sent to the controller', function () {
    openRulesEditor($this->alphaAdmin)
        ->set('rules_source', 'drop ethertype banana;')
        ->call('saveRules')
        ->assertSet('rules_error', 'Line 1, column 16: Invalid numeric value.');

    expect($this->controller['rules'])->toBe([['type' => 'ACTION_ACCEPT']]);
    expect($this->network->fresh()->rules_source)->toBeNull();
});

test('a controller rejection stores nothing', function () {
    $this->rejectWrites = true;

    openRulesEditor($this->alphaAdmin)
        ->set('rules_source', SSH_RULES)
        ->call('saveRules');

    expect($this->network->fresh()->rules_source)->toBeNull();
    expect(AuditLog::where('action', 'network.rules_updated')->exists())->toBeFalse();
});

test('rules cannot be saved to another team\'s network', function () {
    $this->actingAs($this->alphaAdmin);

    Livewire::test('pages::zerotier.network-edit-modal')
        ->call('open', S::BETA_NETWORK_ID, S::BETA_TOKEN_ID)
        ->set('rules_source', 'drop;')
        ->call('saveRules');

    expect(ZerotierNetwork::where('network_id', S::BETA_NETWORK_ID)->value('rules_source'))->toBeNull();
    expect(Http::recorded()->contains(fn ($p) => $p[0]->method() === 'POST' && str_contains($p[0]->url(), S::BETA_NETWORK_ID)))->toBeFalse();
});

// ─── Change detection ────────────────────────────────────────────────────

test('rules changed outside WireTier are detected after a sync', function () {
    app(FlowRulesService::class)->apply($this->network->fresh(), SSH_RULES);
    expect($this->network->fresh()->rulesState())->toBe('managed');

    // Someone edits the rules directly on the controller.
    $this->controller['rules'] = [['type' => 'ACTION_DROP']];
    ZerotierSyncService::syncNetwork($this->network->fresh(), force: true);

    expect($this->network->fresh()->rulesState())->toBe('drifted');

    openRulesEditor($this->alphaAdmin)
        ->assertSet('rules_state', 'drifted')
        ->assertSet('rules_source', SSH_RULES)
        ->assertSee('changed outside WireTier');
});

test('rules set by another tool are shown as unmanaged', function () {
    $this->controller['rules'] = [['type' => 'MATCH_ETHERTYPE', 'not' => true, 'or' => false, 'etherType' => 2048], ['type' => 'ACTION_DROP'], ['type' => 'ACTION_ACCEPT']];

    openRulesEditor($this->alphaAdmin)
        ->assertSet('rules_state', 'unmanaged')
        ->assertSet('rules_source', '')
        ->assertSee('set by another tool');
});

// ─── Members ─────────────────────────────────────────────────────────────

test('sync stores member capabilities and tags', function () {
    $this->memberConfig['capabilities'] = [1000];
    $this->memberConfig['tags'] = [[2000, 1]];

    ZerotierSyncService::syncNetwork($this->network->fresh(), force: true);

    $member = ZerotierMember::where('node_id', 'aabb000001')->first();
    expect($member->capabilities)->toBe([1000]);
    expect($member->tags)->toBe([[2000, 1]]);
});

test('team admin grants capabilities and tags using the script\'s names', function () {
    app(FlowRulesService::class)->apply($this->network->fresh(), SSH_RULES);
    // Another tool set an unrelated tag; it must survive the edit.
    $this->memberConfig['tags'] = [[9999, 5]];
    ZerotierSyncService::syncNetwork($this->network->fresh(), force: true);

    $this->actingAs($this->alphaAdmin);

    $page = Livewire::test('pages::zerotier.members', ['networkId' => S::ALPHA_NETWORK_ID, 'tokenId' => S::ALPHA_TOKEN_ID])
        ->call('editMemberModal', 'aabb000001')
        ->assertSee('Tag: dept')
        ->set('edit_capabilities', ['1000'])
        ->set('edit_tags.2000', '2')
        ->call('saveMember')
        ->assertHasNoErrors();

    expect($this->memberConfig['capabilities'])->toBe([1000]);
    expect($this->memberConfig['tags'])->toBe([[9999, 5], [2000, 2]]);

    // The table shows names rather than IDs.
    $page->assertSee('ssh')->assertSee('dept=sales')->assertSee('#9999=5');
});

test('a team member who is not an admin cannot change capabilities or tags', function () {
    app(FlowRulesService::class)->apply($this->network->fresh(), SSH_RULES);
    ZerotierSyncService::syncNetwork($this->network->fresh(), force: true);

    $this->actingAs($this->alphaMember);

    Livewire::test('pages::zerotier.members', ['networkId' => S::ALPHA_NETWORK_ID, 'tokenId' => S::ALPHA_TOKEN_ID])
        ->call('editMemberModal', 'aabb000001')
        ->assertDontSee('Tag: dept')
        ->set('edit_member_name', 'renamed')
        ->set('edit_capabilities', ['1000'])
        ->call('saveMember');

    expect($this->memberConfig['name'])->toBe('renamed');
    expect($this->memberConfig['capabilities'])->toBe([]);
});

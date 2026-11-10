<?php

use App\Models\AuditLog;
use App\Models\FlowRuleRevision;
use App\Models\User;
use App\Models\ZerotierMember;
use App\Models\ZerotierNetwork;
use App\Services\FlowRules\FlowRuleDecompiler;
use App\Services\FlowRules\FlowRulesNotRecordedException;
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

test('rules set by another tool open as a script rebuilt from them', function () {
    $this->controller['rules'] = [['type' => 'MATCH_ETHERTYPE', 'not' => true, 'or' => false, 'etherType' => 2048], ['type' => 'ACTION_DROP'], ['type' => 'ACTION_ACCEPT']];

    openRulesEditor($this->alphaAdmin)
        ->assertSet('rules_state', 'unmanaged')
        ->assertSet('rules_from_live', true)
        ->assertSet('rules_error', null)
        ->assertSee('set by another tool')
        ->assertSee('rebuilt the script below')
        ->assertSet('rules_source', fn ($src) => str_contains($src, 'not ethertype ipv4'));
});

test('saving a rebuilt script adopts the live rules without changing them', function () {
    $this->controller['rules'] = [['type' => 'MATCH_IP_DEST_PORT_RANGE', 'not' => false, 'or' => false, 'start' => 22, 'end' => 22], ['type' => 'ACTION_DROP'], ['type' => 'ACTION_ACCEPT']];
    $this->controller['capabilities'] = [['id' => 5, 'default' => false, 'rules' => [['type' => 'ACTION_ACCEPT']]]];
    $this->controller['tags'] = [['id' => 9, 'default' => 3]];
    $before = FlowRuleDecompiler::canonical($this->controller);

    openRulesEditor($this->alphaAdmin)
        ->call('saveRules')
        ->assertSet('rules_state', 'managed')
        ->assertSet('rules_from_live', false);

    expect(FlowRuleDecompiler::canonical($this->controller))->toBe($before);
    expect($this->network->fresh()->rules_meta['capabilities'])->toHaveKey('cap_5');
});

test('live rules the language cannot express leave the editor empty and say why', function () {
    $this->controller['rules'] = [['type' => 'ACTION_PRIORITY', 'qosBucket' => 2], ['type' => 'ACTION_ACCEPT']];

    openRulesEditor($this->alphaAdmin)
        ->assertSet('rules_state', 'unmanaged')
        ->assertSet('rules_source', '')
        ->assertSet('rules_from_live', false)
        ->assertSee('Saving a script here will replace them')
        ->assertSee('ACTION_PRIORITY');
});

test('drifted rules can be loaded into the editor with their saved names', function () {
    app(FlowRulesService::class)->apply($this->network->fresh(), SSH_RULES);
    // Someone changes the tag rule on the controller.
    $this->controller['rules'][0]['value'] = 1;
    ZerotierSyncService::syncNetwork($this->network->fresh(), force: true);

    openRulesEditor($this->alphaAdmin)
        ->assertSet('rules_state', 'drifted')
        ->assertSet('rules_source', SSH_RULES)
        ->assertSee('Load live rules')
        ->call('confirmLoadLiveRules')
        ->assertSet('rules_from_live', true)
        ->assertSet('rules_source', fn ($src) => str_contains($src, 'tdiff dept eng') && str_contains($src, 'cap ssh'));
});

test('loading live rules over unsaved edits asks first in a Flux modal', function () {
    app(FlowRulesService::class)->apply($this->network->fresh(), SSH_RULES);
    $this->controller['rules'] = [['type' => 'ACTION_DROP']];
    ZerotierSyncService::syncNetwork($this->network->fresh(), force: true);

    openRulesEditor($this->alphaAdmin)
        ->set('rules_source', "# my edits\naccept;")
        ->call('confirmLoadLiveRules')
        ->assertDispatched('modal-show', name: 'loadLiveConfirm')
        ->assertSet('rules_source', "# my edits\naccept;")
        ->call('loadLiveRules')
        ->assertSet('rules_from_live', true);
});

test('a team member who is not an admin cannot load live rules', function () {
    $this->controller['rules'] = [['type' => 'ACTION_DROP']];

    openRulesEditor($this->alphaMember)
        ->call('loadLiveRules')
        ->assertSet('rules_source', '');
});

// ─── History ─────────────────────────────────────────────────────────────

test('each save is kept in the rules history with who saved it', function () {
    openRulesEditor($this->alphaAdmin)
        ->set('rules_source', SSH_RULES)
        ->call('saveRules')
        ->set('rules_source', "drop;\n")
        ->call('saveRules');

    $revisions = $this->network->fresh()->ruleRevisions;
    expect($revisions)->toHaveCount(2);
    expect($revisions[0]->source)->toBe("drop;\n");
    expect($revisions[1]->source)->toBe(SSH_RULES);
    expect($revisions[1]->user_id)->toBe($this->alphaAdmin->id);
    expect($revisions[1]->capability_count)->toBe(1);

    openRulesEditor($this->alphaAdmin)
        ->assertSee('History (2)')
        ->assertSee($this->alphaAdmin->name)
        ->assertSee('Live');
});

test('a saved version can be loaded and saved again to roll back', function () {
    $service = app(FlowRulesService::class);
    $this->actingAs($this->alphaAdmin);
    $service->apply($this->network->fresh(), SSH_RULES);
    $sshRules = $this->controller['rules'];
    $service->apply($this->network->fresh(), "drop;\n");

    $old = $this->network->fresh()->ruleRevisions->last();

    openRulesEditor($this->alphaAdmin)
        ->call('confirmLoadRevision', $old->id)
        ->assertSet('rules_source', SSH_RULES)
        ->assertSee('Save Rules to roll back')
        ->call('saveRules')
        ->assertSet('rules_loaded_label', '');

    expect($this->controller['rules'])->toBe($sshRules);
    expect($this->network->fresh()->ruleRevisions)->toHaveCount(3);
});

test('loading a version over unsaved edits asks first in a Flux modal', function () {
    $this->actingAs($this->alphaAdmin);
    app(FlowRulesService::class)->apply($this->network->fresh(), SSH_RULES);
    $revision = $this->network->fresh()->ruleRevisions->first();

    openRulesEditor($this->alphaAdmin)
        ->set('rules_source', "# my edits\naccept;")
        ->call('confirmLoadRevision', $revision->id)
        ->assertDispatched('modal-show', name: 'loadRevisionConfirm')
        ->assertSet('rules_source', "# my edits\naccept;")
        ->call('loadRevision')
        ->assertSet('rules_source', SSH_RULES);
});

test('another network\'s history cannot be loaded', function () {
    $beta = ZerotierNetwork::where('network_id', S::BETA_NETWORK_ID)->first();
    $foreign = FlowRuleRevision::create([
        'zerotier_network_id' => $beta->id, 'source' => "# beta secret\naccept;", 'hash' => str_repeat('0', 64),
        'rule_count' => 1, 'capability_count' => 0, 'tag_count' => 0,
    ]);

    openRulesEditor($this->alphaAdmin)
        ->call('confirmLoadRevision', $foreign->id)
        ->call('loadRevision')
        ->assertSet('rules_source', FlowRulesService::DEFAULT_SOURCE);
});

test('a team member who is not an admin cannot load history', function () {
    $this->actingAs($this->alphaAdmin);
    app(FlowRulesService::class)->apply($this->network->fresh(), SSH_RULES);
    $revision = $this->network->fresh()->ruleRevisions->first();

    openRulesEditor($this->alphaMember)
        ->call('confirmLoadRevision', $revision->id)
        ->assertSet('rules_source', '')
        ->assertDontSee('History (');
});

test('history keeps only the most recent versions', function () {
    $this->actingAs($this->alphaAdmin);
    $service = app(FlowRulesService::class);
    for ($i = 0; $i < FlowRuleRevision::KEEP + 3; $i++) {
        $service->apply($this->network->fresh(), "# version {$i}\naccept;\n");
    }

    $revisions = $this->network->fresh()->ruleRevisions;
    expect($revisions)->toHaveCount(FlowRuleRevision::KEEP);
    expect($revisions->first()->source)->toContain('version '.(FlowRuleRevision::KEEP + 2));
    expect($revisions->last()->source)->toContain('version 3');
});

test('deleting a network deletes its rules history', function () {
    $this->actingAs($this->alphaAdmin);
    app(FlowRulesService::class)->apply($this->network->fresh(), SSH_RULES);

    $this->network->fresh()->delete();

    expect(FlowRuleRevision::count())->toBe(0);
});

test('rules the controller accepted but WireTier failed to record are not reported as unchanged', function () {
    // The controller takes the rules, then the local write fails.
    FlowRuleRevision::creating(fn () => throw new RuntimeException('database went away'));

    expect(fn () => app(FlowRulesService::class)->apply($this->network->fresh(), SSH_RULES))
        ->toThrow(FlowRulesNotRecordedException::class);

    // The rules are live, the local write was rolled back as a whole, so the
    // network reads as changed outside WireTier rather than half-recorded.
    expect($this->controller['capabilities'])->not->toBeEmpty();
    $network = $this->network->fresh();
    expect($network->rules_source)->toBeNull();
    expect(FlowRuleRevision::count())->toBe(0);
    expect($network->rulesState($this->controller))->toBe('unmanaged');
});

test('the editor says the rules are live when they could not be recorded', function () {
    FlowRuleRevision::creating(fn () => throw new RuntimeException('database went away'));

    openRulesEditor($this->alphaAdmin)
        ->set('rules_source', SSH_RULES)
        ->call('saveRules')
        ->assertDispatched('network-updated');

    expect(AuditLog::where('action', 'network.rules_updated')->first()?->details)
        ->toMatchArray(['recorded' => false]);
});

test('the script size limit counts bytes, which is what the database stores', function () {
    // Under the limit in characters, over it in bytes.
    $script = '# '.str_repeat('é', 40000)."\naccept;\n";
    expect(mb_strlen($script))->toBeLessThan(FlowRulesService::MAX_SOURCE_BYTES);

    openRulesEditor($this->alphaAdmin)
        ->set('rules_source', $script)
        ->assertSet('rules_error', FlowRulesService::tooLargeMessage())
        ->call('saveRules');

    expect($this->controller['rules'])->toBe([['type' => 'ACTION_ACCEPT']]);
    expect($this->network->fresh()->rules_source)->toBeNull();
});

test('a network released by a deleted team gets its rules and history back on import', function () {
    $this->actingAs($this->alphaAdmin);
    app(FlowRulesService::class)->apply($this->network->fresh(), SSH_RULES);
    app(FlowRulesService::class)->apply($this->network->fresh(), SSH_RULES."# second version\n");

    Livewire::test('pages::settings.team', ['id' => S::ALPHA_TEAM_ID])->call('deleteTeam');

    expect(ZerotierNetwork::where('network_id', S::ALPHA_NETWORK_ID)->exists())->toBeFalse();
    expect(FlowRuleRevision::whereNull('zerotier_network_id')->where('network_id', S::ALPHA_NETWORK_ID)->count())->toBe(2);

    $this->actingAs(User::where('email', 'superadmin@security-test.local')->first());
    Livewire::test('pages::zerotier.networks')
        ->set('selectedToken', S::ALPHA_TOKEN_ID)
        ->set('import_team_selections', [S::ALPHA_NETWORK_ID => S::BETA_TEAM_ID])
        ->call('importNetwork', S::ALPHA_NETWORK_ID);

    $imported = ZerotierNetwork::where('network_id', S::ALPHA_NETWORK_ID)->first();
    expect($imported->team_id)->toBe(S::BETA_TEAM_ID);
    expect($imported->rules_source)->toBe(SSH_RULES."# second version\n");
    expect($imported->rules_meta['capabilities'])->toHaveKey('ssh');
    expect($imported->ruleRevisions()->count())->toBe(2);
    expect($imported->rulesState($this->controller))->toBe('managed');
});

test('rules applied before history existed are kept when a team is deleted', function () {
    $this->actingAs($this->alphaAdmin);
    app(FlowRulesService::class)->apply($this->network->fresh(), SSH_RULES);
    FlowRuleRevision::query()->delete();

    Livewire::test('pages::settings.team', ['id' => S::ALPHA_TEAM_ID])->call('deleteTeam');

    $kept = FlowRuleRevision::where('network_id', S::ALPHA_NETWORK_ID)->sole();
    expect($kept->source)->toBe(SSH_RULES);
    expect($kept->capability_count)->toBe(1);
    expect($kept->user_id)->toBeNull();
});

test('released history is deleted when the network is deleted from the controller', function () {
    $this->actingAs($this->alphaAdmin);
    app(FlowRulesService::class)->apply($this->network->fresh(), SSH_RULES);
    Livewire::test('pages::settings.team', ['id' => S::ALPHA_TEAM_ID])->call('deleteTeam');

    $this->actingAs(User::where('email', 'superadmin@security-test.local')->first());
    Livewire::test('pages::zerotier.networks')
        ->set('selectedToken', S::ALPHA_TOKEN_ID)
        ->set('delete_untracked_id', S::ALPHA_NETWORK_ID)
        ->call('deleteUntrackedNetwork');

    expect(FlowRuleRevision::count())->toBe(0);
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

test('flag tag values are shown by flag name when every bit is named', function () {
    app(FlowRulesService::class)->apply($this->network->fresh(), "tag role\n id 3000\n flag 0 admin\n flag 1 audit\n flag 2,3 ops\n;\naccept;\n");
    $this->actingAs($this->alphaAdmin);

    $page = Livewire::test('pages::zerotier.members', ['networkId' => S::ALPHA_NETWORK_ID, 'tokenId' => S::ALPHA_TOKEN_ID]);

    expect($page->instance()->tagLabels([[3000, 3], [3000, 1], [3000, 13], [3000, 16], [3000, 4], [3000, 0]]))
        ->toBe(['role=admin|audit', 'role=admin', 'role=admin|ops', 'role=16', 'role=4', 'role=0']);
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

// ─── Confirmation ────────────────────────────────────────────────────────

test('save rules asks for confirmation in a Flux modal before applying', function () {
    openRulesEditor($this->alphaAdmin)
        ->set('rules_source', SSH_RULES)
        ->call('confirmSaveRules')
        ->assertDispatched('modal-show', name: 'saveRulesConfirm');

    // Opening the confirmation applies nothing.
    expect($this->controller['rules'])->toBe([['type' => 'ACTION_ACCEPT']]);
    expect($this->network->fresh()->rules_source)->toBeNull();
});

test('save rules confirmation is not offered for a script with errors', function () {
    openRulesEditor($this->alphaAdmin)
        ->set('rules_source', 'drop ethertype banana;')
        ->call('confirmSaveRules')
        ->assertNotDispatched('modal-show', name: 'saveRulesConfirm');
});

test('load example confirms before replacing an edited script, but not an untouched one', function () {
    openRulesEditor($this->alphaAdmin)
        ->call('confirmLoadExample')
        ->assertNotDispatched('modal-show', name: 'loadExampleConfirm')
        ->assertSet('rules_source', FlowRulesService::EXAMPLE_SOURCE);

    openRulesEditor($this->alphaAdmin)
        ->set('rules_source', 'accept;')
        ->call('confirmLoadExample')
        ->assertDispatched('modal-show', name: 'loadExampleConfirm')
        ->assertSet('rules_source', 'accept;');
});

test('views never use native browser dialogs', function () {
    // Confirmations must use Flux confirm modals, not alert/confirm/prompt
    // (Livewire's wire:confirm calls the browser's confirm()).
    $offenders = collect(File::allFiles(resource_path()))
        ->filter(fn ($f) => str_ends_with($f->getFilename(), '.php') || str_ends_with($f->getFilename(), '.js'))
        ->filter(fn ($f) => preg_match('/wire:confirm|window\.(alert|confirm|prompt)\s*\(|(?<![\w.:>-])(alert|confirm|prompt)\s*\(/', $f->getContents()))
        ->map(fn ($f) => $f->getRelativePathname())
        ->values()
        ->all();

    expect($offenders)->toBe([]);
});

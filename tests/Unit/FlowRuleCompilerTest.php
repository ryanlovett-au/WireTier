<?php

use App\Services\FlowRules\FlowRuleCompileException;
use App\Services\FlowRules\FlowRuleCompiler;
use App\Services\FlowRules\FlowRulesService;

/*
 * Parity: tests/Fixtures/flow-rules/parity.json holds the output of ZeroTier's
 * own rule-compiler.js (ZeroTierOne dev branch) for each source script, so the
 * PHP port must produce identical rules/capabilities/tags — or the same error
 * message on the same line. (Error columns are not compared: the original
 * counts columns from 0 on line 1 and from 1 on later lines.)
 */
dataset('parity cases', function () {
    $cases = json_decode(file_get_contents(__DIR__.'/../Fixtures/flow-rules/parity.json'), true);

    foreach ($cases as $name => $case) {
        yield $name => [$case];
    }
});

test('compiles identically to ZeroTier rule-compiler.js', function (array $case) {
    if (isset($case['error'])) {
        try {
            FlowRuleCompiler::compile($case['source']);
            $this->fail('Expected a compile error: '.$case['error']['message']);
        } catch (FlowRuleCompileException $e) {
            expect($e->getMessage())->toBe($case['error']['message']);
            expect($e->sourceLine)->toBe($case['error']['line']);
        }

        return;
    }

    $compiled = FlowRuleCompiler::compile($case['source']);

    expect($compiled->rules)->toEqual($case['rules']);
    expect($compiled->capabilities)->toEqual($case['capabilities']);
    expect($compiled->tags)->toEqual($case['tags']);
})->with('parity cases');

// ─── Deliberate deviations from the original ────────────────────────────

test('characteristic masks combining bit 63 with other high bits are correct', function () {
    // The original's 32-bit JS bitwise ops produce 4000000000000000 here,
    // silently dropping the inbound bit.
    $rules = FlowRuleCompiler::compile("drop chr inbound,multicast;\naccept;")->rules;

    expect($rules[0]['mask'])->toBe('c000000000000000');
});

test('tag flag on bit 31 is accepted as an unsigned value', function () {
    $compiled = FlowRuleCompiler::compile("tag t\n id 1\n flag 31 top\n;\naccept tand t top;");

    expect($compiled->tags['t']['flags']['top'])->toBe(0x80000000);
    expect($compiled->rules[0]['value'])->toBe(0x80000000);
});

test('tee without a target is a positioned error, not an exception', function () {
    FlowRuleCompiler::compile('tee 0;');
})->throws(FlowRuleCompileException::class, 'The tee and watch actions require two paremters');

test('tee and redirect targets must be hex ZeroTier addresses', function () {
    FlowRuleCompiler::compile('redirect zzzzzzzzzz;');
})->throws(FlowRuleCompileException::class, 'Missing or invalid ZeroTier address target for redirect.');

test('recursive macros are rejected rather than overflowing the stack', function () {
    FlowRuleCompiler::compile("macro loop\n include loop\n;\ninclude loop");
})->throws(FlowRuleCompileException::class, 'nested too deeply');

test('rule sets larger than the controller limit are rejected', function () {
    $source = str_repeat("drop\n ethertype arp\n;\n", 600);

    FlowRuleCompiler::compile($source);
})->throws(FlowRuleCompileException::class, 'at most 1024');

test('capabilities larger than the controller limit are rejected', function () {
    $source = "cap big\n id 1\n".str_repeat(" drop ethertype arp;\n", 40).";\n";

    FlowRuleCompiler::compile($source);
})->throws(FlowRuleCompileException::class, 'at most 64');

// ─── Output shape ────────────────────────────────────────────────────────

test('error positions are 1-based line and column', function () {
    try {
        FlowRuleCompiler::compile("drop\n  nonsense 1\n;");
        $this->fail('Expected a compile error');
    } catch (FlowRuleCompileException $e) {
        expect($e->sourceLine)->toBe(2);
        expect($e->sourceColumn)->toBe(3);
        expect($e->describe())->toBe('Line 2, column 3: Unrecognized match type "nonsense".');
    }
});

test('toNetworkConfig produces the controller payload shape', function () {
    $compiled = FlowRuleCompiler::compile("cap ssh\n id 5\n default\n accept dport 22;\n;\ntag dept\n id 9\n enum 1 eng\n default eng\n;\naccept;");

    expect($compiled->toNetworkConfig())->toBe([
        'rules' => [['type' => 'ACTION_ACCEPT']],
        'capabilities' => [[
            'id' => 5,
            'default' => true,
            'rules' => [
                ['type' => 'MATCH_IP_DEST_PORT_RANGE', 'not' => false, 'or' => false, 'start' => 22, 'end' => 22],
                ['type' => 'ACTION_ACCEPT'],
            ],
        ]],
        'tags' => [['id' => 9, 'default' => 1]],
    ]);
});

test('an empty script clears rules, capabilities and tags', function () {
    expect(FlowRuleCompiler::compile('')->toNetworkConfig())
        ->toBe(['rules' => [], 'capabilities' => [], 'tags' => []]);
});

test('metadata keeps the names the controller discards', function () {
    $meta = FlowRuleCompiler::compile("cap ssh\n id 5\n accept;\n;\ntag dept\n id 9\n enum 1 eng\n flag 0 remote\n;\naccept;")->metadata();

    expect($meta)->toBe([
        'capabilities' => ['ssh' => ['id' => 5, 'default' => false]],
        'tags' => ['dept' => ['id' => 9, 'default' => null, 'enums' => ['eng' => 1], 'flags' => ['remote' => 1]]],
    ]);
});

test('rules after a bare action get an explanatory hint', function () {
    try {
        FlowRuleCompiler::compile("accept;\n\ndrop\n ipprotocol tcp\n;");
        $this->fail('Expected a compile error');
    } catch (FlowRuleCompileException $e) {
        expect($e->getMessage())->toBe('Unrecognized match type "drop".');
        expect($e->describe())->toContain('must be the last rule');
    }
});

test('rules added above the default script compile', function () {
    $source = "drop\n ipprotocol tcp\n dport 23\n;\n".FlowRulesService::DEFAULT_SOURCE;

    expect(FlowRuleCompiler::compile($source)->rules)->toHaveCount(4);
});

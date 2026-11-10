<?php

use App\Services\FlowRules\FlowRuleCompiler;
use App\Services\FlowRules\FlowRuleDecompileException;
use App\Services\FlowRules\FlowRuleDecompiler;
use App\Services\FlowRules\FlowRulesService;

/*
 * The decompiler must rebuild a script that compiles back to exactly the
 * rules it was given, or refuse. Anything else would silently change a
 * network's policy when an admin saves an adopted script.
 */

function roundTrips(string $source, bool $withNames): void
{
    $compiled = FlowRuleCompiler::compile($source);
    $meta = $withNames ? $compiled->metadata() : [];

    $script = FlowRuleDecompiler::decompile($compiled->toNetworkConfig(), $meta);
    $again = FlowRuleCompiler::compile($script);

    expect(FlowRuleDecompiler::canonical($again->toNetworkConfig()))
        ->toBe(FlowRuleDecompiler::canonical($compiled->toNetworkConfig()));

    if ($withNames) {
        expect($again->metadata())->toEqual($compiled->metadata());
    }
}

dataset('compilable parity sources', function () {
    $cases = json_decode(file_get_contents(__DIR__.'/../Fixtures/flow-rules/parity.json'), true);

    foreach ($cases as $name => $case) {
        if (! isset($case['error'])) {
            yield $name => [$case['source']];
        }
    }
});

test('every parity fixture round-trips with generated names', function (string $source) {
    roundTrips($source, withNames: false);
})->with('compilable parity sources');

test('every parity fixture round-trips with its saved names, enums and flags', function (string $source) {
    roundTrips($source, withNames: true);
})->with('compilable parity sources');

test('the built-in scripts round-trip', function () {
    roundTrips(FlowRulesService::EXAMPLE_SOURCE, withNames: true);
    roundTrips(FlowRulesService::DEFAULT_SOURCE, withNames: false);
});

test('random scripts round-trip', function () {
    mt_srand(20261110);

    $matches = [
        fn () => 'ztsrc '.sprintf('%010x', mt_rand(0, 0xFFFFFFF)),
        fn () => 'ztdest '.sprintf('%010x', mt_rand(0, 0xFFFFFFF)),
        fn () => 'vlan '.mt_rand(0, 4095),
        fn () => 'vlanpcp '.mt_rand(0, 7),
        fn () => 'vlandei '.mt_rand(0, 1),
        fn () => 'ethertype '.['ipv4', 'arp', 'ipv6', '0x88cc', (string) mt_rand(0, 0xFFFF)][mt_rand(0, 4)],
        fn () => 'ipprotocol '.['tcp', 'udp', 'icmp4', 'icmp6', (string) mt_rand(0, 255)][mt_rand(0, 4)],
        fn () => 'macsrc '.implode(':', array_map(fn () => sprintf('%02X', mt_rand(0, 255)), range(1, 6))),
        fn () => 'macdest '.implode('-', array_map(fn () => sprintf('%02x', mt_rand(0, 255)), range(1, 6))),
        fn () => 'ipsrc '.long2ip(mt_rand(0, 0xFFFFFFFF)).'/'.mt_rand(0, 32),
        fn () => 'ipdest fd'.sprintf('%02x', mt_rand(0, 255)).'::'.dechex(mt_rand(0, 0xFFFF)).'/'.mt_rand(0, 128),
        fn () => 'iptos '.mt_rand(0, 255).' '.($a = mt_rand(0, 200)).'-'.($a + mt_rand(0, 55)),
        fn () => 'icmp '.mt_rand(0, 255).' '.mt_rand(-1, 255),
        fn () => ['sport', 'dport', 'framesize'][mt_rand(0, 2)].' '.(mt_rand(0, 1) ? mt_rand(0, 65535) : ($a = mt_rand(0, 60000)).'-'.($a + mt_rand(0, 5535))),
        fn () => 'chr '.implode(',', (array) array_rand(array_flip(['inbound', 'multicast', 'broadcast', 'ipauth', 'macauth', 'tcp_syn', 'tcp_ack', 'tcp_fin', '20', '40']), mt_rand(1, 4))),
        fn () => 'random '.(mt_rand(0, 1000000) / 1000000),
        fn () => ['tand', 'tor', 'txor', 'tdiff', 'teq', 'tseq', 'treq'][mt_rand(0, 6)].' '.['dept', 'role', (string) mt_rand(0, 99999)][mt_rand(0, 2)].' '.['eng', 'ops', 'admin', (string) mt_rand(0, 0xFFFF)][mt_rand(0, 3)],
    ];

    $rule = function () use ($matches) {
        $action = ['drop', 'accept', 'break', 'tee', 'watch', 'redirect'][mt_rand(0, 5)];
        $head = match ($action) {
            'tee', 'watch' => "{$action} ".mt_rand(-1, 1500).' '.sprintf('%010x', mt_rand(0, 0xFFFFFFF)),
            'redirect' => "{$action} ".sprintf('%010x', mt_rand(0, 0xFFFFFFF)),
            default => $action,
        };
        $parts = [];
        for ($i = mt_rand($head === $action ? 1 : 0, 4); $i > 0; $i--) {
            $parts[] = (count($parts) ? ['and ', 'or ', ''][mt_rand(0, 2)] : '').(mt_rand(0, 3) === 0 ? 'not ' : '').$matches[mt_rand(0, count($matches) - 1)]();
        }

        return $head.($parts ? ' '.implode(' ', $parts) : '').';';
    };

    $checked = 0;
    for ($n = 0; $n < 1500; $n++) {
        $script = "tag dept id 2000 enum 1 eng enum 2 ops default 1;\ntag role id 2001 flag 0 admin flag 1,2 ops;\n";
        if (mt_rand(0, 1)) {
            $script .= 'cap c'.$n.' id '.mt_rand(0, 9999).(mt_rand(0, 1) ? ' default' : '').' '.$rule()." ;\n";
        }
        for ($r = mt_rand(1, 6); $r > 0; $r--) {
            $script .= $rule()."\n";
        }
        $script .= mt_rand(0, 1) ? 'accept;' : 'drop;';

        try {
            FlowRuleCompiler::compile($script);
        } catch (Throwable) {
            continue; // the generator can produce invalid scripts; skip them
        }

        roundTrips($script, withNames: (bool) mt_rand(0, 1));
        $checked++;
    }

    expect($checked)->toBeGreaterThan(1000);
});

test('accepts the controller\'s normalised rendering of rules', function () {
    $live = [
        'rules' => [
            ['type' => 'MATCH_MAC_SOURCE', 'not' => false, 'or' => false, 'mac' => 'AA:BB:CC:DD:EE:FF'],
            ['type' => 'MATCH_IPV6_DEST', 'not' => true, 'or' => false, 'ip' => 'fd00:0:0:0:0:0:0:1/64'],
            ['type' => 'MATCH_ICMP', 'not' => false, 'or' => false, 'icmpType' => 8, 'icmpCode' => null],
            ['type' => 'ACTION_TEE', 'not' => false, 'or' => false, 'address' => 'ABCDEF0123', 'flags' => 0, 'length' => 0],
            ['type' => 'MATCH_CHARACTERISTICS', 'not' => false, 'or' => false, 'mask' => '8000000000000002'],
            ['type' => 'ACTION_DROP', 'not' => false, 'or' => false],
            ['type' => 'ACTION_ACCEPT', 'not' => false, 'or' => false],
        ],
        'capabilities' => [['id' => 7, 'default' => false, 'rules' => [['type' => 'ACTION_ACCEPT', 'not' => false, 'or' => false]]]],
        'tags' => [['id' => 9, 'default' => null]],
    ];

    $script = FlowRuleDecompiler::decompile($live);

    expect($script)
        ->toContain('macsrc aa:bb:cc:dd:ee:ff')
        ->toContain('not ipdest fd00::1/64')
        ->toContain('icmp 8 -1')
        ->toContain('tee 0 abcdef0123')
        ->toContain('chr inbound,tcp_syn')
        ->toContain('cap cap_7')
        ->toContain('tag tag_9')
        ->toContain('names were generated');

    expect(FlowRuleDecompiler::canonical(FlowRuleCompiler::compile($script)->toNetworkConfig()))
        ->toBe(FlowRuleDecompiler::canonical($live));
});

test('a bare action in the middle of the rules is written so it does not swallow the next rule', function () {
    $live = ['rules' => [
        ['type' => 'ACTION_BREAK'],
        ['type' => 'MATCH_ETHERTYPE', 'etherType' => 0x0800],
        ['type' => 'ACTION_DROP'],
        ['type' => 'ACTION_ACCEPT'],
    ]];

    $script = FlowRuleDecompiler::decompile($live);

    expect($script)->toContain("break and;\n")->toEndWith("accept;\n");
});

test('refuses rules it cannot reproduce exactly', function (array $live, string $message) {
    expect(fn () => FlowRuleDecompiler::decompile($live))
        ->toThrow(FlowRuleDecompileException::class, $message);
})->with([
    'unknown rule type' => [['rules' => [['type' => 'MATCH_INTEGER_RANGE', 'start' => 1, 'end' => 2], ['type' => 'ACTION_ACCEPT']]], 'MATCH_INTEGER_RANGE'],
    'priority action' => [['rules' => [['type' => 'ACTION_PRIORITY', 'qosBucket' => 3]]], 'ACTION_PRIORITY'],
    'unknown field' => [['rules' => [['type' => 'ACTION_TEE', 'address' => 'abcdef0123', 'length' => 0, 'flags' => 4]]], 'flags'],
    'negated action' => [['rules' => [['type' => 'ACTION_DROP', 'not' => true]]], 'not'],
    'dangling match' => [['rules' => [['type' => 'ACTION_ACCEPT'], ['type' => 'MATCH_VLAN_ID', 'vlanId' => 1]]], 'not followed by an action'],
    'out of range port' => [['rules' => [['type' => 'MATCH_IP_DEST_PORT_RANGE', 'start' => 1, 'end' => 70000], ['type' => 'ACTION_ACCEPT']]], 'MATCH_IP_DEST_PORT_RANGE.end'],
    'wrong address family' => [['rules' => [['type' => 'MATCH_IPV4_SOURCE', 'ip' => 'fd00::/8'], ['type' => 'ACTION_ACCEPT']]], 'MATCH_IPV4_SOURCE.ip'],
    'rules not a list' => [['rules' => 'accept'], 'not a list'],
    'duplicate capability ids' => [['rules' => [], 'capabilities' => [['id' => 1, 'rules' => []], ['id' => 1, 'rules' => []]]], 'does not compile'],
]);

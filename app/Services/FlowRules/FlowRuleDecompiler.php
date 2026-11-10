<?php

namespace App\Services\FlowRules;

/**
 * Rebuilds a rules script from a network's compiled rules, so rules set by
 * another tool, or changed outside WireTier, can be adopted and edited here.
 *
 * The controller stores only compiled rules. Capability and tag names (and
 * tag enums and flags) come from WireTier's saved metadata when it has a
 * name for that ID, and are generated (cap_1000, tag_2000) otherwise.
 *
 * Every script is recompiled and compared with the input before it is
 * returned. Anything the rules language cannot express exactly, such as rule
 * types or fields the compiler never emits, raises FlowRuleDecompileException
 * instead of producing a script that would quietly change the rules when it
 * is saved.
 */
final class FlowRuleDecompiler
{
    private const ACTIONS = [
        'ACTION_DROP' => 'drop',
        'ACTION_ACCEPT' => 'accept',
        'ACTION_BREAK' => 'break',
        'ACTION_TEE' => 'tee',
        'ACTION_WATCH' => 'watch',
        'ACTION_REDIRECT' => 'redirect',
    ];

    /** Match type => [keyword, canonical field spec]. */
    private const MATCHES = [
        'MATCH_SOURCE_ZEROTIER_ADDRESS' => ['ztsrc', ['zt' => 'zt']],
        'MATCH_DEST_ZEROTIER_ADDRESS' => ['ztdest', ['zt' => 'zt']],
        'MATCH_VLAN_ID' => ['vlan', ['vlanId' => 'u32']],
        'MATCH_VLAN_PCP' => ['vlanpcp', ['vlanPcp' => 'u32']],
        'MATCH_VLAN_DEI' => ['vlandei', ['vlanDei' => 'u32']],
        'MATCH_ETHERTYPE' => ['ethertype', ['etherType' => 'u32']],
        'MATCH_IP_PROTOCOL' => ['ipprotocol', ['ipProtocol' => 'u32']],
        'MATCH_MAC_SOURCE' => ['macsrc', ['mac' => 'mac']],
        'MATCH_MAC_DEST' => ['macdest', ['mac' => 'mac']],
        'MATCH_IPV4_SOURCE' => ['ipsrc', ['ip' => 'ipv4']],
        'MATCH_IPV4_DEST' => ['ipdest', ['ip' => 'ipv4']],
        'MATCH_IPV6_SOURCE' => ['ipsrc', ['ip' => 'ipv6']],
        'MATCH_IPV6_DEST' => ['ipdest', ['ip' => 'ipv6']],
        'MATCH_IP_TOS' => ['iptos', ['mask' => 'u8', 'start' => 'u8', 'end' => 'u8']],
        'MATCH_ICMP' => ['icmp', ['icmpType' => 'u8', 'icmpCode' => '?u8']],
        'MATCH_IP_SOURCE_PORT_RANGE' => ['sport', ['start' => 'u16', 'end' => 'u16']],
        'MATCH_IP_DEST_PORT_RANGE' => ['dport', ['start' => 'u16', 'end' => 'u16']],
        'MATCH_FRAME_SIZE_RANGE' => ['framesize', ['start' => 'u16', 'end' => 'u16']],
        'MATCH_CHARACTERISTICS' => ['chr', ['mask' => 'mask64']],
        'MATCH_RANDOM' => ['random', ['probability' => 'u32']],
        'MATCH_TAGS_BITWISE_AND' => ['tand', ['id' => 'u32', 'value' => 'u32']],
        'MATCH_TAGS_BITWISE_OR' => ['tor', ['id' => 'u32', 'value' => 'u32']],
        'MATCH_TAGS_BITWISE_XOR' => ['txor', ['id' => 'u32', 'value' => 'u32']],
        'MATCH_TAGS_DIFFERENCE' => ['tdiff', ['id' => 'u32', 'value' => 'u32']],
        'MATCH_TAGS_EQUAL' => ['teq', ['id' => 'u32', 'value' => 'u32']],
        'MATCH_TAG_SENDER' => ['tseq', ['id' => 'u32', 'value' => 'u32']],
        'MATCH_TAG_RECEIVER' => ['treq', ['id' => 'u32', 'value' => 'u32']],
    ];

    /** Names used for IP protocols ("icmp" itself is a reserved word). */
    private const PROTOCOL_NAMES = [
        0x01 => 'icmp4', 0x02 => 'igmp', 0x04 => 'ipip', 0x06 => 'tcp', 0x08 => 'egp',
        0x09 => 'igp', 0x11 => 'udp', 0x1B => 'rdp', 0x32 => 'esp', 0x33 => 'ah',
        0x3A => 'icmp6', 0x73 => 'l2tp', 0x84 => 'sctp', 0x88 => 'udplite',
    ];

    /** Names chosen for each capability and tag ID, plus tag enums/flags. */
    private array $capNames = [];

    private array $tagNames = [];

    private array $tagMeta = [];

    private bool $generatedNames = false;

    /**
     * @param  array  $networkConfig  The controller's network config (rules, capabilities, tags)
     * @param  array  $meta  WireTier's saved rules_meta, used for names when the IDs match
     *
     * @throws FlowRuleDecompileException
     */
    public static function decompile(array $networkConfig, array $meta = []): string
    {
        return (new self)->run($networkConfig, $meta);
    }

    /**
     * The compiled rules in a canonical, comparable form: values normalised,
     * defaults filled in, capabilities and tags keyed by ID. Two configs that
     * canonicalise identically enforce the same policy.
     *
     * @throws FlowRuleDecompileException for anything not expressible as a script
     */
    public static function canonical(array $networkConfig): array
    {
        $rules = self::listOf($networkConfig['rules'] ?? [], 'rules');

        $caps = [];
        foreach (self::listOf($networkConfig['capabilities'] ?? [], 'capabilities') as $cap) {
            $id = self::u32($cap['id'] ?? null, 'capability id');
            $caps[$id] = [
                'default' => (bool) ($cap['default'] ?? false),
                'rules' => array_map(self::canonicalRule(...), self::listOf($cap['rules'] ?? [], 'capability rules')),
            ];
        }
        ksort($caps);

        $tags = [];
        foreach (self::listOf($networkConfig['tags'] ?? [], 'tags') as $tag) {
            $id = self::u32($tag['id'] ?? null, 'tag id');
            $tags[$id] = ['default' => isset($tag['default']) ? self::u32($tag['default'], 'tag default') : null];
        }
        ksort($tags);

        return [
            'rules' => array_map(self::canonicalRule(...), $rules),
            'capabilities' => $caps,
            'tags' => $tags,
        ];
    }

    private function run(array $networkConfig, array $meta): string
    {
        $canonical = self::canonical($networkConfig);

        $this->chooseNames($canonical, $meta);

        $out = [
            '# Rebuilt by WireTier from the rules live on the controller.',
        ];
        if ($this->generatedNames) {
            $out[] = '# Capability and tag names were generated from their IDs; rename them freely.';
        }
        $out[] = '';

        // Definitions in the controller's order, so the recompiled lists match it.
        foreach (self::listOf($networkConfig['tags'] ?? [], 'tags') as $tag) {
            $out[] = $this->renderTag(self::u32($tag['id'], 'tag id'), $canonical['tags']);
            $out[] = '';
        }
        foreach (self::listOf($networkConfig['capabilities'] ?? [], 'capabilities') as $cap) {
            $out[] = $this->renderCap(self::u32($cap['id'], 'capability id'), $canonical['capabilities']);
            $out[] = '';
        }

        $base = $this->renderRules($canonical['rules'], '', true);
        if ($base !== '') {
            $out[] = $base;
        }

        $script = rtrim(implode("\n", $out))."\n";

        $this->verify($script, $canonical);

        return $script;
    }

    // ─── Names ───────────────────────────────────────────────────────────

    private function chooseNames(array $canonical, array $meta): void
    {
        $used = [];

        $savedCaps = [];
        foreach ((array) ($meta['capabilities'] ?? []) as $name => $info) {
            $savedCaps[(int) ($info['id'] ?? -1)] ??= (string) $name;
        }
        $savedTags = [];
        foreach ((array) ($meta['tags'] ?? []) as $name => $info) {
            $savedTags[(int) ($info['id'] ?? -1)] ??= ['name' => (string) $name, 'info' => $info];
        }

        foreach (array_keys($canonical['tags']) as $id) {
            $saved = $savedTags[$id] ?? null;
            $this->tagNames[$id] = $this->pickName($saved['name'] ?? null, "tag_{$id}", $used);
            $this->tagMeta[$id] = $saved ? $this->savedTagValues($saved['info']) : ['enums' => [], 'flags' => []];
        }
        foreach (array_keys($canonical['capabilities']) as $id) {
            $this->capNames[$id] = $this->pickName($savedCaps[$id] ?? null, "cap_{$id}", $used);
        }
    }

    private function pickName(?string $saved, string $generated, array &$used): string
    {
        $name = $saved !== null && self::usableName($saved) && ! isset($used[$saved]) ? $saved : null;

        if ($name === null) {
            $this->generatedNames = true;
            $name = $generated;
            for ($n = 2; isset($used[$name]); $n++) {
                $name = "{$generated}_{$n}";
            }
        }

        $used[$name] = true;

        return $name;
    }

    /** Saved enums and flags for a tag, keeping only ones the script can express. */
    private function savedTagValues(mixed $info): array
    {
        $enums = [];
        foreach ((array) ($info['enums'] ?? []) as $name => $value) {
            if (self::usableName((string) $name) && is_int($value) && $value >= 0 && $value <= 0xFFFFFFFF) {
                $enums[mb_strtolower((string) $name)] = $value;
            }
        }

        $flags = [];
        foreach ((array) ($info['flags'] ?? []) as $name => $mask) {
            if (self::usableName((string) $name) && is_int($mask) && $mask > 0 && $mask <= 0xFFFFFFFF) {
                $flags[mb_strtolower((string) $name)] = $mask;
            }
        }

        return ['enums' => $enums, 'flags' => $flags];
    }

    /** A name the compiler accepts and that can also appear as a match argument. */
    private static function usableName(string $name): bool
    {
        return $name !== ''
            && $name === mb_strtolower($name)
            && ! ctype_digit($name[0])
            && preg_match('/^[0-9_\p{L}]+$/u', $name) === 1
            && ! isset(FlowRuleCompiler::RESERVED_WORDS[$name]);
    }

    // ─── Rendering ───────────────────────────────────────────────────────

    private function renderTag(int $id, array $tags): string
    {
        $lines = ['tag '.$this->tagNames[$id], "\tid {$id}"];

        foreach ($this->tagMeta[$id]['enums'] as $name => $value) {
            $lines[] = "\tenum {$value} {$name}";
        }
        foreach ($this->tagMeta[$id]['flags'] as $name => $mask) {
            $bits = [];
            for ($b = 0; $b < 32; $b++) {
                if ($mask & (1 << $b)) {
                    $bits[] = $b;
                }
            }
            $lines[] = "\tflag ".implode(',', $bits)." {$name}";
        }
        if ($tags[$id]['default'] !== null) {
            $lines[] = "\tdefault {$tags[$id]['default']}";
        }
        $lines[] = ';';

        return implode("\n", $lines);
    }

    private function renderCap(int $id, array $caps): string
    {
        $lines = ['cap '.$this->capNames[$id], "\tid {$id}"];
        if ($caps[$id]['default']) {
            $lines[] = "\tdefault";
        }
        $rules = $this->renderRules($caps[$id]['rules'], "\t", false);
        if ($rules !== '') {
            $lines[] = $rules;
        }
        $lines[] = ';';

        return implode("\n", $lines);
    }

    /**
     * Render a rule list (matches followed by their action) as script text.
     *
     * A bare action written as "accept;" leaves its block open in this
     * language, so it can only end a top-level script. Anywhere else a bare
     * action is written "accept and;" ("and" is a no-op match).
     */
    private function renderRules(array $rules, string $indent, bool $topLevel): string
    {
        $groups = [];
        $matches = [];

        foreach ($rules as $rule) {
            if (str_starts_with($rule['type'], 'MATCH_')) {
                $matches[] = $rule;

                continue;
            }
            $groups[] = [$rule, $matches];
            $matches = [];
        }

        if ($matches !== []) {
            throw new FlowRuleDecompileException('The rules end with matches that are not followed by an action.');
        }

        $out = [];
        $last = count($groups) - 1;

        foreach ($groups as $i => [$action, $groupMatches]) {
            $head = $indent.self::ACTIONS[$action['type']];
            if ($action['type'] === 'ACTION_TEE' || $action['type'] === 'ACTION_WATCH') {
                $head .= " {$action['length']} {$action['address']}";
            } elseif ($action['type'] === 'ACTION_REDIRECT') {
                $head .= " {$action['address']}";
            }

            if ($groupMatches === []) {
                $bare = $head === $indent.self::ACTIONS[$action['type']];
                $out[] = $head.($bare && ! ($topLevel && $i === $last) ? ' and;' : ';');

                continue;
            }

            $lines = [$head];
            foreach ($groupMatches as $k => $match) {
                $prefix = $match['or'] ? 'or ' : ($k > 0 ? 'and ' : '');
                $lines[] = $indent."\t".$prefix.($match['not'] ? 'not ' : '').$this->renderMatch($match);
            }
            $lines[] = $indent.';';
            $out[] = implode("\n", $lines);
        }

        return implode("\n\n", $out);
    }

    private function renderMatch(array $m): string
    {
        [$keyword] = self::MATCHES[$m['type']];

        return $keyword.' '.match ($m['type']) {
            'MATCH_SOURCE_ZEROTIER_ADDRESS', 'MATCH_DEST_ZEROTIER_ADDRESS' => $m['zt'],
            'MATCH_VLAN_ID' => $m['vlanId'],
            'MATCH_VLAN_PCP' => $m['vlanPcp'],
            'MATCH_VLAN_DEI' => $m['vlanDei'],
            'MATCH_ETHERTYPE' => array_search($m['etherType'], FlowRuleCompiler::ETHERTYPES, true) ?: sprintf('0x%04x', $m['etherType']),
            'MATCH_IP_PROTOCOL' => self::PROTOCOL_NAMES[$m['ipProtocol']] ?? $m['ipProtocol'],
            'MATCH_MAC_SOURCE', 'MATCH_MAC_DEST' => $m['mac'],
            'MATCH_IPV4_SOURCE', 'MATCH_IPV4_DEST', 'MATCH_IPV6_SOURCE', 'MATCH_IPV6_DEST' => $m['ip'],
            'MATCH_IP_TOS' => $m['mask'].' '.self::range($m['start'], $m['end']),
            'MATCH_ICMP' => $m['icmpType'].' '.($m['icmpCode'] ?? -1),
            'MATCH_IP_SOURCE_PORT_RANGE', 'MATCH_IP_DEST_PORT_RANGE', 'MATCH_FRAME_SIZE_RANGE' => self::range($m['start'], $m['end']),
            'MATCH_CHARACTERISTICS' => self::characteristics($m['mask']),
            'MATCH_RANDOM' => self::probability($m['probability']),
            default => $this->tagArgs($m['id'], $m['value']),
        };
    }

    private function tagArgs(int $id, int $value): string
    {
        if (! isset($this->tagNames[$id])) {
            return "{$id} {$value}";
        }

        $name = array_search($value, $this->tagMeta[$id]['enums'], true);

        // Flags are looked up before enums, so an enum name that is also a
        // flag name would resolve to the flag; fall back to the number.
        if ($name !== false && ! isset($this->tagMeta[$id]['flags'][$name])) {
            return $this->tagNames[$id].' '.$name;
        }

        return $this->tagNames[$id].' '.$value;
    }

    private static function range(int $start, int $end): string
    {
        return $start === $end ? (string) $start : "{$start}-{$end}";
    }

    /** A 16-hex-digit mask as a comma list of characteristic names and bit numbers. */
    private static function characteristics(string $mask): string
    {
        $names = array_flip(FlowRuleCompiler::CHARACTERISTIC_BITS);
        $hi = hexdec(substr($mask, 0, 8));
        $lo = hexdec(substr($mask, 8, 8));
        $parts = [];

        for ($bit = 63; $bit >= 0; $bit--) {
            $set = $bit >= 32 ? ($hi >> ($bit - 32)) & 1 : ($lo >> $bit) & 1;
            if ($set) {
                $parts[] = $names[$bit] ?? (string) $bit;
            }
        }

        // An empty list (",") compiles to a zero mask; "0" would mean bit 0.
        return $parts === [] ? ',' : implode(',', $parts);
    }

    /** The shortest decimal that the compiler turns back into $probability. */
    private static function probability(int $probability): string
    {
        if ($probability >= 4294967295) {
            return '1';
        }

        $p = ($probability + 0.5) / 4294967295;
        for ($digits = 1; $digits <= 17; $digits++) {
            $s = rtrim(rtrim(sprintf("%.{$digits}F", $p), '0'), '.');
            if ((int) floor(4294967295 * (float) $s) === $probability) {
                return $s;
            }
        }

        throw new FlowRuleDecompileException("Cannot express random probability {$probability} exactly.");
    }

    // ─── Verification ────────────────────────────────────────────────────

    private function verify(string $script, array $canonical): void
    {
        try {
            $compiled = FlowRuleCompiler::compile($script);
        } catch (FlowRuleCompileException $e) {
            throw new FlowRuleDecompileException('The rebuilt script does not compile: '.$e->describe(), 0, $e);
        }

        if (self::canonical($compiled->toNetworkConfig()) !== $canonical) {
            throw new FlowRuleDecompileException('The rules use a combination the rules language cannot reproduce exactly.');
        }
    }

    // ─── Canonical form ──────────────────────────────────────────────────

    private static function canonicalRule(mixed $rule): array
    {
        if (! is_array($rule) || ! is_string($rule['type'] ?? null)) {
            throw new FlowRuleDecompileException('A rule has no type.');
        }

        $type = $rule['type'];
        $isAction = isset(self::ACTIONS[$type]);

        if ($isAction) {
            $spec = match ($type) {
                'ACTION_TEE', 'ACTION_WATCH' => ['address' => 'zt', 'length' => 'length'],
                'ACTION_REDIRECT' => ['address' => 'zt'],
                default => [],
            };
        } elseif (isset(self::MATCHES[$type])) {
            $spec = self::MATCHES[$type][1];
        } else {
            throw new FlowRuleDecompileException("Rule type {$type} has no equivalent in the rules language.");
        }

        $out = ['type' => $type];
        if (! $isAction) {
            $out['not'] = (bool) ($rule['not'] ?? false);
            $out['or'] = (bool) ($rule['or'] ?? false);
        }

        foreach ($spec as $field => $kind) {
            $out[$field] = self::value($rule[$field] ?? null, $kind, "{$type}.{$field}");
        }

        foreach ($rule as $key => $value) {
            if ($key === 'type' || isset($spec[$key])) {
                continue;
            }
            // Fields the controller adds with a value the compiler implies.
            $implied = in_array($key, ['not', 'or'], true) ? (! $isAction || ! $value) : ($key === 'flags' && ! $value);
            if (! $implied) {
                throw new FlowRuleDecompileException("Rule field {$type}.{$key} has no equivalent in the rules language.");
            }
        }

        if (isset($out['start'], $out['end']) && $out['start'] > $out['end']) {
            throw new FlowRuleDecompileException("{$type} has an empty range.");
        }

        return $out;
    }

    private static function value(mixed $v, string $kind, string $what): mixed
    {
        return match ($kind) {
            'u8' => self::uint($v, 0xFF, $what),
            'u16' => self::uint($v, 0xFFFF, $what),
            'u32' => self::u32($v, $what),
            '?u8' => $v === null ? null : self::uint($v, 0xFF, $what),
            'length' => is_int($v) && $v >= -1 && $v <= 0xFFFF ? $v : self::invalid($what),
            'zt' => is_string($v) && preg_match('/^[0-9a-f]{10}$/i', $v) ? strtolower($v) : self::invalid($what),
            'mac' => self::mac($v, $what),
            'ipv4' => self::ip($v, 4, $what),
            'ipv6' => self::ip($v, 6, $what),
            'mask64' => is_string($v) && preg_match('/^[0-9a-f]{1,16}$/i', $v) ? str_pad(strtolower($v), 16, '0', STR_PAD_LEFT) : self::invalid($what),
        };
    }

    private static function u32(mixed $v, string $what): int
    {
        return self::uint($v, 0xFFFFFFFF, $what);
    }

    private static function uint(mixed $v, int $max, string $what): int
    {
        return is_int($v) && $v >= 0 && $v <= $max ? $v : self::invalid($what);
    }

    private static function mac(mixed $v, string $what): string
    {
        $hex = is_string($v) ? preg_replace('/[^0-9a-f]/', '', strtolower($v)) : '';

        return strlen($hex) === 12 ? implode(':', str_split($hex, 2)) : self::invalid($what);
    }

    /** "address/bits", normalised; the family must match the rule type. */
    private static function ip(mixed $v, int $family, string $what): string
    {
        if (! is_string($v) || substr_count($v, '/') !== 1) {
            self::invalid($what);
        }

        [$addr, $bits] = explode('/', $v);
        $packed = @inet_pton($addr);
        $max = $family === 4 ? 32 : 128;

        if ($packed === false || strlen($packed) !== ($family === 4 ? 4 : 16) || ! ctype_digit($bits) || (int) $bits > $max) {
            self::invalid($what);
        }

        return inet_ntop($packed).'/'.(int) $bits;
    }

    private static function listOf(mixed $v, string $what): array
    {
        if (! is_array($v) || ! array_is_list($v)) {
            throw new FlowRuleDecompileException("The controller's {$what} are not a list.");
        }

        return $v;
    }

    private static function invalid(string $what): never
    {
        throw new FlowRuleDecompileException("Rule field {$what} has a value the rules language cannot express.");
    }
}

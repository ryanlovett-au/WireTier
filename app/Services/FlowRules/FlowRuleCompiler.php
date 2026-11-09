<?php

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * PHP port of rule-compiler.js from ZeroTierOne
 * (https://github.com/zerotier/ZeroTierOne/tree/dev/rule-compiler),
 * (c) ZeroTier, Inc. The port follows the original's parsing behaviour
 * exactly — including its quirks — so that a rules script compiles to the
 * same output here as in ZeroTier Central. Deliberate deviations:
 *
 *  - Bit masks (chr, tag flags) use 64-bit arithmetic. The original's 32-bit
 *    signed JS bitwise ops corrupt masks that combine bit 31 with other bits
 *    (e.g. `chr inbound,multicast` loses the inbound bit).
 *  - Malformed input that makes the original throw a TypeError returns a
 *    positioned syntax error instead of "Unexpected exception".
 *  - tee/watch/redirect targets must be 10 hex digits. The original accepts
 *    any 10-character string, which the controller then parses as address 0.
 *  - Macro recursion is bounded, and the controller's array size limits are
 *    enforced so a script is never silently truncated by the controller.
 */

namespace App\Services\FlowRules;

final class FlowRuleCompiler
{
    /** Controller limits from ZeroTierOne.h. */
    public const MAX_RULES = 1024;

    public const MAX_CAPABILITIES = 128;

    public const MAX_CAPABILITY_RULES = 64;

    public const MAX_TAGS = 128;

    private const MAX_MACRO_DEPTH = 32;

    // Names for bits in characteristics -- 0==LSB, 63==MSB
    private const CHARACTERISTIC_BITS = [
        'inbound' => 63,
        'multicast' => 62,
        'broadcast' => 61,
        'ipauth' => 60,
        'macauth' => 59,
        'tcp_fin' => 0,
        'tcp_syn' => 1,
        'tcp_rst' => 2,
        'tcp_psh' => 3,
        'tcp_ack' => 4,
        'tcp_urg' => 5,
        'tcp_ece' => 6,
        'tcp_cwr' => 7,
        'tcp_ns' => 8,
        'tcp_rs2' => 9,
        'tcp_rs1' => 10,
        'tcp_rs0' => 11,
    ];

    // Shorthand names for common ethernet types
    private const ETHERTYPES = [
        'ipv4' => 0x0800,
        'arp' => 0x0806,
        'wol' => 0x0842,
        'rarp' => 0x8035,
        'ipv6' => 0x86DD,
        'atalk' => 0x809B,
        'aarp' => 0x80F3,
        'ipx_a' => 0x8137,
        'ipx_b' => 0x8138,
    ];

    // Shorthand names for common IP protocols
    private const IP_PROTOCOLS = [
        'icmp' => 0x01,
        'icmp4' => 0x01,
        'icmpv4' => 0x01,
        'igmp' => 0x02,
        'ipip' => 0x04,
        'tcp' => 0x06,
        'egp' => 0x08,
        'igp' => 0x09,
        'udp' => 0x11,
        'rdp' => 0x1B,
        'esp' => 0x32,
        'ah' => 0x33,
        'icmp6' => 0x3A,
        'icmpv6' => 0x3A,
        'l2tp' => 0x73,
        'sctp' => 0x84,
        'udplite' => 0x88,
    ];

    // Keywords that open new blocks that must be terminated by a semicolon
    private const OPEN_BLOCK_KEYWORDS = [
        'macro' => true, 'tag' => true, 'cap' => true, 'drop' => true, 'accept' => true,
        'tee' => true, 'watch' => true, 'redirect' => true, 'break' => true, 'priority' => true,
    ];

    // Reserved words that can't be used as tag, capability, or rule set names
    private const RESERVED_WORDS = [
        'macro' => true, 'tag' => true, 'cap' => true, 'default' => true,
        'drop' => true, 'accept' => true, 'tee' => true, 'watch' => true, 'redirect' => true,
        'break' => true, 'priority' => true,
        'ztsrc' => true, 'ztdest' => true, 'vlan' => true, 'vlanpcp' => true, 'vlandei' => true,
        'ethertype' => true, 'macsrc' => true, 'macdest' => true, 'ipsrc' => true, 'ipdest' => true,
        'iptos' => true, 'ipprotocol' => true, 'icmp' => true, 'sport' => true, 'dport' => true,
        'chr' => true, 'framesize' => true, 'random' => true, 'tand' => true, 'tor' => true,
        'txor' => true, 'tdiff' => true, 'teq' => true, 'tseq' => true, 'treq' => true,
        'type' => true, 'enum' => true, 'class' => true, 'define' => true, 'import' => true,
        'include' => true, 'log' => true, 'not' => true, 'xor' => true, 'or' => true,
        'and' => true, 'set' => true, 'var' => true, 'let' => true,
    ];

    private const KEYWORD_TO_API_MAP = [
        'drop' => 'ACTION_DROP',
        'accept' => 'ACTION_ACCEPT',
        'tee' => 'ACTION_TEE',
        'watch' => 'ACTION_WATCH',
        'redirect' => 'ACTION_REDIRECT',
        'break' => 'ACTION_BREAK',
        'priority' => 'ACTION_PRIORITY',

        'ztsrc' => 'MATCH_SOURCE_ZEROTIER_ADDRESS',
        'ztdest' => 'MATCH_DEST_ZEROTIER_ADDRESS',
        'vlan' => 'MATCH_VLAN_ID',
        'vlanpcp' => 'MATCH_VLAN_PCP',
        'vlandei' => 'MATCH_VLAN_DEI',
        'ethertype' => 'MATCH_ETHERTYPE',
        'macsrc' => 'MATCH_MAC_SOURCE',
        'macdest' => 'MATCH_MAC_DEST',
        // ipsrc / ipdest: chosen per address family below
        'iptos' => 'MATCH_IP_TOS',
        'ipprotocol' => 'MATCH_IP_PROTOCOL',
        'icmp' => 'MATCH_ICMP',
        'sport' => 'MATCH_IP_SOURCE_PORT_RANGE',
        'dport' => 'MATCH_IP_DEST_PORT_RANGE',
        'chr' => 'MATCH_CHARACTERISTICS',
        'framesize' => 'MATCH_FRAME_SIZE_RANGE',
        'random' => 'MATCH_RANDOM',
        'tand' => 'MATCH_TAGS_BITWISE_AND',
        'tor' => 'MATCH_TAGS_BITWISE_OR',
        'txor' => 'MATCH_TAGS_BITWISE_XOR',
        'tdiff' => 'MATCH_TAGS_DIFFERENCE',
        'teq' => 'MATCH_TAGS_EQUAL',
        'tseq' => 'MATCH_TAG_SENDER',
        'treq' => 'MATCH_TAG_RECEIVER',
    ];

    // Number of args for each match
    private const MATCH_ARG_COUNTS = [
        'ztsrc' => 1, 'ztdest' => 1, 'vlan' => 1, 'vlanpcp' => 1, 'vlandei' => 1,
        'ethertype' => 1, 'macsrc' => 1, 'macdest' => 1, 'ipsrc' => 1, 'ipdest' => 1,
        'iptos' => 2, 'ipprotocol' => 1, 'icmp' => 2, 'sport' => 1, 'dport' => 1,
        'chr' => 1, 'framesize' => 1, 'random' => 1, 'tand' => 2, 'tor' => 2,
        'txor' => 2, 'tdiff' => 2, 'teq' => 2, 'tseq' => 2, 'treq' => 2,
    ];

    private const IPV6_REGEX = '/(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/';

    private const IPV4_REGEX = '/((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])/';

    /**
     * Compile a rules script.
     *
     * @throws FlowRuleCompileException on any syntax or semantic error
     */
    public static function compile(string $source): CompiledRules
    {
        $tree = self::parse($source);

        // Pass 2: parse tree into capabilities, tags, macros and document-level rules.
        $baseRuleTree = [];
        $macros = [];
        $caps = [];
        $tags = [];

        for ($i = 0; $i < count($tree); $i++) {
            $keyword = self::isToken($tree[$i]) ? mb_strtolower($tree[$i]['t']) : null;

            if ($keyword === 'macro') {
                $macro = self::definitionBlock($tree, $i, 'Macro definition is missing name.');
                $i++;
                $macroName = mb_strtolower($macro[0]['t']);

                $params = [];
                $parenIdx = mb_strpos($macroName, '(');
                if ($parenIdx !== false && $parenIdx > 0) {
                    $pns = preg_split('/[,)]+/', mb_substr($macroName, $parenIdx + 1));
                    foreach ($pns as $k => $pn) {
                        if ($pn !== '') {
                            $params[$pn] = $k;
                        }
                    }
                    $macroName = mb_substr($macroName, 0, $parenIdx);
                }

                if (! self::isValidName($macroName)) {
                    throw self::error($macro[0], 'Invalid macro name.');
                }
                if (isset(self::RESERVED_WORDS[$macroName])) {
                    throw self::error($macro[0], 'Macro name is a reserved word.');
                }
                if (isset($macros[$macroName])) {
                    throw self::error($macro[0], 'Multiple definition of macro name.');
                }

                $macros[$macroName] = ['params' => $params, 'rules' => array_slice($macro, 1)];
            } elseif ($keyword === 'tag') {
                $tag = self::definitionBlock($tree, $i, 'Tag definition is missing name.');
                $i++;
                [$tagName, $definition] = self::parseTag($tag, $tags);
                $tags[$tagName] = $definition;
            } elseif ($keyword === 'cap') {
                $cap = self::definitionBlock($tree, $i, 'Capability definition is missing name.');
                $i++;
                [$capName, $definition] = self::parseCap($cap, $caps);
                $caps[$capName] = $definition;
            } else {
                $baseRuleTree[] = $tree[$i];
            }
        }

        // Pass 3: render low-level ZeroTier rules arrays for capabilities and base.
        foreach ($caps as $capName => $cap) {
            $rendered = [];
            self::renderActions($cap['rules'], $rendered, $macros, $tags, [], 0);
            $caps[$capName]['rules'] = $rendered;

            if (count($rendered) > self::MAX_CAPABILITY_RULES) {
                throw new FlowRuleCompileException("Capability \"{$capName}\" has ".count($rendered).' rules; the controller allows at most '.self::MAX_CAPABILITY_RULES.'.', 0, 0);
            }
        }

        $rules = [];
        self::renderActions($baseRuleTree, $rules, $macros, $tags, [], 0);

        if (count($rules) > self::MAX_RULES) {
            throw new FlowRuleCompileException('The rule set compiles to '.count($rules).' rules; the controller allows at most '.self::MAX_RULES.'.', 0, 0);
        }
        if (count($caps) > self::MAX_CAPABILITIES) {
            throw new FlowRuleCompileException('Too many capabilities; the controller allows at most '.self::MAX_CAPABILITIES.'.', 0, 0);
        }
        if (count($tags) > self::MAX_TAGS) {
            throw new FlowRuleCompileException('Too many tags; the controller allows at most '.self::MAX_TAGS.'.', 0, 0);
        }

        return new CompiledRules($rules, $caps, $tags);
    }

    // ─── Pass 1: tokenizer ───────────────────────────────────────────────

    /**
     * Parse source into a tree. Tokens are ['t' => string, 'l' => line, 'c' => column];
     * a block is a non-empty list of tokens and nested blocks. Blocks open after
     * an OPEN_BLOCK_KEYWORDS token and close at a token ending in ';'.
     */
    private static function parse(string $src): array
    {
        $src = str_replace(["\r\n", "\r"], "\n", $src);

        $stack = [[]];
        $buf = '';
        $tokLine = 0;
        $tokCol = 0;
        $skipRestOfLine = false;
        $line = 1;
        $col = 0;

        $flush = function () use (&$stack, &$buf, &$tokLine, &$tokCol) {
            if ($buf === '') {
                return;
            }

            $endOfBlock = false;
            if (str_ends_with($buf, ';')) {
                $endOfBlock = true;
                $buf = substr($buf, 0, -1);
            }

            $top = count($stack) - 1;
            if ($buf !== '') {
                $stack[$top][] = ['t' => $buf, 'l' => $tokLine, 'c' => $tokCol];
            }

            if ($endOfBlock && count($stack) > 1 && count($stack[$top]) > 0) {
                $block = array_pop($stack);
                $stack[count($stack) - 1][] = $block;
            } elseif (isset(self::OPEN_BLOCK_KEYWORDS[$buf])) {
                $stack[] = [];
            }

            $buf = '';
        };

        foreach (mb_str_split($src) as $ch) {
            $col++;

            if ($skipRestOfLine) {
                if ($ch === "\n") {
                    $skipRestOfLine = false;
                    $line++;
                    $col = 0;
                }

                continue;
            }

            if ($ch === "\n" || $ch === "\t" || $ch === ' ') {
                $flush();
                if ($ch === "\n") {
                    $line++;
                    $col = 0;
                }

                continue;
            }

            if ($buf === '') {
                if ($ch === '#') {
                    $skipRestOfLine = true;

                    continue;
                }
                $tokLine = $line;
                $tokCol = $col;
            }
            $buf .= $ch;
        }

        // Trailing token: strip a final ';' but do not open or close blocks.
        if ($buf !== '') {
            if (str_ends_with($buf, ';')) {
                $buf = substr($buf, 0, -1);
            }
            if ($buf !== '') {
                $stack[count($stack) - 1][] = ['t' => $buf, 'l' => $tokLine, 'c' => $tokCol];
            }
        }

        // Close any unterminated non-empty blocks.
        while (count($stack) > 1 && count($stack[count($stack) - 1]) > 0) {
            $block = array_pop($stack);
            $stack[count($stack) - 1][] = $block;
        }

        return $stack[0];
    }

    // ─── Pass 2: definitions ─────────────────────────────────────────────

    /** The block following a macro/tag/cap keyword, whose first element must be its name token. */
    private static function definitionBlock(array $tree, int $i, string $missingMessage): array
    {
        $next = $tree[$i + 1] ?? null;

        if (! is_array($next) || self::isToken($next) || ! self::isToken($next[0])) {
            throw self::error($tree[$i], $missingMessage);
        }

        return $next;
    }

    /** @return array{0: string, 1: array{id: int, default: ?int, enums: array, flags: array}} */
    private static function parseTag(array $tag, array $tags): array
    {
        $tagName = mb_strtolower($tag[0]['t']);

        if (! self::isValidName($tagName)) {
            throw self::error($tag[0], 'Invalid tag name.');
        }
        if (isset(self::RESERVED_WORDS[$tagName])) {
            throw self::error($tag[0], 'Tag name is a reserved word.');
        }
        if (isset($tags[$tagName])) {
            throw self::error($tag[0], 'Multiple definition of tag name.');
        }

        $flags = [];
        $enums = [];
        $id = -1;
        $dfl = null;
        $count = count($tag);

        for ($k = 1; $k < $count; $k++) {
            if (! self::isToken($tag[$k])) {
                throw self::error($tag[$k], 'Unrecognized keyword in tag definition.');
            }

            $tkeyword = mb_strtolower($tag[$k]['t']);

            if ($tkeyword === 'id') {
                if ($id >= 0) {
                    throw self::error($tag[$k], 'Duplicate tag id definition.');
                }
                if ($k + 1 >= $count) {
                    throw self::error($tag[$k], 'Missing numeric value for ID.');
                }
                $id = self::parseNum(self::text($tag[++$k]));
                if ($id < 0 || $id > 0xFFFFFFFF) {
                    throw self::error($tag[$k], 'Invalid or out of range tag ID.');
                }
            } elseif ($tkeyword === 'default') {
                if ($dfl !== null) {
                    throw self::error($tag[$k], 'Duplicate tag default directive.');
                }
                if ($k + 1 >= $count || ! self::isToken($tag[$k + 1])) {
                    throw self::error($tag[$k], 'Missing value for default.');
                }
                $dfl = $tag[++$k]['t'];
            } elseif ($tkeyword === 'flag') {
                if ($k + 2 >= $count) {
                    throw self::error($tag[$k], 'Missing tag flag name or bit index.');
                }
                $k++;
                $mask = 0;
                foreach (preg_split('/[,]+/', self::text($tag[$k])) as $bit) {
                    $b = mb_strtolower($bit);
                    if (isset($flags[$b])) {
                        $mask |= $flags[$b];
                    } else {
                        $b = self::parseNum($b);
                        if ($b < 0 || $b > 31) {
                            throw self::error($tag[$k], 'Bit index invalid, out of range, or references an undefined flag name.');
                        }
                        $mask |= 1 << $b;
                    }
                }
                $flagName = mb_strtolower(self::text($tag[++$k]));
                if (! self::isValidName($flagName)) {
                    throw self::error($tag[$k], 'Invalid or reserved flag name.');
                }
                if (isset($flags[$flagName])) {
                    throw self::error($tag[$k], 'Duplicate flag name in tag definition.');
                }
                $flags[$flagName] = $mask;
            } elseif ($tkeyword === 'enum') {
                if ($k + 2 >= $count) {
                    throw self::error($tag[$k], 'Missing tag enum name or value.');
                }
                $k++;
                $value = self::parseNum(self::text($tag[$k]));
                if ($value < 0 || $value > 0xFFFFFFFF) {
                    throw self::error($tag[$k], 'Tag enum value invalid or out of range.');
                }
                $enumName = mb_strtolower(self::text($tag[++$k]));
                if (! self::isValidName($enumName)) {
                    throw self::error($tag[$k], 'Invalid or reserved tag enum name.');
                }
                if (isset($enums[$enumName])) {
                    throw self::error($tag[$k], 'Duplicate enum name in tag definition.');
                }
                $enums[$enumName] = $value;
            } else {
                throw self::error($tag[$k], 'Unrecognized keyword in tag definition.');
            }
        }

        if ($id < 0) {
            throw self::error($tag[0], 'Tag definition is missing a numeric ID.');
        }

        // The default may name an enum or flag (case-sensitively, as in the
        // original), or be a number.
        if (is_string($dfl)) {
            if (array_key_exists($dfl, $enums)) {
                $dfl = $enums[$dfl];
            } elseif (array_key_exists($dfl, $flags)) {
                $dfl = $flags[$dfl];
            } else {
                $dfl = abs(self::parseIntLoose($dfl)) & 0xFFFFFFFF;
            }
        }

        return [$tagName, ['id' => $id, 'default' => $dfl, 'enums' => $enums, 'flags' => $flags]];
    }

    /** @return array{0: string, 1: array{id: int, default: bool, rules: array}} */
    private static function parseCap(array $cap, array $caps): array
    {
        $capName = mb_strtolower($cap[0]['t']);

        if (! self::isValidName($capName)) {
            throw self::error($cap[0], 'Invalid capability name.');
        }
        if (isset(self::RESERVED_WORDS[$capName])) {
            throw self::error($cap[0], 'Capability name is a reserved word.');
        }
        if (isset($caps[$capName])) {
            throw self::error($cap[0], 'Multiple definition of capability name.');
        }

        $capRules = [];
        $id = -1;
        $dfl = false;
        $count = count($cap);

        for ($k = 1; $k < $count; $k++) {
            $dn = self::isToken($cap[$k]) ? mb_strtolower($cap[$k]['t']) : null;

            if ($dn === 'id') {
                if ($id >= 0) {
                    throw self::error($cap[$k], 'Duplicate id directive in capability definition.');
                }
                if ($k + 1 >= $count) {
                    throw self::error($cap[$k], 'Missing value for ID.');
                }
                $id = self::parseNum(self::text($cap[++$k]));
                if ($id < 0 || $id > 0xFFFFFFFF) {
                    throw self::error($cap[$k - 1], 'Invalid or out of range capability ID.');
                }
                foreach ($caps as $other) {
                    if ($other['id'] === $id) {
                        throw self::error($cap[$k - 1], 'Duplicate capability ID.');
                    }
                }
            } elseif ($dn === 'default') {
                $dfl = true;
            } else {
                $capRules[] = $cap[$k];
            }
        }

        if ($id < 0) {
            throw self::error($cap[0], 'Capability definition is missing a numeric ID.');
        }

        return [$capName, ['id' => $id, 'default' => $dfl, 'rules' => $capRules]];
    }

    // ─── Pass 3: rendering ───────────────────────────────────────────────

    private static function renderActions(array $rtree, array &$rules, array $macros, array $tags, array $params, int $depth): void
    {
        if ($depth > self::MAX_MACRO_DEPTH) {
            throw self::error($rtree[0] ?? null, 'Macros are nested too deeply (recursive include?).');
        }

        $count = count($rtree);

        for ($k = 0; $k < $count; $k++) {
            $action = self::isToken($rtree[$k]) ? mb_strtolower($rtree[$k]['t']) : '';

            if ($action === '') {
                continue;
            }

            if ($action === 'include') {
                if ($k + 1 >= $count || ! self::isToken($rtree[$k + 1])) {
                    throw self::error($rtree[$k], 'Include directive is missing a macro name.');
                }
                $macroName = $rtree[++$k]['t'];

                $macroParamArray = [];
                $parenIdx = mb_strpos($macroName, '(');
                if ($parenIdx !== false && $parenIdx > 0) {
                    foreach (preg_split('/[,)]+/', mb_substr($macroName, $parenIdx + 1)) as $pn) {
                        if ($pn !== '') {
                            $macroParamArray[] = $pn;
                        }
                    }
                    $macroName = mb_substr($macroName, 0, $parenIdx);
                }

                $macro = $macros[$macroName] ?? null;
                if (! $macro) {
                    throw self::error($rtree[$k], 'Macro name not found.');
                }

                $macroParams = [];
                foreach ($macro['params'] as $param => $pidx) {
                    if ($pidx >= count($macroParamArray)) {
                        throw self::error($rtree[$k], 'Missing one or more required macro parameter.');
                    }
                    $macroParams[$param] = $macroParamArray[$pidx];
                }

                self::renderActions($macro['rules'], $rules, $macros, $tags, $macroParams, $depth + 1);
            } elseif ($action === 'drop' || $action === 'accept' || $action === 'break') {
                // Actions without arguments
                if ($k + 1 < $count && self::isBlock($rtree[$k + 1])) {
                    self::renderMatches($rtree[++$k], $rules, $tags, $params);
                }
                $rules[] = ['type' => self::KEYWORD_TO_API_MAP[$action]];
            } elseif ($action === 'tee' || $action === 'watch') {
                // Actions with arguments (max length, ZeroTier address)
                if (! ($k + 1 < $count && self::isBlock($rtree[$k + 1]))) {
                    throw self::error($rtree[$k], 'The tee and watch actions require two paremters (max length or 0 for all, target).');
                }
                $mtree = $rtree[++$k];
                if (count($mtree) < 2) {
                    throw self::error($mtree[0], 'The tee and watch actions require two paremters (max length or 0 for all, target).');
                }
                $maxLength = self::parseNum(self::text($mtree[0]));
                if ($maxLength < -1 || $maxLength > 0xFFFF) {
                    throw self::error($mtree[0], 'Tee/watch max packet length to forward invalid or out of range.');
                }
                $target = self::text($mtree[1]);
                if (strlen($target) !== 10 || ! ctype_xdigit($target)) {
                    throw self::error($mtree[1], 'Missing or invalid ZeroTier address target for tee/watch.');
                }
                self::renderMatches(array_slice($mtree, 2), $rules, $tags, $params);
                $rules[] = ['type' => self::KEYWORD_TO_API_MAP[$action], 'address' => $target, 'length' => $maxLength];
            } elseif ($action === 'redirect') {
                if (! ($k + 1 < $count && self::isBlock($rtree[$k + 1]))) {
                    throw self::error($rtree[$k], 'The redirect action requires a target parameter.');
                }
                $mtree = $rtree[++$k];
                $target = self::text($mtree[0]);
                if (strlen($target) !== 10 || ! ctype_xdigit($target)) {
                    throw self::error($mtree[0], 'Missing or invalid ZeroTier address target for redirect.');
                }
                self::renderMatches(array_slice($mtree, 1), $rules, $tags, $params);
                $rules[] = ['type' => self::KEYWORD_TO_API_MAP[$action], 'address' => $target];
            } else {
                throw self::error($rtree[$k], 'Unrecognized action or directive in rule set.');
            }
        }
    }

    private static function renderMatches(array $mtree, array &$rules, array $tags, array $params): void
    {
        $not = false;
        $or = false;
        $count = count($mtree);

        for ($k = 0; $k < $count; $k++) {
            $match = self::isToken($mtree[$k]) ? mb_strtolower($mtree[$k]['t']) : '';

            if ($match === '' || $match === 'and') {
                // AND is the default
                continue;
            }
            if ($match === 'not') {
                $not = true;

                continue;
            }
            if ($match === 'or') {
                $or = true;

                continue;
            }

            $argCount = self::MATCH_ARG_COUNTS[$match] ?? 0;
            if (! $argCount) {
                throw self::error($mtree[$k], 'Unrecognized match type "'.$match.'".');
            }

            // Each arg: [value, position-token]
            $args = [];
            for ($i = 0; $i < $argCount; $i++) {
                if (++$k >= $count) {
                    throw self::error($mtree[$k - 1], 'Missing argument(s) to match.');
                }
                $node = $mtree[$k];
                if (! self::isToken($node) || isset(self::RESERVED_WORDS[$node['t']])) {
                    throw self::error($mtree[$k - 1], 'Missing argument(s) to match (invalid argument or argument is reserved word).');
                }
                if (str_starts_with($node['t'], '$')) {
                    if (! array_key_exists($node['t'], $params)) {
                        throw self::error($node, 'Undefined variable name.');
                    }
                    $args[] = [$params[$node['t']], $node];
                } else {
                    $args[] = [$node['t'], $node];
                }
            }

            $base = ['type' => self::KEYWORD_TO_API_MAP[$match] ?? null, 'not' => $not, 'or' => $or];

            switch ($match) {
                case 'ztsrc':
                case 'ztdest':
                    $zt = self::cleanHex($args[0][0]);
                    if (strlen($zt) !== 10) {
                        throw self::error($args[0][1], 'Invalid ZeroTier address.');
                    }
                    $rules[] = $base + ['zt' => $zt];
                    break;

                case 'vlan':
                case 'vlanpcp':
                case 'vlandei':
                case 'ethertype':
                case 'ipprotocol':
                    $num = match ($match) {
                        'ethertype' => self::ETHERTYPES[$args[0][0]] ?? null,
                        'ipprotocol' => self::IP_PROTOCOLS[$args[0][0]] ?? null,
                        default => null,
                    };
                    $num ??= self::parseNum($args[0][0]);
                    if ($num < 0 || $num > 0xFFFFFFFF) {
                        throw self::error($args[0][1], 'Invalid numeric value.');
                    }
                    $field = ['vlan' => 'vlanId', 'vlanpcp' => 'vlanPcp', 'vlandei' => 'vlanDei', 'ethertype' => 'etherType', 'ipprotocol' => 'ipProtocol'][$match];
                    $rules[] = $base + [$field => $num];
                    break;

                case 'random':
                    $num = self::parseFloatLoose($args[0][0]);
                    $num = max(0.0, min(1.0, $num));
                    $rules[] = $base + ['probability' => (int) floor(4294967295 * $num)];
                    break;

                case 'macsrc':
                case 'macdest':
                    $mac = self::cleanMac($args[0][0]);
                    if (strlen($mac) !== 17) {
                        throw self::error($args[0][1], 'Invalid MAC address.');
                    }
                    $rules[] = $base + ['mac' => $mac];
                    break;

                case 'ipsrc':
                case 'ipdest':
                    $ip = $args[0][0];
                    $slashIdx = strpos($ip, '/');
                    if ($slashIdx === false || $slashIdx <= 0) {
                        throw self::error($args[0][1], 'Missing /bits netmask length designation in IP.');
                    }
                    $ipOnly = substr($ip, 0, $slashIdx);
                    if (preg_match(self::IPV6_REGEX, $ipOnly)) {
                        $type = $match === 'ipsrc' ? 'MATCH_IPV6_SOURCE' : 'MATCH_IPV6_DEST';
                    } elseif (preg_match(self::IPV4_REGEX, $ipOnly)) {
                        $type = $match === 'ipsrc' ? 'MATCH_IPV4_SOURCE' : 'MATCH_IPV4_DEST';
                    } else {
                        throw self::error($args[0][1], 'Invalid IP address (not valid IPv4 or IPv6).');
                    }
                    $rules[] = ['type' => $type, 'not' => $not, 'or' => $or, 'ip' => $ip];
                    break;

                case 'icmp':
                    $icmpType = self::parseNum($args[0][0]);
                    if ($icmpType < 0 || $icmpType > 0xFF) {
                        throw self::error($args[0][1], 'Missing or invalid ICMP type.');
                    }
                    $icmpCode = self::parseNum($args[1][0]); // -1 okay, indicates don't match code
                    if ($icmpCode > 0xFF) {
                        throw self::error($args[1][1], 'Invalid ICMP code (use -1 for none).');
                    }
                    $rules[] = $base + ['icmpType' => $icmpType, 'icmpCode' => $icmpCode < 0 ? null : $icmpCode];
                    break;

                case 'sport':
                case 'dport':
                case 'framesize':
                    [$fn, $tn] = self::parseRange($args[0], 'Invalid numeric range.');
                    if ($fn < 0 || $fn > 0xFFFF || $tn < 0 || $tn > 0xFFFF || $tn < $fn) {
                        throw self::error($args[0][1], 'Invalid numeric range.');
                    }
                    $rules[] = $base + ['start' => $fn, 'end' => $tn];
                    break;

                case 'iptos':
                    $mask = self::parseNum($args[0][0]);
                    if ($mask < 0 || $mask > 0xFF) {
                        throw self::error($args[0][1], 'Invalid mask.');
                    }
                    [$fn, $tn] = self::parseRange($args[1], 'Invalid value range.');
                    if ($fn < 0 || $fn > 0xFF || $tn < 0 || $tn > 0xFF || $tn < $fn) {
                        throw self::error($args[1][1], 'Invalid value range.');
                    }
                    $rules[] = $base + ['mask' => $mask, 'start' => $fn, 'end' => $tn];
                    break;

                case 'chr':
                    $mask = 0;
                    foreach (preg_split('/[,]+/', $args[0][0]) as $name) {
                        if ($name === '') {
                            continue;
                        }
                        $bit = self::CHARACTERISTIC_BITS[$name] ?? self::parseNum($name);
                        if ($bit < 0 || $bit > 63) {
                            throw self::error($args[0][1], 'Invalid bit index (range 0-63) or unrecognized name.');
                        }
                        $mask |= 1 << $bit;
                    }
                    // 16 hex digits; sprintf %x treats the int as unsigned.
                    $rules[] = $base + ['mask' => sprintf('%016x', $mask)];
                    break;

                default: // tand, tor, txor, tdiff, teq, tseq, treq
                    $tag = $tags[$args[0][0]] ?? null;
                    if ($tag) {
                        $tagId = $tag['id'];
                        $tagValue = $args[1][0];
                        if (array_key_exists($tagValue, $tag['flags'])) {
                            $tagValue = $tag['flags'][$tagValue];
                        } elseif (array_key_exists($tagValue, $tag['enums'])) {
                            $tagValue = $tag['enums'][$tagValue];
                        } else {
                            $tagValue = self::parseNum($tagValue);
                        }
                    } else {
                        $tagId = self::parseNum($args[0][0]);
                        $tagValue = self::parseNum($args[1][0]);
                    }
                    if ($tagId < 0 || $tagId > 0xFFFFFFFF) {
                        throw self::error($args[0][1], 'Undefined tag name and invalid tag value.');
                    }
                    if ($tagValue < 0 || $tagValue > 0xFFFFFFFF) {
                        throw self::error($args[1][1], 'Invalid tag value or unrecognized flag/enum name.');
                    }
                    $rules[] = $base + ['id' => $tagId, 'value' => $tagValue];
                    break;
            }

            $not = false;
            $or = false;
        }
    }

    // ─── Helpers ─────────────────────────────────────────────────────────

    private static function isToken(mixed $node): bool
    {
        return is_array($node) && isset($node['t']);
    }

    private static function isBlock(mixed $node): bool
    {
        return is_array($node) && ! isset($node['t']) && $node !== [];
    }

    /** A node's text, or '' for a block (the original would coerce/throw). */
    private static function text(mixed $node): string
    {
        return self::isToken($node) ? $node['t'] : '';
    }

    private static function error(mixed $node, string $message): FlowRuleCompileException
    {
        // Blocks carry no position of their own; use their first token's.
        while (is_array($node) && ! isset($node['t']) && $node !== []) {
            $node = $node[0];
        }

        return new FlowRuleCompileException($message, $node['l'] ?? 0, $node['c'] ?? 0);
    }

    /** Checks whether something is a valid capability, tag, macro, flag or enum name. */
    private static function isValidName(string $n): bool
    {
        return $n !== '' && ! ctype_digit($n[0]) && preg_match('/^[0-9_\p{L}]+$/u', $n) === 1;
    }

    /**
     * Mirrors the original _parseNum(): "0x"-prefixed hex or decimal, parsed
     * from the leading digits like JS parseInt(); -1 when unparseable.
     */
    private static function parseNum(string $n): int
    {
        if ($n === '') {
            return -1;
        }

        $n = strtolower($n);

        if (strlen($n) > 2 && str_starts_with($n, '0x')) {
            if (! preg_match('/^[+-]?[0-9a-f]+/', substr($n, 2), $m)) {
                return -1;
            }

            return self::boundedInt($m[0], 16);
        }

        if (! preg_match('/^[+-]?[0-9]+/', $n, $m)) {
            return -1;
        }

        return self::boundedInt($m[0], 10);
    }

    /** JS parseInt(s) without a radix: auto-detects a 0x prefix; 0 when unparseable. */
    private static function parseIntLoose(string $s): int
    {
        $s = strtolower(trim($s));

        if (preg_match('/^([+-]?)0x([0-9a-f]+)/', $s, $m)) {
            return self::boundedInt($m[1].$m[2], 16);
        }

        return preg_match('/^[+-]?[0-9]+/', $s, $m) ? self::boundedInt($m[0], 10) : 0;
    }

    /** JS parseFloat(s) || 0. */
    private static function parseFloatLoose(string $s): float
    {
        return preg_match('/^[+-]?(\d+\.?\d*|\.\d+)(e[+-]?\d+)?/i', trim($s), $m) ? (float) $m[0] : 0.0;
    }

    /**
     * Parse signed digits, saturating values too large for 32 bits (which
     * every caller rejects as out of range) instead of overflowing.
     */
    private static function boundedInt(string $digits, int $base): int
    {
        $sign = 1;
        if ($digits[0] === '-' || $digits[0] === '+') {
            $sign = $digits[0] === '-' ? -1 : 1;
            $digits = substr($digits, 1);
        }

        $digits = ltrim($digits, '0');
        if ($digits === '') {
            return 0;
        }
        if (strlen($digits) > ($base === 16 ? 12 : 15)) {
            return $sign * PHP_INT_MAX;
        }

        return $sign * intval($digits, $base);
    }

    /** @return array{0: int, 1: int} [from, to] from "N" or "N-M" */
    private static function parseRange(array $arg, string $message): array
    {
        $value = $arg[0];
        $dash = strpos($value, '-');

        if ($dash !== false && $dash > 0) {
            $parts = explode('-', $value);
            if (count($parts) !== 2) {
                throw self::error($arg[1], $message);
            }

            return [self::parseNum($parts[0]), self::parseNum($parts[1])];
        }

        $n = self::parseNum($value);

        return [$n, $n];
    }

    private static function cleanMac(string $m): string
    {
        $out = '';
        $charCount = 0;

        foreach (str_split(strtolower($m)) as $c) {
            if (strlen($out) >= 17) {
                break;
            }
            if (ctype_xdigit($c)) {
                $out .= $c;
                $charCount++;
                if (strlen($out) !== 17 && $charCount >= 2) {
                    $out .= ':';
                    $charCount = 0;
                }
            }
        }

        return $out;
    }

    private static function cleanHex(string $m): string
    {
        return preg_replace('/[^0-9a-f]/', '', strtolower($m));
    }
}

<?php

namespace App\Services\FlowRules;

/**
 * The output of FlowRuleCompiler: the controller payload plus the names the
 * controller does not store (capability/tag names, tag enums and flags).
 */
final class CompiledRules
{
    /**
     * @param  list<array<string, mixed>>  $rules  Base rule set, in controller JSON form
     * @param  array<string, array{id: int, default: bool, rules: list<array<string, mixed>>}>  $capabilities  Keyed by name
     * @param  array<string, array{id: int, default: ?int, enums: array<string, int>, flags: array<string, int>}>  $tags  Keyed by name
     */
    public function __construct(
        public readonly array $rules,
        public readonly array $capabilities,
        public readonly array $tags,
    ) {}

    /**
     * The fields to POST to /controller/network/{id}. Always includes all
     * three keys so an emptied script also clears capabilities and tags.
     *
     * @return array{rules: list<array>, capabilities: list<array>, tags: list<array>}
     */
    public function toNetworkConfig(): array
    {
        return [
            'rules' => $this->rules,
            'capabilities' => array_values(array_map(fn ($c) => [
                'id' => $c['id'],
                'default' => $c['default'],
                'rules' => $c['rules'],
            ], $this->capabilities)),
            'tags' => array_values(array_map(fn ($t) => [
                'id' => $t['id'],
                'default' => $t['default'],
            ], $this->tags)),
        ];
    }

    /**
     * Name metadata for the UI (member capability/tag pickers).
     *
     * @return array{capabilities: array<string, array{id: int, default: bool}>, tags: array<string, array{id: int, default: ?int, enums: array<string, int>, flags: array<string, int>}>}
     */
    public function metadata(): array
    {
        return [
            'capabilities' => array_map(fn ($c) => ['id' => $c['id'], 'default' => $c['default']], $this->capabilities),
            'tags' => $this->tags,
        ];
    }
}

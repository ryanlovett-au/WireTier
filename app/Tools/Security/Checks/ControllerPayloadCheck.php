<?php

namespace App\Tools\Security\Checks;

use App\Tools\Security\Analysis\LivewireSurface;
use App\Tools\Security\Analysis\Lookups;
use App\Tools\Security\Analysis\PhpMethod;
use App\Tools\Security\Analysis\PhpSource;
use App\Tools\Security\Analysis\Taint;
use App\Tools\Security\AuditReport;

/**
 * Client-controlled data written to a ZeroTier controller without validation.
 *
 * ControllerApiInputCheck asks *which* network a call targets; this asks
 * *what* it sends. A public Livewire property is whatever the browser last
 * sent - a string where an array was expected, an array of objects where IP
 * strings were expected - so every client-writable property that reaches the
 * config payload of a controller write must be checked by a validate() call
 * in the method (or a component helper it calls). Properties typed bool, int
 * or float are exempt: Livewire coerces updates to the declared type.
 */
final class ControllerPayloadCheck
{
    public const CATEGORY = 'Controller Payload Validation';

    /** Controller writes, and the 0-based position of their config argument. */
    public const WRITES = [
        'createNetwork' => 0,
        'updateNetwork' => 1,
        'updateNetworkMember' => 2,
    ];

    private const SCALAR_TYPES = ['bool', 'boolean', 'int', 'integer', 'float', 'double'];

    /** @return list<array<string, mixed>> */
    public function check(PhpSource $source): array
    {
        if (! $source->isLivewire()) {
            return [];
        }

        $surface = new LivewireSurface($source);
        $types = array_column($source->properties(), 'type', 'name');
        $props = array_keys(array_filter(
            $surface->clientWritableProperties(),
            fn ($line, $name) => ! in_array(strtolower((string) ($types[$name] ?? '')), self::SCALAR_TYPES, true),
            ARRAY_FILTER_USE_BOTH,
        ));
        if ($props === []) {
            return [];
        }

        $sink = '/->('.implode('|', array_keys(self::WRITES)).')\s*\(/';
        $findings = [];

        foreach ($source->methods() as $method) {
            $statements = $method->statements();
            $validated = $this->validatedKeys($source, $method);

            foreach ($statements as $st) {
                if (! preg_match_all($sink, $st['text'], $m, PREG_OFFSET_CAPTURE)) {
                    continue;
                }
                foreach ($m[1] as [$call, $offset]) {
                    $args = Lookups::argSpan($st['text'], $offset);
                    $payload = $args === null ? null : (Lookups::splitArgs($args)[self::WRITES[$call]] ?? null);
                    if ($payload === null) {
                        continue;
                    }

                    foreach ($props as $prop) {
                        if (in_array($prop, $validated, true) || ! $this->flowsInto($prop, $statements, $payload)) {
                            continue;
                        }

                        $findings[] = AuditReport::finding(
                            'medium',
                            self::CATEGORY,
                            $source->path,
                            $st['line'],
                            "Client-writable \$this->{$prop} reaches the {$call}() payload in {$method->name}() without validation",
                            "Validate it before the call, e.g. \$this->validate(['{$prop}' => ...]) with rules for its expected shape",
                        );
                    }
                }
            }
        }

        return $findings;
    }

    /**
     * Does $prop reach the payload expression, directly or through locals
     * assigned from it earlier in the method?
     *
     * @param  list<array{text: string, line: int}>  $statements
     */
    private function flowsInto(string $prop, array $statements, string $payload): bool
    {
        $taint = new Taint([$prop]);
        $taint->propagate($statements);

        return $taint->touches($payload);
    }

    /**
     * Property names covered by validate()/validateOnly() keys in the method
     * or in a component helper it calls (`'edit_routes.*.target'` covers
     * `edit_routes`).
     *
     * @return list<string>
     */
    private function validatedKeys(PhpSource $source, PhpMethod $method): array
    {
        $bodies = [$method->body];
        if (preg_match_all('/\$this->(\w+)\s*\(/', $method->body, $calls)) {
            foreach ($calls[1] as $name) {
                $helper = $source->method($name);
                if ($helper !== null && $helper !== $method) {
                    $bodies[] = $helper->body;
                }
            }
        }

        $keys = [];
        foreach ($bodies as $body) {
            if (! preg_match_all('/->validate(?:Only)?\s*\(/', $body, $v, PREG_OFFSET_CAPTURE)) {
                continue;
            }
            foreach ($v[0] as [, $offset]) {
                $args = Lookups::argSpan($body, $offset) ?? '';
                if (preg_match_all('/[\'"](\w+)(?:\.[^\'"]*)?[\'"]\s*=>/', $args, $k)) {
                    array_push($keys, ...$k[1]);
                }
            }
        }

        return array_values(array_unique($keys));
    }
}

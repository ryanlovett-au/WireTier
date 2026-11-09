<?php

namespace App\Tools\Security\Checks;

use App\Tools\Security\AuditReport;

/**
 * Blade output inside an attribute that Alpine or Livewire evaluates as
 * JavaScript (x-data, x-init, @click, :class, wire:click, …).
 *
 * `{{ }}` HTML-escapes, turning `'` into `&#039;`, but the browser decodes
 * entities in attribute values before Alpine/Livewire read them, so
 * `wire:click="open('{{ $name }}')"` with a name containing `'` breaks out
 * of the string and runs script. Values from the agent (restic snapshot ids,
 * file names, unit names, log text) are the realistic source: a compromised
 * server can then run script in an operator's browser. `@js()` /
 * `Js::from()` encode for this context.
 *
 * Safe without encoding: numbers, model keys (`->id`, `->uuid`), loop
 * counters, and values already JSON/JS-encoded.
 */
final class JsAttributeEchoCheck
{
    public const CATEGORY = 'Alpine/Livewire JS Injection';

    /** Directives whose value is a name or string, not a JS expression. */
    private const NOT_JS = ['wire:model', 'wire:key', 'wire:loading', 'wire:target', 'wire:ignore', 'wire:navigate', 'wire:dirty', 'wire:offline', 'wire:replace', 'wire:stream', 'wire:transition', 'wire:cloak', 'wire:confirm', 'wire:current', 'wire:ref', 'wire:id', 'wire:name', 'wire:snapshot', 'wire:effects', 'wire:island', 'wire:sort', 'x-ref', 'x-transition', 'x-cloak', 'x-ignore', 'x-teleport', 'x-id'];

    /** @return list<array<string, mixed>> */
    public function check(string $file, string $content): array
    {
        if (! str_ends_with($file, '.blade.php')) {
            return [];
        }

        $findings = [];
        // Double-quoted attribute values (Blade inside them can't contain a
        // bare `"` without ending the attribute, so this split is safe).
        $re = '/(?<=[\s<])((?:x-[\w:.-]+|@[\w:.-]+|:[\w.-]+|wire:[\w.-]+))\s*=\s*"([^"]*)"/';
        if (! preg_match_all($re, $content, $m, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
            return [];
        }

        foreach ($m as $attr) {
            [$name, $offset] = $attr[1];
            $value = $attr[2][0];
            $base = preg_replace('/[.:].*$/', '', preg_replace('/^(wire:\w+).*$/', '$1', $name));
            if (in_array($base, self::NOT_JS, true) || in_array(preg_replace('/\..*$/', '', $name), self::NOT_JS, true)) {
                continue;
            }
            // `:href`, `:src`, `:id` etc. take a JS expression too, so all
            // `:attr` bindings count; plain HTML attributes never match the regex.

            foreach (['{!!' => '!!}', '{{' => '}}'] as $open => $close) {
                $pos = 0;
                while (($start = strpos($value, $open, $pos)) !== false) {
                    $end = strpos($value, $close, $start + strlen($open));
                    if ($end === false) {
                        break;
                    }
                    $expr = trim(substr($value, $start + strlen($open), $end - $start - strlen($open)));
                    $pos = $end + strlen($close);
                    if ($open === '{{' && $this->safe($expr)) {
                        continue;
                    }
                    $line = substr_count(substr($content, 0, $offset), "\n") + 1;
                    $severity = match (true) {
                        $open === '{!!' => 'high',
                        // Usually a database key, but agent-reported ids
                        // (restic snapshot ids) look the same: confirm.
                        (bool) preg_match('/\[[\'"]\w*id[\'"]\]\s*$|->\w+_id\s*$/', $expr) => 'low',
                        default => 'medium',
                    };
                    $findings[] = AuditReport::finding(
                        $severity,
                        self::CATEGORY,
                        $file,
                        $line,
                        sprintf('%s %s %s %s inside %s: entities are decoded before Alpine/Livewire evaluates it, so a quote in the value runs as script', $open, $this->short($expr), $close, $open === '{!!' ? '(unescaped)' : '', $name),
                        'Pass the value with @js($value) / Js::from($value) instead of {{ }} inside the JS expression',
                    );
                }
            }
        }

        return $findings;
    }

    /** Values that can't carry a quote. */
    private function safe(string $expr): bool
    {
        $expr = trim($expr);

        return (bool) preg_match('/^(?:
              -?\d+(?:\.\d+)?                                   # number literal
            | \(\s*(?:int|float|bool)\s*\).+                    # cast
            | (?:intval|count|json_encode|route|asset|\\\\?Js::from|\\\\?Illuminate\\\\Support\\\\Js::from)\s*\(.+
            | \$loop->(?:index|iteration|remaining|count|depth)
            | \$[\w>\-\[\]\'"]*->(?:id|uuid|getKey\(\))      # model key
            | \$[\w]*(?:Id|_id)                                 # a local or param that is an id (scalar)
            | \$this->\w*(?:Id|_id)                             # an id property
            | \$\w+->(?:id|uuid)\s*\?\?\s*[\'"]{0,1}[\w-]*[\'"]{0,1}
            | \$\w+\s*\?\s*[\'"]\w*[\'"]\s*:\s*[\'"]\w*[\'"]   # $x ? \'a\' : \'b\'
            | \$\w+->(?:count\(\)|timestamp|getTimestamp\(\))
            | __\(\s*\'[^\'$]*\'\s*\)                           # a translation literal
            | \$[\w>-]+\s*\?\s*\'[^\']*\'\s*:\s*\'[^\']*\'      # ternary of two literals
        )$/x', $expr);
    }

    private function short(string $expr): string
    {
        return strlen($expr) > 60 ? substr($expr, 0, 57).'...' : $expr;
    }
}

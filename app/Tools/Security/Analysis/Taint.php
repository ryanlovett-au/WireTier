<?php

namespace App\Tools\Security\Analysis;

/**
 * Request-controlled values within one method: client-writable `$this->prop`
 * reads, tainted parameters, and locals assigned from either.
 *
 * Propagation is deliberately simple and errs towards "still tainted":
 *  - string/array built-ins (trim, array_values, implode, collect, …) and
 *    plain expressions keep the taint;
 *  - casts and predicate-style helpers (intval, in_array, preg_match, …)
 *    clear it;
 *  - a call to one of the app's own methods or a static (`$this->x(...)`,
 *    `Model::find(...)`) clears it: what comes back is a model or a value
 *    the method produced, and a lookup keyed by tainted input is judged at
 *    the lookup itself, not downstream.
 */
final class Taint
{
    /** Built-ins whose result is still the caller's data. */
    private const PRESERVING = ['trim', 'ltrim', 'rtrim', 'strtolower', 'strtoupper', 'ucfirst', 'ucwords', 'lcfirst', 'array_values', 'array_filter', 'array_map', 'array_unique', 'array_merge', 'array_slice', 'array_keys', 'array_column', 'implode', 'explode', 'preg_split', 'preg_replace', 'str_replace', 'sprintf', 'substr', 'mb_substr', 'collect', 'json_encode', 'json_decode', 'compact', 'array_diff', 'array_combine', 'array_reverse', 'end', 'reset', 'current', 'data_get', 'urldecode', 'rawurldecode', 'base64_decode', 'html_entity_decode', 'strval', 'mb_strtolower', 'str_pad', 'wordwrap', 'nl2br'];

    /** Results that can't carry a caller-chosen string. */
    private const CLEARING = ['intval', 'floatval', 'boolval', 'count', 'in_array', 'array_key_exists', 'preg_match', 'filter_var', 'ctype_digit', 'ctype_alnum', 'ctype_alpha', 'is_numeric', 'is_int', 'is_string', 'is_array', 'is_null', 'isset', 'empty', 'strlen', 'mb_strlen', 'abs', 'max', 'min', 'round', 'floor', 'ceil', 'hash', 'md5', 'sha1', 'crc32', 'password_hash'];

    /** @var array<string, true> */
    private array $props = [];

    /** @var array<string, true> */
    private array $vars = [];

    /** @param list<string> $props */
    public function __construct(array $props = [])
    {
        foreach ($props as $p) {
            $this->props[$p] = true;
        }
    }

    public function addVariable(string $name): void
    {
        $this->vars[$name] = true;
    }

    public function hasSources(): bool
    {
        return $this->props !== [] || $this->vars !== [];
    }

    /** @param list<array{text: string, line: int}> $statements */
    public function propagate(array $statements): void
    {
        // Two passes so a loop body that taints a variable used earlier in
        // the same loop is still caught.
        for ($pass = 0; $pass < 2; $pass++) {
            foreach ($statements as $st) {
                $this->absorb($st['text']);
            }
        }
    }

    /** Does $text read a tainted value? */
    public function touches(string $text): bool
    {
        return $this->sources($text) !== [];
    }

    /**
     * The tainted sources $text reads, as written (`$this->form_paths`,
     * `$serverId`).
     *
     * @return list<string>
     */
    public function sources(string $text): array
    {
        $found = [];
        if ($this->props && preg_match_all('/\$this->('.implode('|', array_map(fn ($p) => preg_quote($p, '/'), array_keys($this->props))).')\b(?!\s*\()/', $text, $m)) {
            foreach ($m[1] as $p) {
                $found['$this->'.$p] = true;
            }
        }
        if ($this->vars && preg_match_all('/(?<![\w>$])\$('.implode('|', array_map(fn ($v) => preg_quote($v, '/'), array_keys($this->vars))).')\b/', $text, $m)) {
            foreach ($m[1] as $v) {
                $found['$'.$v] = true;
            }
        }

        return array_keys($found);
    }

    /** Does an assignment of $expr carry the taint to its target? */
    public function carries(string $expr): bool
    {
        $expr = trim($expr);
        if (! $this->touches($expr)) {
            return false;
        }

        // Casts.
        if (preg_match('/^\(\s*(int|integer|bool|boolean|float|double)\s*\)/i', $expr)) {
            return false;
        }

        // Outermost call: a clearing built-in, an allow-list intersection,
        // a pass-through built-in (judged by its arguments), or app code.
        if (preg_match('/^\\\\?(\w+)\s*\(/', $expr, $m) && ! str_starts_with($expr, '$')) {
            $fn = strtolower($m[1]);
            $args = $this->topLevelArgs($expr, strlen($m[0]) - 1);
            if (in_array($fn, self::CLEARING, true)) {
                return false;
            }
            if (in_array($fn, ['array_intersect', 'array_intersect_key'], true) && $args !== null) {
                // Only an allow-list if one side is clean.
                foreach ($args as $arg) {
                    if (! $this->carries($arg)) {
                        return false;
                    }
                }

                return true;
            }
            if (in_array($fn, self::PRESERVING, true) && $args !== null) {
                foreach ($args as $arg) {
                    if ($this->carries($arg)) {
                        return true;
                    }
                }

                return false;
            }
        }
        if (preg_match('/^(?:\$this->|self::|static::|parent::|[A-Z][\w\\\\]*::)\w+\s*\(/', $expr) && ! preg_match('/^(?:Str|Arr|Collection)::/', $expr)) {
            // A chain that ends in a plain property read of a tainted value
            // (`$this->x()->{$this->y}`) is rare enough to ignore.
            return false;
        }

        return true;
    }

    /**
     * Top-level arguments of the call whose '(' is at $open, or null when
     * the call isn't the whole expression (`f($x) . $y`).
     *
     * @return list<string>|null
     */
    private function topLevelArgs(string $expr, int $open): ?array
    {
        $depth = 0;
        $args = [];
        $buf = '';
        $quote = null;
        $len = strlen($expr);
        for ($i = $open; $i < $len; $i++) {
            $c = $expr[$i];
            if ($quote !== null) {
                $buf .= $c;
                if ($c === '\\') {
                    $buf .= $expr[++$i] ?? '';
                } elseif ($c === $quote) {
                    $quote = null;
                }

                continue;
            }
            if ($c === "'" || $c === '"') {
                $quote = $c;
                $buf .= $c;
            } elseif ($c === '(' || $c === '[') {
                if ($depth++ > 0) {
                    $buf .= $c;
                }
            } elseif ($c === ')' || $c === ']') {
                if (--$depth === 0) {
                    $args[] = trim($buf);

                    return trim(substr($expr, $i + 1)) === '' ? array_values(array_filter($args, fn ($a) => $a !== '')) : null;
                }
                $buf .= $c;
            } elseif ($c === ',' && $depth === 1) {
                $args[] = trim($buf);
                $buf = '';
            } else {
                $buf .= $c;
            }
        }

        return null;
    }

    private function absorb(string $statement): void
    {
        // foreach ($src as $k => $v) / foreach ($src as $v)
        if (preg_match('/^foreach\s*\((.+)\s+as\s+(?:\$(\w+)\s*=>\s*)?(?:&\s*)?\$(\w+)\s*\)/', $statement, $m)) {
            if ($this->carries($m[1])) {
                if ($m[2] !== '') {
                    $this->vars[$m[2]] = true;
                }
                $this->vars[$m[3]] = true;
            }

            return;
        }

        // $x = expr / $x ??= expr / $x .= expr / [$a, $b] = expr / list(...) = expr
        if (preg_match('/^(\[[^\]]*\]|list\s*\([^)]*\)|\$\w+)\s*(?:\?\?=|\.=|=)(?!=)\s*(.+)$/s', $statement, $m)) {
            if (! $this->carries($m[2])) {
                return;
            }
            if (preg_match_all('/\$(\w+)/', $m[1], $vars)) {
                foreach ($vars[1] as $v) {
                    if ($v !== 'this') {
                        $this->vars[$v] = true;
                    }
                }
            }
        }
    }
}

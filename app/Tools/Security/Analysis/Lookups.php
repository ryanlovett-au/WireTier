<?php

namespace App\Tools\Security\Analysis;

/**
 * Record lookups keyed by a value, and whether such a lookup is scoped to
 * the caller's records.
 */
final class Lookups
{
    /** Calls that fetch a record by key. Group 1 = the call as written. */
    private const SINKS = [
        '/((?:::|->)(?:find|findOrFail|findMany|findOrNew|whereKey|firstWhere))\s*\(/',
        '/((?:::|->)(?:where|orWhere|whereIn|firstWhere)\s*\(\s*[\'"](?:\w+\.)?(?:id|uuid|token|\w+_id)[\'"])/',
    ];

    /**
     * Lookups in $statement whose argument span reads a tainted value.
     *
     * @return list<array{call: string, sources: list<string>}>
     */
    public static function taintedIn(string $statement, Taint $taint): array
    {
        $out = [];
        foreach (self::SINKS as $re) {
            if (! preg_match_all($re, $statement, $m, PREG_OFFSET_CAPTURE)) {
                continue;
            }
            foreach ($m[1] as [$call, $offset]) {
                // Only a query that starts from a model/DB static reaches
                // arbitrary rows. `$record->relation()->find()` is scoped by
                // its parent and `$collection->firstWhere()` filters rows
                // already loaded.
                if (! self::queriesTable(substr($statement, 0, $offset))) {
                    continue;
                }
                $args = self::argSpan($statement, $offset);
                if ($args === null) {
                    continue;
                }
                $sources = $taint->sources($args);
                if ($sources !== []) {
                    $out[] = ['call' => self::label($statement, $offset, $call), 'sources' => $sources];
                }
            }
        }

        return $out;
    }

    /** Does $statement contain any table lookup at all? */
    public static function any(string $statement): bool
    {
        foreach (self::SINKS as $re) {
            if (preg_match_all($re, $statement, $m, PREG_OFFSET_CAPTURE)) {
                foreach ($m[1] as [, $offset]) {
                    if (self::queriesTable(substr($statement, 0, $offset))) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Does the chain leading up to a call start from a model or DB static
     * (`Server::`, `Server::query()->`, `DB::table(...)->`)? Walks back from
     * the call over balanced (...) / [...] groups to the start of the chain:
     * an unmatched '(' or '[', or a ',', '=', '?', ':' or space at depth 0.
     */
    private static function queriesTable(string $before): bool
    {
        $depth = 0;
        $start = 0;
        for ($i = strlen($before) - 1; $i >= 0; $i--) {
            $c = $before[$i];
            if ($c === ')' || $c === ']') {
                $depth++;
            } elseif ($c === '(' || $c === '[') {
                if ($depth === 0) {
                    $start = $i + 1;
                    break;
                }
                $depth--;
            } elseif ($depth === 0 && (in_array($c, [',', '=', '?', ';', '!', '{'], true) || ($c === ':' && ($before[$i - 1] ?? '') !== ':' && ($before[$i + 1] ?? '') !== ':'))) {
                $start = $i + 1;
                break;
            } elseif ($depth === 0 && $c === ' ' && ! preg_match('/^\s*->/', substr($before, $i))) {
                // A space ends the chain unless it's a line-broken `->` hop.
                $start = $i + 1;
                break;
            }
        }
        $chain = ltrim(substr($before, $start));

        // `Model::...->` before the call, or just `Model` when the call is
        // the static itself (the offset sits on its `::`).
        return (bool) preg_match('/^\\\\?(?:[A-Z][\w\\\\]*|DB)(?:::|$)/', $chain);
    }

    /**
     * Is the lookup chain in $statement scoped to the caller's records?
     *  - a team constraint (team_id, whereBelongsTo, forTeam, ->team())
     *  - a relation query off an object (`$server->services()->find(...)`)
     *  - another *_id constraint on a value the client doesn't control
     *    (`->where('server_id', $this->serverId)` with serverId #[Locked])
     */
    public static function scoped(string $statement, Taint $taint): bool
    {
        // A bare mention of team_id is not a constraint: `->value('team_id')`
        // or `->pluck('team_id')` reads it, and `where('team_id', $clientValue)`
        // lets the client pick the team. Team constraints are judged with the
        // other *_id constraints below, on whether the client controls the value.
        if (preg_match('/whereBelongsTo\s*\(|forTeam\s*\(|->team\(\)|ownedBy\s*\(/', $statement)) {
            return true;
        }
        if (preg_match('/\$\w+(?:->\w+)*->\w+\(\)\s*->\s*(?:find|findOrFail|where|whereKey|first|firstWhere|whereIn)\b/', $statement)) {
            return true;
        }
        // A constraint on the caller's own identity (`where('email', auth()->user()->email)`).
        if (preg_match('/where\s*\(\s*[\'"][\w.]+[\'"]\s*,[^;]*?(?:auth\(\)|Auth::|->user\(\))/', $statement)) {
            return true;
        }
        if (preg_match_all('/where\s*\(\s*[\'"](?:\w+\.)?(\w+_id)[\'"]\s*,\s*([^)]+)\)/', $statement, $m, PREG_SET_ORDER)) {
            foreach ($m as $w) {
                if (! $taint->touches($w[2])) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Is the record assigned at $index checked for ownership afterwards
     * (`abort_unless($x->team_id === ...)`, `if ($x->server_id !== $id)`,
     * `hasAbilityIn($x->team_id, ...)`)?
     *
     * @param  list<array{text: string, line: int}>  $statements
     */
    public static function checkedAfter(array $statements, int $index): bool
    {
        if (! preg_match('/^\$((?:this->)?\w+)\s*=/', $statements[$index]['text'], $m)) {
            return false;
        }
        $var = preg_quote($m[1], '/');
        $limit = min(count($statements), $index + 10);
        for ($j = $index + 1; $j < $limit; $j++) {
            $text = $statements[$j]['text'];

            // A membership lookup on the record that fails for anyone else:
            // `TeamUser::where('team_id', $team->id)->where('user_id', auth()->user()->id)->firstOrFail()`.
            if (preg_match('/\$'.$var.'\??->id\b/', $text)
                && preg_match('/auth\(\)->(?:id\(\)|user\(\)->id)|Auth::id\(\)/', $text)
                && preg_match('/->firstOrFail\(\)/', $text)) {
                return true;
            }

            $ownership = preg_match('/\$'.$var.'\??->(?:team_id|server_id|user_id|team\b)/', $text)
                || preg_match('/(?:isTeamAdminOf|hasAbilityIn|belongsToTeam|canAdministerTeam|isMemberOf|authorize)\s*\([^;]*\$'.$var.'\b/', $text);
            if (! $ownership) {
                continue;
            }
            // The owner is compared or gated here, or resolved (through a
            // scoped finder) and gated within the next few statements:
            // `$server = $this->findServer($x->server_id); if (! $server) abort(404);`
            for ($k = $j; $k < min(count($statements), $j + 5); $k++) {
                if (preg_match('/abort|authorize|hasAbilityIn|isTeamAdminOf|throw|return|[!=]==?/', $statements[$k]['text'])) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Is a tainted source itself passed to a membership / ability check
     * anywhere in the method (`belongsToTeam($teamId)`, `isTeamAdminOf($id)`)?
     * That gates the record before or after it's loaded.
     *
     * @param  list<array{text: string, line: int}>  $statements
     * @param  list<string>  $sources
     */
    public static function sourceGated(array $statements, array $sources): bool
    {
        foreach ($sources as $src) {
            $re = '/(?:belongsToTeam|isTeamAdminOf|hasAbilityIn|canAdministerTeam|isMemberOf|canAccessTeam)\s*\(\s*'.preg_quote($src, '/').'\b/';
            foreach ($statements as $st) {
                if (preg_match($re, $st['text'])) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Split an argument list at top-level commas.
     *
     * @return list<string>
     */
    public static function splitArgs(string $args): array
    {
        $out = [];
        $buf = '';
        $depth = 0;
        $quote = null;
        $len = strlen($args);
        for ($i = 0; $i < $len; $i++) {
            $c = $args[$i];
            if ($quote !== null) {
                $buf .= $c;
                if ($c === '\\') {
                    $buf .= $args[++$i] ?? '';
                } elseif ($c === $quote) {
                    $quote = null;
                }

                continue;
            }
            if ($c === "'" || $c === '"') {
                $quote = $c;
            } elseif ($c === '(' || $c === '[') {
                $depth++;
            } elseif ($c === ')' || $c === ']') {
                $depth--;
            } elseif ($c === ',' && $depth === 0) {
                $out[] = trim($buf);
                $buf = '';

                continue;
            }
            $buf .= $c;
        }
        if (trim($buf) !== '') {
            $out[] = trim($buf);
        }

        return $out;
    }

    /**
     * The balanced argument text of the call whose name starts at $offset.
     */
    public static function argSpan(string $statement, int $offset): ?string
    {
        $open = strpos($statement, '(', $offset);
        if ($open === false) {
            return null;
        }
        $depth = 0;
        $len = strlen($statement);
        $quote = null;
        for ($i = $open; $i < $len; $i++) {
            $c = $statement[$i];
            if ($quote !== null) {
                if ($c === '\\') {
                    $i++;
                } elseif ($c === $quote) {
                    $quote = null;
                }

                continue;
            }
            if ($c === "'" || $c === '"') {
                $quote = $c;
            } elseif ($c === '(') {
                $depth++;
            } elseif ($c === ')') {
                $depth--;
                if ($depth === 0) {
                    return substr($statement, $open + 1, $i - $open - 1);
                }
            }
        }

        return null;
    }

    /** "ZerotierNetwork::find()" - the model or receiver plus the call. */
    private static function label(string $statement, int $offset, string $call): string
    {
        $name = preg_replace('/^(::|->)/', '', preg_replace('/\s*\(.*/s', '', $call));
        $before = substr($statement, 0, $offset);
        if (str_starts_with($call, '::') && preg_match('/([A-Z]\w*)$/', $before, $m)) {
            return $m[1].'::'.$name.'()';
        }

        return '->'.$name.'()';
    }
}

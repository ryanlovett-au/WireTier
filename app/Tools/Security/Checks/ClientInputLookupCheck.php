<?php

namespace App\Tools\Security\Checks;

use App\Tools\Security\Analysis\Gates;
use App\Tools\Security\Analysis\LivewireSurface;
use App\Tools\Security\Analysis\Lookups;
use App\Tools\Security\Analysis\PhpMethod;
use App\Tools\Security\Analysis\PhpSource;
use App\Tools\Security\Analysis\Taint;
use App\Tools\Security\AuditReport;

/**
 * Livewire's IDOR: a record lookup keyed by something the browser controls,
 * with nothing tying the record to the caller.
 *
 * Request-controlled = any client-writable property (whatever its name; the
 * old check only knew `$id`, `$commandId` and a few other exact names, which
 * is how `$snapshotsCommandId` slipped through) or a parameter of a public
 * method, plus locals derived from them. A lookup is fine when the chain is
 * team-scoped, goes through a relation of an already-authorised record, adds
 * an owner constraint on a value the client doesn't control, or the record's
 * team/server is checked before use.
 */
final class ClientInputLookupCheck
{
    public const CATEGORY = 'Livewire Client Input';

    /**
     * @param  list<string>  $sharedModels  Models every team may look up by a
     *                                      client-chosen key by design (not team-owned).
     */
    public function __construct(private readonly array $sharedModels = []) {}

    /** @return list<array<string, mixed>> */
    public function check(PhpSource $source): array
    {
        if (! $source->isLivewire()) {
            return [];
        }

        $surface = new LivewireSurface($source);
        $writable = $surface->clientWritableProperties();
        $findings = [];

        foreach ($source->methods() as $method) {
            $taint = $surface->taint($method);
            if (! $taint->hasSources() || Gates::adminOnly($method)) {
                continue;
            }
            $statements = $method->statements();

            foreach ($statements as $i => $st) {
                foreach (Lookups::taintedIn($st['text'], $taint) as $hit) {
                    if ($this->isShared($hit['call'])) {
                        continue;
                    }
                    if (Lookups::scoped($st['text'], $taint) || Lookups::checkedAfter($statements, $i) || Lookups::sourceGated($statements, $hit['sources'])) {
                        continue;
                    }
                    $findings[] = $this->finding($source, $st['line'], $method->name, $hit['call'], $hit['sources'], $writable);
                }

                // Indirection through one of the component's own finders.
                if (preg_match_all('/\$this->(\w+)\s*\(/', $st['text'], $calls, PREG_OFFSET_CAPTURE)) {
                    foreach ($calls[1] as [$name, $offset]) {
                        $helper = $source->method($name);
                        if ($helper === null || $helper->body === '' || $helper === $method) {
                            continue; // abstract / host-provided: judged where it's implemented
                        }
                        $args = Lookups::argSpan($st['text'], $offset);
                        $sources = $args === null ? [] : $taint->sources($args);
                        if ($sources === [] || ! $this->helperLooksUpUnscoped($helper)) {
                            continue;
                        }
                        if (Lookups::scoped($st['text'], $taint) || Lookups::checkedAfter($statements, $i) || Lookups::sourceGated($statements, $sources)) {
                            continue;
                        }
                        $findings[] = $this->finding($source, $st['line'], $method->name, '$this->'.$name.'() (an unscoped lookup)', $sources, $writable);
                    }
                }
            }
        }

        return $findings;
    }

    /** Is the lookup on a model shared across teams ("ZerotierToken::findOrFail()")? */
    private function isShared(string $call): bool
    {
        foreach ($this->sharedModels as $model) {
            if (str_starts_with($call, $model.'::')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Does a helper key a table lookup by one of its own parameters with no
     * scope (judged by the same rules as a direct lookup)?
     */
    private function helperLooksUpUnscoped(PhpMethod $helper): bool
    {
        $taint = new Taint;
        foreach ($helper->paramNames() as $p) {
            $taint->addVariable($p);
        }
        $statements = $helper->statements();
        $taint->propagate($statements);
        foreach ($statements as $i => $st) {
            foreach (Lookups::taintedIn($st['text'], $taint) as $hit) {
                if (! $this->isShared($hit['call']) && ! Lookups::scoped($st['text'], $taint) && ! Lookups::checkedAfter($statements, $i) && ! Lookups::sourceGated($statements, $hit['sources'])) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @param  list<string>  $sources
     * @param  array<string, int>  $writable
     */
    private function finding(PhpSource $source, int $line, string $method, string $call, array $sources, array $writable): array
    {
        $props = array_values(array_filter($sources, fn ($s) => str_starts_with($s, '$this->')));
        $what = $props !== []
            ? 'Client-writable '.implode(', ', $props).' (not #[Locked])'
            : 'Client-supplied '.implode(', ', $sources);

        return AuditReport::finding(
            'high',
            self::CATEGORY,
            $source->path,
            $line,
            "{$what} keys {$call} in {$method}() with no team or owner scope - a client can point it at another team's record",
            $props !== []
                ? 'Add #[Locked] if only the server sets it, and scope the query (team_id, a locked owner id, or a relation of an authorised record)'
                : 'Scope the query (team_id, a locked owner id, or a relation of an authorised record), or check the record\'s team before use',
        );
    }
}

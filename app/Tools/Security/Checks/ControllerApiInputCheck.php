<?php

namespace App\Tools\Security\Checks;

use App\Tools\Security\Analysis\Gates;
use App\Tools\Security\Analysis\LivewireSurface;
use App\Tools\Security\Analysis\Lookups;
use App\Tools\Security\Analysis\PhpSource;
use App\Tools\Security\AuditReport;

/**
 * WireTier's other IDOR: a ZeroTier controller call aimed at a network the
 * browser chose, with nothing tying that network to the caller's team.
 *
 * ClientInputLookupCheck covers database lookups, but most WireTier actions
 * never load a record: they hand a network ID straight to ZerotierService,
 * and the controller acts on any network it hosts. So a client-writable
 * property or action parameter reaching the network-ID argument of a
 * controller call is only safe when the method first resolves that network
 * through a team-scoped lookup (and bails when it isn't found), or is
 * restricted to system admins, who may act on every network.
 */
final class ControllerApiInputCheck
{
    public const CATEGORY = 'Controller API Input';

    /** ZerotierService methods whose first argument is the network to act on. */
    public const NETWORK_METHODS = [
        'getControllerNetwork', 'updateNetwork', 'deleteNetwork',
        'getNetworkMembers', 'getNetworkMember', 'updateNetworkMember',
        'authorizeMember', 'deauthorizeMember', 'deleteMember',
        'joinNetwork', 'leaveNetwork',
    ];

    /** Calls that only read from the controller. */
    private const READS = ['getControllerNetwork', 'getNetworkMembers', 'getNetworkMember'];

    /** @return list<array<string, mixed>> */
    public function check(PhpSource $source): array
    {
        if (! $source->isLivewire()) {
            return [];
        }

        $surface = new LivewireSurface($source);
        $writable = $surface->clientWritableProperties();
        $sink = '/->('.implode('|', self::NETWORK_METHODS).')\s*\(/';
        $findings = [];

        foreach ($source->methods() as $method) {
            $taint = $surface->taint($method);
            if (! $taint->hasSources() || Gates::adminOnly($method)) {
                continue;
            }

            $statements = $method->statements();
            foreach ($statements as $i => $st) {
                if (! preg_match_all($sink, $st['text'], $m, PREG_OFFSET_CAPTURE)) {
                    continue;
                }
                foreach ($m[1] as [$call, $offset]) {
                    $args = Lookups::argSpan($st['text'], $offset);
                    $networkArg = $args === null ? '' : (Lookups::splitArgs($args)[0] ?? '');
                    $sources = $taint->sources($networkArg);
                    if ($sources === [] || $this->ownershipResolvedBefore($source, $statements, $i, $sources)) {
                        continue;
                    }

                    $findings[] = $this->finding($source, $st['line'], $method->name, $call, $sources, $writable);
                }
            }
        }

        return $findings;
    }

    /**
     * Before statement $index, is one of $sources passed to a team-scoped
     * lookup (inline, or through one of the component's own helpers whose
     * body is team-scoped), with the result checked so the method stops
     * when the caller doesn't own the network?
     *
     * @param  list<array{text: string, line: int}>  $statements
     * @param  list<string>  $sources
     */
    private function ownershipResolvedBefore(PhpSource $source, array $statements, int $index, array $sources): bool
    {
        $mentions = '/(?:'.implode('|', array_map(fn ($s) => preg_quote($s, '/'), $sources)).')\b/';

        for ($j = 0; $j < $index; $j++) {
            $text = $statements[$j]['text'];
            if (! preg_match($mentions, $text) || ! preg_match('/^\$(\w+)\s*=/', $text, $assign)) {
                continue;
            }

            $scoped = (bool) preg_match('/team_id/', $text);
            if (! $scoped && preg_match_all('/\$this->(\w+)\s*\(/', $text, $calls)) {
                foreach ($calls[1] as $name) {
                    $helper = $source->method($name);
                    if ($helper !== null && preg_match('/team_id/', $helper->body)) {
                        $scoped = true;
                        break;
                    }
                }
            }
            if (! $scoped) {
                continue;
            }

            // The resolved record must gate what follows: `if (! $x)`,
            // `abort_unless($x ...)`, or `$x ?? abort(...)`.
            $var = preg_quote($assign[1], '/');
            for ($k = $j; $k < $index; $k++) {
                if (preg_match('/if\s*\(\s*!\s*\$'.$var.'\b|abort_(?:unless|if)\s*\([^;]*\$'.$var.'\b|\$'.$var.'\s*\?\?\s*abort/', $statements[$k]['text'])) {
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
        $verb = in_array($call, self::READS, true) ? 'reads' : 'acts on';

        return AuditReport::finding(
            in_array($call, self::READS, true) ? 'medium' : 'critical',
            self::CATEGORY,
            $source->path,
            $line,
            "{$what} is the network ID for ZerotierService::{$call}() in {$method}() - the controller {$verb} any network it hosts, so a client can target another team's",
            $props !== []
                ? 'Add #[Locked] if only the server sets it, and resolve the network through a team-scoped ZerotierNetwork lookup (bail if not found) before calling the controller'
                : 'Resolve the network through a team-scoped ZerotierNetwork lookup and bail if not found, then use the record\'s network_id',
        );
    }
}

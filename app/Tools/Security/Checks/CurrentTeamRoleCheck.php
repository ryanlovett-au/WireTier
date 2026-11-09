<?php

namespace App\Tools\Security\Checks;

use App\Tools\Security\Analysis\LivewireSurface;
use App\Tools\Security\Analysis\PhpSource;
use App\Tools\Security\AuditReport;

/**
 * A role checked on the user's *current* team while the component acts on a
 * team of its own choosing.
 *
 * User::isTeamAdmin(), canManageNetworks() and the teamUser relation all read
 * the role the user holds in their current team. A page that loads some other
 * team (e.g. /settings/team/{id} into `public Team $current_team`) and gates
 * its actions with those helpers lets an admin of their current team act on
 * any team they merely belong to. The check there has to name the team being
 * acted on, e.g. canAdministerTeam($this->team->id).
 *
 * Flags a client-callable method that uses a current-team role helper and
 * reads a Team-typed property of the component (or one assigned from a Team
 * lookup), unless the method also checks a role against that team's id.
 */
final class CurrentTeamRoleCheck
{
    public const CATEGORY = 'Current-Team Role Check';

    /** Role helpers that answer for the current team only. */
    private const CURRENT_TEAM_HELPERS = '/->(isTeamAdmin|canManageNetworks)\s*\(\s*\)|->teamUser\b/';

    /** Role checks that take the team being acted on. */
    private const TEAM_SPECIFIC_GATES = '/canAdministerTeam\s*\(|belongsToTeam\s*\(|isTeamAdminOf\s*\(/';

    /** @return list<array<string, mixed>> */
    public function check(PhpSource $source): array
    {
        if (! $source->isLivewire()) {
            return [];
        }

        $teamProps = $this->teamProperties($source);
        if ($teamProps === []) {
            return [];
        }

        $surface = new LivewireSurface($source);
        $propRef = '/\$this->('.implode('|', array_map(fn ($p) => preg_quote($p, '/'), $teamProps)).')\b/';
        $findings = [];

        foreach ($source->methods() as $method) {
            if (! $surface->isClientCallable($method)) {
                continue;
            }
            if (! preg_match($propRef, $method->body, $prop) || preg_match(self::TEAM_SPECIFIC_GATES, $method->body)) {
                continue;
            }
            if (! preg_match(self::CURRENT_TEAM_HELPERS, $method->body, $helper)) {
                // A one-hop helper of the component may hold the check.
                $helper = $this->viaHelper($source, $method->body);
                if ($helper === null) {
                    continue;
                }
            }

            $findings[] = AuditReport::finding(
                'high',
                self::CATEGORY,
                $source->path,
                $method->startLine,
                "{$method->name}() acts on \$this->{$prop[1]} but gates with {$helper[0]}, which checks the role in the user's current team - an admin there can act on any team they belong to",
                'Check the role in the team being acted on, e.g. auth()->user()->canAdministerTeam($this->'.$prop[1].'->id)',
            );
        }

        return $findings;
    }

    /**
     * Properties holding a Team: typed `Team $x`, or assigned from a Team
     * lookup (`$this->x = Team::find(...)`) anywhere in the component.
     *
     * @return list<string>
     */
    private function teamProperties(PhpSource $source): array
    {
        $props = [];
        foreach ($source->properties() as $p) {
            if ($p['type'] !== null && LivewireSurface::isModelType($p['type']) && basename(str_replace('\\', '/', $p['type'])) === 'Team') {
                $props[] = $p['name'];
            }
        }
        if (preg_match_all('/\$this->(\w+)\s*=\s*Team::/', $source->code, $m)) {
            array_push($props, ...$m[1]);
        }

        return array_values(array_unique($props));
    }

    /** @return array{0: string}|null the current-team helper reached through a $this->x() call */
    private function viaHelper(PhpSource $source, string $body): ?array
    {
        if (! preg_match_all('/\$this->(\w+)\s*\(/', $body, $calls)) {
            return null;
        }
        foreach ($calls[1] as $name) {
            $helper = $source->method($name);
            if ($helper === null || preg_match(self::TEAM_SPECIFIC_GATES, $helper->body)) {
                continue;
            }
            if (preg_match(self::CURRENT_TEAM_HELPERS, $helper->body, $m)) {
                return [$m[0].' (via '.$name.'())'];
            }
        }

        return null;
    }
}

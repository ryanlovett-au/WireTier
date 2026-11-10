<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Sends members of a team that requires two-factor authentication to the
 * security page until they set it up.
 *
 * This is the user-facing half; the enforcement is in User: without 2FA the
 * team resolves to null and its admin rights don't apply, so Livewire actions
 * and any route this middleware isn't on get no access to the team either.
 */
class RequireTeamTwoFactor
{
    /** Pages a member must still reach: setting up 2FA, and choosing another team. */
    private const ALLOWED_ROUTES = ['security.edit', 'teams.index', 'teams.switch', 'password.confirm', 'password.confirmation'];

    public function handle(Request $request, Closure $next): Response
    {
        $team = $request->user()?->teamAwaitingTwoFactor();

        if ($team === null || $request->routeIs(...self::ALLOWED_ROUTES)) {
            return $next($request);
        }

        if ($request->expectsJson()) {
            abort(403, "{$team->name} requires two-factor authentication.");
        }

        return redirect()->route('security.edit')->with('two_factor_required', $team->name);
    }
}

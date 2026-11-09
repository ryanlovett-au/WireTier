<?php

namespace App\Tools\Security\Analysis;

/**
 * Method-level authorisation gates the per-statement checks rely on.
 */
final class Gates
{
    /**
     * Restricted to system admins: the method returns or aborts unless
     * auth()->user()->isAdmin(). System admins work across every team by
     * design, so a lookup or controller call keyed by client input is not a
     * cross-team leak there.
     */
    public static function adminOnly(PhpMethod $method): bool
    {
        return (bool) preg_match('/if\s*\(\s*!\s*auth\(\)->user\(\)->isAdmin\(\)\s*\)\s*\{?\s*(?:return|abort)/', $method->body)
            || (bool) preg_match('/abort_unless\s*\(\s*auth\(\)->user\(\)->isAdmin\(\)/', $method->body);
    }
}

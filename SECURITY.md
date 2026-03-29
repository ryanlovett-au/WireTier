# Security

WireTier includes a built-in security testing framework with static analysis, runtime tests, and a deterministic test data seeder. This document covers how the tools work, what they test, and how to use them during development.

## Quick Start

```bash
# Run the static security audit
php artisan security:audit

# Run the full security test suite (audit + Pest tests)
php artisan security:test

# Run just the Pest security tests
php artisan test tests/Feature/Security/
```

## Tools

### `security:audit` — Static Code Analysis

Scans the codebase for security issues without executing any code. Checks PHP files, Blade templates, config files, and route definitions.

```bash
# Default table output
php artisan security:audit

# JSON output (for CI pipelines)
php artisan security:audit --format=json

# Filter by severity
php artisan security:audit --severity=high

# Show remediation suggestions
php artisan security:audit --fix
```

**Severity levels:** CRITICAL, HIGH, MEDIUM, LOW, INFO

**What it scans:**

| Category | What it checks |
|----------|---------------|
| Team Isolation | Unscoped `findOrFail()` and `where()` queries on ZerotierNetwork without `team_id` |
| Authorization | Public Livewire methods performing writes without `isAdmin()` or `isTeamAdmin()` checks |
| Mass Assignment | Models using `$guarded = []` without explicit `$fillable` |
| XSS | Unescaped `{!! !!}` output, `addslashes()` misuse in Blade templates |
| SSRF | Host URL scheme validation, empty token fallback in ZerotierService |
| Path Injection | `validatePathSegment()` presence for URL path parameters |
| Info Disclosure | `$e->getMessage()` displayed in user-facing toasts, `APP_DEBUG=true` in `.env.example` |
| Session Security | Session encryption defaults, cookie security settings |
| Security Headers | Middleware for X-Frame-Options, X-Content-Type-Options, HSTS |
| Rate Limiting | Throttle middleware on routes, per-user API rate limiting in ZerotierService |
| Livewire | Public model properties that could expose sensitive fields to the client |
| Authentication | Password reset token expiry, Livewire update endpoint protection |
| Open Redirect | `redirect()->back()` usage that follows the Referer header |

The audit exits with code 1 if any HIGH or CRITICAL findings exist, making it suitable for CI gates.

### `security:test` — Runtime Test Orchestrator

Runs the static audit followed by the Pest security test suite.

```bash
# Run audit + tests
php artisan security:test

# Seed the database first (for manual testing against a live instance)
php artisan security:test --seed
```

The `--seed` option runs `SecurityTestSeeder` to populate the database with deterministic test data (two teams, multiple users at each role, controller tokens, and networks).

### Pest Security Tests

All security tests live under `tests/Feature/Security/` and use the `RefreshDatabase` trait with SQLite in-memory (configured via `.env.testing`).

```
tests/Feature/Security/
  AuthenticationTest.php        — Login rate limiting, 2FA, session management
  InvitationSecurityTest.php    — Invitation lifecycle, single-use, expiry
  MembersPageTest.php           — Member operations, team isolation, authorization
  ModelSecurityTest.php         — Mass assignment, serialization, raw SQL safety
  NetworksPageTest.php          — Network CRUD, team scoping, import flow
  PeersPageTest.php             — Peers page access, admin gating
  SessionSecurityTest.php       — Session config, headers, rate limiting, redirects
  TeamSettingsTest.php          — Team management, role checks, data exposure
  TokensPageTest.php            — Token CRUD, admin guards, delete protection
  ZerotierServiceTest.php       — SSRF, path injection, scheme validation
```

## Test Patterns

### Functional Tests

Each Livewire component has functional tests that verify core operations work correctly. These serve as regression protection when applying security fixes.

```php
test('createNetwork creates DB record and calls API', function () {
    defaultHttpFakes();
    $this->actingAs($this->alphaAdmin);

    Livewire::test('pages::zerotier.networks')
        ->set('new_network_name', 'New Network')
        ->set('new_network_subnet', '10.42.0.0/24')
        ->call('createNetwork')
        ->assertHasNoErrors();

    $network = ZerotierNetwork::where('network_id', 'aaaa000001ffffff')->first();
    expect($network)->not->toBeNull();
});
```

### Security Exposure Tests

When a vulnerability is discovered but not yet fixed, the test documents it using the skip-on-fail pattern. The test passes once the fix is applied.

```php
test('viewer cannot save networks', function () {
    $this->actingAs($this->alphaViewer);

    Livewire::test('pages::zerotier.networks')
        ->set('edit_name', 'HACKED')
        ->call('saveNetwork');

    try {
        expect($network->name)->toBe($originalName);
    } catch (\Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: saveNetwork() does not block viewers');
    }
});
```

When the test skips, it produces a `WARN` line in the output with a `SECURITY EXPOSURE:` prefix describing the vulnerability. Once fixed, the assertion passes and the skip is never reached.

### Http Fakes

ZeroTier API calls are mocked using `Http::fake()` with callback-based fakes that return realistic responses for each endpoint:

```php
function defaultHttpFakes(): void
{
    Http::fake(function ($request) {
        $url = $request->url();
        if (str_contains($url, '/status')) {
            return Http::response(['address' => 'aaaa000001', 'version' => '1.14.0', 'online' => true]);
        }
        if (preg_match('#/controller/network/([a-zA-Z0-9_]+)$#', $url, $m)) {
            return Http::response(['nwid' => $m[1], 'name' => 'Net '.$m[1], 'private' => true, ...]);
        }
        // ... endpoint-specific responses
    });
}
```

### Test Data

`SecurityTestSeeder` creates deterministic test data with fixed UUIDs:

| Entity | Details |
|--------|---------|
| Admin Team | Super-admin user, system-wide privileges |
| Team Alpha | Admin, member, and viewer users. 6 permissions. 1 network. |
| Team Beta | Admin and member users. 4 permissions. 1 network. |
| Orphan User | No team membership |
| 2 Controller Tokens | Global (admin-managed), one per "controller" |
| 2 Networks | One per team, each on a different token |

## Security Architecture

### Token Model

Controller tokens are **global and admin-managed**. Only members of the admin team (configured via `ADMIN_TEAM_UUID`) can create, edit, delete, or test tokens. Non-admin teams see tokens by name only — the `host`, `node_address`, and `token` fields are in `$hidden` on the model and excluded via `select('id', 'name')` queries.

### Network Isolation

Networks are scoped to teams via `team_id` on `zerotier_networks`. The networks page loads only DB-tracked networks for the current team, enriched with live API data. Admins can discover and import untracked networks from controllers, assigning them to any team.

### Authorization Model

| Check | Used By | Meaning |
|-------|---------|---------|
| `isAdmin()` | Tokens page, peers page, import flow | User's current team matches `ADMIN_TEAM_UUID` |
| `isTeamAdmin()` | Network CRUD, member operations, team settings | User is a system admin OR has `admin` role in their current team |
| `belongsToTeam()` | Team settings mount | User has a TeamUser record for the team |

Every Livewire method that performs a write operation has its own authorization check, independent of the page-level `mount()` guard (defense-in-depth).

### Input Validation

`ZerotierService` validates all inputs before making API calls:
- **Host URL:** Must use `http` or `https` scheme (rejects `file://`, `ftp://`, etc.)
- **Path segments:** Network IDs, node IDs, and addresses must match `[a-zA-Z0-9_-]+` (rejects `../`, `;`, URL-encoded traversal)
- **Empty tokens:** Throws `InvalidArgumentException` instead of falling back to localhost

### Rate Limiting

- **Route-level:** `throttle:60,1` middleware on all web and settings routes
- **API-level:** `RateLimiter` in `ZerotierService::client()` — 120 requests per user per minute across all controller operations
- **Auth-level:** Fortify rate limiting on login (5/minute) and 2FA (5/minute)

### Security Headers

The `SecurityHeaders` middleware adds to every response:

| Header | Value |
|--------|-------|
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` (HTTPS only) |

### Livewire Endpoint

The Livewire update endpoint (`/livewire/update`) is restricted to authenticated users via `Livewire::setUpdateRoute()` in `bootstrap/app.php`. Since all Livewire components require authentication, unauthenticated requests to the update endpoint are rejected at the routing layer.

## Fixes Applied

| Severity | Issue | Fix |
|----------|-------|-----|
| HIGH | `isTeamAdmin()` returned true for all users | Replace `->first()` on resolved HasOne with direct property access |
| HIGH | Mass assignment on 6 models via `$guarded = []` | Replace with explicit `$fillable` on each model |
| HIGH | `removeUser()` and `deleteTeam()` missing admin checks | Add `isTeamAdmin()` guard |
| HIGH | Member authorize/deauthorize/delete had no authorization | Add `isTeamAdmin()` guard to all member write operations |
| MEDIUM | SSRF via non-HTTP host schemes | Validate scheme is `http` or `https` in constructor |
| MEDIUM | Path injection via networkId/nodeId | Add `validatePathSegment()` regex check on all path parameters |
| MEDIUM | Empty token fell back to localhost:9993 | Throw `InvalidArgumentException` |
| MEDIUM | `$e->getMessage()` in user-facing toasts | Replace with generic messages, log via `report($e)` |
| MEDIUM | No security response headers | Add `SecurityHeaders` middleware |
| MEDIUM | Session encryption default was false | Change default to `true` |
| MEDIUM | Password reset token expired in 60 minutes | Reduce to 30 minutes |
| MEDIUM | `addslashes()` for JS escaping | Replace with `Js::from()` |
| MEDIUM | No rate limiting on API calls | Add per-user `RateLimiter` in ZerotierService |
| LOW | `redirect()->back()` open redirect | Replace with `redirect()->route('dashboard')` |
| LOW | `APP_DEBUG=true` in `.env.example` | Change to `false` |

## CI Integration

Add to your CI pipeline:

```yaml
- name: Security Audit
  run: php artisan security:audit --format=json --severity=high

- name: Security Tests
  run: php artisan test tests/Feature/Security/ --env=testing
```

The audit command exits with code 1 on any HIGH or CRITICAL finding, failing the pipeline.

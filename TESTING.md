# Testing

WireTier maintains 100% code coverage across all application files with 251+ tests and 490+ assertions. This document covers the testing architecture, how to run tests, and how to maintain coverage as the codebase grows.

## Quick Start

```bash
# Run all tests
php artisan test --env=testing

# Run with coverage report
php artisan test --coverage --env=testing

# Run with minimum coverage enforcement (fails CI if below threshold)
php artisan test --coverage --min=100 --env=testing

# Run a specific test file
php artisan test tests/Feature/Security/MembersPageTest.php --env=testing

# Run a specific test by name
php artisan test --filter="viewer cannot authorize members" --env=testing
```

## Test Environment

Tests run against SQLite in-memory via `.env.testing` — never your real database. Key settings:

| Setting | Value | Why |
|---------|-------|-----|
| `DB_CONNECTION` | `sqlite` | Fast, isolated, no external dependencies |
| `DB_DATABASE` | `:memory:` | Fresh database per test, no cleanup needed |
| `CACHE_STORE` | `array` | In-memory cache, isolated between tests |
| `SESSION_DRIVER` | `array` | No session persistence between tests |
| `MAIL_MAILER` | `array` | Emails captured, never sent |
| `QUEUE_CONNECTION` | `sync` | Jobs run immediately, no queue worker needed |

The `RefreshDatabase` trait is applied globally to all Feature tests via `tests/Pest.php`.

## Coverage Requirements

**PCOV** is required for coverage reports. Install it once:

```bash
CFLAGS="-I/opt/homebrew/include" pecl install pcov
```

The `phpunit.xml` `<source>` directive covers the `app/` directory. Security tooling files (`Security_Audit`, `Security_Test`, `AuditReport`) are excluded from coverage targets as they run via artisan commands, not HTTP/Livewire requests.

## Test Organisation

```
tests/
  Feature/
    Auth/                    — Authentication, registration, 2FA, password reset
    Mail/                    — Mail rendering tests
    Middleware/              — SecurityHeaders middleware
    Models/                  — Relationships, edge cases, computed attributes
    Providers/               — AppServiceProvider password rules
    Services/                — ZerotierService, SyncService, StatsService edge cases
    Settings/                — Profile, security settings pages
    Security/                — Security audit, team isolation, authorization
      AuditLogTest.php       — Audit log recording, viewer access, filters
      AuthenticationTest.php — Rate limiting, 2FA, session management
      InvitationSecurityTest — Invitation lifecycle, single-use, cleanup
      MembersPageTest.php    — Member CRUD, team isolation, viewer restrictions
      ModelSecurityTest.php  — Mass assignment, serialization, raw SQL
      NetworksPageTest.php   — Network CRUD, team scoping, import flow
      PeersPageTest.php      — Admin gating, data loading
      SessionSecurityTest.php— Config checks, headers, rate limiting
      SyncServiceTest.php    — Sync creation, updates, removal, team isolation
      TeamSettingsTest.php   — Team management, role checks
      TokensPageTest.php     — Token CRUD, admin guards, delete protection
      ZerotierServiceTest.php— SSRF, path injection, scheme validation
    RenderTest.php           — Smoke tests for every page/component
    DashboardTest.php        — Guest redirect, authenticated access
```

## Test Patterns

### Smoke Tests (RenderTest.php)

Every Livewire component and blade view is mounted and checked for rendering errors. These catch undefined variables, missing imports, and blade syntax errors across all user roles:

```php
test('networks page renders for team viewer', function () {
    $this->actingAs($this->alphaViewer);
    Livewire::test('pages::zerotier.networks')->assertStatus(200);
});
```

### Functional Tests

Verify that core operations produce the expected database state:

```php
test('createNetwork creates DB record and calls API', function () {
    defaultHttpFakes();
    $this->actingAs($this->alphaAdmin);

    Livewire::test('pages::zerotier.networks')
        ->set('new_network_name', 'New Network')
        ->call('createNetwork');

    expect(ZerotierNetwork::where('network_id', 'aaaa000001ffffff')->first())->not->toBeNull();
});
```

### Security Tests

Verify that authorization checks block unauthorized access:

```php
test('viewer cannot authorize members', function () {
    $this->actingAs($this->alphaViewer);

    Livewire::test('pages::zerotier.members', [...])
        ->call('authorizeMember', 'aabb000001');

    // Member should NOT have been authorized
    expect($member->authorised)->toBeFalse();
});
```

### Edge Case Tests

Exercise error handling, exception paths, and boundary conditions:

```php
test('syncNetwork returns false when API fails', function () {
    Http::fake(fn () => throw new RuntimeException('Connection refused'));
    Log::shouldReceive('warning')->once();

    expect(ZerotierSyncService::syncNetwork($network))->toBeFalse();
});
```

### Relationship Tests

Verify all Eloquent relationships return the correct types:

```php
test('ZerotierNetwork belongs to team', function () {
    $network = ZerotierNetwork::where('network_id', SecurityTestSeeder::ALPHA_NETWORK_ID)->first();
    expect($network->team)->toBeInstanceOf(Team::class);
});
```

## Http Fakes

ZeroTier API calls are mocked using callback-based `Http::fake()` that returns realistic responses per endpoint:

```php
Http::fake(function ($request) {
    $url = $request->url();

    if (str_contains($url, '/status')) {
        return Http::response(['address' => 'aaaa000001', 'version' => '1.14.0', 'online' => true]);
    }
    if (preg_match('#/controller/network/([a-zA-Z0-9_]+)$#', $url, $m)) {
        return Http::response(['nwid' => $m[1], 'name' => 'Net', 'private' => true, ...]);
    }
    // ... per-endpoint responses
});
```

This pattern ensures tests exercise the real code paths (URL construction, response parsing, error handling) while never hitting an actual controller.

## Test Data

`SecurityTestSeeder` creates deterministic fixtures with fixed UUIDs:

| Entity | Details |
|--------|---------|
| Admin Team | Super-admin user with system privileges |
| Team Alpha | Admin, member, viewer users. 6 permissions. 1 network. |
| Team Beta | Admin, member users. 4 permissions. 1 network. |
| Orphan User | No team membership |
| 2 Controller Tokens | Global (admin-managed) |
| 2 Networks | One per team, each on a different token |

Constants like `SecurityTestSeeder::ALPHA_TEAM_ID` provide stable references across all test files.

## Adding New Tests

When adding a new feature:

1. **Write functional tests** — verify the happy path works and produces correct DB state
2. **Write authorization tests** — verify each role (admin, member, viewer) gets the expected access
3. **Write edge case tests** — exercise error handling, empty states, and boundary conditions
4. **Add a smoke test** — add a render test in `RenderTest.php` for any new page/component
5. **Run coverage** — `php artisan test --coverage --min=100 --env=testing` to verify no gaps
6. **Run pint** — `vendor/bin/pint` to ensure code style compliance

### Coverage Checklist

For 100% coverage, ensure you test:

- Every `public` method on models, services, and commands
- Both branches of every `if`/`else` (especially auth checks and error handlers)
- Every `catch` block (use `Http::fake()` or `Log::shouldReceive()` to trigger exceptions)
- Every Eloquent relationship (`->team`, `->members`, `->networks`)
- Every model attribute accessor (`->expired`, `->initials()`)
- Production-specific code paths (temporarily set environment in the test)

## CI Integration

```yaml
- name: Run Tests
  run: php artisan test --env=testing

- name: Coverage Gate
  run: php artisan test --coverage --min=100 --env=testing

- name: Security Audit
  run: php artisan security:audit --format=json --severity=high

- name: Code Style
  run: vendor/bin/pint --test
```

The coverage gate fails the pipeline if any application file drops below 100%.

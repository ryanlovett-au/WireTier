<?php

use App\Models\User;
use Database\Seeders\SecurityTestSeeder;

beforeEach(function () {
    $this->seed(SecurityTestSeeder::class);
    config(['laratier.admin_team' => SecurityTestSeeder::ADMIN_TEAM_ID]);
});

test('login is rate limited after repeated failures', function () {
    $user = User::factory()->create();

    // Attempt login 6 times with wrong password (limit is 5/minute)
    for ($i = 0; $i < 6; $i++) {
        $response = $this->post('/login', [
            'email' => $user->email,
            'password' => 'wrong-password',
        ]);
    }

    // The 6th attempt should be rate limited
    $response->assertStatus(429);
});

test('unauthenticated access redirects to login', function () {
    $routes = [
        route('dashboard'),
        route('zerotier.networks'),
        route('zerotier.tokens'),
        route('zerotier.peers'),
        route('teams.index'),
        route('teams.show'),
    ];

    foreach ($routes as $route) {
        $this->get($route)->assertRedirect('/login');
    }
});

test('two factor authentication rate limiting works', function () {
    $user = User::factory()->withTwoFactor()->create();

    // Start login
    $this->post('/login', [
        'email' => $user->email,
        'password' => 'password',
    ]);

    // Attempt 2FA 6 times with wrong code
    for ($i = 0; $i < 6; $i++) {
        $response = $this->post('/two-factor-challenge', [
            'code' => '000000',
        ]);
    }

    // Should be rate limited
    $response->assertStatus(429);
});


test('password confirmation required for security settings', function () {
    $user = User::factory()->create();
    $this->actingAs($user);

    // If password confirm is enabled, should redirect
    if (\Laravel\Fortify\Features::optionEnabled(
        \Laravel\Fortify\Features::twoFactorAuthentication(), 'confirmPassword'
    )) {
        $this->get(route('security.edit'))
            ->assertRedirect(route('password.confirm'));
    } else {
        $this->get(route('security.edit'))->assertOk();
    }
});

test('session regenerates on login', function () {
    $user = User::factory()->create();

    $sessionId = session()->getId();

    $this->post('/login', [
        'email' => $user->email,
        'password' => 'password',
    ]);

    // Session ID should change after login to prevent fixation
    expect(session()->getId())->not->toBe($sessionId);
});

test('logout invalidates session', function () {
    $user = User::factory()->create();
    $this->actingAs($user);

    $this->post('/logout');

    // Should no longer be authenticated
    $this->get(route('dashboard'))->assertRedirect('/login');
});

test('registration creates verified user only when email verification passes', function () {
    // Register a new user
    $this->post('/register', [
        'name' => 'Test User',
        'email' => 'test@example.com',
        'password' => 'SecureP@ssw0rd!',
        'password_confirmation' => 'SecureP@ssw0rd!',
    ]);

    $user = User::where('email', 'test@example.com')->first();
    expect($user)->not->toBeNull();

    // User should be unverified initially (if email verification is enabled)
    if (class_exists(\Laravel\Fortify\Features::class) && in_array('email-verification', config('fortify.features', []))) {
        expect($user->email_verified_at)->toBeNull();
    }
});

test('password validation applies minimum length requirement', function () {
    // Even in non-production, Password::default() applies at minimum the Laravel default
    $response = $this->post('/register', [
        'name' => 'Test',
        'email' => fake()->unique()->safeEmail(),
        'password' => 'short',
        'password_confirmation' => 'short',
    ]);

    $response->assertSessionHasErrors('password');
});

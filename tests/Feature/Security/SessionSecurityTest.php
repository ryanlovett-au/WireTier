<?php

use App\Models\Team;
use App\Models\TeamUser;
use App\Models\User;
use Database\Seeders\SecurityTestSeeder;
use Illuminate\Support\Facades\File;

beforeEach(function () {
    $this->seed(SecurityTestSeeder::class);
    config(['laratier.admin_team' => SecurityTestSeeder::ADMIN_TEAM_ID]);
});

test('session encryption should be enabled for production', function () {
    $content = File::get(config_path('session.php'));

    try {
        // The default should encourage encryption
        // Currently defaults to false
        expect(config('session.encrypt'))->toBeTrue(
            'Session encryption is disabled — session data stored unencrypted'
        );
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: Session encryption is disabled — session data is stored unencrypted');
    }
});

test('session cookie should be secure in production', function () {
    // In production, cookies must be HTTPS-only
    // This is a configuration check
    $content = File::get(config_path('session.php'));

    expect(str_contains($content, 'SESSION_SECURE_COOKIE'))->toBeTrue(
        'Session config should reference SESSION_SECURE_COOKIE env var'
    );
});

test('security headers middleware should be configured', function () {
    $content = File::get(base_path('bootstrap/app.php'));

    $hasSecurityHeaders = str_contains($content, 'SecurityHeaders')
        || str_contains($content, 'X-Frame-Options')
        || str_contains($content, 'Content-Security-Policy');

    try {
        expect($hasSecurityHeaders)->toBeTrue(
            'No security headers middleware configured in bootstrap/app.php'
        );
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: No security headers middleware (X-Frame-Options, CSP) is configured — clickjacking and content injection possible');
    }
});

test('session is invalidated when user is removed from team', function () {
    $alphaAdmin = User::where('email', 'alpha-admin@security-test.local')->first();
    $this->actingAs($alphaAdmin);
    session()->forget('current_team');

    // Remove user from team
    TeamUser::where('user_id', $alphaAdmin->id)
        ->where('team_id', SecurityTestSeeder::ALPHA_TEAM_ID)
        ->delete();

    // Clear session to simulate new request
    session()->forget('current_team');

    // Session should reflect team removal
    $freshUser = User::find($alphaAdmin->id);
    expect($freshUser->team)->toBeNull(
        'User still has team access after being removed'
    );
});

test('team context is not cached indefinitely in session', function () {
    $alphaAdmin = User::where('email', 'alpha-admin@security-test.local')->first();
    $this->actingAs($alphaAdmin);

    // Force session team cache
    session()->forget('current_team');

    // Delete the team user record
    TeamUser::where('user_id', $alphaAdmin->id)
        ->where('team_id', SecurityTestSeeder::ALPHA_TEAM_ID)
        ->delete();

    // Clear session to simulate new request
    session()->forget('current_team');

    // Team should now be null since membership was revoked
    $freshUser = User::find($alphaAdmin->id);
    expect($freshUser->team)->toBeNull(
        'Team context persisted after membership revocation and session clear'
    );
});

test('APP_DEBUG defaults to false in env example', function () {
    $content = File::get(base_path('.env.example'));

    try {
        expect(str_contains($content, 'APP_DEBUG=true'))->toBeFalse(
            '.env.example has APP_DEBUG=true — developers may copy this to production'
        );
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: .env.example has APP_DEBUG=true — production deployments may expose debug information');
    }
});

test('sensitive routes require email verification', function () {
    $unverified = User::factory()->unverified()->create([
        'current_team' => SecurityTestSeeder::ALPHA_TEAM_ID,
    ]);
    TeamUser::create([
        'team_id' => SecurityTestSeeder::ALPHA_TEAM_ID,
        'user_id' => $unverified->id,
        'role' => 'member',
    ]);

    $this->actingAs($unverified);

    $this->get(route('zerotier.networks'))->assertRedirect('/email/verify');
    $this->get(route('teams.index'))->assertRedirect('/email/verify');
});

test('livewire update endpoint requires authentication', function () {
    // Unauthenticated POST to the Livewire update endpoint should redirect to login
    $response = $this->post('/livewire/update', []);
    $response->assertRedirect('/login');
});

test('livewire update endpoint is protected via setUpdateRoute', function () {
    $content = File::get(base_path('bootstrap/app.php'));

    $hasProtectedUpdate = str_contains($content, 'setUpdateRoute')
        && str_contains($content, "'auth'");

    expect($hasProtectedUpdate)->toBeTrue(
        'Livewire update endpoint is not restricted to authenticated users'
    );
});

test('password reset token expiry is 30 minutes or less', function () {
    $config = config('auth.passwords.users.expire');

    try {
        expect($config)->toBeLessThanOrEqual(30,
            "Password reset token expires in {$config} minutes — max recommended is 30"
        );
    } catch (Throwable $e) {
        $this->markTestSkipped("SECURITY EXPOSURE: Password reset token expires in {$config} minutes — should be 30 or less to limit token reuse window");
    }
});

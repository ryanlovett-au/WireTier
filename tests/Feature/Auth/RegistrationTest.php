<?php

use App\Models\Team;
use App\Models\TeamInvitation;
use App\Models\User;
use Laravel\Fortify\Features;

beforeEach(function () {
    $this->skipUnlessFortifyHas(Features::registration());
    config(['wiretier.registration' => 'open']);
});

test('registration screen can be rendered', function () {
    $response = $this->get(route('register'));

    $response->assertOk();
});

test('new users can register', function () {
    $response = $this->post(route('register.store'), [
        'name' => 'John Doe',
        'email' => 'test@example.com',
        'password' => 'password',
        'password_confirmation' => 'password',
    ]);

    $response->assertSessionHasNoErrors()
        ->assertRedirect(route('dashboard', absolute: false));

    $this->assertAuthenticated();
});

test('invite mode blocks registration without a pending invitation', function () {
    config(['wiretier.registration' => 'invite']);

    $response = $this->from(route('register'))->post(route('register.store'), [
        'name' => 'Jane Doe',
        'email' => 'uninvited@example.com',
        'password' => 'password',
        'password_confirmation' => 'password',
    ]);

    $response->assertRedirect(route('register'));
    $response->assertSessionHasErrors('email');
    $this->assertGuest();
    expect(User::where('email', 'uninvited@example.com')->exists())->toBeFalse();
});

test('invite mode allows registration with a pending invitation', function () {
    config(['wiretier.registration' => 'invite']);

    $team = Team::create(['name' => 'Inviters']);
    TeamInvitation::create([
        'team_id' => $team->id,
        'email' => 'invited@example.com',
        'role' => 'member',
    ]);

    $response = $this->post(route('register.store'), [
        'name' => 'Jane Doe',
        'email' => 'invited@example.com',
        'password' => 'password',
        'password_confirmation' => 'password',
    ]);

    $response->assertSessionHasNoErrors();
    $this->assertAuthenticated();
});

test('invite mode rejects registration with an expired invitation', function () {
    config(['wiretier.registration' => 'invite']);

    $team = Team::create(['name' => 'Inviters']);
    TeamInvitation::create([
        'team_id' => $team->id,
        'email' => 'expired@example.com',
        'role' => 'member',
        'expires' => now()->subDay()->format('Y-m-d'),
    ]);

    $response = $this->from(route('register'))->post(route('register.store'), [
        'name' => 'Jane Doe',
        'email' => 'expired@example.com',
        'password' => 'password',
        'password_confirmation' => 'password',
    ]);

    $response->assertSessionHasErrors('email');
    $this->assertGuest();
});

test('register page shows invite-only notice when invite mode is enabled', function () {
    config(['wiretier.registration' => 'invite']);

    $this->get(route('register'))
        ->assertOk()
        ->assertSee('Registration is by invitation only');
});

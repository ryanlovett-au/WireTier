<?php

use App\Models\User;

test('User team clears invalid session data', function () {
    $user = User::factory()->create();
    $this->actingAs($user);

    // Put invalid (non-Team) data in session
    session(['current_team' => 'invalid-string']);

    // Accessing team should clear the invalid session data and return null
    expect($user->team)->toBeNull();
    expect(session('current_team'))->toBeNull();
});

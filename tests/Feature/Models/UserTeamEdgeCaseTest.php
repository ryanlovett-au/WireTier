<?php

use App\Models\Team;
use App\Models\User;

test('User team ignores session data and resolves from membership', function () {
    $user = User::factory()->create();
    $this->actingAs($user);

    // The team is no longer cached in the session (a stale copy kept granting
    // access after removal), so neither junk nor a real Team there has effect.
    session(['current_team' => 'invalid-string']);
    expect($user->team)->toBeNull();

    session(['current_team' => Team::factory()->create()]);
    expect($user->fresh()->team)->toBeNull();
});

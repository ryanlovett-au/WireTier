<?php

use App\Providers\AppServiceProvider;
use Illuminate\Validation\Rules\Password;

test('production password rules enforce complexity', function () {
    // Temporarily set environment to production to exercise the password defaults callback
    app()->detectEnvironment(fn () => 'production');

    // Re-bootstrap the password defaults
    (new AppServiceProvider(app()))->boot();

    $rules = Password::defaults();

    // Verify the production rules are active by testing a weak password
    $validator = validator(['password' => 'weak'], ['password' => $rules]);
    expect($validator->fails())->toBeTrue();

    // A strong password should pass
    $validator = validator(['password' => 'Str0ng!Pass#2024'], ['password' => $rules]);
    expect($validator->fails())->toBeFalse();

    // Reset environment
    app()->detectEnvironment(fn () => 'testing');
});

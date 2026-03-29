<?php

use App\Models\AuditLog;
use App\Models\User;

test('login creates audit log entry', function () {
    $user = User::factory()->create();
    $this->post('/login', ['email' => $user->email, 'password' => 'password']);
    expect(AuditLog::where('action', 'auth.login')->exists())->toBeTrue();
});

test('logout creates audit log entry', function () {
    $this->actingAs(User::factory()->create());
    $this->post('/logout');
    expect(AuditLog::where('action', 'auth.logout')->exists())->toBeTrue();
});

test('registration creates audit log entry', function () {
    $this->post('/register', [
        'name' => 'Audit Test',
        'email' => 'audit-event@test.local',
        'password' => 'Password123!',
        'password_confirmation' => 'Password123!',
    ]);
    expect(AuditLog::where('action', 'auth.registered')->exists())->toBeTrue();
});

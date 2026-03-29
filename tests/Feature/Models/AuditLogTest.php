<?php

use App\Models\AuditLog;
use Database\Seeders\SecurityTestSeeder;

beforeEach(fn () => $this->seed(SecurityTestSeeder::class));

test('forTeam scope filters by team', function () {
    AuditLog::record('test.alpha', teamId: SecurityTestSeeder::ALPHA_TEAM_ID);
    AuditLog::record('test.beta', teamId: SecurityTestSeeder::BETA_TEAM_ID);

    $logs = AuditLog::forTeam(SecurityTestSeeder::ALPHA_TEAM_ID)->get();
    foreach ($logs as $log) {
        expect($log->team_id)->toBe(SecurityTestSeeder::ALPHA_TEAM_ID);
    }
});

test('forAction scope filters by action prefix with wildcard', function () {
    AuditLog::record('network.created', teamId: SecurityTestSeeder::ALPHA_TEAM_ID);
    AuditLog::record('team.updated', teamId: SecurityTestSeeder::ALPHA_TEAM_ID);

    $logs = AuditLog::forAction('network.*')->get();
    foreach ($logs as $log) {
        expect($log->action)->toStartWith('network.');
    }
});

test('forAction scope filters exact action', function () {
    AuditLog::record('network.created', teamId: SecurityTestSeeder::ALPHA_TEAM_ID);
    AuditLog::record('network.deleted', teamId: SecurityTestSeeder::ALPHA_TEAM_ID);

    $logs = AuditLog::forAction('network.created')->get();
    expect($logs)->toHaveCount(1);
    expect($logs->first()->action)->toBe('network.created');
});

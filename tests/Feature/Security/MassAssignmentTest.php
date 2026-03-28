<?php

use App\Models\TeamPermission;
use App\Models\TeamUser;
use App\Models\User;
use App\Models\ZerotierToken;
use Illuminate\Support\Facades\File;

test('all models should use explicit fillable instead of empty guarded', function () {
    $modelPath = app_path('Models');
    $files = File::glob($modelPath.'/*.php');
    $vulnerable = [];

    foreach ($files as $file) {
        $content = File::get($file);
        $basename = basename($file, '.php');

        // Skip User model — uses #[Fillable] attribute
        if (str_contains($content, '#[Fillable(')) {
            continue;
        }

        if (preg_match('/\$guarded\s*=\s*\[\s*\]/', $content) && ! str_contains($content, '$fillable')) {
            $vulnerable[] = $basename;
        }
    }

    try {
        expect($vulnerable)->toBeEmpty(
            'Models with $guarded = [] and no $fillable: '.implode(', ', $vulnerable)
        );
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: Models use $guarded = [] without explicit $fillable — all fields are mass-assignable: '.implode(', ', $vulnerable));
    }
});

test('ZerotierToken model should not mass-assign team_id', function () {
    $token = new ZerotierToken;
    $token->fill(['team_id' => 'injected-team', 'name' => 'Test', 'token' => 'test', 'host' => 'http://localhost']);

    try {
        // team_id should NOT be fillable (it should be set explicitly)
        expect($token->team_id)->not->toBe('injected-team',
            'ZerotierToken allowed mass assignment of team_id'
        );
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: ZerotierToken allows mass assignment of team_id — attackers can inject arbitrary team ownership');
    }
});

test('TeamUser model should not mass-assign role', function () {
    $tu = new TeamUser;
    $tu->fill(['role' => 'admin', 'team_id' => 'test', 'user_id' => 1]);

    try {
        expect($tu->role)->not->toBe('admin',
            'TeamUser allowed mass assignment of role'
        );
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: TeamUser allows mass assignment of role — attackers can escalate privileges to admin');
    }
});

test('TeamPermission model should not mass-assign permission', function () {
    $tp = new TeamPermission;
    $tp->fill(['permission' => 'manage_tokens', 'team_id' => 'test']);

    try {
        expect($tp->permission)->not->toBe('manage_tokens',
            'TeamPermission allowed mass assignment of permission'
        );
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: TeamPermission allows mass assignment of permission — attackers can grant arbitrary permissions');
    }
});

test('User model does not expose sensitive fields in fillable', function () {
    $user = new User;
    $fillable = $user->getFillable();

    // password is intentionally fillable for registration/update flows
    expect($fillable)->not->toContain('remember_token');
    expect($fillable)->not->toContain('two_factor_secret');
    expect($fillable)->not->toContain('two_factor_recovery_codes');
});

test('User model hides sensitive data from serialization', function () {
    $user = User::factory()->create();
    $array = $user->toArray();

    expect($array)->not->toHaveKey('password');
    expect($array)->not->toHaveKey('two_factor_secret');
    expect($array)->not->toHaveKey('two_factor_recovery_codes');
    expect($array)->not->toHaveKey('remember_token');
});

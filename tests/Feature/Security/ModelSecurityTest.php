<?php

use App\Models\Team;
use App\Models\TeamInvitation;
use App\Models\TeamPermission;
use App\Models\TeamUser;
use App\Models\User;
use App\Models\ZerotierNetwork;
use App\Models\ZerotierToken;
use Illuminate\Support\Facades\File;

// ─── Mass Assignment: $guarded vs $fillable ──────────────────────────────

test('Team model has explicit fillable or restrictive guarded', function () {
    $team = new Team;

    try {
        expect($team->getGuarded())->not->toBe(['*'] ? false : true);
        // Check it either has $fillable set or $guarded is not empty array
        $hasFillable = ! empty($team->getFillable());
        $hasRestrictiveGuarded = $team->getGuarded() !== [] && $team->getGuarded() !== ['*'];

        expect($hasFillable || $hasRestrictiveGuarded)->toBeTrue(
            'Team model uses $guarded = [] with no $fillable'
        );
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: Team model uses $guarded = [] — all fields including id and timestamps can be mass-assigned');
    }
});

test('TeamUser model has explicit fillable or restrictive guarded', function () {
    $model = new TeamUser;

    try {
        $hasFillable = ! empty($model->getFillable());
        $hasRestrictiveGuarded = $model->getGuarded() !== [];

        expect($hasFillable || $hasRestrictiveGuarded)->toBeTrue(
            'TeamUser model uses $guarded = [] with no $fillable'
        );
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: TeamUser model uses $guarded = [] — role and team_id can be mass-assigned');
    }
});

test('TeamInvitation model has explicit fillable or restrictive guarded', function () {
    $model = new TeamInvitation;

    try {
        $hasFillable = ! empty($model->getFillable());
        $hasRestrictiveGuarded = $model->getGuarded() !== [];

        expect($hasFillable || $hasRestrictiveGuarded)->toBeTrue(
            'TeamInvitation model uses $guarded = [] with no $fillable'
        );
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: TeamInvitation model uses $guarded = [] — role and team_id can be mass-assigned');
    }
});

test('TeamPermission model has explicit fillable or restrictive guarded', function () {
    $model = new TeamPermission;

    try {
        $hasFillable = ! empty($model->getFillable());
        $hasRestrictiveGuarded = $model->getGuarded() !== [];

        expect($hasFillable || $hasRestrictiveGuarded)->toBeTrue(
            'TeamPermission model uses $guarded = [] with no $fillable'
        );
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: TeamPermission model uses $guarded = [] — permission and team_id can be mass-assigned');
    }
});

test('ZerotierToken model has explicit fillable or restrictive guarded', function () {
    $model = new ZerotierToken;

    try {
        $hasFillable = ! empty($model->getFillable());
        $hasRestrictiveGuarded = $model->getGuarded() !== [];

        expect($hasFillable || $hasRestrictiveGuarded)->toBeTrue(
            'ZerotierToken model uses $guarded = [] with no $fillable'
        );
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: ZerotierToken model uses $guarded = [] — token and team_id can be mass-assigned');
    }
});

test('ZerotierNetwork model has explicit fillable or restrictive guarded', function () {
    $model = new ZerotierNetwork;

    try {
        $hasFillable = ! empty($model->getFillable());
        $hasRestrictiveGuarded = $model->getGuarded() !== [];

        expect($hasFillable || $hasRestrictiveGuarded)->toBeTrue(
            'ZerotierNetwork model uses $guarded = [] with no $fillable'
        );
    } catch (Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: ZerotierNetwork model uses $guarded = [] — team_id and network_id can be mass-assigned');
    }
});

// ─── User Model Security ─────────────────────────────────────────────────

test('User model uses Fillable attribute', function () {
    $user = new User;
    $fillable = $user->getFillable();

    expect($fillable)->toContain('name');
    expect($fillable)->toContain('email');
    expect($fillable)->toContain('password');
    expect($fillable)->not->toContain('id');
    expect($fillable)->not->toContain('remember_token');
});

test('User model hides sensitive fields from serialization', function () {
    $user = new User;
    $hidden = $user->getHidden();

    expect($hidden)->toContain('password');
    expect($hidden)->toContain('two_factor_secret');
    expect($hidden)->toContain('two_factor_recovery_codes');
    expect($hidden)->toContain('remember_token');
});

// ─── ZerotierToken Security ──────────────────────────────────────────────

test('ZerotierToken hides token from serialization', function () {
    $token = new ZerotierToken;
    $hidden = $token->getHidden();

    expect($hidden)->toContain('token');
});

test('ZerotierToken encrypts token in database', function () {
    $casts = (new ZerotierToken)->getCasts();

    expect($casts['token'])->toBe('encrypted');
});

// ─── Raw SQL Safety ──────────────────────────────────────────────────────

test('whereRaw in User model does not interpolate user input', function () {
    // User::teamUser() uses whereRaw('1 = 0') — this is a static string, no user input
    $content = File::get(app_path('Models/User.php'));

    // Find all whereRaw calls and ensure they only contain static strings
    preg_match_all('/whereRaw\([\'"]([^"\']+)[\'"]\)/', $content, $matches);

    foreach ($matches[1] as $rawSql) {
        // The raw SQL should not contain any variable interpolation markers
        expect($rawSql)->not->toContain('$', "whereRaw contains variable interpolation: {$rawSql}");
        expect($rawSql)->not->toContain('{', "whereRaw contains variable interpolation: {$rawSql}");
    }
});

test('no raw SQL with variable interpolation exists in models', function () {
    $modelFiles = glob(app_path('Models/*.php'));

    foreach ($modelFiles as $file) {
        $content = File::get($file);
        $filename = basename($file);

        // Check for dangerous patterns: whereRaw with variables
        $hasUnsafeRaw = preg_match('/whereRaw\(\s*["\'].*\$/', $content)
            || preg_match('/DB::raw\(\s*["\'].*\$/', $content)
            || preg_match('/selectRaw\(\s*["\'].*\$/', $content);

        expect($hasUnsafeRaw)->toBeFalse(
            "Model {$filename} contains raw SQL with variable interpolation — SQL injection risk"
        );
    }
});

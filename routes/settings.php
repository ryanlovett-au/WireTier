<?php

use App\Models\AuditLog;
use App\Models\Team;
use Illuminate\Support\Facades\Route;
use Laravel\Fortify\Features;

Route::middleware(['auth', 'throttle:60,1'])->group(function () {
    Route::redirect('settings', 'settings/profile');

    Route::livewire('settings/profile', 'pages::settings.profile')->name('profile.edit');
});

Route::middleware(['auth', 'verified', 'throttle:60,1'])->group(function () {
    Route::livewire('settings/appearance', 'pages::settings.appearance')->name('appearance.edit');

    Route::livewire('settings/security', 'pages::settings.security')
        ->middleware(
            when(
                Features::canManageTwoFactorAuthentication()
                    && Features::optionEnabled(Features::twoFactorAuthentication(), 'confirmPassword'),
                ['password.confirm'],
                [],
            ),
        )
        ->name('security.edit');

    // Team routes
    Route::livewire('settings/teams', 'pages::settings.teams')->name('teams.index');
    Route::livewire('settings/team/{id?}', 'pages::settings.team')->name('teams.show');

    // Team switcher
    Route::post('teams/{id}/switch', function (string $id) {
        $user = auth()->user();
        $team = Team::findOrFail($id);

        abort_unless($user->teams()->where('team_id', $id)->exists(), 403);

        $user->current_team = $id;
        $user->save();
        session()->forget('current_team');

        AuditLog::record('team.switched', 'team', $id, ['team_name' => $team->name]);

        return redirect()->route('dashboard');
    })->name('teams.switch');
});

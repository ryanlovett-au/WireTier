<?php

namespace App\Providers;

use App\Models\AuditLog;
use Carbon\CarbonImmutable;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\Registered;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Illuminate\Validation\Rules\Password;
use Livewire\Livewire;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        $this->configureDefaults();
        $this->registerAuditListeners();

        Livewire::setUpdateRoute(function ($handle) {
            // throttle:300,1 (per user) caps flooding of heavy actions while
            // leaving room for polling and the debounced live rules editor.
            return Route::post('/livewire/update', $handle)
                ->middleware(['web', 'auth', 'throttle:300,1']);
        });
    }

    protected function registerAuditListeners(): void
    {
        Event::listen(Login::class, function (Login $event) {
            AuditLog::record('auth.login', teamId: null);
        });

        Event::listen(Logout::class, function (Logout $event) {
            AuditLog::record('auth.logout', teamId: null);
        });

        Event::listen(Registered::class, function (Registered $event) {
            AuditLog::record('auth.registered', details: ['email' => $event->user->email], teamId: null);
        });
    }

    /**
     * Configure default behaviors for production-ready applications.
     */
    protected function configureDefaults(): void
    {
        Date::use(CarbonImmutable::class);

        DB::prohibitDestructiveCommands(
            app()->isProduction(),
        );

        Password::defaults(fn (): ?Password => app()->isProduction()
            ? Password::min(12)
                ->mixedCase()
                ->letters()
                ->numbers()
                ->symbols()
                ->uncompromised()
            : null,
        );
    }
}

<?php

namespace App\Providers;

use App\Actions\Fortify\CreateNewUser;
use App\Actions\Fortify\ResetUserPassword;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Str;
use Laravel\Fortify\Fortify;

class FortifyServiceProvider extends ServiceProvider
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
        $this->configureActions();
        $this->configureViews();
        $this->configureRateLimiting();
    }

    /**
     * Configure Fortify actions.
     */
    private function configureActions(): void
    {
        Fortify::resetUserPasswordsUsing(ResetUserPassword::class);
        Fortify::createUsersUsing(CreateNewUser::class);
    }

    /**
     * Configure Fortify views.
     */
    private function configureViews(): void
    {
        Fortify::loginView(fn () => view('pages::auth.login'));
        Fortify::verifyEmailView(fn () => view('pages::auth.verify-email'));
        Fortify::twoFactorChallengeView(fn () => view('pages::auth.two-factor-challenge'));
        Fortify::confirmPasswordView(fn () => view('pages::auth.confirm-password'));
        Fortify::registerView(fn () => view('pages::auth.register'));
        Fortify::resetPasswordView(fn () => view('pages::auth.reset-password'));
        Fortify::requestPasswordResetLinkView(fn () => view('pages::auth.forgot-password'));
    }

    /**
     * Configure rate limiting.
     */
    private function configureRateLimiting(): void
    {
        RateLimiter::for('two-factor', function (Request $request) {
            return Limit::perMinute(5)->by($request->session()->get('login.id'));
        });

        RateLimiter::for('login', function (Request $request) {
            $throttleKey = Str::transliterate(Str::lower($request->input(Fortify::username())).'|'.$request->ip());

            return Limit::perMinute(5)->by($throttleKey);
        });

        // Group limiter for the whole Fortify route surface
        // (config('fortify.middleware')), ported from Moonscape/OMS. GET page
        // views aren't metered: a normal sign-up flow touches several auth
        // pages in under a minute, and a blanket per-IP throttle would 429 a
        // legitimate user. The per-credential 'login' and 'two-factor'
        // limiters above still run on their own routes; whichever caps first
        // wins.
        RateLimiter::for('auth', function (Request $request) {
            if (in_array($request->method(), ['GET', 'HEAD'], true)) {
                return Limit::none();
            }

            // Password-reset POSTs: tight and keyed by email, so one victim's
            // inbox can't be flooded with reset links.
            if ($request->is('forgot-password', 'reset-password')) {
                $key = Str::transliterate(Str::lower((string) $request->input('email')).'|'.$request->ip());

                return Limit::perMinute(5)->by($key);
            }

            // Other state-changing POSTs (register, logout, 2FA setup, resend
            // verification): a generous per-IP net that a full sign-up flow
            // won't trip but that still caps scripted flooding.
            return Limit::perMinute(20)->by((string) $request->ip());
        });
    }
}

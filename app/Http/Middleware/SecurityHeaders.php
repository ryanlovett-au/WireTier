<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Vite;
use Symfony\Component\HttpFoundation\Response;

class SecurityHeaders
{
    public function handle(Request $request, Closure $next): Response
    {
        $csp = config('wiretier.csp', 'enforce');

        // A fresh nonce per request, picked up by @vite and Livewire's script
        // tags, and passed to @fluxAppearance / @fluxScripts in the layouts.
        if ($csp !== 'off') {
            Vite::useCspNonce();
        }

        $response = $next($request);

        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');
        $response->headers->set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

        if ($request->secure()) {
            $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        }

        if ($csp !== 'off' && ($nonce = Vite::cspNonce())) {
            $header = $csp === 'report-only' ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
            $response->headers->set($header, $this->contentSecurityPolicy($nonce));
        }

        return $response;
    }

    /**
     * Inline <script> runs only with this request's nonce, so injected markup
     * can't run script tags or on* handlers, load scripts from elsewhere, or
     * send data to other origins.
     *
     * 'unsafe-eval' is required: Alpine (bundled with Livewire, used by Flux
     * and our x-data/x-init attributes) evaluates directive expressions with
     * new Function(). Inline styles stay allowed because Flux and Livewire set
     * style attributes, which nonces can't cover.
     */
    protected function contentSecurityPolicy(string $nonce): string
    {
        return implode('; ', array_map(
            fn ($directive, $sources) => $directive.' '.implode(' ', $sources),
            array_keys($policy = self::directives($nonce, $this->viteDevServer())),
            $policy,
        ));
    }

    /**
     * The policy as directive => sources. Public so security:audit can check
     * what production allows (no dev server) without sending a request.
     *
     * @param  list<string>  $hot  Vite dev server sources (local only)
     * @return array<string, list<string>>
     */
    public static function directives(string $nonce, array $hot = []): array
    {
        return [
            'default-src' => ["'self'"],
            'script-src' => ["'self'", "'nonce-{$nonce}'", "'unsafe-eval'", ...$hot],
            'style-src' => ["'self'", "'unsafe-inline'", 'https://fonts.bunny.net', ...$hot],
            'font-src' => ["'self'", 'https://fonts.bunny.net', 'data:'],
            'img-src' => ["'self'", 'data:', 'blob:'],
            'connect-src' => ["'self'", ...$hot, ...array_map(fn ($o) => preg_replace('#^http#', 'ws', $o), $hot)],
            'object-src' => ["'none'"],
            'base-uri' => ["'self'"],
            'form-action' => ["'self'"],
            'frame-ancestors' => ["'none'"],
        ];
    }

    /**
     * The Vite dev server's origin while `npm run dev` is running locally.
     * CSP host sources can't express IPv6 literals (Vite often listens on
     * http://[::1]:5173), so those fall back to allowing the scheme; this
     * only ever applies in the local environment.
     */
    protected function viteDevServer(): array
    {
        if (! app()->environment('local') || ! Vite::isRunningHot()) {
            return [];
        }

        $url = trim((string) @file_get_contents(Vite::hotFile()));

        if (! preg_match('#^(https?)://([^/\s]+)#', $url, $m)) {
            return [];
        }

        return str_starts_with($m[2], '[') ? ["{$m[1]}:"] : [$m[0]];
    }
}

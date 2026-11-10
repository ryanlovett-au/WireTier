<?php

use App\Http\Middleware\SecurityHeaders;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

test('sets standard security headers', function () {
    $middleware = new SecurityHeaders;
    $request = Request::create('/test');
    $response = $middleware->handle($request, fn () => new Response('ok'));

    expect($response->headers->get('X-Frame-Options'))->toBe('DENY');
    expect($response->headers->get('X-Content-Type-Options'))->toBe('nosniff');
    expect($response->headers->get('Referrer-Policy'))->toBe('strict-origin-when-cross-origin');
    expect($response->headers->get('Permissions-Policy'))->toBe('camera=(), microphone=(), geolocation=()');
});

test('sets HSTS on HTTPS requests', function () {
    $middleware = new SecurityHeaders;
    $request = Request::create('/test', 'GET', server: ['HTTPS' => 'on']);
    $response = $middleware->handle($request, fn () => new Response('ok'));

    expect($response->headers->get('Strict-Transport-Security'))->toBe('max-age=31536000; includeSubDomains');
});

test('does not set HSTS on HTTP requests', function () {
    $middleware = new SecurityHeaders;
    $request = Request::create('/test');
    $response = $middleware->handle($request, fn () => new Response('ok'));

    expect($response->headers->get('Strict-Transport-Security'))->toBeNull();
});

// ─── Content-Security-Policy ─────────────────────────────────────────────

function cspNonce(string $policy): ?string
{
    return preg_match("/'nonce-([^']+)'/", $policy, $m) ? $m[1] : null;
}

test('pages get a nonce-based Content-Security-Policy that every script tag carries', function () {
    $response = $this->get('/login')->assertOk();

    $policy = $response->headers->get('Content-Security-Policy');
    expect($policy)
        ->toContain("default-src 'self'")
        ->toContain("object-src 'none'")
        ->toContain("base-uri 'self'")
        ->toContain("form-action 'self'")
        ->toContain("frame-ancestors 'none'")
        ->not->toContain("script-src 'self' 'unsafe-inline'");

    $nonce = cspNonce($policy);
    expect($nonce)->not->toBeNull();

    // Livewire, Flux and Vite script tags all carry this request's nonce.
    preg_match_all('/<script\b[^>]*>/i', $response->getContent(), $tags);
    expect($tags[0])->not->toBeEmpty();
    foreach ($tags[0] as $tag) {
        expect($tag)->toContain("nonce=\"{$nonce}\"");
    }
});

test('each response gets a fresh nonce', function () {
    $first = cspNonce($this->get('/login')->headers->get('Content-Security-Policy'));
    $second = cspNonce($this->get('/login')->headers->get('Content-Security-Policy'));

    expect($first)->not->toBe($second);
});

test('the policy can be switched to report-only or off', function () {
    config(['wiretier.csp' => 'report-only']);
    $response = $this->get('/login');
    expect($response->headers->get('Content-Security-Policy'))->toBeNull();
    expect($response->headers->get('Content-Security-Policy-Report-Only'))->toContain("default-src 'self'");

    config(['wiretier.csp' => 'off']);
    $response = $this->get('/login');
    expect($response->headers->get('Content-Security-Policy'))->toBeNull();
    expect($response->headers->get('Content-Security-Policy-Report-Only'))->toBeNull();
});

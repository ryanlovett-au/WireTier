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

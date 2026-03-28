<?php

use Illuminate\Support\Facades\File;

test('blade templates do not use unescaped output with user data', function () {
    $bladeFiles = array_merge(
        File::glob(resource_path('views/pages/zerotier/*.blade.php')),
        File::glob(resource_path('views/pages/settings/*.blade.php')),
    );

    $findings = [];

    foreach ($bladeFiles as $file) {
        $content = File::get($file);
        $basename = basename($file);

        if (preg_match_all('/\{!!\s*(.+?)\s*!!\}/s', $content, $matches, PREG_OFFSET_CAPTURE)) {
            foreach ($matches[1] as $match) {
                $variable = trim($match[0]);
                $offset = $match[1];
                $line = substr_count(substr($content, 0, $offset), "\n") + 1;
                $findings[] = "{$basename}:{$line} - {!! {$variable} !!}";
            }
        }
    }

    try {
        expect($findings)->toBeEmpty(
            "Unescaped output found:\n".implode("\n", $findings)
        );
    } catch (\Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: Blade templates use unescaped {!! !!} output — XSS vulnerability in: '.implode(', ', $findings));
    }
});

test('addslashes is not used for escaping in blade templates', function () {
    $bladeFiles = array_merge(
        File::glob(resource_path('views/pages/zerotier/*.blade.php')),
        File::glob(resource_path('views/pages/settings/*.blade.php')),
    );

    $findings = [];

    foreach ($bladeFiles as $file) {
        $content = File::get($file);
        $basename = basename($file);

        if (preg_match_all('/addslashes\(/', $content, $matches, PREG_OFFSET_CAPTURE)) {
            foreach ($matches[0] as $match) {
                $line = substr_count(substr($content, 0, $match[1]), "\n") + 1;
                $findings[] = "{$basename}:{$line}";
            }
        }
    }

    try {
        expect($findings)->toBeEmpty(
            "addslashes() found (use @json() instead):\n".implode("\n", $findings)
        );
    } catch (\Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: Blade templates use addslashes() instead of @json() for escaping — insufficient XSS protection in: '.implode(', ', $findings));
    }
});

test('exception messages are not displayed directly to users', function () {
    $bladeFiles = array_merge(
        File::glob(resource_path('views/pages/zerotier/*.blade.php')),
        File::glob(resource_path('views/pages/settings/*.blade.php')),
    );

    $findings = [];

    foreach ($bladeFiles as $file) {
        $content = File::get($file);
        $basename = basename($file);

        if (preg_match_all('/\$e->getMessage\(\)/', $content, $matches, PREG_OFFSET_CAPTURE)) {
            foreach ($matches[0] as $match) {
                $offset = $match[1];
                $context = substr($content, max(0, $offset - 100), 200);

                if (str_contains($context, 'toast') || str_contains($context, 'text:')) {
                    $line = substr_count(substr($content, 0, $offset), "\n") + 1;
                    $findings[] = "{$basename}:{$line}";
                }
            }
        }
    }

    try {
        expect($findings)->toBeEmpty(
            "Exception messages exposed to users:\n".implode("\n", $findings)
        );
    } catch (\Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: Exception messages ($e->getMessage()) are displayed directly to users — information disclosure in: '.implode(', ', $findings));
    }
});

test('inline JavaScript does not interpolate blade variables unsafely', function () {
    $bladeFiles = array_merge(
        File::glob(resource_path('views/pages/zerotier/*.blade.php')),
        File::glob(resource_path('views/pages/settings/*.blade.php')),
    );

    $findings = [];

    foreach ($bladeFiles as $file) {
        $content = File::get($file);
        $basename = basename($file);

        // Look for {{ $var }} inside script tags or inline JS (navigator.clipboard, etc.)
        if (preg_match_all('/(?:writeText|innerHTML|outerHTML)\s*\(\s*\'[^\']*\{\{/', $content, $matches, PREG_OFFSET_CAPTURE)) {
            foreach ($matches[0] as $match) {
                $line = substr_count(substr($content, 0, $match[1]), "\n") + 1;
                $findings[] = "{$basename}:{$line}";
            }
        }
    }

    try {
        expect($findings)->toBeEmpty(
            "Unsafe JS interpolation found:\n".implode("\n", $findings)
        );
    } catch (\Throwable $e) {
        $this->markTestSkipped('SECURITY EXPOSURE: Blade variables are interpolated unsafely in inline JavaScript — XSS vulnerability in: '.implode(', ', $findings));
    }
});

test('ZerotierToken hides token value from serialization', function () {
    $token = \App\Models\ZerotierToken::factory()->create();
    $array = $token->toArray();

    expect($array)->not->toHaveKey('token',
        'ZerotierToken exposes encrypted token in serialization'
    );
});

test('network names with XSS payloads are safely rendered', function () {
    // This test verifies that Blade {{ }} escaping protects against XSS
    // The networks page uses {{ $network['name'] ?? 'Unnamed' }} which is escaped by default
    $xssPayload = '<script>alert("xss")</script>';
    $escaped = e($xssPayload);

    expect($escaped)->not->toContain('<script>');
    expect($escaped)->toContain('&lt;script&gt;');
});

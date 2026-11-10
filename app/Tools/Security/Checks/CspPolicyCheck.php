<?php

namespace App\Tools\Security\Checks;

use App\Tools\Security\AuditReport;

/**
 * What the Content-Security-Policy actually allows, not just whether the
 * header is sent. The policy only protects against injected markup while
 * scripts are limited to the nonce and our own origin; one 'unsafe-inline'
 * or `https:` added to "fix" a blocked script quietly turns it off.
 *
 * Fallbacks follow the spec: script-src and object-src fall back to
 * default-src; base-uri, form-action and frame-ancestors have no fallback.
 */
final class CspPolicyCheck
{
    public const CATEGORY = 'Content-Security-Policy';

    /**
     * @param  array<string, list<string>>  $directives  directive => sources
     * @param  string  $content  the file the policy is defined in, for line numbers
     * @return list<array<string, mixed>>
     */
    public function check(array $directives, string $file, string $content = ''): array
    {
        $directives = array_change_key_case($directives, CASE_LOWER);
        $findings = [];
        $add = function (string $severity, string $directive, string $description, string $remediation) use (&$findings, $file, $content) {
            $findings[] = AuditReport::finding($severity, self::CATEGORY, $file, $this->lineOf($content, $directive), $description, $remediation);
        };

        $scriptDirective = isset($directives['script-src']) ? 'script-src' : 'default-src';
        $scripts = $directives[$scriptDirective] ?? null;

        if ($scripts === null) {
            $add('high', 'script-src', 'The CSP has neither script-src nor default-src - scripts from anywhere can run', "Add script-src 'self' 'nonce-…'");
        } else {
            $lower = array_map('strtolower', $scripts);

            if (in_array("'unsafe-inline'", $lower, true)) {
                $add('high', $scriptDirective, "{$scriptDirective} allows 'unsafe-inline' - injected <script> tags and on* handlers run", "Remove 'unsafe-inline' and give the blocked script the nonce (Vite::cspNonce()) instead");
            }

            $open = array_values(array_filter($scripts, fn (string $s) => $this->anySource($s)));
            if ($open !== []) {
                $add('high', $scriptDirective, $scriptDirective.' allows scripts from '.implode(' ', $open).' - any site (or a data:/blob: URL) can supply script', 'Allow only \'self\', the nonce and specific https:// hosts');
            }

            if (in_array("'unsafe-eval'", $lower, true)) {
                $add('low', $scriptDirective, "{$scriptDirective} allows 'unsafe-eval' - injected Alpine attributes (x-data, x-init, @click) can still run code, so Blade escaping remains the defence there", "Drop it if Alpine's CSP build becomes usable with Livewire and Flux");
            }
        }

        if (! isset($directives['default-src'])) {
            $add('medium', 'default-src', 'The CSP has no default-src - any directive not listed (frames, media, workers, manifests) allows every host', "Add default-src 'self'");
        }

        foreach ($directives as $directive => $sources) {
            if ($directive === $scriptDirective) {
                continue;
            }
            if (in_array('*', $sources, true)) {
                $add('medium', $directive, "{$directive} allows any host (*)", 'List the hosts this directive needs');
            }
        }

        $objects = $directives['object-src'] ?? $directives['default-src'] ?? null;
        if ($objects !== ["'none'"]) {
            $add('medium', 'object-src', "object-src is not 'none' - plugin content (<object>, <embed>) can load and run outside the script rules", "Set object-src 'none'");
        }

        if (! isset($directives['base-uri'])) {
            $add('medium', 'base-uri', 'The CSP has no base-uri - an injected <base> tag can repoint every relative script and form URL', "Add base-uri 'self'");
        }

        if (! isset($directives['form-action'])) {
            $add('low', 'form-action', 'The CSP has no form-action - an injected form can post to another site', "Add form-action 'self'");
        }

        if (! isset($directives['frame-ancestors'])) {
            $add('low', 'frame-ancestors', 'The CSP has no frame-ancestors - only X-Frame-Options stops the app being framed', "Add frame-ancestors 'none'");
        }

        return $findings;
    }

    /** A source that matches any host: `*`, a wildcard host, or a bare scheme. */
    private function anySource(string $source): bool
    {
        return str_contains($source, '*') || (bool) preg_match('/^(?:https?|wss?|data|blob|filesystem):$/i', $source);
    }

    private function lineOf(string $content, string $directive): int
    {
        foreach (explode("\n", $content) as $i => $line) {
            if (str_contains($line, "'{$directive}'")) {
                return $i + 1;
            }
        }

        return 0;
    }
}

<?php

namespace App\Tools\Security\Checks;

use App\Tools\Security\AuditReport;

/**
 * Script in a Blade view that the Content-Security-Policy will block: Flux
 * directives without the nonce, <script> tags without it, inline on*
 * handlers and javascript: URLs.
 *
 * Blocked script fails closed (the page breaks rather than becoming unsafe),
 * but nothing else catches it before a deploy, and the tempting fix is to
 * loosen the policy. @vite and Livewire add the nonce themselves.
 */
final class CspNonceCheck
{
    public const CATEGORY = 'CSP Nonces';

    /** Script types the browser doesn't execute, so the CSP doesn't apply. */
    private const DATA_TYPES = '/\btype\s*=\s*["\']?(?:application\/(?:ld\+)?json|text\/template|text\/x-template|importmap)\b/i';

    /** @return list<array<string, mixed>> */
    public function check(string $file, string $content): array
    {
        if (! str_ends_with($file, '.blade.php')) {
            return [];
        }

        $findings = [];
        $add = function (int $offset, string $description, string $remediation) use (&$findings, $file, $content) {
            $line = substr_count(substr($content, 0, $offset), "\n") + 1;
            $findings[] = AuditReport::finding('medium', self::CATEGORY, $file, $line, $description, $remediation);
        };

        // Flux renders its own <script>/<style> tags and only adds a nonce when given one.
        preg_match_all('/@(fluxScripts|fluxAppearance)\b([^\n]*)/', $content, $m, PREG_SET_ORDER | PREG_OFFSET_CAPTURE);
        foreach ($m as $hit) {
            if (! str_contains($hit[2][0], 'nonce')) {
                $add($hit[0][1], "@{$hit[1][0]} has no nonce - the CSP blocks Flux's script and the page breaks", "Use @{$hit[1][0]}(['nonce' => Vite::cspNonce()])");
            }
        }

        preg_match_all('/<script\b[^>]*>/i', $content, $m, PREG_OFFSET_CAPTURE);
        foreach ($m[0] as [$tag, $offset]) {
            if (! preg_match('/\snonce\s*=/i', $tag) && ! preg_match(self::DATA_TYPES, $tag)) {
                $add($offset, '<script> tag has no nonce - the CSP blocks it', 'Add nonce="{{ Vite::cspNonce() }}", or move the code into resources/js');
            }
        }

        // Plain HTML handlers only; Alpine's x-on:/@ and wire: attributes are fine.
        preg_match_all('/<[a-zA-Z][\w:.-]*\b[^>]*?\s(on[a-z]+)\s*=/', $content, $m, PREG_SET_ORDER | PREG_OFFSET_CAPTURE);
        foreach ($m as $hit) {
            $add($hit[1][1], "Inline {$hit[1][0]}= handler - the CSP blocks it", 'Use an Alpine @'.substr($hit[1][0], 2).' handler or wire: action instead');
        }

        preg_match_all('/\b(?:href|src|action|formaction)\s*=\s*["\']\s*javascript:/i', $content, $m, PREG_OFFSET_CAPTURE);
        foreach ($m[0] as [, $offset]) {
            $add($offset, 'javascript: URL - the CSP blocks it', 'Use an Alpine @click handler or wire: action instead');
        }

        return $findings;
    }
}

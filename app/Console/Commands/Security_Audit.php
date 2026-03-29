<?php

namespace App\Console\Commands;

use App\Tools\Security\AuditReport;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;

class Security_Audit extends Command
{
    protected $signature = 'security:audit
        {--format=table : Output format (table, json)}
        {--severity=all : Filter by severity (critical, high, medium, low, info, all)}
        {--fix : Show remediation suggestions}';

    protected $description = 'Run static security analysis on the WireTier codebase';

    private array $findings = [];

    public function handle(): int
    {
        $this->info('WireTier Security Audit');
        $this->info('======================');
        $this->newLine();

        $this->scan_unscoped_find_or_fail();
        $this->scan_unscoped_network_queries();

        $this->scan_missing_authorization();
        $this->scan_mass_assignment();
        $this->scan_xss_unescaped_output();
        $this->scan_addslashes_usage();
        $this->scan_ssrf_risk();
        $this->scan_url_parameter_injection();
        $this->scan_information_disclosure();
        $this->scan_session_security();
        $this->scan_missing_security_headers();
        $this->scan_rate_limiting();
        $this->scan_password_reset_config();
        $this->scan_open_redirects();
        $this->scan_livewire_property_exposure();
        $this->scan_debug_mode();

        $format = $this->option('format');
        $severity = $this->option('severity');
        $showFix = $this->option('fix');

        if ($format === 'json') {
            $this->line(AuditReport::render_json($this->findings, $severity));
        } else {
            AuditReport::render_table($this, $this->findings, $severity, $showFix);
            AuditReport::render_summary($this, $this->findings);
        }

        $summary = AuditReport::summary($this->findings);

        return ($summary['critical'] + $summary['high']) > 0 ? 1 : 0;
    }

    // ─── Scan: Unscoped findOrFail ────────────────────────────────────

    private function scan_unscoped_find_or_fail(): void
    {
        $files = $this->get_zerotier_blade_files();

        foreach ($files as $file) {
            $content = File::get($file);
            $methods = $this->extract_methods($content);

            // ZerotierTokens are global (admin-managed) — no team_id scoping needed.
            // Only check ZerotierNetwork findOrFail for missing team scope.
            foreach ($methods as $method => $body) {
                if (str_contains($body, 'ZerotierNetwork::findOrFail') || str_contains($body, 'ZerotierNetwork::find(')) {
                    if (! str_contains($body, 'team_id') && ! str_contains($body, '->team->') && $method !== 'mount') {
                        $line = $this->find_line($content, 'ZerotierNetwork::find');
                        $this->findings[] = AuditReport::finding(
                            'critical',
                            'Team Isolation',
                            $file,
                            $line,
                            "ZerotierNetwork::find() in {$method}() has no team_id scope — any authenticated user can access any network",
                            "Add ->where('team_id', auth()->user()->team->id) or verify network belongs to current team before use"
                        );
                    }
                }
            }
        }
    }

    // ─── Scan: Unscoped ZerotierNetwork queries ──────────────────────

    private function scan_unscoped_network_queries(): void
    {
        $files = $this->get_zerotier_blade_files();

        foreach ($files as $file) {
            $content = File::get($file);

            // Look for ZerotierNetwork::where('network_id', ...) without team_id
            if (preg_match_all('/ZerotierNetwork::where\([\'"]network_id[\'"]/', $content, $matches, PREG_OFFSET_CAPTURE)) {
                foreach ($matches[0] as $match) {
                    $offset = $match[1];
                    // Get context: the next 200 chars after the match
                    $context = substr($content, $offset, 200);

                    if (! str_contains($context, 'team_id')) {
                        $line = substr_count(substr($content, 0, $offset), "\n") + 1;
                        $operation = str_contains($context, '->update') ? 'update' : (str_contains($context, '->delete') ? 'delete' : 'query');
                        $this->findings[] = AuditReport::finding(
                            'critical',
                            'Team Isolation',
                            $file,
                            $line,
                            "ZerotierNetwork::{$operation}() scoped by network_id only — missing team_id check allows cross-team modification",
                            "Chain ->where('team_id', auth()->user()->team->id) to scope the query"
                        );
                    }
                }
            }
        }
    }

    // Note: scan_global_token_loading removed — ZerotierTokens are intentionally
    // global (admin-managed). All teams share the same controller tokens.

    // ─── Scan: Missing authorization on public Livewire methods ──────

    private function scan_missing_authorization(): void
    {
        $files = $this->get_zerotier_blade_files();
        $lifecycle = ['mount', 'render', 'boot', 'booted', 'hydrate', 'dehydrate', 'updating', 'updated'];
        $authPatterns = ['isAdmin()', 'isTeamAdmin()', 'abort(403)', 'abort_unless(', 'TeamPermission::check('];

        foreach ($files as $file) {
            $content = File::get($file);
            $methods = $this->extract_methods($content);

            foreach ($methods as $method => $body) {
                // Skip lifecycle, getters, and non-state-changing methods
                if (in_array($method, $lifecycle)) {
                    continue;
                }
                if (str_starts_with($method, 'get') && str_ends_with($method, 'Property')) {
                    continue;
                }
                if (str_starts_with($method, 'updated')) {
                    continue;
                }
                if (str_starts_with($method, 'hydrate')) {
                    continue;
                }

                // Only flag methods that perform writes (API calls, DB updates, redirects)
                $isWriteMethod = str_contains($body, '->save()')
                    || str_contains($body, '->update(')
                    || str_contains($body, '->delete(')
                    || str_contains($body, '->create(')
                    || str_contains($body, 'authorizeMember')
                    || str_contains($body, 'deauthorizeMember')
                    || str_contains($body, 'deleteMember')
                    || str_contains($body, '$this->getService()->')
                    || str_contains($body, '->post(')
                    || str_contains($body, '->put(');

                if (! $isWriteMethod) {
                    continue;
                }

                // Check if method has any authorization check
                $hasAuth = false;
                foreach ($authPatterns as $pattern) {
                    if (str_contains($body, $pattern)) {
                        $hasAuth = true;
                        break;
                    }
                }

                if (! $hasAuth) {
                    $line = $this->find_line($content, "function {$method}(");
                    $this->findings[] = AuditReport::finding(
                        'high',
                        'Authorization',
                        $file,
                        $line,
                        "{$method}() performs state-changing operations without any authorization check",
                        'Add isAdmin(), isTeamAdmin(), or role-based check before performing the action'
                    );
                }
            }
        }
    }

    // ─── Scan: Mass assignment ($guarded = []) ───────────────────────

    private function scan_mass_assignment(): void
    {
        $modelPath = app_path('Models');
        $files = File::glob($modelPath.'/*.php');

        foreach ($files as $file) {
            $content = File::get($file);
            $basename = basename($file, '.php');

            // Check for $guarded = [] without $fillable
            if (preg_match('/\$guarded\s*=\s*\[\s*\]/', $content) && ! str_contains($content, '$fillable')) {
                // User model uses #[Fillable] attribute instead
                if (str_contains($content, '#[Fillable(')) {
                    continue;
                }

                $line = $this->find_line($content, '$guarded');
                $this->findings[] = AuditReport::finding(
                    'high',
                    'Mass Assignment',
                    $file,
                    $line,
                    "{$basename} uses \$guarded = [] with no \$fillable — all attributes are mass-assignable",
                    'Replace with explicit $fillable listing only the intended attributes'
                );
            }
        }
    }

    // ─── Scan: XSS - Unescaped output ────────────────────────────────

    private function scan_xss_unescaped_output(): void
    {
        $bladeFiles = $this->get_all_blade_files();

        foreach ($bladeFiles as $file) {
            $content = File::get($file);

            // {!! !!} — raw HTML output
            if (preg_match_all('/\{!!\s*(.+?)\s*!!\}/s', $content, $matches, PREG_OFFSET_CAPTURE)) {
                foreach ($matches[1] as $match) {
                    $variable = trim($match[0]);
                    $offset = $match[1];
                    $line = substr_count(substr($content, 0, $offset), "\n") + 1;

                    $this->findings[] = AuditReport::finding(
                        'high',
                        'XSS',
                        $file,
                        $line,
                        "Unescaped output {!! {$variable} !!} — potential XSS if data is user-controlled",
                        'Use {{ }} for escaped output, or validate the source is trusted'
                    );
                }
            }
        }
    }

    // ─── Scan: addslashes() misuse ───────────────────────────────────

    private function scan_addslashes_usage(): void
    {
        $bladeFiles = $this->get_all_blade_files();

        foreach ($bladeFiles as $file) {
            $content = File::get($file);

            if (preg_match_all('/addslashes\(/', $content, $matches, PREG_OFFSET_CAPTURE)) {
                foreach ($matches[0] as $match) {
                    $offset = $match[1];
                    $line = substr_count(substr($content, 0, $offset), "\n") + 1;

                    $this->findings[] = AuditReport::finding(
                        'medium',
                        'XSS',
                        $file,
                        $line,
                        'addslashes() used for escaping — insufficient for XSS prevention in HTML/JS contexts',
                        'Use @json() for JavaScript contexts or e() / {{ }} for HTML contexts'
                    );
                }
            }
        }
    }

    // ─── Scan: SSRF risk in ZerotierService ──────────────────────────

    private function scan_ssrf_risk(): void
    {
        $file = app_path('Services/ZerotierService.php');
        if (! File::exists($file)) {
            return;
        }

        $content = File::get($file);

        if (str_contains($content, '->baseUrl(') && str_contains($content, '$zerotierToken->host')) {
            $line = $this->find_line($content, 'baseUrl');
            $this->findings[] = AuditReport::finding(
                'medium',
                'SSRF',
                $file,
                $line,
                'ZerotierToken host URL used directly as HTTP base URL — no validation against internal addresses',
                'Validate host is not a private/internal IP (127.x, 10.x, 172.16-31.x, 169.254.x, etc.) before making requests'
            );
        }

        // Hardcoded localhost fallback
        if (str_contains($content, 'http://localhost:9993')) {
            $line = $this->find_line($content, 'localhost:9993');
            $this->findings[] = AuditReport::finding(
                'low',
                'SSRF',
                $file,
                $line,
                'Hardcoded localhost:9993 fallback when token is empty — could query local ZeroTier instance',
                'Throw an exception if token is empty rather than falling back to localhost'
            );
        }
    }

    // ─── Scan: URL parameter injection ───────────────────────────────

    private function scan_url_parameter_injection(): void
    {
        $file = app_path('Services/ZerotierService.php');
        if (! File::exists($file)) {
            return;
        }

        $content = File::get($file);

        // Find string interpolation in HTTP paths
        if (preg_match_all('/->(?:get|post|delete)\(\s*"[^"]*\{\$\w+\}/', $content, $matches, PREG_OFFSET_CAPTURE)) {
            $reported = false;
            foreach ($matches[0] as $match) {
                if (! $reported) {
                    $offset = $match[1];
                    $line = substr_count(substr($content, 0, $offset), "\n") + 1;
                    $this->findings[] = AuditReport::finding(
                        'medium',
                        'Injection',
                        $file,
                        $line,
                        'User-supplied parameters interpolated directly into HTTP URL paths without format validation',
                        'Validate networkId/nodeId as hex-only strings (e.g. /^[a-f0-9]+$/) before interpolation'
                    );
                    $reported = true;
                }
            }
        }
    }

    // ─── Scan: Information disclosure ─────────────────────────────────

    private function scan_information_disclosure(): void
    {
        $bladeFiles = $this->get_all_blade_files();

        foreach ($bladeFiles as $file) {
            $content = File::get($file);

            // $e->getMessage() displayed to user
            if (preg_match_all('/\$e->getMessage\(\)/', $content, $matches, PREG_OFFSET_CAPTURE)) {
                foreach ($matches[0] as $match) {
                    $offset = $match[1];
                    $context = substr($content, max(0, $offset - 100), 200);

                    // Only flag if it's in a toast/flash (user-visible)
                    if (str_contains($context, 'toast') || str_contains($context, 'flash') || str_contains($context, 'text:')) {
                        $line = substr_count(substr($content, 0, $offset), "\n") + 1;
                        $this->findings[] = AuditReport::finding(
                            'medium',
                            'Info Disclosure',
                            $file,
                            $line,
                            'Exception message displayed to user — may leak internal details (paths, API errors, SQL)',
                            'Log the full exception server-side, show a generic error to the user'
                        );
                    }
                }
            }
        }
    }

    // ─── Scan: Session security ──────────────────────────────────────

    private function scan_session_security(): void
    {
        $file = config_path('session.php');
        if (! File::exists($file)) {
            return;
        }

        $content = File::get($file);

        // Session encryption
        if (str_contains($content, 'SESSION_ENCRYPT') && str_contains($content, 'false')) {
            $line = $this->find_line($content, 'encrypt');
            $this->findings[] = AuditReport::finding(
                'medium',
                'Session Security',
                $file,
                $line,
                'Session encryption defaults to false — session data stored unencrypted',
                'Set SESSION_ENCRYPT=true in production .env'
            );
        }

        // Secure cookie
        if (str_contains($content, 'SESSION_SECURE_COOKIE') && ! str_contains($content, 'true')) {
            $line = $this->find_line($content, 'secure');
            $this->findings[] = AuditReport::finding(
                'low',
                'Session Security',
                $file,
                $line,
                'Session secure cookie not enforced by default — cookies may transmit over HTTP',
                'Set SESSION_SECURE_COOKIE=true in production .env'
            );
        }
    }

    // ─── Scan: Missing security headers ──────────────────────────────

    private function scan_missing_security_headers(): void
    {
        $file = base_path('bootstrap/app.php');
        if (! File::exists($file)) {
            return;
        }

        $content = File::get($file);

        // Check for security headers middleware
        $hasSecurityHeaders = str_contains($content, 'X-Frame-Options')
            || str_contains($content, 'SecurityHeaders')
            || str_contains($content, 'Content-Security-Policy');

        if (! $hasSecurityHeaders) {
            $this->findings[] = AuditReport::finding(
                'medium',
                'Security Headers',
                $file,
                0,
                'No security headers middleware configured (X-Frame-Options, CSP, X-Content-Type-Options, HSTS)',
                'Add middleware to set X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Strict-Transport-Security, and Content-Security-Policy'
            );
        }

        // Check Livewire update endpoint is behind auth
        $hasProtectedUpdate = str_contains($content, 'setUpdateRoute')
            && str_contains($content, "'auth'");

        if (! $hasProtectedUpdate) {
            $this->findings[] = AuditReport::finding(
                'high',
                'Livewire Update Endpoint',
                $file,
                0,
                'Livewire update endpoint is not restricted to authenticated users — unauthenticated requests can interact with Livewire components',
                "Add Livewire::setUpdateRoute() in bootstrap/app.php with ['web', 'auth'] middleware"
            );
        }
    }

    // ─── Scan: Rate limiting gaps ────────────────────────────────────

    private function scan_rate_limiting(): void
    {
        $routeFiles = [base_path('routes/web.php'), base_path('routes/settings.php')];

        foreach ($routeFiles as $file) {
            if (! File::exists($file)) {
                continue;
            }
            $content = File::get($file);

            if (! str_contains($content, 'throttle') && ! str_contains($content, 'RateLimiter')) {
                $this->findings[] = AuditReport::finding(
                    'medium',
                    'Rate Limiting',
                    $file,
                    0,
                    'No rate limiting middleware applied to routes — vulnerable to brute force and abuse',
                    'Add throttle middleware to sensitive routes (team operations, ZeroTier API calls)'
                );
            }
        }

        // Check Livewire components for rate limiting on write operations
        $files = $this->get_zerotier_blade_files();
        foreach ($files as $file) {
            $content = File::get($file);
            $basename = basename($file);

            // Components that interact with external APIs should have rate limiting
            if (str_contains($content, 'ZerotierService') && ! str_contains($content, 'RateLimiter') && ! str_contains($content, 'throttle')) {
                $this->findings[] = AuditReport::finding(
                    'medium',
                    'Rate Limiting',
                    $file,
                    0,
                    "No rate limiting on ZeroTier API calls in {$basename} — external API can be abused",
                    'Implement per-user rate limiting on methods that make external API calls'
                );
            }
        }
    }

    // ─── Scan: Password reset config ─────────────────────────────────

    private function scan_password_reset_config(): void
    {
        $file = config_path('auth.php');
        if (! File::exists($file)) {
            return;
        }

        $content = File::get($file);

        if (preg_match("/'expire'\s*=>\s*(\d+)/", $content, $match)) {
            $expiry = (int) $match[1];
            if ($expiry > 30) {
                $line = $this->find_line($content, "'expire'");
                $this->findings[] = AuditReport::finding(
                    'medium',
                    'Authentication',
                    $file,
                    $line,
                    "Password reset token expires in {$expiry} minutes — recommended max is 30 minutes",
                    'Reduce password reset token expiry to 15-30 minutes'
                );
            }
        }
    }

    // ─── Scan: Open redirects ────────────────────────────────────────

    private function scan_open_redirects(): void
    {
        $files = [base_path('routes/web.php'), base_path('routes/settings.php')];

        foreach ($files as $file) {
            if (! File::exists($file)) {
                continue;
            }
            $content = File::get($file);

            if (str_contains($content, 'redirect()->back()')) {
                $line = $this->find_line($content, 'redirect()->back()');
                $this->findings[] = AuditReport::finding(
                    'low',
                    'Open Redirect',
                    $file,
                    $line,
                    'redirect()->back() follows Referer header — potential open redirect if Referer is manipulated',
                    "Use redirect('/dashboard') or redirect()->intended() with a safe default"
                );
            }
        }
    }

    // ─── Scan: Livewire property exposure ────────────────────────────

    private function scan_livewire_property_exposure(): void
    {
        $files = array_merge($this->get_zerotier_blade_files(), $this->get_settings_blade_files());

        foreach ($files as $file) {
            $content = File::get($file);
            $basename = basename($file);

            // Look for public properties that are models or contain sensitive data
            if (preg_match_all('/public\s+(?:Team|User|ZerotierToken)\s+\$(\w+)/', $content, $matches, PREG_OFFSET_CAPTURE)) {
                foreach ($matches[1] as $match) {
                    $propName = $match[0];
                    $offset = $match[1];
                    $line = substr_count(substr($content, 0, $offset), "\n") + 1;

                    $this->findings[] = AuditReport::finding(
                        'medium',
                        'Data Exposure',
                        $file,
                        $line,
                        "Eloquent model exposed as public Livewire property \${$propName} — all attributes sent to client",
                        'Use #[Locked] attribute or expose only specific fields instead of full model'
                    );
                }
            }
        }
    }

    // ─── Scan: Debug mode default ────────────────────────────────────

    private function scan_debug_mode(): void
    {
        $file = base_path('.env.example');
        if (! File::exists($file)) {
            return;
        }

        $content = File::get($file);

        if (preg_match('/APP_DEBUG\s*=\s*true/i', $content)) {
            $line = $this->find_line($content, 'APP_DEBUG');
            $this->findings[] = AuditReport::finding(
                'low',
                'Info Disclosure',
                $file,
                $line,
                'APP_DEBUG=true in .env.example — developers may copy this to production and leak stack traces',
                'Set APP_DEBUG=false in .env.example to encourage secure defaults'
            );
        }
    }

    // ─── Helpers ─────────────────────────────────────────────────────

    private function get_zerotier_blade_files(): array
    {
        $dir = resource_path('views/pages/zerotier');
        if (! File::isDirectory($dir)) {
            return [];
        }

        return File::glob($dir.'/*.blade.php');
    }

    private function get_settings_blade_files(): array
    {
        $dir = resource_path('views/pages/settings');
        if (! File::isDirectory($dir)) {
            return [];
        }

        return File::glob($dir.'/*.blade.php');
    }

    private function get_all_blade_files(): array
    {
        return array_merge(
            $this->get_zerotier_blade_files(),
            $this->get_settings_blade_files(),
            File::glob(resource_path('views/pages/*.blade.php')),
        );
    }

    private function extract_methods(string $content): array
    {
        $methods = [];

        // Extract the PHP class section (before the Blade template)
        if (preg_match('/^<\?php(.+?)\?>/s', $content, $phpSection)) {
            $php = $phpSection[1];

            // Match public/protected function declarations and their bodies
            if (preg_match_all('/(?:public|protected)\s+function\s+(\w+)\s*\([^)]*\)[^{]*\{/s', $php, $matches, PREG_OFFSET_CAPTURE)) {
                for ($i = 0; $i < count($matches[0]); $i++) {
                    $methodName = $matches[1][$i][0];
                    $startOffset = $matches[0][$i][1] + strlen($matches[0][$i][0]);

                    // Find matching closing brace
                    $depth = 1;
                    $pos = $startOffset;
                    while ($pos < strlen($php) && $depth > 0) {
                        if ($php[$pos] === '{') {
                            $depth++;
                        }
                        if ($php[$pos] === '}') {
                            $depth--;
                        }
                        $pos++;
                    }

                    $methods[$methodName] = substr($php, $startOffset, $pos - $startOffset - 1);
                }
            }
        }

        return $methods;
    }

    private function find_line(string $content, string $needle): int
    {
        $pos = strpos($content, $needle);
        if ($pos === false) {
            return 0;
        }

        return substr_count(substr($content, 0, $pos), "\n") + 1;
    }
}

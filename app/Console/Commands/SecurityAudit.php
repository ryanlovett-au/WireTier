<?php

namespace App\Console\Commands;

use App\Http\Middleware\SecurityHeaders;
use App\Tools\Security\Analysis\LivewireSurface;
use App\Tools\Security\Analysis\PhpSource;
use App\Tools\Security\AuditReport;
use App\Tools\Security\Checks\ClientInputLookupCheck;
use App\Tools\Security\Checks\ControllerApiInputCheck;
use App\Tools\Security\Checks\ControllerPayloadCheck;
use App\Tools\Security\Checks\CspNonceCheck;
use App\Tools\Security\Checks\CspPolicyCheck;
use App\Tools\Security\Checks\CurrentTeamRoleCheck;
use App\Tools\Security\Checks\JsAttributeEchoCheck;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use Symfony\Component\Process\ExecutableFinder;
use Symfony\Component\Process\Process;

/**
 * Static security audit of the WireTier codebase.
 *
 * Ported from the scanner shared by our sister apps (OMS, then Moonscape,
 * which added the tokenizer/taint analysis in app/Tools/Security). Generic
 * scanners are kept as-is; the WireTier-specific ones cover what made it
 * vulnerable in practice: ZeroTier controller calls aimed at a client-chosen
 * network (Controller API Input), roles checked on the current team while
 * acting on another (Current-Team Role Check), and the system-admin check.
 */
class SecurityAudit extends Command
{
    protected $signature = 'security:audit
        {--output=table : Output format (table, json)}
        {--severity=all : Filter by severity (critical, high, medium, low, info, all)}
        {--fix : Show remediation suggestions}
        {--category= : Filter by category substring (e.g. "Livewire Client Input")}
        {--offline : Skip the dependency advisory check (it queries the composer and npm advisory databases)}';

    protected $description = 'Run a static security audit of the WireTier codebase';

    /**
     * Models owned by a team: every lookup must be tied to the caller's team.
     */
    public const TEAM_SCOPED_MODELS = ['ZerotierNetwork', 'ZerotierMember', 'TeamInvitation', 'FlowRuleRevision'];

    /**
     * Models every team may look up by a client-chosen key by design.
     * Controllers (ZerotierToken) are shared: any team may create networks
     * on any active controller, and only system admins manage them.
     */
    public const SHARED_MODELS = ['ZerotierToken'];

    /**
     * Models whose public Livewire exposure would leak hidden attributes.
     */
    public const SENSITIVE_MODELS = ['User', 'ZerotierToken'];

    /**
     * Reviewed findings that are correct by design. Each entry names the
     * category, the file by path suffix (matched at a path boundary), a
     * substring of the description, and why it's accepted. An entry that no
     * longer matches anything is reported as stale, so the list can't quietly
     * hide a different finding later.
     *
     * @var list<array{category: string, file: string, match: string, reason: string}>
     */
    public const SUPPRESSIONS = [
        [
            'category' => 'Dangerous Functions',
            'file' => 'app/Console/Commands/Security_Test.php',
            'match' => 'passthru()',
            'reason' => 'security:test runs Pest with a fixed command built from PHP_BINARY and the project path; no user input reaches it.',
        ],
        [
            'category' => 'XSS',
            'file' => 'resources/views/welcome.blade.php',
            'match' => '{!! $iconPath !!}',
            'reason' => 'Feature-card SVG paths are string literals defined in the same template; nothing user-supplied is rendered.',
        ],
        [
            'category' => 'Content-Security-Policy',
            'file' => 'app/Http/Middleware/SecurityHeaders.php',
            'match' => "'unsafe-eval'",
            'reason' => 'Alpine (bundled with Livewire, used by Flux) evaluates directive expressions with new Function(); its CSP build does not support Livewire and Flux. Blade escaping and the Alpine/Livewire JS Injection check cover injected attributes.',
        ],
    ];

    /**
     * Whether scanners() includes the dependency advisory check. Off unless
     * handle() turns it on, so tests calling scanners() stay offline.
     */
    public bool $includeDependencies = false;

    public function handle(): int
    {
        $this->includeDependencies = ! $this->option('offline');
        $json = $this->option('output') === 'json';
        $progress = fn (string $line) => $json ? null : $this->line($line);

        if (! $json) {
            $this->info('Starting WireTier security audit...');
            $this->newLine();
        }

        $findings = [];
        foreach ($this->scanners() as $label => $scan) {
            $progress('  Scanning: '.$label.'...');
            $findings = array_merge($findings, $scan());
        }

        if (! $json) {
            $this->newLine();
            $this->info('Scan complete.');
        }

        [$findings, $suppressed, $stale] = self::applySuppressions($findings, static::SUPPRESSIONS);
        foreach ($stale as $entry) {
            $findings[] = AuditReport::finding(
                'medium',
                'Stale Suppression',
                $entry['file'],
                0,
                'Suppression for '.$entry['category'].' "'.$entry['match'].'" no longer matches any finding - remove it or update it',
                'Delete the entry from SecurityAudit::SUPPRESSIONS',
            );
        }

        if ($suppressed > 0 && ! $json) {
            $this->line("  Excluded {$suppressed} reviewed finding(s) (see SecurityAudit::SUPPRESSIONS).");
            $this->newLine();
        }

        if ($category = $this->option('category')) {
            $findings = array_values(array_filter(
                $findings,
                fn ($f) => stripos($f['category'], $category) !== false,
            ));
        }

        $severity = $this->option('severity');
        $showFix = (bool) $this->option('fix');

        if ($json) {
            $this->line(AuditReport::renderJson($findings, $severity));
        } else {
            AuditReport::renderTable($this, $findings, $severity, $showFix);
            AuditReport::renderSummary($this, $findings);
        }

        $summary = AuditReport::summary(AuditReport::filter($findings, $severity));

        return ($summary['critical'] > 0 || $summary['high'] > 0) ? self::FAILURE : self::SUCCESS;
    }

    /**
     * Every scanner, by label. Public so the scanner tests can run the whole
     * audit and individual scanners.
     *
     * @return array<string, callable(): list<array<string, mixed>>>
     */
    public function scanners(): array
    {
        $livewire = fn () => $this->livewireComponentFiles();

        $dependencies = $this->includeDependencies
            ? ['Dependency Advisories' => fn () => $this->scanDependencies()]
            : [];

        return $dependencies + [
            // Access control
            'Livewire Client Input' => fn () => $this->runSourceCheck(new ClientInputLookupCheck(self::SHARED_MODELS), $livewire()),
            'Controller API Input' => fn () => $this->runSourceCheck(new ControllerApiInputCheck, $livewire()),
            'Current-Team Role Checks' => fn () => $this->runSourceCheck(new CurrentTeamRoleCheck, $livewire()),
            'Livewire Authorization' => fn () => $this->scanLivewireAuthorization(),
            'Admin Check Integrity' => fn () => $this->scanAdminCheckIntegrity(),
            'Livewire Update Endpoint' => fn () => $this->scanLivewireUpdateEndpoint(),
            'Unauthenticated Routes' => fn () => $this->scanUnauthenticatedRoutes(),
            'Route Model Binding' => fn () => $this->scanRouteModelBinding(),

            // Injection and output
            'SQL Injection' => fn () => $this->scanSqlInjection(),
            'Controller URL Paths' => fn () => $this->scanControllerUrlPaths(),
            'Controller Payload Validation' => fn () => $this->runSourceCheck(new ControllerPayloadCheck, $livewire()),
            'Blade XSS' => fn () => $this->scanBladeXss(),
            'Alpine/Livewire JS Injection' => function () {
                $check = new JsAttributeEchoCheck;
                $out = [];
                foreach ($this->allBladeFiles() as $file) {
                    array_push($out, ...$check->check($file, (string) file_get_contents($file)));
                }

                return $out;
            },
            'Dangerous Functions' => fn () => $this->scanDangerousFunctions(),
            'Open Redirects' => fn () => $this->scanOpenRedirects(),
            'Controller Host (SSRF)' => fn () => $this->scanControllerHost(),

            // Data handling
            'Mass Assignment' => fn () => $this->scanMassAssignment(),
            'Livewire Model Exposure' => fn () => $this->scanLivewireModelExposure(),
            'Livewire File Uploads' => fn () => $this->scanLivewireFileUploads(),
            'Credential Exposure' => fn () => $this->scanCredentialExposure(),
            'Sensitive Logging' => fn () => $this->scanSensitiveLogging(),
            'Exception Disclosure' => fn () => $this->scanExceptionDisclosure(),

            // Configuration
            'Rate Limiting' => fn () => $this->scanRateLimiting(),
            'Session Configuration' => fn () => $this->scanSessionConfig(),
            'CSRF Exclusions' => fn () => $this->scanCsrfExclusions(),
            'Security Headers' => fn () => $this->scanSecurityHeaders(),
            'Content-Security-Policy' => fn () => $this->scanContentSecurityPolicy(),
            'CSP Nonces' => function () {
                $check = new CspNonceCheck;
                $out = [];
                foreach ($this->allBladeFiles() as $file) {
                    array_push($out, ...$check->check($file, (string) file_get_contents($file)));
                }

                return $out;
            },
            'Password Reset Expiry' => fn () => $this->scanPasswordResetExpiry(),
            'Debug Default' => fn () => $this->scanDebugDefault(),
        ];
    }

    /**
     * @param  list<string>  $files
     * @return list<array<string, mixed>>
     */
    private function runSourceCheck(object $check, array $files): array
    {
        $out = [];
        foreach (array_unique($files) as $file) {
            array_push($out, ...$check->check(PhpSource::fromFile($file)));
        }

        return $out;
    }

    /**
     * Drop findings a suppression covers; return what's left, how many were
     * dropped, and the suppressions that matched nothing.
     *
     * @param  list<array<string, mixed>>  $findings
     * @param  list<array{category: string, file: string, match: string, reason: string}>  $suppressions
     * @return array{0: list<array<string, mixed>>, 1: int, 2: list<array{category: string, file: string, match: string, reason: string}>}
     */
    public static function applySuppressions(array $findings, array $suppressions): array
    {
        $used = array_fill(0, count($suppressions), false);
        $kept = [];
        foreach ($findings as $f) {
            $hit = false;
            foreach ($suppressions as $i => $sup) {
                if (self::suppresses($sup, $f)) {
                    $used[$i] = $hit = true;
                }
            }
            if (! $hit) {
                $kept[] = $f;
            }
        }
        $stale = [];
        foreach ($suppressions as $i => $sup) {
            if (! $used[$i]) {
                $stale[] = $sup;
            }
        }

        return [$kept, count($findings) - count($kept), $stale];
    }

    /** @param array{category: string, file: string, match: string} $sup */
    public static function suppresses(array $sup, array $finding): bool
    {
        $file = str_replace('\\', '/', (string) $finding['file']);
        $suffix = ltrim(str_replace('\\', '/', $sup['file']), '/');

        return $finding['category'] === $sup['category']
            && ($file === $suffix || str_ends_with($file, '/'.$suffix))
            && str_contains((string) $finding['description'], $sup['match']);
    }

    // ─── WireTier scanners ───────────────────────────────────────────────────

    /** Role/admin helpers that authorise an action. */
    private const ROLE_GATES = '/->(?:isAdmin|isTeamAdmin|canManageNetworks|canAdministerTeam|canAdminister)\s*\(|\$this->authorize\s*\(|Gate::(?:allows|denies|authorize)/';

    /** ZerotierService calls that change controller state. */
    private const CONTROLLER_WRITES = '/->(?:createNetwork|updateNetwork|deleteNetwork|updateNetworkMember|authorizeMember|deauthorizeMember|deleteMember|joinNetwork|leaveNetwork)\s*\(|FlowRulesService|->apply\s*\(/';

    /**
     * Flag client-callable Livewire actions that change team resources (in
     * the database or on a ZeroTier controller) with no role check at all.
     * Who may act is this scanner's question; which record they may act on
     * is the Client Input / Controller API Input checks'.
     */
    private function scanLivewireAuthorization(): array
    {
        $findings = [];
        $models = '/\b(?:'.implode('|', [...self::TEAM_SCOPED_MODELS, ...self::SHARED_MODELS, 'Team', 'TeamUser']).')\b/';
        $dbWrites = '/->(?:create|update|delete|save|forceDelete|firstOrCreate|updateOrCreate|destroy)\s*\(|::(?:create|destroy|firstOrCreate|updateOrCreate)\s*\(/';

        foreach ($this->livewireComponentFiles() as $file) {
            $source = PhpSource::fromFile($file);
            if (! $source->isLivewire()) {
                continue;
            }
            $surface = new LivewireSurface($source);

            foreach ($source->methods() as $method) {
                if (! $surface->isClientCallable($method)) {
                    continue;
                }
                $body = $method->body;

                $controllerWrite = (bool) preg_match(self::CONTROLLER_WRITES, $body);
                $teamWrite = preg_match($dbWrites, $body) && preg_match($models, $body);
                if (! $controllerWrite && ! $teamWrite) {
                    continue;
                }

                if (preg_match(self::ROLE_GATES, $body) || $this->gatedViaHelper($source, $body)) {
                    continue;
                }

                // Self-service: only the caller's own membership row is reachable.
                if (preg_match('/where\s*\(\s*[\'"]user_id[\'"]\s*,\s*auth\(\)->(?:id\(\)|user\(\)->id)/', $body)) {
                    continue;
                }

                $findings[] = AuditReport::finding(
                    'high',
                    'Livewire Authorization',
                    $file,
                    $method->startLine,
                    $method->name.'() changes team resources'.($controllerWrite ? ' on the ZeroTier controller' : '').' with no role check',
                    'Gate it with canManageNetworks() / isTeamAdmin() for the current team, or canAdministerTeam($teamId) for a specific team',
                );
            }
        }

        return $findings;
    }

    private function gatedViaHelper(PhpSource $source, string $body): bool
    {
        if (! preg_match_all('/\$this->(\w+)\s*\(/', $body, $calls)) {
            return false;
        }
        foreach ($calls[1] as $name) {
            $helper = $source->method($name);
            if ($helper !== null && preg_match(self::ROLE_GATES, $helper->body)) {
                return true;
            }
        }

        return false;
    }

    /**
     * User::isAdmin() grants system-wide access. Selecting the admin team as
     * the current team must not be enough: the user has to still hold an
     * unexpired membership of it, or a removed admin keeps their access.
     */
    private function scanAdminCheckIntegrity(): array
    {
        $file = app_path('Models/User.php');
        if (! File::exists($file)) {
            return [];
        }

        $method = PhpSource::fromFile($file)->method('isAdmin');
        if ($method === null) {
            return [];
        }

        $checksMembership = preg_match('/TeamUser::|->teams\(\)|teamUser\b|belongsToTeam\s*\(/', $method->body);
        $checksExpiry = preg_match('/active\(\)|expires|expired/', $method->body);

        if ($checksMembership && $checksExpiry) {
            return [];
        }

        return [AuditReport::finding(
            'critical',
            'Admin Check Integrity',
            $file,
            $method->startLine,
            $checksMembership
                ? 'isAdmin() checks admin-team membership but not its expiry - an expired admin keeps system-wide access'
                : 'isAdmin() trusts the selected current_team without checking admin-team membership - a removed admin keeps system-wide access',
            'Require an unexpired TeamUser row for the admin team, e.g. TeamUser::where(...)->active()->exists()',
        )];
    }

    /**
     * Network and member IDs are interpolated into controller URL paths;
     * every such method must validate them first.
     */
    private function scanControllerUrlPaths(): array
    {
        $file = app_path('Services/ZerotierService.php');
        if (! File::exists($file)) {
            return [];
        }

        $findings = [];
        foreach (PhpSource::fromFile($file)->methods() as $method) {
            if (! preg_match_all('/->(?:get|post|put|patch|delete)\s*\(\s*"[^"]*\{\$(\w+)\}/', $method->body, $m)) {
                continue;
            }
            foreach (array_unique($m[1]) as $var) {
                if (! preg_match('/validatePathSegment\s*\(\s*\$'.preg_quote($var, '/').'\b/', $method->body)) {
                    $findings[] = AuditReport::finding(
                        'high',
                        'Controller URL Paths',
                        $file,
                        $method->startLine,
                        $method->name.'() interpolates $'.$var.' into a controller URL path without validatePathSegment()',
                        'Call self::validatePathSegment($'.$var.', ...) before building the URL',
                    );
                }
            }
        }

        return $findings;
    }

    /**
     * Controller hosts are admin-entered URLs used as the HTTP base URL; the
     * scheme must be restricted so a host can't become file://, gopher:// etc.
     */
    private function scanControllerHost(): array
    {
        $file = app_path('Services/ZerotierService.php');
        if (! File::exists($file)) {
            return [];
        }

        $content = File::get($file);
        if (str_contains($content, '->baseUrl(') && ! (str_contains($content, 'parse_url') && preg_match("/\['http',\s*'https'\]/", $content))) {
            return [AuditReport::finding(
                'medium',
                'Controller Host (SSRF)',
                $file,
                $this->lineOf($content, '->baseUrl('),
                'Controller host URL is used as the HTTP base URL without restricting its scheme to http/https',
                'Validate parse_url($host, PHP_URL_SCHEME) is http or https before building the client',
            )];
        }

        return [];
    }

    /**
     * Public Livewire properties holding a model with hidden attributes:
     * Livewire dehydrates the model into the page, so keep it off the client.
     */
    private function scanLivewireModelExposure(): array
    {
        $findings = [];
        foreach ($this->livewireComponentFiles() as $file) {
            $source = PhpSource::fromFile($file);
            if (! $source->isLivewire()) {
                continue;
            }
            foreach ($source->properties() as $p) {
                $type = $p['type'] === null ? null : basename(str_replace('\\', '/', $p['type']));
                if ($p['visibility'] === 'public' && in_array($type, self::SENSITIVE_MODELS, true)) {
                    $findings[] = AuditReport::finding(
                        'medium',
                        'Livewire Model Exposure',
                        $file,
                        $p['line'],
                        "Public property \${$p['name']} holds a {$type} model - it is dehydrated into the page",
                        'Expose only the fields the view needs, or keep the model in a protected property',
                    );
                }
            }
        }

        return $findings;
    }

    /**
     * Exception messages shown to users can leak paths, SQL and controller
     * internals. Toasts and flashes should show a generic message.
     */
    private function scanExceptionDisclosure(): array
    {
        $findings = [];
        foreach ($this->livewireComponentFiles() as $file) {
            $lines = $this->lines($file);
            foreach ($lines as $i => $line) {
                if ($this->isCommentLine($line) || ! preg_match('/\$\w+->getMessage\(\)/', $line)) {
                    continue;
                }
                $window = implode("\n", array_slice($lines, max(0, $i - 3), 7));
                if (preg_match('/Flux::toast|session\(\)->flash|->flash\(|text:/', $window)) {
                    $findings[] = AuditReport::finding(
                        'medium',
                        'Exception Disclosure',
                        $file,
                        $i + 1,
                        'Exception message shown to the user - may leak internal details',
                        'Log the exception (report($e)) and show a generic message',
                    );
                }
            }
        }

        return $findings;
    }

    private function scanPasswordResetExpiry(): array
    {
        $file = config_path('auth.php');
        if (! File::exists($file)) {
            return [];
        }

        $content = File::get($file);
        if (preg_match("/'expire'\s*=>\s*(\d+)/", $content, $m) && (int) $m[1] > 60) {
            return [AuditReport::finding(
                'low',
                'Password Reset Expiry',
                $file,
                $this->lineOf($content, "'expire'"),
                "Password reset links stay valid for {$m[1]} minutes",
                'Keep reset links to 60 minutes or less',
            )];
        }

        return [];
    }

    private function scanDebugDefault(): array
    {
        $file = base_path('.env.example');
        if (! File::exists($file)) {
            return [];
        }

        $content = File::get($file);
        if (preg_match('/^APP_DEBUG\s*=\s*true/mi', $content) && preg_match('/^APP_ENV\s*=\s*production/mi', $content)) {
            return [AuditReport::finding(
                'medium',
                'Debug Default',
                $file,
                $this->lineOf($content, 'APP_DEBUG'),
                'APP_DEBUG=true alongside APP_ENV=production in .env.example - copied as-is it leaks stack traces',
                'Set APP_DEBUG=false in the production example',
            )];
        }

        return [];
    }

    /**
     * Known vulnerabilities in installed packages: composer audit (PHP) and
     * npm audit (JS, production dependencies). Both query advisory databases,
     * so this needs network access; a tool that can't run is reported as info
     * rather than failing the audit.
     */
    private function scanDependencies(): array
    {
        $findings = [];

        if (File::exists(base_path('composer.lock'))) {
            $result = $this->runJsonTool(['composer', 'audit', '--format=json', '--locked', '--no-interaction']);
            $findings = is_array($result)
                ? array_merge($findings, self::parseComposerAudit($result, base_path('composer.lock')))
                : array_merge($findings, [$this->toolUnavailable('composer audit', $result, 'composer.lock')]);
        }

        if (File::exists(base_path('package-lock.json'))) {
            $result = $this->runJsonTool(['npm', 'audit', '--omit=dev', '--json']);
            $findings = is_array($result)
                ? array_merge($findings, self::parseNpmAudit($result, base_path('package-lock.json')))
                : array_merge($findings, [$this->toolUnavailable('npm audit', $result, 'package-lock.json')]);
        }

        return $findings;
    }

    /**
     * Run a tool that prints JSON. Audit tools exit non-zero when they find
     * something, so the exit code is ignored and stdout is parsed instead.
     *
     * @param  list<string>  $command
     * @return array<string, mixed>|string decoded JSON, or why it couldn't run
     */
    private function runJsonTool(array $command): array|string
    {
        $binary = (new ExecutableFinder)->find($command[0]);
        if ($binary === null) {
            return $command[0].' is not installed or not on PATH';
        }

        $process = new Process([$binary, ...array_slice($command, 1)], base_path(), null, null, 120);
        try {
            $process->run();
        } catch (\Throwable $e) {
            return $e->getMessage();
        }

        $decoded = json_decode($process->getOutput(), true);

        return is_array($decoded) ? $decoded : (trim($process->getErrorOutput()) ?: 'no JSON output');
    }

    private function toolUnavailable(string $tool, string $reason, string $file): array
    {
        return AuditReport::finding(
            'info',
            'Dependency Advisories',
            base_path($file),
            0,
            "Could not run {$tool} ({$reason}) - dependency advisories were not checked",
            'Run the audit with network access, or check '.$file.' manually',
        );
    }

    /**
     * Findings from `composer audit --format=json`.
     *
     * @param  array<string, mixed>  $report
     * @return list<array<string, mixed>>
     */
    public static function parseComposerAudit(array $report, string $file): array
    {
        $findings = [];

        foreach ($report['advisories'] ?? [] as $package => $advisories) {
            foreach ($advisories as $advisory) {
                $severity = strtolower((string) ($advisory['severity'] ?? ''));
                $id = $advisory['cve'] ?? $advisory['advisoryId'] ?? null;
                $findings[] = AuditReport::finding(
                    in_array($severity, ['critical', 'high', 'medium', 'low'], true) ? $severity : 'medium',
                    'Dependency Advisories',
                    $file,
                    0,
                    "{$package}: ".trim((string) ($advisory['title'] ?? 'security advisory')).($id ? " ({$id})" : ''),
                    'Update '.$package.' (composer update '.$package.' --with-all-dependencies)'.(isset($advisory['link']) ? ' - '.$advisory['link'] : ''),
                );
            }
        }

        foreach ($report['abandoned'] ?? [] as $package => $replacement) {
            $findings[] = AuditReport::finding(
                'low',
                'Dependency Advisories',
                $file,
                0,
                "{$package} is abandoned and will not receive security fixes",
                is_string($replacement) && $replacement !== '' ? "Replace it with {$replacement}" : 'Replace it with a maintained package',
            );
        }

        return $findings;
    }

    /**
     * Findings from `npm audit --json` (report version 2): one per
     * vulnerable package, with npm's "moderate" mapped to medium.
     *
     * @param  array<string, mixed>  $report
     * @return list<array<string, mixed>>
     */
    public static function parseNpmAudit(array $report, string $file): array
    {
        $findings = [];

        foreach ($report['vulnerabilities'] ?? [] as $package => $vuln) {
            $severity = match ($vuln['severity'] ?? '') {
                'critical' => 'critical',
                'high' => 'high',
                'moderate' => 'medium',
                'low' => 'low',
                default => 'info',
            };
            $titles = collect($vuln['via'] ?? [])
                ->map(fn ($via) => is_array($via) ? ($via['title'] ?? null) : null)
                ->filter()->unique()->take(2)->implode('; ');
            $via = collect($vuln['via'] ?? [])->filter(fn ($v) => is_string($v))->implode(', ');

            $findings[] = AuditReport::finding(
                $severity,
                'Dependency Advisories',
                $file,
                0,
                "npm {$package}: ".($titles !== '' ? $titles : 'vulnerable through '.($via !== '' ? $via : 'a dependency')).(! empty($vuln['isDirect']) ? '' : ' (transitive)'),
                ($vuln['fixAvailable'] ?? false) ? 'Run npm audit fix' : 'No fix available yet - check whether the vulnerable path is reachable',
            );
        }

        return $findings;
    }

    // ─── Shared scanners (from the OMS / Moonscape audit) ────────────────────

    /**
     * Flag raw SQL expressions that interpolate variables rather than using bindings.
     *
     * @param  array<string>|null  $files  Override the scan file set (used by tests).
     */
    private function scanSqlInjection(?array $files = null): array
    {
        $findings = [];
        $files ??= $this->phpSourceFiles();

        $rawHelpers = '(whereRaw|selectRaw|orderByRaw|havingRaw|joinRaw|DB::raw|fromRaw|groupByRaw)';
        $dbStatements = '(DB::statement|DB::select|DB::insert|DB::update|DB::delete|DB::unprepared)';

        foreach ($files as $file) {
            $lines = $this->lines($file);

            foreach ($lines as $i => $line) {
                // (1) Raw helpers — whereRaw / selectRaw / orderByRaw / etc.
                if (preg_match('/'.$rawHelpers.'\s*\(/', $line, $match, PREG_OFFSET_CAPTURE)) {
                    $context = $this->callArgSpan($lines, $i, $match[0][1]);
                    if ($context !== null
                        && (preg_match('/\.\s*\$[a-zA-Z_]/', $context)
                            || preg_match('/"[^"\n]*\{\s*\$[a-zA-Z_]/', $context))) {
                        $findings[] = AuditReport::finding(
                            'critical',
                            'SQL Injection',
                            $file,
                            $i + 1,
                            $match[1][0].'() interpolates a variable - possible SQL injection',
                            'Use parameter bindings: '.$match[1][0].'(\'col = ?\', [$value])',
                        );
                    }
                }

                // (2) DB::statement / DB::select / DB::insert / etc. — column names cannot be bound.
                if (preg_match('/'.$dbStatements.'\s*\(/', $line, $match, PREG_OFFSET_CAPTURE)) {
                    $context = $this->callArgSpan($lines, $i, $match[0][1]);
                    if ($context !== null
                        && (preg_match('/\.\s*\$[a-zA-Z_]/', $context)
                            || preg_match('/"[^"\n]*\{\s*\$[a-zA-Z_]/', $context))) {
                        $findings[] = AuditReport::finding(
                            'critical',
                            'SQL Injection',
                            $file,
                            $i + 1,
                            $match[1][0].'() interpolates a variable - possible SQL injection',
                            'Pass bound parameters as the second argument instead of concatenating',
                        );
                    }
                }

                // (3) orderBy($var) / orderByDesc($var) — column names are NOT bound.
                if (preg_match('/->(orderBy|orderByDesc)\s*\(\s*\$([a-zA-Z_]\w*)/', $line, $match)) {
                    $var = $match[2];
                    // Heuristic: trace back ~20 lines to see if $var came from request / wire input.
                    $back = implode("\n", array_slice($lines, max(0, $i - 20), min($i, 20) + 1));
                    $fromUser = preg_match('/\$'.preg_quote($var, '/').'\s*=\s*(?:[^;]*?)(?:\$request->|request\(\)|\$this->\w+\s*;|\$_GET|\$_POST)/', $back)
                        || preg_match('/function\s+\w+\s*\([^)]*\$'.preg_quote($var, '/').'\b/', $back);
                    if ($fromUser) {
                        $findings[] = AuditReport::finding(
                            'high',
                            'SQL Injection',
                            $file,
                            $i + 1,
                            $match[1].'($'.$var.') uses an unbound column name from user input',
                            'Whitelist the column name against a known set before passing to orderBy()',
                        );
                    }
                }
            }
        }

        return $findings;
    }

    /**
     * Extract the argument span of a call site — characters between the
     * opening `(` at or after $callStartCol on line $startIdx and its
     * matching close, walking forward up to 8 lines and tracking string +
     * paren depth so we never bleed into the next statement.
     *
     * Returns the bracketed body (without the outer parens), or null when
     * we can't locate a `(` on the start line.
     */
    private function callArgSpan(array $lines, int $startIdx, int $callStartCol): ?string
    {
        $startLine = $lines[$startIdx] ?? '';
        $openPos = strpos($startLine, '(', $callStartCol);
        if ($openPos === false) {
            return null;
        }

        $buf = '';
        $depth = 0;
        $inString = false;
        $stringChar = '';
        $max = min($startIdx + 8, count($lines));

        for ($idx = $startIdx; $idx < $max; $idx++) {
            $cur = $lines[$idx];
            $j = ($idx === $startIdx) ? $openPos : 0;
            $len = strlen($cur);
            for (; $j < $len; $j++) {
                $ch = $cur[$j];
                if ($inString) {
                    $buf .= $ch;
                    if ($ch === '\\' && $j + 1 < $len) {
                        $buf .= $cur[$j + 1];
                        $j++;

                        continue;
                    }
                    if ($ch === $stringChar) {
                        $inString = false;
                    }

                    continue;
                }
                if ($ch === '"' || $ch === "'") {
                    $inString = true;
                    $stringChar = $ch;
                    $buf .= $ch;

                    continue;
                }
                if ($ch === '(') {
                    $depth++;
                    if ($depth > 1) {
                        $buf .= $ch;
                    }

                    continue;
                }
                if ($ch === ')') {
                    $depth--;
                    if ($depth === 0) {
                        return $buf;
                    }
                    $buf .= $ch;

                    continue;
                }
                $buf .= $ch;
            }
            $buf .= "\n";
        }

        return $buf;
    }

    /**
     * Flag models with missing, empty, or typo'd mass-assignment guards.
     */
    private function scanMassAssignment(): array
    {
        $findings = [];

        foreach ($this->phpFilesIn([app_path('Models')]) as $file) {
            $content = File::get($file);
            $name = pathinfo($file, PATHINFO_FILENAME);

            if (preg_match('/protected\s+\$guraded\b/', $content)) {
                $findings[] = AuditReport::finding(
                    'critical',
                    'Mass Assignment',
                    $file,
                    $this->lineOf($content, '$guraded'),
                    'Typo: $guraded instead of $guarded - model is unguarded',
                    'Rename to $guarded',
                );

                continue;
            }

            if (preg_match('/protected\s+\$guarded\s*=\s*\[\s*\]/', $content)) {
                $findings[] = AuditReport::finding(
                    'critical',
                    'Mass Assignment',
                    $file,
                    $this->lineOf($content, '$guarded'),
                    'Empty $guarded - every column is mass-assignable',
                    "Set \$guarded = ['id'] or define \$fillable",
                );

                continue;
            }

            $hasGuarded = (bool) preg_match('/protected\s+\$guarded\b/', $content);
            // Accept Laravel's #[Fillable(...)] attribute (Illuminate\Database\Eloquent\Attributes\Fillable)
            // as equivalent to the legacy protected $fillable property — both declare an explicit allowlist.
            $hasFillable = (bool) preg_match('/protected\s+\$fillable\b|#\[Fillable\b/', $content);
            $extendsModel = (bool) preg_match('/extends\s+Model\b/', $content);

            if ($extendsModel && ! $hasGuarded && ! $hasFillable) {
                $findings[] = AuditReport::finding(
                    'medium',
                    'Mass Assignment',
                    $file,
                    0,
                    $name.' has neither $guarded nor $fillable defined',
                    "Add \$fillable with explicit columns, or \$guarded = ['id']",
                );
            }
        }

        return $findings;
    }

    /**
     * Verify the Livewire update endpoint is behind the auth middleware.
     */
    private function scanLivewireUpdateEndpoint(): array
    {
        $findings = [];
        $provider = app_path('Providers/AppServiceProvider.php');

        if (! File::exists($provider)) {
            return [];
        }

        $content = File::get($provider);

        if (! preg_match('/Livewire::setUpdateRoute/', $content)) {
            $findings[] = AuditReport::finding(
                'critical',
                'Livewire Update Endpoint',
                $provider,
                0,
                'Livewire::setUpdateRoute() override missing - /livewire/update may be reachable to guests',
                "Call Livewire::setUpdateRoute(fn(\$h) => Route::post('/livewire/update', \$h)->middleware(['web','auth']));",
            );

            return $findings;
        }

        // Find the setUpdateRoute block and confirm the middleware list contains 'auth'.
        // 30-line window accommodates inline documentation comments
        // between the setUpdateRoute( and the ->middleware(...) chain.
        $lines = $this->lines($provider);
        foreach ($lines as $i => $line) {
            if (! str_contains($line, 'setUpdateRoute')) {
                continue;
            }
            $block = implode("\n", array_slice($lines, $i, 30));
            if (! preg_match('/middleware\(\s*\[[^\]]*[\'"]auth[\'"]/', $block)) {
                $findings[] = AuditReport::finding(
                    'critical',
                    'Livewire Update Endpoint',
                    $provider,
                    $i + 1,
                    "Livewire update route override does not apply the 'auth' middleware",
                    "Ensure ->middleware(['web', 'auth']) on the setUpdateRoute closure",
                );
            }
        }

        return $findings;
    }

    /**
     * Flag web routes defined outside an auth middleware group.
     */
    private function scanUnauthenticatedRoutes(): array
    {
        $findings = [];
        $allowedPublic = ['home', 'login', 'register', 'password', 'verification', 'two-factor', 'logout'];

        $allowedPublicExact = [];

        foreach ([base_path('routes/web.php'), base_path('routes/settings.php')] as $file) {
            if (! File::exists($file)) {
                continue;
            }

            $lines = $this->lines($file);
            $authDepth = 0;
            $braceDepth = 0;

            foreach ($lines as $i => $line) {
                if ($this->isCommentLine($line)) {
                    continue;
                }

                if (preg_match('/middleware\(\s*(?:\[[^\]]*[\'"]auth[\'"]|[\'"]auth[\'"])/', $line)) {
                    $authDepth = $braceDepth + 1;
                }

                // Very approximate brace tracking — good enough for our route files.
                $braceDepth += substr_count($line, '{') - substr_count($line, '}');
                if ($braceDepth < $authDepth - 1) {
                    $authDepth = 0;
                }

                if ($authDepth > 0) {
                    continue;
                }

                if (preg_match('/Route::(get|post|put|patch|delete|any|view|livewire|redirect)\s*\(\s*[\'"]([^\'"]+)[\'"]/', $line, $m)) {
                    $path = $m[2];
                    $isAllowed = in_array($path, $allowedPublicExact, true);
                    foreach ($allowedPublic as $allowed) {
                        if ($isAllowed) {
                            break;
                        }
                        if (str_contains($path, $allowed) || $path === '/' || $path === '') {
                            $isAllowed = true;
                            break;
                        }
                    }
                    if (! $isAllowed) {
                        $findings[] = AuditReport::finding(
                            'high',
                            'Unauthenticated Route',
                            $file,
                            $i + 1,
                            'Route "'.$path.'" is defined outside any auth middleware group',
                            "Wrap in Route::middleware(['auth'])->group(...) or justify as a public route",
                        );
                    }
                }
            }
        }

        return $findings;
    }

    /**
     * Check that the login, password reset, 2FA and Livewire update flows have rate limiting.
     */
    private function scanRateLimiting(): array
    {
        $findings = [];

        $webRoutes = base_path('routes/web.php');
        if (File::exists($webRoutes)) {
            $content = File::get($webRoutes);
            if (! preg_match('/throttle/i', $content)) {
                $findings[] = AuditReport::finding(
                    'medium',
                    'Rate Limiting',
                    $webRoutes,
                    0,
                    'No throttle middleware declared in web routes',
                    'Add a throttle to the auth route group to limit request rate',
                );
            }
        }

        // 2FA challenge throttling — Fortify ships a default but it must be configured.
        $fortify = config_path('fortify.php');
        if (File::exists($fortify)) {
            $content = File::get($fortify);
            if (! preg_match('/two-factor[^,]*\bthrottle\b|two_factor[^,]*\bthrottle\b/i', $content)
                && ! preg_match('/limiters[^}]*?two[-_]factor/is', $content)) {
                $findings[] = AuditReport::finding(
                    'high',
                    'Rate Limiting',
                    $fortify,
                    0,
                    '2FA challenge has no rate limit - 6-digit OTP is brute-forceable in seconds',
                    "Configure 'limiters.two-factor' in config/fortify.php (e.g. RateLimiter::for('two-factor', ...))",
                );
            }
        }

        // Fortify login + password reset rate limiters — must bind to email+IP, not just IP.
        $rateLimiters = [
            base_path('app/Providers/AppServiceProvider.php'),
            base_path('app/Providers/FortifyServiceProvider.php'),
            base_path('app/Providers/RouteServiceProvider.php'),
        ];
        $sawLoginLimiter = false;
        $sawPasswordResetLimiter = false;
        $sawTwoFactorLimiter = false;
        foreach ($rateLimiters as $provider) {
            if (! File::exists($provider)) {
                continue;
            }
            $content = File::get($provider);
            if (preg_match('/RateLimiter::for\(\s*[\'"]login[\'"]/', $content)) {
                $sawLoginLimiter = true;
                if (! preg_match('/RateLimiter::for\(\s*[\'"]login[\'"][^}]*(email|Fortify::username)/is', $content)) {
                    $findings[] = AuditReport::finding(
                        'medium',
                        'Rate Limiting',
                        $provider,
                        $this->lineOf($content, "'login'"),
                        'Login rate limiter does not include the submitted email - credential-stuffing rotates IPs',
                        "Key the limiter on Str::lower(\$request->input('email')).'|'.\$request->ip()",
                    );
                }
            }
            if (preg_match('/RateLimiter::for\(\s*[\'"]password-reset[\'"]/', $content)) {
                $sawPasswordResetLimiter = true;
            }
            if (preg_match('/RateLimiter::for\(\s*[\'"]two-factor[\'"]/', $content)) {
                $sawTwoFactorLimiter = true;
            }
        }
        if (! $sawLoginLimiter) {
            $findings[] = AuditReport::finding(
                'medium',
                'Rate Limiting',
                base_path('app/Providers/AppServiceProvider.php'),
                0,
                "No RateLimiter::for('login') named limiter - login brute-force defence relies on global throttle only",
                "Define RateLimiter::for('login', fn ...) keyed on email+IP",
            );
        }
        // Either a named 'password-reset' limiter OR a group throttle on
        // Fortify's route stack (config('fortify.middleware') including a
        // 'throttle:...' entry) is sufficient — Fortify's /forgot-password
        // route only needs SOME upper bound on its request rate; a group
        // throttle covers it just as well as a per-endpoint limiter.
        $fortifyConfig = config_path('fortify.php');
        $sawFortifyGroupThrottle = false;
        if (File::exists($fortifyConfig)) {
            $content = File::get($fortifyConfig);
            if (preg_match('/[\'"]middleware[\'"]\s*=>\s*\[[^\]]*[\'"]throttle:/', $content)) {
                $sawFortifyGroupThrottle = true;
            }
        }
        if (! $sawPasswordResetLimiter && ! $sawFortifyGroupThrottle) {
            $findings[] = AuditReport::finding(
                'medium',
                'Rate Limiting',
                base_path('app/Providers/AppServiceProvider.php'),
                0,
                "No throttle on Fortify's /forgot-password endpoint - request can be flooded",
                "Add 'throttle:6,1' to config('fortify.middleware') OR define a named 'password-reset' RateLimiter::for() in FortifyServiceProvider",
            );
        }
        if (! $sawTwoFactorLimiter) {
            $findings[] = AuditReport::finding(
                'high',
                'Rate Limiting',
                base_path('app/Providers/AppServiceProvider.php'),
                0,
                "No RateLimiter::for('two-factor') named limiter - OTP brute-force is the highest-risk untreated path",
                'Define a two-factor limiter (5/minute by user) and reference it in config/fortify.php',
            );
        }

        // Livewire /update endpoint throttle.
        $appProvider = base_path('app/Providers/AppServiceProvider.php');
        if (File::exists($appProvider)) {
            $content = File::get($appProvider);
            if (preg_match('/setUpdateRoute/', $content)
                && ! preg_match('/setUpdateRoute[^}]*?throttle/is', $content)) {
                $findings[] = AuditReport::finding(
                    'medium',
                    'Rate Limiting',
                    $appProvider,
                    $this->lineOf($content, 'setUpdateRoute'),
                    'Livewire /livewire/update route has no throttle - heavy action methods can be flooded',
                    "Add ->middleware(['web','auth','throttle:120,1']) to the setUpdateRoute closure",
                );
            }
        }

        return $findings;
    }

    /**
     * Flag components using WithFileUploads without validation rules on the property.
     */
    private function scanLivewireFileUploads(): array
    {
        $findings = [];

        foreach ($this->livewireComponentFiles() as $file) {
            $content = File::get($file);
            if (! preg_match('/WithFileUploads|TemporaryUploadedFile/', $content)) {
                continue;
            }

            // Properties holding uploaded files — usually TemporaryUploadedFile|null.
            if (! preg_match_all('/public\s+(?:\?[\w\\\\|]+\s+)?\$(\w+)\s*[=;]/', $content, $props)) {
                continue;
            }

            // Look for a $rules array or $this->validate() call that mentions file rules.
            $hasFileRule = (bool) preg_match('/[\'"]file[\'"]|[\'"]image[\'"]|[\'"]mimes:|[\'"]mimetypes:/', $content);
            $hasValidate = (bool) preg_match('/->validate\(|\$this->rules\b|protected\s+\$rules\b/', $content);

            if (! $hasFileRule || ! $hasValidate) {
                $findings[] = AuditReport::finding(
                    'high',
                    'Livewire File Uploads',
                    $file,
                    $this->lineOf($content, 'WithFileUploads') ?: 0,
                    'Component uses WithFileUploads with no file/mimes/mimetypes validation rules',
                    "Add \$this->validate(['file' => 'required|file|mimes:...|max:...'])",
                );
            }
        }

        return $findings;
    }

    /**
     * Flag route definitions that bind a team-scoped model without ->scopeBindings()
     * (Laravel would otherwise resolve {device} to any device, cross-team).
     *
     * @param  array<int, string>|null  $routeFiles  Override the route files to scan (used by parallel-safe fixture tests).
     */
    private function scanRouteModelBinding(?array $routeFiles = null): array
    {
        $findings = [];
        $bindings = ['network', 'member', 'token', 'team', 'user', 'invitation'];
        $pattern = '\{('.implode('|', $bindings).')\}';

        $routeFiles ??= [base_path('routes/web.php'), base_path('routes/api.php'), base_path('routes/settings.php')];

        foreach ($routeFiles as $file) {
            if (! File::exists($file)) {
                continue;
            }
            $lines = $this->lines($file);
            $content = File::get($file);
            $globalScope = (bool) preg_match('/->scopeBindings\(\)/', $content);

            foreach ($lines as $i => $line) {
                if ($this->isCommentLine($line)) {
                    continue;
                }
                if (! preg_match('/Route::(?:get|post|put|patch|delete|any|livewire)\s*\([\s\S]*?['.preg_quote("'\"", '/').']([^\'"]*'.$pattern.'[^\'"]*)['.preg_quote("'\"", '/').']/', $line, $m)) {
                    continue;
                }

                $block = implode("\n", array_slice($lines, $i, 6));
                if (preg_match('/->scopeBindings\(\)|where\(\s*[\'"]team_id[\'"]/', $block)) {
                    continue;
                }
                if ($globalScope) {
                    continue;
                }

                // A `->where('paramName', 'regex')` constraint declares the param
                // as a plain string in the URL, not an implicit model binding —
                // Laravel resolves it as a route parameter, the handler does its
                // own lookup. Skip when the matched binding has such a where().
                if (preg_match('/->where\(\s*[\'"]'.preg_quote($m[2], '/').'[\'"]\s*,\s*[\'"][^\'"]+[\'"]/', $block)) {
                    continue;
                }

                $findings[] = AuditReport::finding(
                    'high',
                    'Route Model Binding',
                    $file,
                    $i + 1,
                    'Route "'.$m[1].'" uses implicit binding {'.$m[2].'} without ->scopeBindings() - cross-team resolution risk',
                    'Either add ->scopeBindings() or resolve the model manually with a team_id constraint',
                );
            }
        }

        return $findings;
    }

    /**
     * Flag use of shell-executing or code-executing PHP functions in app code / Volt pages.
     * Carve-outs for legitimate Artisan / queue-driver internals are handled by suppress-list if needed.
     */
    private function scanDangerousFunctions(): array
    {
        $findings = [];
        $dangerous = [
            'exec' => 'high',
            'shell_exec' => 'high',
            'passthru' => 'high',
            'system' => 'high',
            'proc_open' => 'high',
            'popen' => 'high',
            'eval' => 'critical',
            'assert' => 'medium',
            'unserialize' => 'high',
            'create_function' => 'critical',
        ];

        foreach ($this->phpSourceFiles() as $file) {
            $lines = $this->lines($file);
            foreach ($lines as $i => $line) {
                if ($this->isCommentLine($line)) {
                    continue;
                }
                // Only code can call: blank out string literals first, so a
                // message or config value naming a function isn't a call.
                $code = preg_replace('/\'(?:\\\\.|[^\'\\\\])*\'|"(?:\\\\.|[^"\\\\])*"/', "''", $line);
                foreach ($dangerous as $fn => $severity) {
                    if (preg_match('/(?<![\w>:$\\\\])'.$fn.'\s*\(/', $code)) {
                        $findings[] = AuditReport::finding(
                            $severity,
                            'Dangerous Functions',
                            $file,
                            $i + 1,
                            'Call to '.$fn.'() - verify input is not attacker-controlled',
                            'Replace with a safer abstraction (Symfony Process for shell, json_decode for serialised data, …)',
                        );
                    }
                }

                // Dynamic include/require with a variable path.
                if (preg_match('/\b(include|include_once|require|require_once)\s+\$/', $line, $m)) {
                    $findings[] = AuditReport::finding(
                        'critical',
                        'Dangerous Functions',
                        $file,
                        $i + 1,
                        $m[1].' with a variable path - file-path injection risk',
                        'Resolve the path against a fixed allowlist before include/require',
                    );
                }
            }
        }

        return $findings;
    }

    /**
     * Flag CSRF exclusions configured via withMiddleware or VerifyCsrfToken.
     *
     * @param  array<int, string>|null  $files  Override the files scanned (used by parallel-safe fixture tests).
     */
    private function scanCsrfExclusions(?array $files = null): array
    {
        $findings = [];
        $candidates = $files ?? [
            base_path('bootstrap/app.php'),
            base_path('app/Http/Middleware/VerifyCsrfToken.php'),
        ];

        foreach ($candidates as $file) {
            if (! File::exists($file)) {
                continue;
            }
            $content = File::get($file);

            // Modern (Laravel 11) — $middleware->validateCsrfTokens(except: [...])
            if (preg_match('/validateCsrfTokens\s*\(\s*except\s*:\s*\[([^\]]+)\]/s', $content, $m)) {
                $entries = trim($m[1]);
                if ($entries !== '' && $entries !== ',') {
                    $findings[] = AuditReport::finding(
                        'high',
                        'CSRF Exclusions',
                        $file,
                        $this->lineOf($content, 'validateCsrfTokens'),
                        'CSRF exclusion list present - each entry weakens form-state protection',
                        'Review excluded URIs; prefer signed routes / webhook signatures over blanket CSRF bypass',
                    );
                }
            }
            // Classic — protected $except = [...]
            if (preg_match('/protected\s+\$except\s*=\s*\[([^\]]+)\]/s', $content, $m)) {
                $entries = trim($m[1]);
                if ($entries !== '' && $entries !== ',') {
                    $findings[] = AuditReport::finding(
                        'high',
                        'CSRF Exclusions',
                        $file,
                        $this->lineOf($content, '$except'),
                        'CSRF $except list present - each entry weakens form-state protection',
                        'Remove entries; webhooks should use signatures, not CSRF bypass',
                    );
                }
            }
        }

        return $findings;
    }

    /**
     * Flag redirect()/Redirect::to() calls whose target traces back to user input.
     */
    private function scanOpenRedirects(): array
    {
        $findings = [];

        foreach ($this->phpSourceFiles() as $file) {
            $lines = $this->lines($file);
            foreach ($lines as $i => $line) {
                if ($this->isCommentLine($line)) {
                    continue;
                }
                if (! preg_match('/(?:return\s+)?(?:redirect|Redirect::to|Redirect::away)\s*\(\s*([^)]+)\)/', $line, $m)) {
                    continue;
                }
                $arg = $m[1];

                // Allow named routes / view shortcuts — these aren't redirects to arbitrary URLs.
                if (str_contains($arg, '->route(') || str_contains($arg, '->intended(')) {
                    continue;
                }

                if (preg_match('/\$request->(input|get|query)\(|request\(\)->(input|get|query)\(|\$_GET\[/', $arg)) {
                    $findings[] = AuditReport::finding(
                        'high',
                        'Open Redirect',
                        $file,
                        $i + 1,
                        'redirect() target sourced directly from request input',
                        'Validate against an allowlist or use redirect()->route() with a named route',
                    );
                }
            }
        }

        return $findings;
    }

    /**
     * Flag Log:: calls that include token / password / secret variables.
     */
    private function scanSensitiveLogging(): array
    {
        $findings = [];

        foreach ($this->phpSourceFiles() as $file) {
            $lines = $this->lines($file);
            foreach ($lines as $i => $line) {
                if ($this->isCommentLine($line)) {
                    continue;
                }
                if (! preg_match('/Log::(?:debug|info|notice|warning|error|critical|alert|emergency)\s*\(/', $line)) {
                    continue;
                }
                $context = implode("\n", array_slice($lines, $i, 3));
                if (preg_match('/\$\w*(token|password|secret|api_key|auth_key)\w*/i', $context)) {
                    $findings[] = AuditReport::finding(
                        'medium',
                        'Sensitive Logging',
                        $file,
                        $i + 1,
                        'Log call appears to include a secret-bearing variable - credentials may land in laravel.log',
                        'Strip / hash the secret before logging, or omit it entirely',
                    );
                }
            }
        }

        return $findings;
    }

    /**
     * Assert SecurityHeaders middleware exists, sets the standard headers, and is wired into the web group.
     */
    private function scanSecurityHeaders(): array
    {
        $findings = [];
        $middleware = app_path('Http/Middleware/SecurityHeaders.php');

        if (! File::exists($middleware)) {
            $findings[] = AuditReport::finding(
                'high',
                'Security Headers',
                base_path('app/Http/Middleware'),
                0,
                'SecurityHeaders middleware is missing entirely',
                'Create app/Http/Middleware/SecurityHeaders.php and register it in the web group',
            );

            return $findings;
        }

        $content = File::get($middleware);
        $required = [
            'X-Frame-Options' => 'high',
            'X-Content-Type-Options' => 'medium',
            'Referrer-Policy' => 'medium',
            'Strict-Transport-Security' => 'high',
            'Content-Security-Policy' => 'medium',
            'Permissions-Policy' => 'low',
        ];
        foreach ($required as $header => $sev) {
            if (! str_contains($content, $header)) {
                $findings[] = AuditReport::finding(
                    $sev,
                    'Security Headers',
                    $middleware,
                    0,
                    'SecurityHeaders does not set '.$header,
                    'Add $response->headers->set(\''.$header.'\', \'…\') with a safe default',
                );
            }
        }

        // Confirm the middleware is actually wired into the web group via bootstrap/app.php.
        $bootstrap = base_path('bootstrap/app.php');
        if (File::exists($bootstrap)) {
            $boot = File::get($bootstrap);
            if (! preg_match('/SecurityHeaders::class|\\\\SecurityHeaders\b/', $boot)) {
                $findings[] = AuditReport::finding(
                    'critical',
                    'Security Headers',
                    $bootstrap,
                    0,
                    'SecurityHeaders middleware exists but is not registered in bootstrap/app.php - headers never reach clients',
                    'Call $middleware->web(append: [\\App\\Http\\Middleware\\SecurityHeaders::class]) in withMiddleware()',
                );
            }
        }

        return $findings;
    }

    /**
     * What the production policy allows (no Vite dev server), and that it is
     * enforced unless WIRETIER_CSP says otherwise.
     */
    private function scanContentSecurityPolicy(): array
    {
        $middleware = app_path('Http/Middleware/SecurityHeaders.php');
        if (! File::exists($middleware) || ! method_exists(SecurityHeaders::class, 'directives')) {
            return [AuditReport::finding(
                'medium',
                CspPolicyCheck::CATEGORY,
                $middleware,
                0,
                'SecurityHeaders::directives() is missing - the audit cannot check what the Content-Security-Policy allows',
                'Keep the policy in a public static directives(string $nonce): array so it can be checked',
            )];
        }

        $findings = (new CspPolicyCheck)->check(SecurityHeaders::directives('audit'), $middleware, File::get($middleware));

        $config = config_path('wiretier.php');
        if (File::exists($config)) {
            $content = File::get($config);
            if (! preg_match("/'csp'\s*=>\s*env\(\s*'WIRETIER_CSP'\s*,\s*'enforce'\s*\)/", $content)) {
                $findings[] = AuditReport::finding(
                    'medium',
                    CspPolicyCheck::CATEGORY,
                    $config,
                    $this->lineOf($content, "'csp'"),
                    "wiretier.csp does not default to 'enforce' - installs without WIRETIER_CSP get no enforced policy",
                    "Use 'csp' => env('WIRETIER_CSP', 'enforce')",
                );
            }
        }

        return $findings;
    }

    /**
     * Spot weak session-cookie flags.
     */
    private function scanSessionConfig(): array
    {
        $findings = [];
        $file = config_path('session.php');

        if (! File::exists($file)) {
            return [];
        }

        $content = File::get($file);

        if (preg_match('/[\'"]same_site[\'"]\s*=>\s*(?:null|env\([^)]*,\s*null\s*\))/', $content)) {
            $findings[] = AuditReport::finding(
                'high',
                'Session Config',
                $file,
                $this->lineOf($content, 'same_site'),
                'Session same_site is null - weakens CSRF protection',
                "Set 'same_site' => 'lax' (or 'strict')",
            );
        }

        if (preg_match('/[\'"]secure[\'"]\s*=>\s*env\([^)]*,\s*(?:false|null)\s*\)/', $content)) {
            $findings[] = AuditReport::finding(
                'medium',
                'Session Config',
                $file,
                $this->lineOf($content, "'secure'"),
                'Session secure flag defaults to false - cookies may traverse HTTP',
                'Default SESSION_SECURE_COOKIE to true and document it in .env.example',
            );
        }

        return $findings;
    }

    /**
     * Flag unescaped Blade output.
     */
    private function scanBladeXss(): array
    {
        $findings = [];
        $base = resource_path('views');

        $files = [];
        foreach (['*.blade.php', '**/*.blade.php'] as $pattern) {
            foreach (File::glob($base.'/'.$pattern) as $f) {
                $files[] = $f;
            }
        }
        // Recurse deeper than File::glob's two-level walk supports.
        foreach (File::allFiles($base) as $f) {
            if (str_ends_with($f->getFilename(), '.blade.php')) {
                $files[] = $f->getRealPath();
            }
        }
        $files = array_unique($files);

        foreach ($files as $file) {
            // Vendor views (framework-bundled mail templates etc.) are out of scope.
            if (str_contains($file, '/views/vendor/')) {
                continue;
            }

            $lines = $this->lines($file);

            foreach ($lines as $i => $line) {
                if (! preg_match_all('/\{!!\s*(.+?)\s*!!\}/', $line, $matches)) {
                    continue;
                }

                foreach ($matches[1] as $expr) {
                    $trimmed = trim($expr);

                    // Known-safe expressions.
                    if (str_contains($expr, 'json_encode')
                        || str_starts_with($trimmed, '__(')
                        || str_starts_with($trimmed, 'Js::from')) {
                        continue;
                    }

                    // Pre-escaped input via e() / htmlspecialchars() / htmlentities() —
                    // anything captured AFTER these helpers runs against escaped text.
                    if (preg_match('/\b(?:e|htmlspecialchars|htmlentities)\s*\(/', $expr)) {
                        continue;
                    }

                    // QR-code SVG generators. Convention is `qrSvg`, `qrCodeSvg`,
                    // `twoFactorQrCodeSvg` — content is encoded as QR matrix pixels,
                    // never interpolated into the SVG markup. Match the expression
                    // for any `qr` + `svg` pairing (case-insensitive between).
                    if (preg_match('/qr[A-Za-z_]*svg/i', $expr)) {
                        continue;
                    }

                    $severity = 'medium';
                    if (preg_match('/\$(name|note|comment|description|text|content|message|input|user|email)/i', $expr)) {
                        $severity = 'high';
                    }

                    $snippet = substr($expr, 0, 60).(strlen($expr) > 60 ? '...' : '');

                    $findings[] = AuditReport::finding(
                        $severity,
                        'XSS',
                        $file,
                        $i + 1,
                        'Unescaped Blade output: {!! '.$snippet.' !!}',
                        'Use {{ }} unless the value is trusted server-generated HTML',
                    );
                }
            }
        }

        return $findings;
    }

    /**
     * Flag env() credentials assigned to model/object properties.
     */
    private function scanCredentialExposure(): array
    {
        $findings = [];

        foreach ($this->phpSourceFiles() as $file) {
            $lines = $this->lines($file);
            foreach ($lines as $i => $line) {
                if (preg_match('/->(?:auth_token|auth_password|auth_key|api_key|api_secret|password|secret|token)\s*=\s*env\(/', $line)) {
                    $findings[] = AuditReport::finding(
                        'high',
                        'Credential Exposure',
                        $file,
                        $i + 1,
                        'Environment credential assigned to an object property - may leak in serialized responses',
                        'Keep credentials in config() and never attach them to models that may be serialized',
                    );
                }
            }
        }

        return $findings;
    }

    // ─── File helpers ────────────────────────────────────────────────────────

    private function phpSourceFiles(): array
    {
        return array_merge(
            $this->phpFilesIn([app_path()]),
            $this->voltFiles(),
        );
    }

    /**
     * Volt single-file components (⚡*.blade.php under resources/views/pages).
     */
    private function voltFiles(): array
    {
        $files = [];
        foreach (File::allFiles(resource_path('views/pages')) as $file) {
            $realPath = $file->getRealPath();
            if (str_ends_with($realPath, '.blade.php')) {
                $files[] = $realPath;
            }
        }

        return $files;
    }

    /**
     * Every Blade template in the app (not just Volt pages) — components,
     * partials, layouts, livewire views.
     */
    private function allBladeFiles(): array
    {
        $dir = resource_path('views');
        if (! File::isDirectory($dir)) {
            return [];
        }

        $files = [];
        foreach (File::allFiles($dir) as $file) {
            if (str_ends_with($file->getRealPath(), '.blade.php')) {
                $files[] = $file->getRealPath();
            }
        }

        return $files;
    }

    /**
     * Every file that hosts Livewire component code:
     *  - Volt single-file components under resources/views/pages
     *  - Full Livewire component classes under app/Livewire
     */
    private function livewireComponentFiles(): array
    {
        return array_merge(
            $this->voltFiles(),
            $this->phpFilesIn([app_path('Livewire')]),
        );
    }

    /**
     * All .php files in the given directories.
     */
    private function phpFilesIn(array $paths): array
    {
        $files = [];
        foreach ($paths as $path) {
            if (! File::isDirectory($path)) {
                continue;
            }
            foreach (File::allFiles($path) as $file) {
                if ($file->getExtension() === 'php') {
                    $files[] = $file->getRealPath();
                }
            }
        }

        return $files;
    }

    private function lines(string $file): array
    {
        // File::exists() check first — a recursive walk can race against
        // concurrent edits (parallel test fixtures, an editor write-rename,
        // a deploy mid-scan). Treat a vanished file as empty rather than
        // aborting the whole audit.
        if (! File::exists($file)) {
            return [];
        }

        try {
            return explode("\n", File::get($file));
        } catch (\Throwable) {
            return [];
        }
    }

    private function isCommentLine(string $line): bool
    {
        $trimmed = ltrim($line);

        return str_starts_with($trimmed, '//')
            || str_starts_with($trimmed, '#')
            || str_starts_with($trimmed, '*')
            || str_starts_with($trimmed, '/*');
    }

    private function lineOf(string $content, string $needle): int
    {
        foreach (explode("\n", $content) as $i => $line) {
            if (str_contains($line, $needle)) {
                return $i + 1;
            }
        }

        return 0;
    }
}

<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Artisan;

class Security_Test extends Command
{
    protected $signature = 'security:test
        {--seed : Run SecurityTestSeeder before tests}
        {--format=table : Output format (table, json)}';

    protected $description = 'Run security tests against WireTier (Pest test suite + static audit)';

    public function handle(): int
    {
        $this->info('WireTier Security Test Suite');
        $this->info('===========================');
        $this->newLine();

        // ─── Step 1: Run static audit ────────────────────────────────
        $this->info('Phase 1: Static Analysis');
        $this->line('Running security:audit...');
        $this->newLine();

        $auditExitCode = Artisan::call('security:audit', [
            '--format' => $this->option('format'),
        ], $this->output);

        $this->newLine();

        // ─── Step 2: Seed test data if requested ─────────────────────
        if ($this->option('seed')) {
            $this->info('Phase 2: Seeding test data...');
            Artisan::call('db:seed', [
                '--class' => 'Database\\Seeders\\SecurityTestSeeder',
            ], $this->output);
            $this->newLine();
        }

        // ─── Step 3: Run Pest security tests ─────────────────────────
        $this->info('Phase '.($this->option('seed') ? '3' : '2').': Runtime Security Tests');
        $this->line('Running tests/Feature/Security...');
        $this->newLine();

        $testExitCode = $this->runPestTests();

        // ─── Summary ─────────────────────────────────────────────────
        $this->newLine();
        $this->line('=====================================');

        if ($auditExitCode === 0 && $testExitCode === 0) {
            $this->info('All security checks passed.');
        } else {
            if ($auditExitCode !== 0) {
                $this->error('Static audit found HIGH/CRITICAL issues.');
            }
            if ($testExitCode !== 0) {
                $this->error('Runtime security tests had failures.');
            }
        }

        $this->newLine();

        return ($auditExitCode !== 0 || $testExitCode !== 0) ? 1 : 0;
    }

    private function runPestTests(): int
    {
        $testPath = base_path('tests/Feature/Security');

        if (! is_dir($testPath)) {
            $this->warn('No security test directory found at tests/Feature/Security');

            return 1;
        }

        $command = implode(' ', [
            PHP_BINARY,
            base_path('vendor/bin/pest'),
            '--colors=always',
            $testPath,
        ]);

        passthru($command, $exitCode);

        return $exitCode;
    }
}

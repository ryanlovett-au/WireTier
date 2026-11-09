<?php

namespace App\Tools\Security;

use Illuminate\Console\Command;

class AuditReport
{
    /**
     * Severity levels and their display properties.
     */
    private static array $severities = [
        'critical' => ['order' => 0, 'label' => 'CRITICAL'],
        'high' => ['order' => 1, 'label' => 'HIGH'],
        'medium' => ['order' => 2, 'label' => 'MEDIUM'],
        'low' => ['order' => 3, 'label' => 'LOW'],
        'info' => ['order' => 4, 'label' => 'INFO'],
    ];

    /**
     * Create a structured finding.
     */
    public static function finding(
        string $severity,
        string $category,
        string $file,
        int $line,
        string $description,
        string $remediation = ''
    ): array {
        return [
            'severity' => $severity,
            'category' => $category,
            'file' => $file,
            'line' => $line,
            'description' => $description,
            'remediation' => $remediation,
        ];
    }

    public static function filter(array $findings, string $severityFilter): array
    {
        if ($severityFilter === 'all') {
            return $findings;
        }

        return array_values(array_filter(
            $findings,
            fn ($f) => $f['severity'] === $severityFilter,
        ));
    }

    public static function sort(array $findings): array
    {
        usort($findings, function ($a, $b) {
            $orderA = self::$severities[$a['severity']]['order'] ?? 99;
            $orderB = self::$severities[$b['severity']]['order'] ?? 99;

            return $orderA <=> $orderB;
        });

        return $findings;
    }

    public static function renderTable(Command $command, array $findings, string $severityFilter = 'all', bool $showFix = false): void
    {
        $findings = self::filter($findings, $severityFilter);
        $findings = self::sort($findings);

        if (empty($findings)) {
            $command->info('No findings to display.');

            return;
        }

        $grouped = [];
        foreach ($findings as $finding) {
            $grouped[$finding['severity']][] = $finding;
        }

        foreach (self::$severities as $severity => $props) {
            if (! isset($grouped[$severity])) {
                continue;
            }

            $command->newLine();
            $label = ' '.$props['label'].' ('.count($grouped[$severity]).' findings) ';

            if ($severity === 'critical') {
                $command->error($label);
            } elseif ($severity === 'high') {
                $command->warn($label);
            } else {
                $command->info($label);
            }

            $headers = ['Category', 'File', 'Line', 'Description'];
            if ($showFix) {
                $headers[] = 'Remediation';
            }

            $rows = [];
            foreach ($grouped[$severity] as $finding) {
                $row = [
                    $finding['category'],
                    self::shortenPath($finding['file']),
                    $finding['line'] > 0 ? $finding['line'] : '-',
                    $finding['description'],
                ];
                if ($showFix) {
                    $row[] = $finding['remediation'];
                }
                $rows[] = $row;
            }

            $command->table($headers, $rows);
        }
    }

    public static function renderJson(array $findings, string $severityFilter = 'all'): string
    {
        $findings = self::filter($findings, $severityFilter);
        $findings = self::sort($findings);

        return json_encode([
            'summary' => self::summary($findings),
            'findings' => $findings,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    public static function renderSummary(Command $command, array $findings): void
    {
        $summary = self::summary($findings);

        $command->newLine();
        $command->line('=== Security Audit Summary ===');
        $command->newLine();

        if ($summary['critical'] > 0) {
            $command->error('  CRITICAL: '.$summary['critical']);
        }
        if ($summary['high'] > 0) {
            $command->warn('  HIGH:     '.$summary['high']);
        }
        if ($summary['medium'] > 0) {
            $command->info('  MEDIUM:   '.$summary['medium']);
        }
        if ($summary['low'] > 0) {
            $command->line('  LOW:      '.$summary['low']);
        }
        if ($summary['info'] > 0) {
            $command->line('  INFO:     '.$summary['info']);
        }

        $command->newLine();
        $command->line('  TOTAL:    '.$summary['total']);
        $command->newLine();
    }

    public static function summary(array $findings): array
    {
        $counts = [
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0,
            'info' => 0,
            'total' => count($findings),
        ];

        foreach ($findings as $finding) {
            if (isset($counts[$finding['severity']])) {
                $counts[$finding['severity']]++;
            }
        }

        return $counts;
    }

    private static function shortenPath(string $path): string
    {
        $base = base_path().'/';

        if (str_starts_with($path, $base)) {
            return substr($path, strlen($base));
        }

        return $path;
    }
}

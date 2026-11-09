<?php

namespace App\Services\FlowRules;

/**
 * A stable fingerprint of a network's compiled flow rules (rules,
 * capabilities and tags), used to detect changes made outside WireTier.
 *
 * Always fingerprint the controller's own copy of the config, never the
 * compiler output: the controller normalises rules on write, so only its
 * rendering is comparable with what a later sync reads back.
 */
final class RulesFingerprint
{
    public static function of(array $networkConfig): string
    {
        $subset = [
            'rules' => $networkConfig['rules'] ?? [],
            'capabilities' => $networkConfig['capabilities'] ?? [],
            'tags' => $networkConfig['tags'] ?? [],
        ];

        return hash('sha256', json_encode(self::canonical($subset), JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION));
    }

    /** The controller's default for a new network: accept everything, no capabilities or tags. */
    public static function isDefault(array $networkConfig): bool
    {
        $rules = $networkConfig['rules'] ?? [['type' => 'ACTION_ACCEPT']];

        return count($rules) === 1
            && ($rules[0]['type'] ?? null) === 'ACTION_ACCEPT'
            && empty($networkConfig['capabilities'])
            && empty($networkConfig['tags']);
    }

    /** Recursively sort object keys; list order is significant and kept. */
    private static function canonical(mixed $value): mixed
    {
        if (! is_array($value)) {
            return $value;
        }

        $value = array_map(self::canonical(...), $value);

        if (! array_is_list($value)) {
            ksort($value);
        }

        return $value;
    }
}

<?php

namespace App\Services;

use App\Models\ZerotierNetwork;
use App\Models\ZerotierToken;
use Illuminate\Support\Facades\Cache;

class ZerotierStatsService
{
    /**
     * Get authorised member counts from the database (no API calls).
     *
     * Returns ['total' => int, 'by_network' => [network_id => int], 'last_updated' => ?int]
     */
    public static function authorisedMembers(?string $teamId = null): array
    {
        $cacheKey = 'zt_stats_authorised_'.($teamId ?? 'all');

        return Cache::flexible($cacheKey, [30, 60], function () use ($teamId) {
            $query = ZerotierNetwork::query();

            if ($teamId) {
                $query->where('team_id', $teamId);
            }

            $networks = $query->withCount([
                'members as authorised_count' => fn ($q) => $q->where('authorised', true),
            ])->get();

            $total = 0;
            $byNetwork = [];

            foreach ($networks as $network) {
                $count = $network->authorised_count ?? 0;
                $total += $count;
                $byNetwork[$network->network_id] = $count;
            }

            $lastSynced = $networks->max('synced_at');

            return [
                'total' => $total,
                'by_network' => $byNetwork,
                'last_updated' => $lastSynced?->timestamp,
            ];
        });
    }

    /**
     * Count networks on the active controllers that no team tracks.
     *
     * Each controller's network list is cached for 60 seconds. A failed call
     * is cached as a failure for 30 seconds (so a dead controller doesn't
     * stall every dashboard load) and reported in 'failed', instead of being
     * mistaken for a controller with no untracked networks.
     *
     * @return array{count: int, last_updated: ?int, failed: list<string>}
     */
    public static function untrackedNetworks(): array
    {
        $tokens = ZerotierToken::where('is_active', true)->get();
        $tracked = array_flip(ZerotierNetwork::pluck('network_id')->all());
        $untracked = [];
        $failed = [];
        $checkedAt = null;

        foreach ($tokens as $token) {
            $result = Cache::get("zt_controller_networks_{$token->id}");

            if (! is_array($result) || ! array_key_exists('ok', $result)) {
                $result = self::fetchControllerNetworks($token);
                Cache::put("zt_controller_networks_{$token->id}", $result, $result['ok'] ? 60 : 30);
            }

            if (! $result['ok']) {
                $failed[] = $token->name;

                continue;
            }

            $checkedAt = $checkedAt === null ? $result['at'] : min($checkedAt, $result['at']);
            foreach ($result['ids'] as $networkId) {
                if (! isset($tracked[$networkId])) {
                    $untracked[$networkId] = true;
                }
            }
        }

        return [
            'count' => count($untracked),
            'last_updated' => $checkedAt,
            'failed' => $failed,
        ];
    }

    /** @return array{ok: bool, ids: list<string>, at: int} */
    private static function fetchControllerNetworks(ZerotierToken $token): array
    {
        try {
            $ids = (new ZerotierService($token))->getControllerNetworks();

            return ['ok' => true, 'ids' => array_values(array_filter($ids, 'is_string')), 'at' => now()->timestamp];
        } catch (\Throwable $e) {
            report($e);

            return ['ok' => false, 'ids' => [], 'at' => now()->timestamp];
        }
    }
}

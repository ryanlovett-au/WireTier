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
     * Get count of untracked networks across all active controllers.
     * Cached per token for 60 seconds to avoid hammering the API on every dashboard load.
     *
     * Returns ['count' => int, 'last_updated' => ?int]
     */
    public static function untrackedNetworks(): array
    {
        $tokens = ZerotierToken::where('is_active', true)->get();
        $trackedIds = ZerotierNetwork::pluck('network_id')->toArray();
        $allControllerNetworkIds = [];

        foreach ($tokens as $token) {
            $controllerNetworks = Cache::remember(
                "zt_controller_networks_{$token->id}",
                60,
                function () use ($token) {
                    Cache::put('zt_untracked_last_updated', now()->timestamp, 120);

                    try {
                        $service = new ZerotierService($token);

                        return $service->getControllerNetworks();
                    } catch (\Exception) {
                        return [];
                    }
                }
            );

            foreach ($controllerNetworks as $networkId) {
                $allControllerNetworkIds[$networkId] = true;
            }
        }

        $untrackedCount = 0;
        foreach (array_keys($allControllerNetworkIds) as $networkId) {
            if (! in_array($networkId, $trackedIds)) {
                $untrackedCount++;
            }
        }

        return [
            'count' => $untrackedCount,
            'last_updated' => Cache::get('zt_untracked_last_updated'),
        ];
    }
}

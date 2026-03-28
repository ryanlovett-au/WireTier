<?php

namespace App\Services;

use App\Models\ZerotierNetwork;
use App\Models\ZerotierToken;
use Illuminate\Support\Facades\Cache;

class ZerotierStatsService
{
    /**
     * Get authorized member counts for all tracked networks, cached per network for 5 minutes.
     *
     * Returns ['total' => int, 'by_network' => [network_id => int]]
     */
    public static function authorizedMembers(?string $teamId = null): array
    {
        $query = ZerotierNetwork::with('zerotierToken');

        if ($teamId) {
            $query->where('team_id', $teamId);
        }

        $networks = $query->get();

        $total = 0;
        $byNetwork = [];

        foreach ($networks as $network) {
            $token = $network->zerotierToken;

            if (! $token || ! $token->is_active) {
                continue;
            }

            $count = Cache::remember(
                "zt_members_{$network->network_id}",
                60,
                function () use ($token, $network) {
                    Cache::put('zt_members_last_updated', now()->timestamp, 60);
                    try {
                        $service = new ZerotierService($token);
                        $members = $service->getNetworkMembers($network->network_id);

                        // Count only authorized members
                        $authorized = 0;
                        foreach (array_keys($members) as $nodeId) {
                            try {
                                $member = $service->getNetworkMember($network->network_id, $nodeId);
                                if ($member['authorized'] ?? false) {
                                    $authorized++;
                                }
                            } catch (\Exception) {
                                // skip
                            }
                        }

                        return $authorized;
                    } catch (\Exception) {
                        return null; // null = couldn't reach API
                    }
                }
            );

            if ($count !== null) {
                $total += $count;
                $byNetwork[$network->network_id] = $count;
            }
        }

        return ['total' => $total, 'by_network' => $byNetwork];
    }
}

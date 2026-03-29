<?php

namespace App\Services;

use App\Models\ZerotierMember;
use App\Models\ZerotierNetwork;
use App\Models\ZerotierToken;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

class ZerotierSyncService
{
    /**
     * Sync a single network and its members from the controller API.
     */
    public static function syncNetwork(ZerotierNetwork $network): bool
    {
        $token = $network->zerotierToken;

        if (! $token || ! $token->is_active) {
            return false;
        }

        try {
            $service = new ZerotierService($token);

            // Sync network config
            $apiNetwork = $service->getControllerNetwork($network->network_id);

            if (! empty($apiNetwork) && isset($apiNetwork['nwid'])) {
                $network->update([
                    'name' => $apiNetwork['name'] ?? $network->name,
                    'private' => $apiNetwork['private'] ?? $network->private,
                    'config' => $apiNetwork,
                    'synced_at' => now(),
                ]);
            }

            // Sync members
            $apiMembers = $service->getNetworkMembers($network->network_id);
            $apiNodeIds = array_keys($apiMembers);

            // Get peer data for online status enrichment
            $peers = collect();

            try {
                $peers = collect($service->getPeers())->keyBy('address');
            } catch (\Exception) {
                // Peer data is optional
            }

            $controllerAddress = substr($network->network_id, 0, 10);
            $syncedNodeIds = [];

            foreach ($apiNodeIds as $nodeId) {
                try {
                    $memberData = $service->getNetworkMember($network->network_id, $nodeId);

                    // Determine online status from peer data
                    $isOnline = false;
                    $latency = -1;
                    $physicalAddress = null;

                    if ($nodeId === $controllerAddress) {
                        $isOnline = true;
                        $latency = 0;
                    } elseif ($peer = $peers->get($nodeId)) {
                        $activePaths = collect($peer['paths'] ?? [])->where('active', true);
                        $isOnline = $activePaths->isNotEmpty();
                        $latency = $peer['latency'] ?? -1;
                        $physicalAddress = $activePaths->first()['address'] ?? ($peer['physicalAddress'] ?? null);
                    }

                    // Build version string
                    $version = null;
                    if (isset($memberData['vMajor'])) {
                        $version = $memberData['vMajor'].'.'.($memberData['vMinor'] ?? 0).'.'.($memberData['vRev'] ?? 0);
                    }

                    ZerotierMember::updateOrCreate(
                        [
                            'zerotier_network_id' => $network->id,
                            'node_id' => $nodeId,
                        ],
                        [
                            'name' => $memberData['name'] ?? null,
                            'authorised' => $memberData['authorized'] ?? false,
                            'active_bridge' => $memberData['activeBridge'] ?? false,
                            'no_auto_assign_ips' => $memberData['noAutoAssignIps'] ?? false,
                            'ip_assignments' => $memberData['ipAssignments'] ?? [],
                            'client_version' => $version,
                            'is_online' => $isOnline,
                            'latency' => $latency,
                            'physical_address' => $physicalAddress,
                            'synced_at' => now(),
                        ]
                    );

                    $syncedNodeIds[] = $nodeId;
                } catch (\Exception $e) {
                    Log::warning("Failed to sync member {$nodeId} on network {$network->network_id}: {$e->getMessage()}");
                }
            }

            // Remove members that no longer exist on the controller
            ZerotierMember::where('zerotier_network_id', $network->id)
                ->whereNotIn('node_id', $syncedNodeIds)
                ->delete();

            // Clear cache for this network's members
            Cache::forget("network_{$network->id}_members");

            return true;
        } catch (\Exception $e) {
            Log::warning("Failed to sync network {$network->network_id}: {$e->getMessage()}");

            return false;
        }
    }

    /**
     * Sync all networks for a specific controller token.
     */
    public static function syncToken(string $tokenId): int
    {
        $networks = ZerotierNetwork::where('zerotier_token_id', $tokenId)->get();
        $synced = 0;

        foreach ($networks as $network) {
            if (self::syncNetwork($network)) {
                $synced++;
            }
        }

        // Clear team-level caches for all affected teams
        $teamIds = $networks->pluck('team_id')->unique();
        foreach ($teamIds as $teamId) {
            Cache::forget("team_{$teamId}_networks_{$tokenId}");
            Cache::forget("zt_stats_authorised_{$teamId}");
        }
        Cache::forget('zt_stats_authorised_all');

        return $synced;
    }

    /**
     * Sync all networks across all active controller tokens.
     */
    public static function syncAll(): int
    {
        $tokens = ZerotierToken::where('is_active', true)->get();
        $totalSynced = 0;

        foreach ($tokens as $token) {
            $totalSynced += self::syncToken($token->id);
        }

        Cache::put('zt_last_synced', now()->timestamp, 120);

        return $totalSynced;
    }
}

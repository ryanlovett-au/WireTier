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
     *
     * @param  bool  $system  Trusted background caller — bypasses the interactive per-user rate limit.
     * @param  bool  $force  Sync even if the network was synced within the debounce window.
     */
    public static function syncNetwork(ZerotierNetwork $network, bool $system = false, bool $force = false): bool
    {
        $token = $network->zerotierToken;

        if (! $token || ! $token->is_active) {
            return false;
        }

        // Debounce: an interactive Refresh within the window is a no-op served
        // from the last sync, so repeated clicks can't spam the controller.
        // Mutations pass $force to guarantee the change is reflected.
        $debounce = (int) config('wiretier.sync_debounce_seconds', 0);

        if (! $force && $debounce > 0 && $network->synced_at && $network->synced_at->gt(now()->subSeconds($debounce))) {
            return true;
        }

        try {
            $service = new ZerotierService($token);

            if ($system) {
                $service->withoutRateLimit();
            }

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

            // Sync members. getNetworkMembers() throws on a failed request, so if
            // we get here $apiNodeIds is the controller's authoritative membership
            // list — an empty list means the controller genuinely has no members,
            // not that the call failed.
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
                } catch (\Exception $e) {
                    // A single member's detail fetch failing (e.g. a transient
                    // error or rate limit) must not drop it from the DB — the
                    // controller still lists it, so leave the existing row intact.
                    Log::warning("Failed to sync member {$nodeId} on network {$network->network_id}: {$e->getMessage()}");
                }
            }

            // Remove members that no longer exist on the controller. Reconcile
            // against the authoritative membership list ($apiNodeIds), not the
            // subset that fetched cleanly, so a partial/rate-limited sync never
            // deletes members the controller still reports.
            ZerotierMember::where('zerotier_network_id', $network->id)
                ->whereNotIn('node_id', $apiNodeIds)
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
    public static function syncToken(string $tokenId, bool $system = false): int
    {
        $networks = ZerotierNetwork::where('zerotier_token_id', $tokenId)->get();
        $synced = 0;

        foreach ($networks as $network) {
            if (self::syncNetwork($network, $system)) {
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
    public static function syncAll(bool $system = true): int
    {
        $tokens = ZerotierToken::where('is_active', true)->get();
        $totalSynced = 0;

        foreach ($tokens as $token) {
            $totalSynced += self::syncToken($token->id, $system);
        }

        Cache::put('zt_last_synced', now()->timestamp, 120);

        return $totalSynced;
    }
}

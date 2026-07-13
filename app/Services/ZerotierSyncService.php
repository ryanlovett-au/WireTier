<?php

namespace App\Services;

use App\Models\ZerotierMember;
use App\Models\ZerotierNetwork;
use App\Models\ZerotierToken;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

class ZerotierSyncService
{
    /**
     * Sync a single network and its members from the controller API.
     *
     * @param  bool  $system  Trusted background caller — bypasses the interactive per-user rate limit.
     * @param  bool  $force  Sync even if the network was synced within the debounce window.
     * @param  ?Collection  $peers  Pre-fetched node-global peer list (keyed by address); fetched here if null.
     */
    public static function syncNetwork(ZerotierNetwork $network, bool $system = false, bool $force = false, ?Collection $peers = null): bool
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
            // The list maps node_id => config revision. The revision lets us skip
            // the per-member detail fetch for members whose config is unchanged.
            $apiMembers = $service->getNetworkMembers($network->network_id);
            $apiNodeIds = array_keys($apiMembers);

            // Peer data (online/latency/physical) is node-global and volatile, so
            // it's fetched once per sync — by syncToken for a whole controller, or
            // here for a standalone single-network sync.
            if ($peers === null) {
                $peers = collect();

                try {
                    $peers = collect($service->getPeers())->keyBy('address');
                } catch (\Exception) {
                    // Peer data is optional
                }
            }

            $controllerAddress = substr($network->network_id, 0, 10);

            // Revisions we already hold, to decide which members actually changed.
            $knownRevisions = ZerotierMember::where('zerotier_network_id', $network->id)
                ->pluck('revision', 'node_id');

            foreach ($apiMembers as $nodeId => $revision) {
                [$isOnline, $latency, $physicalAddress] = self::resolvePeerState($nodeId, $controllerAddress, $peers);

                // Stamp last_seen whenever we observe the member online; leave it
                // untouched otherwise so the "last seen X ago" value persists once
                // the member goes offline. The controller API has no last-online
                // field of its own, so this observed timestamp is the only source.
                $runtime = [
                    'is_online' => $isOnline,
                    'latency' => $latency,
                    'physical_address' => $physicalAddress,
                    'synced_at' => now(),
                ];

                if ($isOnline) {
                    $runtime['last_seen'] = now();
                }

                // Config unchanged: refresh only the volatile runtime fields (from
                // the single peer call) — no per-member detail request needed.
                if (isset($knownRevisions[$nodeId]) && (int) $knownRevisions[$nodeId] === (int) $revision) {
                    ZerotierMember::where('zerotier_network_id', $network->id)
                        ->where('node_id', $nodeId)
                        ->update($runtime);

                    continue;
                }

                // New or changed member: fetch the full config detail.
                try {
                    $memberData = $service->getNetworkMember($network->network_id, $nodeId);

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
                            'revision' => $memberData['revision'] ?? $revision,
                            ...$runtime,
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
     * Resolve a member's volatile runtime state — [online, latency, physical
     * address] — from the node-global peer list. These change every sync and
     * are refreshed without a per-member detail request.
     */
    private static function resolvePeerState(string $nodeId, string $controllerAddress, Collection $peers): array
    {
        if ($nodeId === $controllerAddress) {
            return [true, 0, null];
        }

        if ($peer = $peers->get($nodeId)) {
            $activePaths = collect($peer['paths'] ?? [])->where('active', true);

            return [
                $activePaths->isNotEmpty(),
                $peer['latency'] ?? -1,
                $activePaths->first()['address'] ?? ($peer['physicalAddress'] ?? null),
            ];
        }

        return [false, -1, null];
    }

    /**
     * Fetch the node-global peer list for a token, keyed by address.
     * Returns an empty collection on failure — peer data is optional enrichment.
     */
    private static function fetchPeers(ZerotierToken $token, bool $system): Collection
    {
        try {
            $service = new ZerotierService($token);

            if ($system) {
                $service->withoutRateLimit();
            }

            return collect($service->getPeers())->keyBy('address');
        } catch (\Exception) {
            return collect();
        }
    }

    /**
     * Sync all networks for a specific controller token.
     */
    public static function syncToken(string $tokenId, bool $system = false): int
    {
        $networks = ZerotierNetwork::where('zerotier_token_id', $tokenId)->get();
        $synced = 0;

        // Fetch the node-global peer list once for the whole controller rather
        // than once per network.
        $token = ZerotierToken::find($tokenId);
        $peers = ($token && $token->is_active) ? self::fetchPeers($token, $system) : collect();

        foreach ($networks as $network) {
            if (self::syncNetwork($network, $system, false, $peers)) {
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

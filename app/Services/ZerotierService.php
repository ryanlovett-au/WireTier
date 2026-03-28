<?php

namespace App\Services;

use App\Models\ZerotierToken;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;

class ZerotierService
{
    protected string $baseUrl;

    protected string $token;

    public function __construct(protected ZerotierToken $zerotierToken)
    {
        $this->baseUrl = rtrim($zerotierToken->token ? $zerotierToken->host : 'http://localhost:9993', '/');
        $this->token = $zerotierToken->token;
    }

    protected function client()
    {
        return Http::withHeaders([
            'X-ZT1-Auth' => $this->token,
        ])->baseUrl($this->baseUrl)
            ->timeout(10)
            ->acceptJson();
    }

    // ─── Status ──────────────────────────────────────────────────────

    public function getStatus(): array
    {
        $response = $this->client()->get('/status');

        return $response->json();
    }

    // ─── Controller ──────────────────────────────────────────────────

    public function getController(): array
    {
        $response = $this->client()->get('/controller');

        return $response->json();
    }

    // ─── Controller Networks ─────────────────────────────────────────

    public function getControllerNetworks(): array
    {
        $response = $this->client()->get('/controller/network');

        return $response->json() ?? [];
    }

    public function getControllerNetwork(string $networkId): array
    {
        $response = $this->client()->get("/controller/network/{$networkId}");

        return $response->json();
    }

    public function createNetwork(?array $config = null): array
    {
        $status = $this->getStatus();
        $nodeAddress = $status['address'] ?? null;

        if (! $nodeAddress) {
            throw new \RuntimeException('Could not determine controller node address');
        }

        $response = $this->client()->post("/controller/network/{$nodeAddress}______", $config ?? []);

        return $response->json();
    }

    public function updateNetwork(string $networkId, array $config): array
    {
        $response = $this->client()->post("/controller/network/{$networkId}", $config);

        return $response->json();
    }

    public function deleteNetwork(string $networkId): bool
    {
        $response = $this->client()->delete("/controller/network/{$networkId}");

        return $response->successful();
    }

    // ─── Controller Network Members ──────────────────────────────────

    public function getNetworkMembers(string $networkId): array
    {
        $response = $this->client()->get("/controller/network/{$networkId}/member");

        return $response->json() ?? [];
    }

    public function getNetworkMember(string $networkId, string $nodeId): array
    {
        $response = $this->client()->get("/controller/network/{$networkId}/member/{$nodeId}");

        return $response->json();
    }

    public function updateNetworkMember(string $networkId, string $nodeId, array $config): array
    {
        $response = $this->client()->post("/controller/network/{$networkId}/member/{$nodeId}", $config);

        return $response->json();
    }

    public function authorizeMember(string $networkId, string $nodeId): array
    {
        return $this->updateNetworkMember($networkId, $nodeId, ['authorized' => true]);
    }

    public function deauthorizeMember(string $networkId, string $nodeId): array
    {
        return $this->updateNetworkMember($networkId, $nodeId, ['authorized' => false]);
    }

    public function deleteMember(string $networkId, string $nodeId): bool
    {
        $response = $this->client()->delete("/controller/network/{$networkId}/member/{$nodeId}");

        return $response->successful();
    }

    // ─── Peers ───────────────────────────────────────────────────────

    public function getPeers(): array
    {
        $response = $this->client()->get('/peer');

        return $response->json() ?? [];
    }

    public function getPeer(string $address): array
    {
        $response = $this->client()->get("/peer/{$address}");

        return $response->json();
    }

    // ─── Node Networks (joined) ──────────────────────────────────────

    public function getNetworks(): array
    {
        $response = $this->client()->get('/network');

        return $response->json() ?? [];
    }

    public function joinNetwork(string $networkId): array
    {
        $response = $this->client()->post("/network/{$networkId}", []);

        return $response->json();
    }

    public function leaveNetwork(string $networkId): bool
    {
        $response = $this->client()->delete("/network/{$networkId}");

        return $response->successful();
    }

    // ─── Connection Test ─────────────────────────────────────────────

    public function testConnection(): array
    {
        try {
            $status = $this->getStatus();

            return [
                'success' => true,
                'address' => $status['address'] ?? null,
                'version' => $status['version'] ?? null,
                'online' => $status['online'] ?? false,
            ];
        } catch (ConnectionException $e) {
            return [
                'success' => false,
                'error' => 'Could not connect to ZeroTier service at '.$this->baseUrl,
            ];
        } catch (\Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage(),
            ];
        }
    }
}

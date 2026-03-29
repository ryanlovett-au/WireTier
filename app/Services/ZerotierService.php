<?php

namespace App\Services;

use App\Models\ZerotierToken;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\RateLimiter;

class ZerotierService
{
    protected string $baseUrl;

    protected string $token;

    public function __construct(protected ZerotierToken $zerotierToken)
    {
        if (empty($zerotierToken->token)) {
            throw new \InvalidArgumentException('ZerotierToken has no API token configured');
        }

        $host = $zerotierToken->host;
        $scheme = parse_url($host, PHP_URL_SCHEME);

        if (! in_array($scheme, ['http', 'https'])) {
            throw new \InvalidArgumentException("Invalid host scheme: {$scheme}");
        }

        $this->baseUrl = rtrim($host, '/');
        $this->token = $zerotierToken->token;
    }

    protected static function validatePathSegment(string $value, string $label): void
    {
        if (! preg_match('/^[a-zA-Z0-9_-]+$/', $value)) {
            throw new \InvalidArgumentException("Invalid {$label}: contains unsafe characters");
        }
    }

    protected function client()
    {
        $userId = auth()->id() ?? 'system';
        $key = "zt_api:{$userId}";

        if (RateLimiter::tooManyAttempts($key, 120)) {
            throw new \RuntimeException('Too many API requests. Please wait before trying again.');
        }

        RateLimiter::hit($key, 60);

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
        self::validatePathSegment($networkId, 'networkId');
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

        self::validatePathSegment($nodeAddress, 'nodeAddress');
        $response = $this->client()->post("/controller/network/{$nodeAddress}______", $config ?? []);

        return $response->json();
    }

    public function updateNetwork(string $networkId, array $config): array
    {
        self::validatePathSegment($networkId, 'networkId');
        $response = $this->client()->post("/controller/network/{$networkId}", $config);

        return $response->json();
    }

    public function deleteNetwork(string $networkId): bool
    {
        self::validatePathSegment($networkId, 'networkId');
        $response = $this->client()->delete("/controller/network/{$networkId}");

        return $response->successful();
    }

    // ─── Controller Network Members ──────────────────────────────────

    public function getNetworkMembers(string $networkId): array
    {
        self::validatePathSegment($networkId, 'networkId');
        $response = $this->client()->get("/controller/network/{$networkId}/member");

        return $response->json() ?? [];
    }

    public function getNetworkMember(string $networkId, string $nodeId): array
    {
        self::validatePathSegment($networkId, 'networkId');
        self::validatePathSegment($nodeId, 'nodeId');
        $response = $this->client()->get("/controller/network/{$networkId}/member/{$nodeId}");

        return $response->json();
    }

    public function updateNetworkMember(string $networkId, string $nodeId, array $config): array
    {
        self::validatePathSegment($networkId, 'networkId');
        self::validatePathSegment($nodeId, 'nodeId');
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
        self::validatePathSegment($networkId, 'networkId');
        self::validatePathSegment($nodeId, 'nodeId');
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
        self::validatePathSegment($address, 'address');
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
        self::validatePathSegment($networkId, 'networkId');
        $response = $this->client()->post("/network/{$networkId}", []);

        return $response->json();
    }

    public function leaveNetwork(string $networkId): bool
    {
        self::validatePathSegment($networkId, 'networkId');
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

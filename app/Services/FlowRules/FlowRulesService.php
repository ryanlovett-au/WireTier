<?php

namespace App\Services\FlowRules;

use App\Models\FlowRuleRevision;
use App\Models\ZerotierNetwork;
use App\Services\ZerotierService;
use Illuminate\Support\Facades\DB;
use Throwable;

/**
 * Compiles a rules script and applies it to a network's controller, keeping
 * the script, its name metadata and a fingerprint of the result in WireTier.
 */
class FlowRulesService
{
    /**
     * Upper bound on a rules script in bytes, well above anything the
     * controller can hold. Bytes, not characters: the script is stored in
     * TEXT columns, which hold 65,535 bytes.
     */
    public const MAX_SOURCE_BYTES = 65535;

    /** Starting point offered in the editor. */
    public const EXAMPLE_SOURCE = <<<'RULES'
# Flow rules are evaluated top to bottom; the first matching action wins.
# Anything that matches no rule is dropped, so end with an explicit accept.

# Allow only IPv4, IPv4 ARP and IPv6 Ethernet frames.
drop
	not ethertype ipv4
	and not ethertype arp
	and not ethertype ipv6
;

# Example capability: lets members granted "ssh" open SSH connections.
# cap ssh
# 	id 1000
# 	accept ipprotocol tcp dport 22;
# ;

# Example tag: lets members in the same department talk freely.
# tag department
# 	id 2000
# 	enum 100 engineering
# 	enum 200 sales
# ;
# accept tdiff department 0;

# Accept anything else.
accept;

RULES;

    /** Script equivalent to the controller's default rules. */
    public const DEFAULT_SOURCE = <<<'RULES'
# Accept all traffic (the ZeroTier default).
#
# Add your rules ABOVE this line. Rules are checked top to bottom, and a
# bare action like "accept;" must be the last rule in the script.
accept;

RULES;

    /**
     * Compile and apply $source to the network. Throws FlowRuleCompileException
     * for an invalid script (nothing is sent), the HTTP client's exception if
     * the controller rejects the update (nothing is changed), or
     * FlowRulesNotRecordedException if the controller accepted the rules but
     * WireTier could not store them (the rules ARE live).
     */
    public function apply(ZerotierNetwork $network, string $source, ?ZerotierService $service = null): CompiledRules
    {
        if (strlen($source) > self::MAX_SOURCE_BYTES) {
            throw new FlowRuleCompileException(self::tooLargeMessage(), 0, 0);
        }

        $compiled = FlowRuleCompiler::compile($source);

        $service ??= new ZerotierService($network->zerotierToken);
        $live = $service->updateNetwork($network->network_id, $compiled->toNetworkConfig());

        // From here the rules are live on the controller: a failure must not
        // be reported as "nothing changed".
        try {
            // Fingerprint the controller's normalised copy (see RulesFingerprint).
            if (! isset($live['rules'])) {
                $live = $service->getControllerNetwork($network->network_id);
            }

            $hash = RulesFingerprint::of($live);

            DB::transaction(function () use ($network, $source, $compiled, $hash, $live) {
                $network->update([
                    'config' => array_merge($network->config ?? [], $live),
                    'rules_source' => $source,
                    'rules_meta' => $compiled->metadata(),
                    'rules_hash' => $hash,
                    'rules_updated_at' => now(),
                ]);

                $this->recordRevision($network, $source, $compiled, $hash);
            });
        } catch (Throwable $e) {
            throw new FlowRulesNotRecordedException("Rules applied to {$network->network_id} but not recorded: {$e->getMessage()}", 0, $e);
        }

        return $compiled;
    }

    public static function tooLargeMessage(): string
    {
        return 'The rules script is larger than 64 KB ('.number_format(self::MAX_SOURCE_BYTES).' bytes).';
    }

    /** Keep the applied script in the network's history, pruning the oldest. */
    private function recordRevision(ZerotierNetwork $network, string $source, CompiledRules $compiled, string $hash): void
    {
        FlowRuleRevision::create([
            'zerotier_network_id' => $network->id,
            'network_id' => $network->network_id,
            'user_id' => auth()->id(),
            'source' => $source,
            'meta' => $compiled->metadata(),
            'hash' => $hash,
            'rule_count' => count($compiled->rules),
            'capability_count' => count($compiled->capabilities),
            'tag_count' => count($compiled->tags),
        ]);

        $stale = $network->ruleRevisions()->skip(FlowRuleRevision::KEEP)->take(PHP_INT_MAX)->pluck('id');
        if ($stale->isNotEmpty()) {
            FlowRuleRevision::whereIn('id', $stale)->delete();
        }
    }
}

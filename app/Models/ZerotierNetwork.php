<?php

namespace App\Models;

use App\Services\FlowRules\FlowRuleCompiler;
use App\Services\FlowRules\RulesFingerprint;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class ZerotierNetwork extends Model
{
    use HasFactory;

    protected $keyType = 'string';

    public $incrementing = false;

    protected $fillable = [
        'team_id', 'zerotier_token_id', 'network_id', 'name', 'description', 'private', 'config', 'synced_at',
        'rules_source', 'rules_meta', 'rules_hash', 'rules_updated_at',
    ];

    protected static function booted(): void
    {
        static::creating(function ($model) {
            $model->id = Str::uuid7();
        });

        static::deleting(function (ZerotierNetwork $network) {
            $network->ruleRevisions()->delete();
        });

        // The network list, dashboard counts and untracked count are cached;
        // without this a deleted network stays listed until they expire.
        // After commit: inside a transaction (e.g. team deletion), clearing
        // earlier lets another request re-cache the rows before they're gone.
        static::deleted(function (ZerotierNetwork $network) {
            DB::afterCommit(function () use ($network) {
                Cache::forget("team_{$network->team_id}_networks_{$network->zerotier_token_id}");
                Cache::forget("network_{$network->id}_members");
                Cache::forget("zt_controller_networks_{$network->zerotier_token_id}");
                Cache::forget("zt_stats_authorised_{$network->team_id}");
                Cache::forget('zt_stats_authorised_all');
            });
        });
    }

    protected function casts(): array
    {
        return [
            'private' => 'boolean',
            'config' => 'array',
            'synced_at' => 'datetime',
            'rules_meta' => 'array',
            'rules_updated_at' => 'datetime',
        ];
    }

    /**
     * How this network's live flow rules relate to the script WireTier holds:
     *  - 'managed':   applied by WireTier and unchanged since
     *  - 'drifted':   applied by WireTier, then changed outside it
     *  - 'default':   never set; the controller's default accept-all rules
     *  - 'unmanaged': set by another tool; WireTier has no script for them
     *
     * @param  ?array  $liveConfig  Controller network config; defaults to the last synced copy.
     */
    public function rulesState(?array $liveConfig = null): string
    {
        $live = $liveConfig ?? $this->config ?? [];

        if ($this->rules_hash !== null) {
            return RulesFingerprint::of($live) === $this->rules_hash ? 'managed' : 'drifted';
        }

        return RulesFingerprint::isDefault($live) ? 'default' : 'unmanaged';
    }

    /**
     * Drop WireTier's record of the network (members included) without
     * touching the controller, keeping its rules history by network ID so a
     * later import gets the scripts back (see restoreReleasedRules()). Used
     * when the owning team is deleted.
     */
    public function release(): void
    {
        DB::transaction(function () {
            $this->snapshotCurrentRules();

            FlowRuleRevision::where('zerotier_network_id', $this->id)
                ->update(['zerotier_network_id' => null, 'network_id' => $this->network_id]);

            $this->members()->delete();
            $this->delete();
        });
    }

    /**
     * Re-attach history released by a deleted team and restore its newest
     * script. If the live rules changed since, the network reads as drifted.
     */
    public function restoreReleasedRules(): void
    {
        $released = FlowRuleRevision::whereNull('zerotier_network_id')->where('network_id', $this->network_id);

        if (! $released->exists()) {
            return;
        }

        $released->update(['zerotier_network_id' => $this->id]);
        $latest = $this->ruleRevisions()->first();

        $this->update([
            'rules_source' => $latest->source,
            'rules_meta' => $latest->meta,
            'rules_hash' => $latest->hash,
            'rules_updated_at' => $latest->created_at,
        ]);
    }

    /** Make sure the script in use is in the history (it isn't if it predates history). */
    protected function snapshotCurrentRules(): void
    {
        if ($this->rules_source === null) {
            return;
        }

        $latest = $this->ruleRevisions()->first();

        if ($latest && $latest->source === $this->rules_source && $latest->hash === $this->rules_hash) {
            return;
        }

        try {
            $ruleCount = count(FlowRuleCompiler::compile($this->rules_source)->rules);
        } catch (\Throwable) {
            $ruleCount = 0;
        }

        $revision = new FlowRuleRevision([
            'zerotier_network_id' => $this->id,
            'network_id' => $this->network_id,
            'user_id' => null,
            'source' => $this->rules_source,
            'meta' => $this->rules_meta,
            'hash' => (string) $this->rules_hash,
            'rule_count' => $ruleCount,
            'capability_count' => count($this->rules_meta['capabilities'] ?? []),
            'tag_count' => count($this->rules_meta['tags'] ?? []),
        ]);
        $revision->created_at = $this->rules_updated_at ?? now();
        $revision->save();
    }

    /** Rules scripts applied by WireTier, newest first. */
    public function ruleRevisions(): HasMany
    {
        return $this->hasMany(FlowRuleRevision::class)->orderByDesc('created_at')->orderByDesc('id');
    }

    public function members(): HasMany
    {
        return $this->hasMany(ZerotierMember::class);
    }

    public function team(): BelongsTo
    {
        return $this->belongsTo(Team::class);
    }

    public function zerotierToken(): BelongsTo
    {
        return $this->belongsTo(ZerotierToken::class);
    }
}

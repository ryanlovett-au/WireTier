<?php

namespace App\Models;

use App\Services\FlowRules\RulesFingerprint;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
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

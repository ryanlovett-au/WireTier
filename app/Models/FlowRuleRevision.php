<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Str;

/** A rules script as applied to a network by WireTier, kept for rollback. */
class FlowRuleRevision extends Model
{
    /** Revisions kept per network; older ones are pruned on save. */
    public const KEEP = 50;

    public const UPDATED_AT = null;

    protected $keyType = 'string';

    public $incrementing = false;

    protected $fillable = [
        'zerotier_network_id', 'network_id', 'user_id', 'source', 'meta', 'hash',
        'rule_count', 'capability_count', 'tag_count',
    ];

    protected static function booted(): void
    {
        static::creating(function ($model) {
            $model->id = Str::uuid7();
        });
    }

    protected function casts(): array
    {
        return [
            'meta' => 'array',
        ];
    }

    public function network(): BelongsTo
    {
        return $this->belongsTo(ZerotierNetwork::class, 'zerotier_network_id');
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}

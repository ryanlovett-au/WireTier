<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Str;

class ZerotierMember extends Model
{
    protected $keyType = 'string';

    public $incrementing = false;

    protected $fillable = [
        'zerotier_network_id',
        'node_id',
        'name',
        'description',
        'authorised',
        'active_bridge',
        'no_auto_assign_ips',
        'ip_assignments',
        'last_seen',
        'client_version',
        'is_online',
        'latency',
        'physical_address',
        'synced_at',
    ];

    protected function casts(): array
    {
        return [
            'authorised' => 'boolean',
            'active_bridge' => 'boolean',
            'no_auto_assign_ips' => 'boolean',
            'ip_assignments' => 'array',
            'is_online' => 'boolean',
            'last_seen' => 'datetime',
            'synced_at' => 'datetime',
        ];
    }

    protected static function booted(): void
    {
        static::creating(function ($model) {
            $model->id = Str::uuid7();
        });
    }

    public function network(): BelongsTo
    {
        return $this->belongsTo(ZerotierNetwork::class, 'zerotier_network_id');
    }
}

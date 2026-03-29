<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Str;

class AuditLog extends Model
{
    public $timestamps = false;

    protected $keyType = 'string';

    public $incrementing = false;

    protected $fillable = [
        'user_id',
        'team_id',
        'action',
        'resource_type',
        'resource_id',
        'details',
        'ip_address',
        'created_at',
    ];

    protected function casts(): array
    {
        return [
            'details' => 'array',
            'created_at' => 'datetime',
        ];
    }

    protected static function booted(): void
    {
        static::creating(function ($model) {
            $model->id = Str::uuid7();
            $model->created_at = $model->created_at ?? now();
        });
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function team(): BelongsTo
    {
        return $this->belongsTo(Team::class);
    }

    public function scopeForTeam(Builder $query, string $teamId): Builder
    {
        return $query->where('team_id', $teamId);
    }

    public function scopeForAction(Builder $query, string $action): Builder
    {
        if (str_contains($action, '*')) {
            return $query->where('action', 'like', str_replace('*', '%', $action));
        }

        return $query->where('action', $action);
    }

    public static function record(
        string $action,
        ?string $resourceType = null,
        ?string $resourceId = null,
        ?array $details = null,
        ?string $teamId = null,
    ): self {
        return self::create([
            'user_id' => auth()->id(),
            'team_id' => $teamId ?? auth()->user()?->current_team,
            'action' => $action,
            'resource_type' => $resourceType,
            'resource_id' => $resourceId,
            'details' => $details,
            'ip_address' => request()->ip(),
        ]);
    }
}

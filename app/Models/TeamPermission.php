<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;

class TeamPermission extends Model
{
    protected $keyType = 'string';

    public $incrementing = false;

    protected $fillable = ['team_id', 'permission'];

    protected static function booted(): void
    {
        static::creating(function ($model) {
            $model->id = Str::uuid7();
        });
    }

    public function team(): BelongsTo
    {
        return $this->belongsTo(Team::class);
    }

    public static function permissions($teamId): array
    {
        return Cache::flexible('team_'.$teamId.'_permissions', [30, 60], function () use ($teamId) {
            return TeamPermission::where('team_id', $teamId)->pluck('permission')->toArray();
        });
    }

    public static function check($permission): bool
    {
        if (! auth()->user()->team) {
            return false;
        }

        return in_array($permission, self::permissions(auth()->user()->team->id));
    }
}

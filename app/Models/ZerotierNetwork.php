<?php

namespace App\Models;

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

    protected $fillable = ['team_id', 'zerotier_token_id', 'network_id', 'name', 'description', 'private', 'config', 'synced_at'];

    protected static function booted(): void
    {
        static::creating(function ($model) {
            $model->id = Str::uuid7();
        });
    }

    protected function casts(): array
    {
        return [
            'private' => 'boolean',
            'config' => 'array',
            'synced_at' => 'datetime',
        ];
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

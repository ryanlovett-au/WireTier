<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Str;

class ZerotierToken extends Model
{
    use HasFactory;

    protected $keyType = 'string';

    public $incrementing = false;

    protected $fillable = ['name', 'token', 'host', 'is_active', 'node_address'];

    protected $hidden = ['token', 'host', 'node_address'];

    protected static function booted(): void
    {
        static::creating(function ($model) {
            $model->id = Str::uuid7();
        });
    }

    protected function casts(): array
    {
        return [
            'token' => 'encrypted',
            'is_active' => 'boolean',
        ];
    }

    /**
     * An enabled controller by id, or null. Disabling a controller means
     * WireTier stops talking to it, so every controller call resolves its
     * token through this rather than find()/findOrFail().
     */
    public static function findActive(mixed $id): ?self
    {
        if (! is_string($id) || $id === '') {
            return null;
        }

        return static::where('is_active', true)->find($id);
    }

    public function networks(): HasMany
    {
        return $this->hasMany(ZerotierNetwork::class);
    }
}

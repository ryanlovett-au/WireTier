<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Str;

class TeamUser extends Model
{
    use HasFactory;

    protected $keyType = 'string';

    public $incrementing = false;

    protected $fillable = ['team_id', 'user_id', 'role', 'expires'];

    protected static function booted(): void
    {
        static::creating(function ($model) {
            $model->id = Str::uuid7();
        });

        static::saving(function ($model) {
            if ($model->team_id === config('wiretier.admin_team') && $model->role !== 'admin') {
                throw new \DomainException('Only the admin role is allowed on the admin team.');
            }
        });
    }

    public function team(): BelongsTo
    {
        return $this->belongsTo(Team::class);
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function getExpiredAttribute(): bool
    {
        if (is_null($this->expires)) {
            return false;
        }

        return $this->expires < now()->format('Y-m-d');
    }
}

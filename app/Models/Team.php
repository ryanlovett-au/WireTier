<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasManyThrough;
use Illuminate\Support\Str;

class Team extends Model
{
    use HasFactory;

    protected $keyType = 'string';

    public $incrementing = false;

    protected $fillable = ['name', 'icon', 'colour'];

    protected static function booted(): void
    {
        static::creating(function ($model) {
            $model->id = Str::uuid7();
        });
    }

    public function users(): HasManyThrough
    {
        return $this->hasManyThrough(User::class, TeamUser::class, 'team_id', 'id', 'id', 'user_id');
    }

    public function teamUsers(): HasMany
    {
        return $this->hasMany(TeamUser::class);
    }

    public function zerotierNetworks(): HasMany
    {
        return $this->hasMany(ZerotierNetwork::class);
    }

    public function countUsers(): int
    {
        return TeamUser::where('team_id', $this->id)->count();
    }
}

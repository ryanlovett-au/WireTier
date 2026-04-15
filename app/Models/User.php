<?php

namespace App\Models;

use Database\Factories\UserFactory;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Support\Str;
use Laravel\Fortify\TwoFactorAuthenticatable;

#[Fillable(['name', 'email', 'password', 'current_team'])]
#[Hidden(['password', 'two_factor_secret', 'two_factor_recovery_codes', 'remember_token'])]
class User extends Authenticatable implements MustVerifyEmail
{
    /** @use HasFactory<UserFactory> */
    use HasFactory, Notifiable, TwoFactorAuthenticatable;

    protected $keyType = 'string';

    public $incrementing = false;

    protected static function booted(): void
    {
        static::creating(function ($model) {
            $model->id = Str::uuid7();
        });
    }

    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
        ];
    }

    public function initials(): string
    {
        return Str::of($this->name)
            ->explode(' ')
            ->take(2)
            ->map(fn ($word) => Str::substr($word, 0, 1))
            ->implode('');
    }

    // ─── Team Relationships ──────────────────────────────────────────

    public function getTeamAttribute(): ?Team
    {
        $team = session('current_team', false);
        if ($team instanceof Team) {
            return $team;
        }

        // Clear invalid session data
        if ($team !== false) {
            session()->forget('current_team');
        }

        if (! is_null($this->current_team) && $team = Team::find($this->current_team)) {
            $teamUser = TeamUser::where('team_id', $team->id)->where('user_id', $this->id)->first();

            if ($teamUser) {
                if ($teamUser->expired) {
                    if (TeamUser::where('team_id', $team->id)->count() === 1) {
                        TeamUser::where('team_id', $team->id)->where('user_id', $this->id)
                            ->update(['expires' => now()->addDays(config('wiretier.last_team_member_grace'))->format('Y-m-d')]);

                        return $team;
                    }

                    return null;
                }

                session(['current_team' => $team]);

                return $team;
            }
        }

        session()->forget('current_team');

        return null;
    }

    public function teamUser(): HasOne
    {
        if (! $this->team) {
            return $this->hasOne(TeamUser::class)->whereRaw('1 = 0');
        }

        return $this->hasOne(TeamUser::class)
            ->where('team_id', $this->team->id)
            ->where('user_id', $this->id);
    }

    public function teams(): HasMany
    {
        return $this->hasMany(TeamUser::class)->with('team');
    }

    public function belongsToTeam($teamId): bool
    {
        return TeamUser::where('user_id', $this->id)->where('team_id', $teamId)->exists();
    }

    public function isAdmin(): bool
    {
        return $this->current_team === config('wiretier.admin_team');
    }

    public function isTeamAdmin(): bool
    {
        $teamUser = $this->teamUser;

        return $this->isAdmin() || ($teamUser && $teamUser->role === 'admin');
    }
}

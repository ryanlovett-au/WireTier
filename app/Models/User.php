<?php

namespace App\Models;

use Database\Factories\UserFactory;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\HasMany;
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

    /**
     * Per-instance memo for getTeamAttribute(), keyed by the current_team it
     * was resolved for, so switching teams on the same instance re-resolves.
     */
    protected ?Team $teamMemo = null;

    protected ?TeamUser $membershipMemo = null;

    protected ?string $teamMemoFor = null;

    /**
     * The user's current team, provided they still hold a membership of it.
     *
     * Resolved from the database on every request (memoised within one) rather
     * than cached in the session: a session copy kept granting access after the
     * user was removed from the team or their membership expired.
     */
    public function getTeamAttribute(): ?Team
    {
        $this->resolveCurrentTeamMemo();

        return $this->teamMemo;
    }

    /**
     * The membership row behind the current team (null whenever the team is),
     * resolved together with it so the two can never disagree, including after
     * current_team changes on the same instance.
     */
    public function currentMembership(): ?TeamUser
    {
        $this->resolveCurrentTeamMemo();

        return $this->membershipMemo;
    }

    protected function resolveCurrentTeamMemo(): void
    {
        if ($this->teamMemoFor !== null && $this->teamMemoFor === $this->current_team) {
            return;
        }

        $this->teamMemoFor = $this->current_team;
        [$this->teamMemo, $this->membershipMemo] = $this->resolveCurrentTeam();
    }

    /** @return array{0: ?Team, 1: ?TeamUser} */
    protected function resolveCurrentTeam(): array
    {
        if (is_null($this->current_team) || ! ($team = Team::find($this->current_team))) {
            return [null, null];
        }

        $teamUser = TeamUser::where('team_id', $team->id)->where('user_id', $this->id)->first();

        if (! $teamUser) {
            return [null, null];
        }

        // A team that requires two-factor authentication is closed to members
        // who haven't set it up (see RequireTeamTwoFactor for the redirect).
        if (! $this->meetsTwoFactorRequirementOf($team)) {
            return [null, null];
        }

        if (! $teamUser->expired) {
            return [$team, $teamUser];
        }

        // The last remaining member of a team gets a grace period rather than
        // being locked out of it.
        if (TeamUser::where('team_id', $team->id)->count() === 1) {
            $teamUser->update(['expires' => now()->addDays(config('wiretier.last_team_member_grace'))->format('Y-m-d')]);

            return [$team, $teamUser];
        }

        return [null, null];
    }

    public function teams(): HasMany
    {
        return $this->hasMany(TeamUser::class)->with('team');
    }

    public function belongsToTeam($teamId): bool
    {
        return TeamUser::where('user_id', $this->id)->where('team_id', $teamId)->exists();
    }

    /**
     * Per-instance memo for isAdmin(), which is called many times per request.
     * Not persisted; a fresh request (or fresh()) re-checks the database.
     */
    protected ?bool $isAdminMemo = null;

    protected ?string $isAdminMemoFor = null;

    /**
     * System admin: the admin team is selected AND the user still holds an
     * unexpired membership of it. Checking current_team alone would let a
     * removed or expired admin keep system-wide access indefinitely.
     */
    public function isAdmin(): bool
    {
        $adminTeam = config('wiretier.admin_team');

        if (empty($adminTeam) || $this->current_team !== $adminTeam) {
            return false;
        }

        if ($this->isAdminMemoFor !== $this->current_team) {
            $this->isAdminMemo = null;
            $this->isAdminMemoFor = $this->current_team;
        }

        return $this->isAdminMemo ??= TeamUser::where('team_id', $adminTeam)
            ->where('user_id', $this->id)
            ->active()
            ->exists()
            && $this->meetsTwoFactorRequirementOf($adminTeam);
    }

    /**
     * Whether the user may administer the given team: system admins, or an
     * unexpired 'admin' membership of THAT team. Use this (not isTeamAdmin(),
     * which reflects the current team) whenever acting on a specific team.
     */
    public function canAdministerTeam(string $teamId): bool
    {
        return $this->isAdmin() || (TeamUser::where('team_id', $teamId)
            ->where('user_id', $this->id)
            ->where('role', 'admin')
            ->active()
            ->exists()
            && $this->meetsTwoFactorRequirementOf($teamId));
    }

    /**
     * Whether the user clears a team's two-factor requirement: the team
     * doesn't require it, or the user has confirmed two-factor authentication.
     */
    public function meetsTwoFactorRequirementOf(Team|string|null $team): bool
    {
        $team = is_string($team) ? Team::find($team) : $team;

        return ! $team?->require_two_factor || $this->hasEnabledTwoFactorAuthentication();
    }

    /**
     * The selected team when it requires two-factor authentication that the
     * user (a member of it) hasn't set up yet; null otherwise.
     */
    public function teamAwaitingTwoFactor(): ?Team
    {
        if (is_null($this->current_team) || $this->hasEnabledTwoFactorAuthentication()) {
            return null;
        }

        $team = Team::find($this->current_team);

        return $team?->require_two_factor && $this->belongsToTeam($team->id) ? $team : null;
    }

    /** Whether any team the user belongs to requires two-factor authentication. */
    public function belongsToTeamRequiringTwoFactor(): bool
    {
        return TeamUser::where('user_id', $this->id)
            ->active()
            ->whereIn('team_id', Team::select('id')->where('require_two_factor', true))
            ->exists();
    }

    public function isTeamAdmin(): bool
    {
        $teamUser = $this->currentMembership();

        return $this->isAdmin() || ($teamUser && $teamUser->role === 'admin');
    }

    public function canManageNetworks(): bool
    {
        $teamUser = $this->currentMembership();

        return $this->isAdmin() || ($teamUser && in_array($teamUser->role, ['admin', 'member'], true));
    }
}

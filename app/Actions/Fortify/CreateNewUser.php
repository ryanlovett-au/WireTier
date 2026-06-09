<?php

namespace App\Actions\Fortify;

use App\Concerns\PasswordValidationRules;
use App\Concerns\ProfileValidationRules;
use App\Models\TeamInvitation;
use App\Models\TeamUser;
use App\Models\User;
use Illuminate\Validation\Rule;
use Illuminate\Support\Facades\Validator;
use Laravel\Fortify\Contracts\CreatesNewUsers;

class CreateNewUser implements CreatesNewUsers
{
    use PasswordValidationRules, ProfileValidationRules;

    /**
     * Validate and create a newly registered user.
     *
     * @param  array<string, string>  $input
     */
    public function create(array $input): User
    {
        $rules = [
            ...$this->profileRules(),
            'password' => $this->passwordRules(),
        ];

        if (config('wiretier.registration') === 'invite') {
            $rules['email'] = array_merge((array) $rules['email'], [
                Rule::exists('team_invitations', 'email')->where(function ($query) {
                    $query->where(function ($q) {
                        $q->whereNull('expires')
                            ->orWhere('expires', '>=', now()->format('Y-m-d'));
                    });
                }),
            ]);
        }

        Validator::make($input, $rules, [
            'email.exists' => __('Registration is by invitation only. Please ask a team admin to invite this email address.'),
        ])->validate();

        $user = User::create([
            'name' => $input['name'],
            'email' => $input['email'],
            'password' => $input['password'],
        ]);

        // Process any pending team invitations for this email
        $invitations = TeamInvitation::where('email', $user->email)->get();

        foreach ($invitations as $invitation) {
            if (! $invitation->expired) {
                $role = $invitation->role;

                if ($invitation->team_id === config('wiretier.admin_team') && $role !== 'admin') {
                    $invitation->delete();

                    continue;
                }

                $teamUser = new TeamUser;
                $teamUser->user_id = $user->id;
                $teamUser->team_id = $invitation->team_id;
                $teamUser->role = $role;
                $teamUser->expires = $invitation->expires;
                $teamUser->save();

                // Set as current team if user doesn't have one
                if (is_null($user->current_team)) {
                    $user->current_team = $invitation->team_id;
                    $user->save();
                }
            }

            $invitation->delete();
        }

        return $user;
    }
}

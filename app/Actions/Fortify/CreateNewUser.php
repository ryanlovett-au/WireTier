<?php

namespace App\Actions\Fortify;

use App\Concerns\PasswordValidationRules;
use App\Concerns\ProfileValidationRules;
use App\Models\TeamInvitation;
use App\Models\TeamUser;
use App\Models\User;
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
        Validator::make($input, [
            ...$this->profileRules(),
            'password' => $this->passwordRules(),
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
                $teamUser = new TeamUser;
                $teamUser->user_id = $user->id;
                $teamUser->team_id = $invitation->team_id;
                $teamUser->role = $invitation->role;
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

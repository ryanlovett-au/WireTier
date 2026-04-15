<?php

use App\Mail\TeamInviteUser;

test('TeamInviteUser mail can be rendered', function () {
    $mail = new TeamInviteUser('Test Team', config('wiretier.roles.member'));
    expect($mail->render())->toBeString()->toContain('Test Team');
});

<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Admin Team
    |--------------------------------------------------------------------------
    |
    | The UUID of the admin team. Users in this team have system-wide admin
    | access to manage all teams and settings.
    |
    */
    'admin_team' => env('ADMIN_TEAM_UUID', ''),

    /*
    |--------------------------------------------------------------------------
    | Registration Mode
    |--------------------------------------------------------------------------
    |
    | Controls who can register a new account.
    |
    |   open    - anyone can register (default)
    |   invite  - only emails with a pending, non-expired TeamInvitation may
    |             register
    |   closed  - the /register route is removed entirely
    |
    */
    'registration' => env('WIRETIER_REGISTRATION', 'open'),

    /*
    |--------------------------------------------------------------------------
    | Hide Welcome Page
    |--------------------------------------------------------------------------
    |
    | When true, the marketing welcome page at "/" is hidden. Guests are
    | redirected to the login page and authenticated users go straight to the
    | dashboard.
    |
    */
    'hide_welcome' => env('WIRETIER_HIDE_WELCOME', false),

    /*
    |--------------------------------------------------------------------------
    | Team Roles
    |--------------------------------------------------------------------------
    |
    | Available roles for team members.
    |
    */
    'roles' => [
        'admin' => [
            'name' => 'Admin',
            'description' => 'Full access to manage the team and all resources',
            'colour' => 'red',
        ],
        'member' => [
            'name' => 'Member',
            'description' => 'Can view and manage networks assigned to the team',
            'colour' => 'blue',
        ],
        'viewer' => [
            'name' => 'Viewer',
            'description' => 'Read-only access to team networks',
            'colour' => 'zinc',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Last Team Member Grace Period
    |--------------------------------------------------------------------------
    |
    | Number of days to extend expiry for the last member of a team.
    |
    */
    'last_team_member_grace' => 30,

    /*
    |--------------------------------------------------------------------------
    | Elevate Last Member
    |--------------------------------------------------------------------------
    |
    | Automatically elevate the last remaining team member to admin.
    |
    */
    'elevate_last_member' => true,

];

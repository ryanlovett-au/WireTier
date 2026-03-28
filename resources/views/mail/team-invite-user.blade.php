<x-mail::message>
# You've Been Invited

You have been invited to join the **{{ $teamName }}** team on {{ config('app.name') }} as a **{{ $role['name'] }}**.

To accept this invitation, register for an account and you will be automatically added to the team.

<x-mail::button :url="url('/register')">
Register
</x-mail::button>

Thanks,<br>
{{ config('app.name') }}
</x-mail::message>

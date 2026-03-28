<x-mail::message>
# Added to Team

You have been added to the **{{ $teamName }}** team on {{ config('app.name') }} as a **{{ $role['name'] }}**.

<x-mail::button :url="url('/settings/teams')">
View Teams
</x-mail::button>

Thanks,<br>
{{ config('app.name') }}
</x-mail::message>

<div class="flex items-start max-md:flex-col">
    <div class="me-10 w-full pb-4 md:w-[220px]">
        <flux:navlist aria-label="{{ __('Settings') }}">
            <flux:navlist.item :href="route('profile.edit')" wire:navigate>{{ __('Profile') }}</flux:navlist.item>
            <flux:navlist.item :href="route('security.edit')" wire:navigate>{{ __('Security') }}</flux:navlist.item>
            <flux:navlist.item :href="route('appearance.edit')" wire:navigate>{{ __('Appearance') }}</flux:navlist.item>
        </flux:navlist>

        <flux:navlist aria-label="{{ __('Teams') }}" class="mt-4">
            <flux:navlist.group heading="Teams">
                <flux:navlist.item :href="route('teams.index')" wire:navigate>{{ __('My Teams') }}</flux:navlist.item>
                @if (auth()->user()->team)
                    <flux:navlist.item :href="route('teams.show', auth()->user()->current_team)" wire:navigate>
                        {{ auth()->user()->team->name }}
                    </flux:navlist.item>
                @endif
            </flux:navlist.group>
        </flux:navlist>

        @if (auth()->user()->isTeamAdmin() || auth()->user()->isAdmin())
        <flux:navlist aria-label="{{ __('Security') }}" class="mt-4">
            <flux:navlist.group heading="Security">
                <flux:navlist.item :href="route('audit-log.index')" wire:navigate>{{ __('Audit Log') }}</flux:navlist.item>
            </flux:navlist.group>
        </flux:navlist>
        @endif
    </div>

    <flux:separator class="md:hidden" />

    <div class="flex-1 self-stretch max-md:pt-6">
        <flux:heading>{{ $heading ?? '' }}</flux:heading>
        <flux:subheading>{{ $subheading ?? '' }}</flux:subheading>

        <div class="mt-5 w-full">
            {{ $slot }}
        </div>
    </div>
</div>

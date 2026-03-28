<x-layouts::app :title="$heading ?? 'Settings'">
    <div class="mx-auto max-w-4xl p-6">
        <flux:heading size="xl">Settings</flux:heading>
        <flux:subheading>Manage your profile, team and account settings.</flux:subheading>

        <flux:separator class="my-6" />

        <div class="flex items-start max-md:flex-col">
            <div class="me-10 w-full pb-4 md:w-[220px]">
                <flux:navlist aria-label="Settings">
                    <flux:navlist.item :href="route('profile.edit')" wire:navigate>Profile</flux:navlist.item>
                    <flux:navlist.item :href="route('security.edit')" wire:navigate>Security</flux:navlist.item>
                    <flux:navlist.item :href="route('appearance.edit')" wire:navigate>Appearance</flux:navlist.item>

                    <flux:navlist.group heading="Teams" class="mt-4">
                        <flux:navlist.item :href="route('teams.index')" wire:navigate>My Teams</flux:navlist.item>
                        @if (auth()->user()->team)
                            <flux:navlist.item :href="route('teams.show', ['id' => auth()->user()->current_team])" wire:navigate>
                                {{ auth()->user()->team->name }}
                            </flux:navlist.item>
                        @endif
                    </flux:navlist.group>
                </flux:navlist>
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
    </div>
</x-layouts::app>

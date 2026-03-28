<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}" class="dark">
    <head>
        @include('partials.head')
    </head>
    <body class="min-h-screen bg-white dark:bg-zinc-800">
        <flux:sidebar sticky collapsible="mobile" class="border-e border-zinc-200 bg-zinc-50 dark:border-zinc-700 dark:bg-zinc-900">
            <flux:sidebar.header>
                <x-app-logo :sidebar="true" href="{{ route('dashboard') }}" wire:navigate />
                <flux:sidebar.collapse class="lg:hidden" />
            </flux:sidebar.header>

            <flux:sidebar.nav>
                <flux:sidebar.group :heading="__('Platform')" class="grid">
                    <flux:sidebar.item icon="home" :href="route('dashboard')" :current="request()->routeIs('dashboard')" wire:navigate>
                        {{ __('Dashboard') }}
                    </flux:sidebar.item>
                </flux:sidebar.group>

                <flux:sidebar.group :heading="__('ZeroTier')" class="grid">
                    <flux:sidebar.item icon="globe-alt" :href="route('zerotier.networks')" :current="request()->routeIs('zerotier.networks') || request()->routeIs('zerotier.members')" wire:navigate>
                        {{ __('Networks') }}
                    </flux:sidebar.item>
                    @if (auth()->user()->isAdmin())
                    <flux:sidebar.item icon="signal" :href="route('zerotier.peers')" :current="request()->routeIs('zerotier.peers')" wire:navigate>
                        {{ __('Peers') }}
                    </flux:sidebar.item>
                    <flux:sidebar.item icon="key" :href="route('zerotier.tokens')" :current="request()->routeIs('zerotier.tokens')" wire:navigate>
                        {{ __('Controllers') }}
                    </flux:sidebar.item>
                    <x-zerotier-status />
                    @endif
                </flux:sidebar.group>
            </flux:sidebar.nav>

            <flux:spacer />

            <flux:sidebar.nav>
                @php
                    $userTeams = auth()->user()->teams()->with('team')->get();
                    $activeTeam = auth()->user()->team;
                    $teamColours = [
                        'blue'   => '#3b82f6', 'red'    => '#ef4444', 'green'  => '#22c55e',
                        'purple' => '#a855f7', 'orange' => '#f97316', 'yellow' => '#eab308',
                        'pink'   => '#ec4899', 'indigo' => '#6366f1', 'cyan'   => '#06b6d4',
                        'zinc'   => '#71717a', 'lime'   => '#84cc16', 'teal'   => '#14b8a6',
                    ];
                @endphp
                @if ($userTeams->count() > 0)
                <flux:dropdown position="top" align="start" class="w-full">
                    {{-- Custom trigger matching Flux sidebar.profile hover exactly --}}
                    @php $colour = $teamColours[$activeTeam?->colour] ?? '#6366f1'; @endphp
                    <button type="button" class="group flex items-center w-full rounded-lg p-1 hover:bg-zinc-800/5 dark:hover:bg-white/10">
                        <div class="shrink-0" style="width:2rem;height:2rem;border-radius:0.375rem;background:{{ $colour }};display:flex;align-items:center;justify-content:center;">
                            <flux:icon name="{{ $activeTeam?->icon ?? 'users' }}" class="size-4 text-white" />
                        </div>
                        <div class="mx-2 flex-1 min-w-0 text-left">
                            <div class="text-sm font-medium truncate text-zinc-500 dark:text-white/80 group-hover:text-zinc-800 dark:group-hover:text-white">{{ $activeTeam?->name ?? 'Select Team' }}</div>
                            <div class="text-xs truncate text-zinc-400 dark:text-white/50">{{ ucfirst(auth()->user()->teamUser?->role ?? 'member') }}</div>
                        </div>
                        <div class="shrink-0 ms-auto size-8 flex justify-center items-center">
                            <flux:icon name="chevrons-up-down" variant="micro" class="text-zinc-400 dark:text-white/80 group-hover:text-zinc-800 dark:group-hover:text-white" />
                        </div>
                    </button>

                    <flux:menu class="w-56">
                        <flux:menu.radio.group>
                            @foreach ($userTeams as $tu)
                                @php $tc = $teamColours[$tu->team->colour] ?? '#6366f1'; @endphp
                                <form method="POST" action="{{ route('teams.switch', $tu->team_id) }}">
                                    @csrf
                                    <button type="submit" class="flex items-center gap-2 w-full px-2 py-1.5 rounded-md hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors text-left">
                                        <div style="width:1.5rem;height:1.5rem;border-radius:0.25rem;background:{{ $tc }};display:flex;align-items:center;justify-content:center;flex-shrink:0;">
                                            <flux:icon name="{{ $tu->team->icon ?? 'users' }}" class="size-3 text-white" />
                                        </div>
                                        <span class="flex-1 text-sm truncate text-zinc-700 dark:text-zinc-200">{{ $tu->team->name }}</span>
                                        @if (auth()->user()->current_team === $tu->team_id)
                                            <flux:icon name="check" class="size-4 text-zinc-400 flex-shrink-0" />
                                        @endif
                                    </button>
                                </form>
                            @endforeach
                        </flux:menu.radio.group>
                        <flux:menu.separator />
                        <flux:menu.item icon="cog" :href="route('teams.show', ['id' => auth()->user()->current_team])" wire:navigate>
                            Team Settings
                        </flux:menu.item>
                        <flux:menu.item icon="plus" :href="route('teams.index')" wire:navigate>
                            Create / Join Team
                        </flux:menu.item>
                    </flux:menu>
                </flux:dropdown>
                @endif
            </flux:sidebar.nav>

            <x-desktop-user-menu class="hidden lg:block" :name="auth()->user()->name" />
        </flux:sidebar>

        <!-- Mobile User Menu -->
        <flux:header class="lg:hidden">
            <flux:sidebar.toggle class="lg:hidden" icon="bars-2" inset="left" />

            <flux:spacer />

            <flux:dropdown position="top" align="end">
                <flux:profile
                    :initials="auth()->user()->initials()"
                    icon-trailing="chevron-down"
                />

                <flux:menu>
                    <flux:menu.radio.group>
                        <div class="p-0 text-sm font-normal">
                            <div class="flex items-center gap-2 px-1 py-1.5 text-start text-sm">
                                <flux:avatar
                                    :name="auth()->user()->name"
                                    :initials="auth()->user()->initials()"
                                />

                                <div class="grid flex-1 text-start text-sm leading-tight">
                                    <flux:heading class="truncate">{{ auth()->user()->name }}</flux:heading>
                                    <flux:text class="truncate">{{ auth()->user()->email }}</flux:text>
                                </div>
                            </div>
                        </div>
                    </flux:menu.radio.group>

                    <flux:menu.separator />

                    <flux:menu.radio.group>
                        <flux:menu.item :href="route('profile.edit')" icon="cog" wire:navigate>
                            {{ __('Settings') }}
                        </flux:menu.item>
                    </flux:menu.radio.group>

                    <flux:menu.separator />

                    <form method="POST" action="{{ route('logout') }}" class="w-full">
                        @csrf
                        <flux:menu.item
                            as="button"
                            type="submit"
                            icon="arrow-right-start-on-rectangle"
                            class="w-full cursor-pointer"
                            data-test="logout-button"
                        >
                            {{ __('Log out') }}
                        </flux:menu.item>
                    </form>
                </flux:menu>
            </flux:dropdown>
        </flux:header>

        {{ $slot }}

        @fluxScripts
    </body>
</html>

<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}" class="dark">
    <head>
        @include('partials.head')
    </head>
    <body class="min-h-screen bg-white dark:bg-zinc-800">
        <flux:header container class="border-b border-zinc-200 bg-zinc-50 dark:border-zinc-700 dark:bg-zinc-900">
            <flux:sidebar.toggle class="lg:hidden mr-2" icon="bars-2" inset="left" />

            <x-app-logo href="{{ route('dashboard') }}" wire:navigate />

            <flux:navbar class="-mb-px max-lg:hidden">
                <flux:navbar.item icon="layout-grid" :href="route('dashboard')" :current="request()->routeIs('dashboard')" wire:navigate>
                    {{ __('Dashboard') }}
                </flux:navbar.item>
                <flux:navbar.item icon="globe-alt" :href="route('zerotier.networks')" :current="request()->routeIs('zerotier.*')" wire:navigate>
                    {{ __('Networks') }}
                </flux:navbar.item>
            </flux:navbar>

            <flux:spacer />

            <flux:navbar class="me-1.5 space-x-0.5 rtl:space-x-reverse py-0!">
                @if (auth()->user()->team)
                <flux:tooltip :content="auth()->user()->team->name" position="bottom">
                    <flux:navbar.item class="!h-10 [&>div>svg]:size-5" icon="users" :href="route('teams.show', ['id' => auth()->user()->current_team])" wire:navigate :label="auth()->user()->team->name" />
                </flux:tooltip>
                @endif
            </flux:navbar>

            <x-desktop-user-menu />
        </flux:header>

        <!-- Mobile Menu -->
        <flux:sidebar collapsible="mobile" sticky class="lg:hidden border-e border-zinc-200 bg-zinc-50 dark:border-zinc-700 dark:bg-zinc-900">
            <flux:sidebar.header>
                <x-app-logo :sidebar="true" href="{{ route('dashboard') }}" wire:navigate />
                <flux:sidebar.collapse class="in-data-flux-sidebar-on-desktop:not-in-data-flux-sidebar-collapsed-desktop:-mr-2" />
            </flux:sidebar.header>

            <flux:sidebar.nav>
                <flux:sidebar.group :heading="__('Platform')">
                    <flux:sidebar.item icon="layout-grid" :href="route('dashboard')" :current="request()->routeIs('dashboard')" wire:navigate>
                        {{ __('Dashboard') }}
                    </flux:sidebar.item>
                </flux:sidebar.group>

                <flux:sidebar.group :heading="__('ZeroTier')">
                    <flux:sidebar.item icon="globe-alt" :href="route('zerotier.networks')" wire:navigate>
                        {{ __('Networks') }}
                    </flux:sidebar.item>
                    <flux:sidebar.item icon="signal" :href="route('zerotier.peers')" wire:navigate>
                        {{ __('Peers') }}
                    </flux:sidebar.item>
                    <flux:sidebar.item icon="key" :href="route('zerotier.tokens')" wire:navigate>
                        {{ __('Controllers') }}
                    </flux:sidebar.item>
                </flux:sidebar.group>
            </flux:sidebar.nav>

            <flux:spacer />
        </flux:sidebar>

        {{ $slot }}

        @fluxScripts
    </body>
</html>

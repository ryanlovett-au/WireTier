<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>{{ config('app.name', 'Wiretier') }}</title>
    <link rel="icon" href="/favicon.ico" sizes="any">
    <link rel="icon" href="/favicon.svg" type="image/svg+xml">
    <link rel="apple-touch-icon" href="/apple-touch-icon.png">
    <link rel="preconnect" href="https://fonts.bunny.net">
    <link href="https://fonts.bunny.net/css?family=instrument-sans:400,500,600" rel="stylesheet" />
    @vite(['resources/css/app.css'])
    <style>
        html, body { background-color: #0a0a0a !important; color-scheme: dark; }
        /* Reset any Flux globals that break layout */
        .lp-grid { display: grid !important; }
        .lp-flex { display: flex !important; }
        .lp-block { display: block !important; }
    </style>
</head>
<body class="min-h-screen bg-zinc-950 text-zinc-100 antialiased" style="font-family: 'Instrument Sans', ui-sans-serif, system-ui, sans-serif;">
@php $promo = env('PROMO_MODE', false); @endphp

    {{-- Nav --}}
    <header class="fixed top-0 left-0 right-0 z-50 border-b border-zinc-800 bg-zinc-950/90 backdrop-blur-sm">
        <div class="max-w-6xl mx-auto px-6 flex items-center justify-between" style="height:56px;">
            <a href="/" class="flex items-center gap-2.5 no-underline">
                <span class="flex items-center justify-center rounded-lg bg-orange-500 text-white flex-shrink-0" style="width:32px;height:32px;">
                    <x-app-logo-icon style="width:20px;height:20px;" />
                </span>
                <span class="font-semibold text-zinc-100">Wiretier</span>
            </a>
            <nav class="flex items-center gap-3">
                @if($promo)
                    <a href="https://github.com/ryanlovett/wiretier" target="_blank"
                       class="text-sm font-medium text-white rounded-lg bg-orange-500 hover:bg-orange-600 transition-colors no-underline"
                       style="padding:6px 16px;">
                        View on GitHub
                    </a>
                @elseauth
                    <a href="{{ route('dashboard') }}"
                       class="text-sm font-medium text-white rounded-lg bg-orange-500 hover:bg-orange-600 transition-colors no-underline"
                       style="padding:6px 16px;">
                        Dashboard
                    </a>
                @else
                    <a href="{{ route('login') }}"
                       class="text-sm text-zinc-400 hover:text-zinc-100 transition-colors no-underline">
                        Sign in
                    </a>
                    <a href="{{ route('register') }}"
                       class="text-sm font-medium text-white rounded-lg bg-orange-500 hover:bg-orange-600 transition-colors no-underline"
                       style="padding:6px 16px;">
                        Get started
                    </a>
                @endauth
            </nav>
        </div>
    </header>

    <main style="padding-top:56px;">

        {{-- Hero --}}
        <section class="relative text-center" style="padding: 80px 24px 96px;">

            {{-- Background glow --}}
            <div class="absolute inset-0 overflow-hidden pointer-events-none" style="z-index:0;">
                <div class="absolute left-1/2 rounded-full" style="top:-100px;width:700px;height:500px;transform:translateX(-50%);background:radial-gradient(ellipse, rgba(249,115,22,0.12) 0%, transparent 70%);"></div>
            </div>

            {{-- Grid overlay --}}
            <div class="absolute inset-0 pointer-events-none" style="z-index:0;opacity:0.04;background-image:linear-gradient(rgba(255,255,255,1) 1px, transparent 1px),linear-gradient(90deg, rgba(255,255,255,1) 1px, transparent 1px);background-size:48px 48px;"></div>

            <div class="relative mx-auto" style="z-index:1;max-width:800px;">

                {{-- Badge --}}
                <div class="inline-flex items-center gap-2 rounded-full border border-zinc-700 bg-zinc-900 text-zinc-400 mb-8" style="padding:4px 14px;font-size:12px;font-weight:500;">
                    <span class="rounded-full bg-orange-500" style="width:6px;height:6px;display:inline-block;flex-shrink:0;"></span>
                    Self-hosted ZeroTier controller UI
                </div>

                {{-- Logo mark --}}
                <div class="flex justify-center mb-8">
                    <div class="flex items-center justify-center rounded-2xl bg-orange-500" style="width:80px;height:80px;box-shadow:0 8px 32px rgba(249,115,22,0.3);">
                        <x-app-logo-icon class="text-white" style="width:44px;height:44px;" />
                    </div>
                </div>

                <h1 class="font-semibold text-zinc-50" style="font-size:clamp(2.5rem,5vw,3.75rem);line-height:1.1;letter-spacing:-0.02em;margin-bottom:24px;">
                    Your ZeroTier controller,<br>
                    <span style="color:#f97316;">self-hosted &amp; team-ready.</span>
                </h1>

                <p class="text-zinc-400 mx-auto" style="font-size:1.125rem;line-height:1.7;max-width:560px;margin-bottom:40px;">
                    A self-hosted ZeroTier controller UI built with Laravel and Livewire.<br><br>
                    Run it on your own infrastructure. Wiretier gives your self-hosted ZeroTier controller
                    a powerful web UI — manage networks, authorize members, and share access with your team.
                </p>

                <div class="flex flex-wrap items-center justify-center gap-3">
                    @if($promo)
                        <a href="https://github.com/ryanlovett/wiretier" target="_blank"
                           class="inline-flex items-center font-medium text-white rounded-xl bg-orange-500 hover:bg-orange-600 transition-colors no-underline"
                           style="padding:12px 28px;box-shadow:0 4px 16px rgba(249,115,22,0.25);">
                            View on GitHub
                        </a>
                    @elseauth
                        <a href="{{ route('dashboard') }}"
                           class="inline-flex items-center font-medium text-white rounded-xl bg-orange-500 hover:bg-orange-600 transition-colors no-underline"
                           style="padding:12px 28px;box-shadow:0 4px 16px rgba(249,115,22,0.25);">
                            Go to Dashboard
                        </a>
                    @else
                        <a href="{{ route('register') }}"
                           class="inline-flex items-center font-medium text-white rounded-xl bg-orange-500 hover:bg-orange-600 transition-colors no-underline"
                           style="padding:12px 28px;box-shadow:0 4px 16px rgba(249,115,22,0.25);">
                            Get started
                        </a>
                        <a href="{{ route('login') }}"
                           class="inline-flex items-center font-medium text-zinc-100 rounded-xl border border-zinc-700 bg-zinc-800 hover:bg-zinc-700 transition-colors no-underline"
                           style="padding:12px 28px;">
                            Sign in
                        </a>
                    @endauth
                </div>
            </div>
        </section>

        {{-- How it works --}}
        <section class="border-t border-zinc-800" style="padding:80px 24px;">
            <div class="mx-auto" style="max-width:1152px;">

                <div class="text-center" style="margin-bottom:56px;">
                    <h2 class="font-semibold text-zinc-100" style="font-size:1.5rem;margin-bottom:12px;">How it works</h2>
                    <p class="text-zinc-400 mx-auto" style="max-width:560px;line-height:1.7;">
                        A ZeroTier controller is just a regular ZeroTier node. Every node exposes a local API —
                        Wiretier connects to that API and gives it controller superpowers through a shared web UI.
                    </p>
                </div>

                <div class="lp-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;">
                    @foreach ([
                        ['1', 'Install ZeroTier', 'Install the ZeroTier client on any machine. It becomes a node — and every node is already a controller waiting to be unlocked.'],
                        ['2', 'Add your token', 'Paste your ZeroTier API token into Wiretier. It will automatically detect your node address and verify the connection.'],
                        ['3', 'Manage your networks', 'Browse networks, authorize members, and share access with your team — with roles and permissions built in from the start.'],
                    ] as [$num, $title, $body])
                    <div class="rounded-2xl border border-zinc-800 bg-zinc-900" style="padding:24px;">
                        <div class="flex items-center justify-center rounded-xl bg-zinc-800 font-semibold text-orange-500" style="width:36px;height:36px;font-size:14px;margin-bottom:16px;">{{ $num }}</div>
                        <h3 class="font-medium text-zinc-100" style="margin-bottom:8px;">{{ $title }}</h3>
                        <p class="text-zinc-400" style="font-size:14px;line-height:1.6;">{{ $body }}</p>
                    </div>
                    @endforeach
                </div>
            </div>
        </section>

        {{-- Features --}}
        <section class="border-t border-zinc-800" style="padding:80px 24px;">
            <div class="mx-auto" style="max-width:1152px;">

                <div class="text-center" style="margin-bottom:56px;">
                    <h2 class="font-semibold text-zinc-100" style="font-size:1.5rem;margin-bottom:12px;">Everything your team needs</h2>
                    <p class="text-zinc-400 mx-auto" style="max-width:560px;line-height:1.7;">
                        From inviting teammates to authorizing devices, Wiretier covers the full ZeroTier management workflow.
                    </p>
                </div>

                <div class="lp-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px;">

                    @foreach ([
                        [
                            'Team-based access',
                            'Organise users into teams. Each team has its own controllers, networks, and members — fully isolated from other teams.',
                            '<path stroke-linecap="round" stroke-linejoin="round" d="M18 18.72a9.094 9.094 0 0 0 3.741-.479 3 3 0 0 0-4.682-2.72m.94 3.198.001.031c0 .225-.012.447-.037.666A11.944 11.944 0 0 1 12 21c-2.17 0-4.207-.576-5.963-1.584A6.062 6.062 0 0 1 6 18.719m12 0a5.971 5.971 0 0 0-.941-3.197m0 0A5.995 5.995 0 0 0 12 12.75a5.995 5.995 0 0 0-5.058 2.772m0 0a3 3 0 0 0-4.681 2.72 8.986 8.986 0 0 0 3.74.477m.94-3.197a5.971 5.971 0 0 0-.94 3.197M15 6.75a3 3 0 1 1-6 0 3 3 0 0 1 6 0Zm6 3a2.25 2.25 0 1 1-4.5 0 2.25 2.25 0 0 1 4.5 0Zm-13.5 0a2.25 2.25 0 1 1-4.5 0 2.25 2.25 0 0 1 4.5 0Z" />'
                        ],
                        [
                            'Role-based permissions',
                            'Assign Admin, Member, or Viewer roles with fine-grained control over who can manage networks, tokens, and members.',
                            '<path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z" />'
                        ],
                        [
                            'Network management',
                            'Browse all networks on your controller. Drill in to view configuration, manage members, and track network activity.',
                            '<path stroke-linecap="round" stroke-linejoin="round" d="M12 21a9.004 9.004 0 0 0 8.716-6.747M12 21a9.004 9.004 0 0 1-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 0 1 7.843 4.582M12 3a8.997 8.997 0 0 0-7.843 4.582m15.686 0A11.953 11.953 0 0 1 12 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0 1 21 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0 1 12 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 0 1 3 12c0-1.605.42-3.113 1.157-4.418" />'
                        ],
                        [
                            'Live member status',
                            'See every device on a network with real-time IP, latency, version, and last-seen data. Authorize or deauthorize in one click.',
                            '<path stroke-linecap="round" stroke-linejoin="round" d="M9 17.25v1.007a3 3 0 0 1-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0 1 15 18.257V17.25m6-12V15a2.25 2.25 0 0 1-2.25 2.25H5.25A2.25 2.25 0 0 1 3 15V5.25m18 0A2.25 2.25 0 0 0 18.75 3H5.25A2.25 2.25 0 0 0 3 5.25m18 0H3" />'
                        ],
                        [
                            'Peer topology',
                            'Inspect peer connections for your controller node and understand how devices are connecting across your virtual network.',
                            '<path stroke-linecap="round" stroke-linejoin="round" d="M9.348 14.652a3.75 3.75 0 0 1 0-5.304m5.304 0a3.75 3.75 0 0 1 0 5.304m-7.425 2.121a6.75 6.75 0 0 1 0-9.546m9.546 0a6.75 6.75 0 0 1 0 9.546M5.106 18.894c-3.808-3.807-3.808-9.98 0-13.788m13.788 0c3.808 3.807 3.808 9.98 0 13.788M12 12h.008v.008H12V12Zm.375 0a.375.375 0 1 1-.75 0 .375.375 0 0 1 .75 0Z" />'
                        ],
                        [
                            'Secure by default',
                            'Two-factor authentication, email verification, and encrypted token storage keep your controller credentials safe.',
                            '<path stroke-linecap="round" stroke-linejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z" />'
                        ],
                    ] as [$title, $body, $iconPath])
                    <div class="rounded-2xl border border-zinc-800 bg-zinc-900 transition-colors hover:border-zinc-700" style="padding:24px;">
                        <div class="flex items-center justify-center rounded-xl bg-zinc-800" style="width:40px;height:40px;margin-bottom:16px;">
                            <svg style="width:20px;height:20px;color:#f97316;" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
                                {!! $iconPath !!}
                            </svg>
                        </div>
                        <h3 class="font-medium text-zinc-100" style="margin-bottom:6px;">{{ $title }}</h3>
                        <p class="text-zinc-400" style="font-size:14px;line-height:1.6;">{{ $body }}</p>
                    </div>
                    @endforeach

                </div>
            </div>
        </section>

        {{-- CTA --}}
        <section class="border-t border-zinc-800 text-center" style="padding:80px 24px;">
            <div class="mx-auto" style="max-width:600px;">
                <div class="flex justify-center" style="margin-bottom:24px;">
                    <div class="flex items-center justify-center rounded-2xl border border-zinc-700" style="width:56px;height:56px;background:rgba(249,115,22,0.1);">
                        <x-app-logo-icon style="width:32px;height:32px;color:#f97316;" />
                    </div>
                </div>
                <h2 class="font-semibold text-zinc-100" style="font-size:1.875rem;margin-bottom:16px;">Ready to take control?</h2>
                <p class="text-zinc-400" style="line-height:1.7;margin-bottom:32px;">
                    Set up Wiretier on your own infrastructure and start managing your ZeroTier networks in minutes.
                </p>
                <div class="flex flex-wrap items-center justify-center gap-3">
                    @if($promo)
                        <a href="https://github.com/ryanlovett/wiretier" target="_blank"
                           class="inline-flex items-center font-medium text-white rounded-xl bg-orange-500 hover:bg-orange-600 transition-colors no-underline"
                           style="padding:12px 28px;box-shadow:0 4px 16px rgba(249,115,22,0.25);">
                            View on GitHub
                        </a>
                    @elseauth
                        <a href="{{ route('dashboard') }}"
                           class="inline-flex items-center font-medium text-white rounded-xl bg-orange-500 hover:bg-orange-600 transition-colors no-underline"
                           style="padding:12px 28px;box-shadow:0 4px 16px rgba(249,115,22,0.25);">
                            Go to Dashboard
                        </a>
                    @else
                        <a href="{{ route('register') }}"
                           class="inline-flex items-center font-medium text-white rounded-xl bg-orange-500 hover:bg-orange-600 transition-colors no-underline"
                           style="padding:12px 28px;box-shadow:0 4px 16px rgba(249,115,22,0.25);">
                            Create an account
                        </a>
                        <a href="https://github.com/ryanlovett/wiretier" target="_blank"
                           class="inline-flex items-center font-medium text-zinc-100 rounded-xl border border-zinc-700 bg-zinc-800 hover:bg-zinc-700 transition-colors no-underline"
                           style="padding:12px 28px;">
                            View on GitHub
                        </a>
                    @endauth
                </div>
            </div>
        </section>

    </main>

    {{-- Footer --}}
    <footer class="border-t border-zinc-800" style="padding:32px 24px;">
        <div class="mx-auto flex flex-wrap items-center justify-between gap-4" style="max-width:1152px;">
            <div class="flex items-center gap-2 text-zinc-500" style="font-size:14px;">
                <span class="flex items-center justify-center rounded bg-orange-500 text-white" style="width:20px;height:20px;">
                    <x-app-logo-icon style="width:12px;height:12px;" />
                </span>
                <span>Wiretier</span>
            </div>
            <div class="flex items-center gap-5 text-zinc-500" style="font-size:14px;">
                <a href="https://www.zerotier.com/" target="_blank" class="hover:text-zinc-300 transition-colors no-underline">ZeroTier</a>
                <a href="https://github.com/ryanlovett/wiretier" target="_blank" class="hover:text-zinc-300 transition-colors no-underline">GitHub</a>
                <span>GPL-3.0</span>
            </div>
        </div>
    </footer>

</body>
</html>

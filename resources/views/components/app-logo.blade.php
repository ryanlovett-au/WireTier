@props([
    'sidebar' => false,
])

<a href="{{ $attributes->get('href', '/') }}" wire:navigate class="flex items-center gap-3 px-1 py-1 rounded-lg no-underline">
    <div style="display:flex;aspect-ratio:1;width:2.25rem;height:2.25rem;align-items:center;justify-content:center;border-radius:0.5rem;background:#FF6C2F;flex-shrink:0;">
        <x-app-logo-icon class="size-8 fill-current text-white" />
    </div>
    <span style="font-size:1.1rem;font-weight:700;letter-spacing:-0.01em;color:#52525b;">{{ config('app.name') }}</span>
</a>

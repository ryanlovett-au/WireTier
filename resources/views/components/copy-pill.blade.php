@props([
    'value' => null,
    'icon' => 'size-3',
])

@php
    // If $value is omitted, fall back to a stringified slot. The slot can still
    // override the display content (e.g. for shortened IDs) while $value is
    // what actually gets copied.
    $copyValue = (string) ($value ?? trim((string) $slot));
@endphp

<span
    x-data="{ copied: false }"
    x-on:click.stop="navigator.clipboard.writeText({{ \Illuminate\Support\Js::from($copyValue) }}); copied = true; setTimeout(() => copied = false, 2000)"
    title="Click to copy"
    {{ $attributes->class([
        'group inline-flex items-center gap-1.5 cursor-pointer rounded-full px-2 py-0.5 transition-colors',
        'hover:bg-zinc-100 dark:hover:bg-zinc-800',
    ]) }}
    x-bind:class="copied ? 'bg-zinc-100 dark:bg-zinc-800' : ''"
>
    <span>{{ $slot->isEmpty() ? $copyValue : $slot }}</span>
    <flux:icon
        x-show="!copied"
        name="clipboard"
        class="{{ $icon }} text-zinc-400 opacity-0 group-hover:opacity-100 transition-opacity"
    />
    <flux:icon
        x-show="copied"
        x-cloak
        name="clipboard-document-check"
        class="{{ $icon }} text-green-500"
    />
</span>

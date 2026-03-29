@if (auth()->user()->isAdmin())
@php
    $tokens = \App\Models\ZerotierToken::where('is_active', true)->get();
    $statuses = $tokens->map(function ($token) {
        try {
            $service = new \App\Services\ZerotierService($token);
            $status = $service->getStatus();
            return [
                'online' => $status['online'] ?? false,
                'address' => $status['address'] ?? null,
                'name' => $token->name,
            ];
        } catch (\Exception) {
            return ['online' => false, 'address' => null, 'name' => $token->name];
        }
    });
@endphp

@if ($tokens->count() > 0)
    <div class="px-2 pb-2">
        @foreach ($statuses as $status)
            <div class="flex items-center gap-2 px-2 py-1.5 rounded text-xs text-zinc-500 dark:text-zinc-400">
                <span class="relative flex size-2 shrink-0">
                    @if ($status['online'])
                        <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                        <span class="relative inline-flex rounded-full size-2 bg-green-500"></span>
                    @else
                        <span class="relative inline-flex rounded-full size-2 bg-red-500"></span>
                    @endif
                </span>
                <span class="truncate">
                    {{ $status['name'] }}
                    @if ($status['address'])
                        <span class="font-mono opacity-60">&middot; {{ $status['address'] }}</span>
                    @endif
                </span>
            </div>
        @endforeach
    </div>
@endif
@endif

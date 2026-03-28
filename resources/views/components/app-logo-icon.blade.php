<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 42" {{ $attributes }}>
    {{-- Network topology icon: central hub connected to 4 peer nodes --}}

    {{-- Spoke lines from center to each peer --}}
    <line x1="20" y1="18" x2="20" y2="7"  stroke="currentColor" stroke-width="3" stroke-linecap="round"/>
    <line x1="22" y1="20" x2="33" y2="14" stroke="currentColor" stroke-width="3" stroke-linecap="round"/>
    <line x1="22" y1="22" x2="33" y2="30" stroke="currentColor" stroke-width="3" stroke-linecap="round"/>
    <line x1="20" y1="24" x2="20" y2="35" stroke="currentColor" stroke-width="3" stroke-linecap="round"/>
    <line x1="18" y1="22" x2="7"  y2="30" stroke="currentColor" stroke-width="3" stroke-linecap="round"/>
    <line x1="18" y1="20" x2="7"  y2="14" stroke="currentColor" stroke-width="3" stroke-linecap="round"/>

    {{-- Peer nodes --}}
    <circle cx="20" cy="5"  r="4.5" fill="currentColor"/>
    <circle cx="35" cy="13" r="4.5" fill="currentColor"/>
    <circle cx="35" cy="31" r="4.5" fill="currentColor"/>
    <circle cx="20" cy="37" r="4.5" fill="currentColor"/>
    <circle cx="5"  cy="31" r="4.5" fill="currentColor"/>
    <circle cx="5"  cy="13" r="4.5" fill="currentColor"/>

    {{-- Central controller node (larger) --}}
    <circle cx="20" cy="21" r="6.5" fill="currentColor"/>
</svg>

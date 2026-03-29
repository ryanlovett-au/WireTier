<?php

use Illuminate\Support\Facades\Route;

Route::view('/', 'welcome')->name('home');

Route::middleware(['auth', 'verified', 'throttle:60,1'])->group(function () {
    Route::view('dashboard', 'dashboard')->name('dashboard');

    // ZeroTier routes
    Route::livewire('zerotier/tokens', 'pages::zerotier.tokens')->name('zerotier.tokens');
    Route::livewire('zerotier/networks', 'pages::zerotier.networks')->name('zerotier.networks');
    Route::livewire('zerotier/networks/{networkId}/members/{tokenId}', 'pages::zerotier.members')->name('zerotier.members');
    Route::livewire('zerotier/peers', 'pages::zerotier.peers')->name('zerotier.peers');
});

require __DIR__.'/settings.php';

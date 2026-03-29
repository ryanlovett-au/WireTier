<?php

namespace App\Console\Commands;

use App\Services\ZerotierSyncService;
use Illuminate\Console\Command;

class ZerotierSync extends Command
{
    protected $signature = 'zerotier:sync {--token= : Sync a specific token ID only}';

    protected $description = 'Sync ZeroTier controller data (networks and members) into the database';

    public function handle(): int
    {
        $tokenId = $this->option('token');

        if ($tokenId) {
            $synced = ZerotierSyncService::syncToken($tokenId);
            $this->info("Synced {$synced} network(s) for token {$tokenId}.");
        } else {
            $synced = ZerotierSyncService::syncAll();
            $this->info("Synced {$synced} network(s) across all controllers.");
        }

        return self::SUCCESS;
    }
}

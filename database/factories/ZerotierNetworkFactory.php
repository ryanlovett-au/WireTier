<?php

namespace Database\Factories;

use App\Models\Team;
use App\Models\ZerotierNetwork;
use App\Models\ZerotierToken;
use Illuminate\Database\Eloquent\Factories\Factory;

/** @extends Factory<ZerotierNetwork> */
class ZerotierNetworkFactory extends Factory
{
    protected $model = ZerotierNetwork::class;

    public function definition(): array
    {
        return [
            'team_id' => Team::factory(),
            'zerotier_token_id' => ZerotierToken::factory(),
            'network_id' => fake()->regexify('[a-f0-9]{16}'),
            'name' => fake()->words(2, true).' Network',
            'description' => fake()->sentence(),
            'private' => true,
            'config' => [],
        ];
    }
}

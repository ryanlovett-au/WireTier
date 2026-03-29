<?php

namespace Database\Factories;

use App\Models\ZerotierToken;
use Illuminate\Database\Eloquent\Factories\Factory;

/** @extends Factory<ZerotierToken> */
class ZerotierTokenFactory extends Factory
{
    protected $model = ZerotierToken::class;

    public function definition(): array
    {
        return [
            'name' => fake()->words(2, true).' Controller',
            'token' => fake()->sha256(),
            'host' => 'http://localhost:9993',
            'is_active' => true,
            'node_address' => fake()->regexify('[a-f0-9]{10}'),
        ];
    }

    public function inactive(): static
    {
        return $this->state(fn () => ['is_active' => false]);
    }
}

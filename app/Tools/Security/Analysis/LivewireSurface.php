<?php

namespace App\Tools\Security\Analysis;

/**
 * What a browser controls in a Livewire component (or a trait used by one).
 *
 * In Livewire the "request" is the component snapshot plus the update and
 * call payloads, so request-controlled data is:
 *  - every public, non-static property without #[Locked] (the client can
 *    send an update for it; #[Url] / #[Session] / #[Modelable] state is no
 *    safer). Eloquent-model properties are excluded: Livewire refuses client
 *    updates to them.
 *  - the parameters of every public method. Actions, #[On] / getListeners()
 *    handlers and updated*() hooks are all reachable from the client with
 *    client-chosen arguments ($wire.call(), Livewire.dispatch(), a property
 *    update), and mount() parameters come from the route.
 */
final class LivewireSurface
{
    /** Lifecycle methods a client cannot call directly (their params can still be tainted). */
    private const LIFECYCLE = ['mount', 'boot', 'booted', 'hydrate', 'dehydrate', 'render', 'rendering', 'rendered', 'placeholder', 'exception', 'getlisteners', 'rules', 'messages', 'validationattributes'];

    /** @var array<string, true>|null */
    private static ?array $modelClasses = null;

    public function __construct(public readonly PhpSource $source) {}

    /**
     * Client-writable properties: public, non-static, not #[Locked], not an
     * Eloquent model.
     *
     * @return array<string, int> name => declaration line
     */
    public function clientWritableProperties(): array
    {
        $out = [];
        foreach ($this->source->properties() as $p) {
            if ($p['visibility'] !== 'public' || $p['static'] || in_array('Locked', $p['attributes'], true)) {
                continue;
            }
            if ($p['type'] !== null && self::isModelType($p['type'])) {
                continue;
            }
            $out[$p['name']] = $p['line'];
        }

        return $out;
    }

    /** Public, non-static methods whose parameters a client supplies. */
    public function takesClientInput(PhpMethod $m): bool
    {
        return $m->visibility === 'public' && ! $m->static && ! $m->hasAttribute('Computed');
    }

    /** Methods a client can invoke by name ($wire.call / wire:click). */
    public function isClientCallable(PhpMethod $m): bool
    {
        if (! $this->takesClientInput($m)) {
            return false;
        }
        $lower = strtolower($m->name);

        return ! in_array($lower, self::LIFECYCLE, true)
            && ! str_starts_with($lower, 'updating')
            && ! str_starts_with($lower, 'updated')
            && ! str_starts_with($lower, 'hydrate')
            && ! str_starts_with($lower, 'dehydrate')
            && ! str_starts_with($lower, '__');
    }

    /**
     * Track request-controlled values through one method: client-writable
     * properties, the method's own parameters when a client supplies them,
     * and locals assigned from either.
     */
    public function taint(PhpMethod $m): Taint
    {
        $taint = new Taint(array_keys($this->clientWritableProperties()));
        if ($this->takesClientInput($m)) {
            foreach ($m->params as $p) {
                // Model-typed parameters arrive via route binding / Livewire's
                // model resolution, not as a raw client value.
                // Scalar-typed parameters (int, bool, float) can't carry a
                // string either.
                if ($p['type'] !== null && in_array(strtolower($p['type']), ['int', 'bool', 'float', 'integer', 'boolean'], true)) {
                    continue;
                }
                if ($p['type'] === null || ! self::isModelType($p['type'])) {
                    $taint->addVariable($p['name']);
                }
            }
        }
        $taint->propagate($m->statements());

        return $taint;
    }

    /** Is $type an Eloquent model (App\Models\X, or the base Model)? */
    public static function isModelType(string $type): bool
    {
        $short = basename(str_replace('\\', '/', $type));
        if (in_array($short, ['Model', 'Collection', 'EloquentCollection'], true)) {
            return true;
        }
        if (self::$modelClasses === null) {
            self::$modelClasses = [];
            foreach (glob(app_path('Models/*.php')) ?: [] as $f) {
                self::$modelClasses[basename($f, '.php')] = true;
            }
        }

        return isset(self::$modelClasses[$short]);
    }
}

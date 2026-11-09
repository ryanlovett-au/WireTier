<?php

namespace App\Tools\Security\Analysis;

/**
 * A PHP file (or the PHP head of a ⚡ single-file component) read with the
 * tokenizer, so braces and keywords inside strings and comments can't throw
 * method or property boundaries off the way line-and-regex splitting can.
 *
 * Exposes class-level properties and methods with their attributes, which is
 * what the Livewire-aware checks need: whether a property is #[Locked], which
 * methods are client-callable, and the parameters a client can pass them.
 */
final class PhpSource
{
    /** @var list<array{name: string, visibility: string, static: bool, type: ?string, attributes: list<string>, line: int}> */
    private array $properties = [];

    /** @var list<PhpMethod> */
    private array $methods = [];

    /** @var list<string> */
    private array $lines;

    private bool $livewire = false;

    public function __construct(public readonly string $path, public readonly string $code)
    {
        $this->lines = explode("\n", $code);
        $this->parse();
    }

    public static function fromFile(string $path): self
    {
        return new self($path, (string) file_get_contents($path));
    }

    /** @return list<array{name: string, visibility: string, static: bool, type: ?string, attributes: list<string>, line: int}> */
    public function properties(): array
    {
        return $this->properties;
    }

    /** @return list<PhpMethod> */
    public function methods(): array
    {
        return $this->methods;
    }

    public function method(string $name): ?PhpMethod
    {
        foreach ($this->methods as $m) {
            if (strcasecmp($m->name, $name) === 0) {
                return $m;
            }
        }

        return null;
    }

    public function line(int $number): string
    {
        return $this->lines[$number - 1] ?? '';
    }

    /**
     * A Livewire component or a trait meant for one: extends Component (a
     * class or a ⚡ file's anonymous class), or a trait under app/Livewire.
     */
    public function isLivewire(): bool
    {
        return $this->livewire;
    }

    private function parse(): void
    {
        $tokens = token_get_all($this->code);
        $count = count($tokens);

        $depth = 0;
        $classDepths = [];       // brace depth at which each open class/trait body sits
        $pendingClass = false;   // saw class/trait keyword, waiting for its '{'
        $attributes = [];        // attribute names collected before the next member
        $modifiers = [];
        $type = null;

        for ($i = 0; $i < $count; $i++) {
            $t = $tokens[$i];
            $id = is_array($t) ? $t[0] : null;
            $text = is_array($t) ? $t[1] : $t;

            if ($id === T_CLASS || $id === T_TRAIT) {
                // `X::class` is not a declaration.
                $prev = $this->prevSignificant($tokens, $i);
                if ($prev !== null && $prev[1] === '::') {
                    continue;
                }
                $pendingClass = true;
                if ($id === T_TRAIT && str_contains($this->path, '/Livewire/')) {
                    $this->livewire = true;
                }

                continue;
            }

            if ($id === T_EXTENDS && $pendingClass) {
                $next = $this->nextSignificant($tokens, $i);
                if ($next !== null && preg_match('/(^|\\\\)Component$/', $next[1])) {
                    $this->livewire = true;
                }

                continue;
            }

            if ($text === '{' || $id === T_CURLY_OPEN || $id === T_DOLLAR_OPEN_CURLY_BRACES) {
                $depth++;
                if ($pendingClass && $text === '{') {
                    $classDepths[] = $depth;
                    $pendingClass = false;
                }
                $attributes = $modifiers = [];
                $type = null;

                continue;
            }

            if ($text === '}') {
                if ($classDepths && end($classDepths) === $depth) {
                    array_pop($classDepths);
                }
                $depth--;
                $attributes = $modifiers = [];
                $type = null;

                continue;
            }

            $inClassBody = $classDepths && end($classDepths) === $depth;
            if (! $inClassBody) {
                continue;
            }

            if ($id === T_ATTRIBUTE) {
                [$names, $i] = $this->readAttribute($tokens, $i);
                array_push($attributes, ...$names);

                continue;
            }

            if (in_array($id, [T_PUBLIC, T_PROTECTED, T_PRIVATE, T_STATIC, T_READONLY, T_ABSTRACT, T_FINAL, T_VAR], true)) {
                $modifiers[] = strtolower($text);

                continue;
            }

            if ($id === T_FUNCTION) {
                $nameTok = $this->nextSignificant($tokens, $i);
                if ($nameTok === null || $nameTok[0] !== T_STRING) {
                    continue;
                }
                $this->methods[] = $this->readMethod($tokens, $i, $nameTok[1], $modifiers, $attributes, $depth);
                // readMethod consumed the body; resume after it.
                $i = $this->methodEndIndex;
                $attributes = $modifiers = [];
                $type = null;

                continue;
            }

            if ($id === T_VARIABLE && $modifiers) {
                $this->properties[] = [
                    'name' => substr($text, 1),
                    'visibility' => $this->visibility($modifiers),
                    'static' => in_array('static', $modifiers, true),
                    'type' => $type,
                    'attributes' => $attributes,
                    'line' => $t[2],
                ];
                // Skip the default value up to ';' or ',' (a ',' keeps the
                // modifiers for `public $a, $b;`).
                $nest = 0;
                for ($i++; $i < $count; $i++) {
                    $s = is_array($tokens[$i]) ? $tokens[$i][1] : $tokens[$i];
                    if ($s === '(' || $s === '[') {
                        $nest++;
                    } elseif ($s === ')' || $s === ']') {
                        $nest--;
                    } elseif ($nest === 0 && $s === ';') {
                        $attributes = $modifiers = [];
                        $type = null;
                        break;
                    } elseif ($nest === 0 && $s === ',') {
                        break;
                    }
                }

                continue;
            }

            if ($modifiers && in_array($id, [T_STRING, T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED, T_ARRAY], true)) {
                $type = ltrim($text, '\\');

                continue;
            }

            if ($text === ';' || $id === T_USE || $id === T_CONST || $id === T_CASE) {
                $attributes = $modifiers = [];
                $type = null;
            }
        }
    }

    private int $methodEndIndex = 0;

    /**
     * @param  list<string>  $modifiers
     * @param  list<string>  $attributes
     */
    private function readMethod(array $tokens, int $i, string $name, array $modifiers, array $attributes, int $depth): PhpMethod
    {
        $count = count($tokens);
        $startLine = $tokens[$i][2];

        // Parameters: from the first '(' to its match.
        for ($j = $i; $j < $count && $this->text($tokens[$j]) !== '('; $j++);
        $paramStart = $j;
        $nest = 0;
        for (; $j < $count; $j++) {
            $s = $this->text($tokens[$j]);
            if ($s === '(') {
                $nest++;
            } elseif ($s === ')') {
                $nest--;
                if ($nest === 0) {
                    break;
                }
            }
        }
        $params = $this->readParams(array_slice($tokens, $paramStart + 1, $j - $paramStart - 1));

        // Body: next '{' (or ';' for an abstract/interface method).
        for ($j++; $j < $count; $j++) {
            $s = $this->text($tokens[$j]);
            if ($s === '{' || $s === ';') {
                break;
            }
        }
        if ($j >= $count || $this->text($tokens[$j]) === ';') {
            $this->methodEndIndex = $j;

            return new PhpMethod($name, $this->visibility($modifiers), in_array('static', $modifiers, true), $params, $attributes, $startLine, $startLine, '', []);
        }

        $bodyStart = $j;
        $nest = 0;
        for (; $j < $count; $j++) {
            $t = $tokens[$j];
            $s = $this->text($t);
            if ($s === '{' || (is_array($t) && in_array($t[0], [T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], true))) {
                $nest++;
            } elseif ($s === '}') {
                $nest--;
                if ($nest === 0) {
                    break;
                }
            }
        }
        $this->methodEndIndex = $j;

        $bodyTokens = array_slice($tokens, $bodyStart, $j - $bodyStart + 1);
        $endLine = $this->lineOfToken($tokens, $j) ?? $startLine;
        $body = implode('', array_map(fn ($t) => $this->text($t), $bodyTokens));

        return new PhpMethod($name, $this->visibility($modifiers), in_array('static', $modifiers, true), $params, $attributes, $startLine, $endLine, $body, $bodyTokens);
    }

    /** @return list<array{name: string, type: ?string}> */
    private function readParams(array $tokens): array
    {
        $params = [];
        $type = null;
        $nest = 0;
        foreach ($tokens as $t) {
            $s = $this->text($t);
            if ($s === '(' || $s === '[') {
                $nest++;
            } elseif ($s === ')' || $s === ']') {
                $nest--;
            } elseif ($nest === 0 && $s === ',') {
                $type = null;
            } elseif ($nest === 0 && is_array($t) && in_array($t[0], [T_STRING, T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED, T_ARRAY], true) && $type === null) {
                $type = ltrim($t[1], '\\');
            } elseif ($nest === 0 && is_array($t) && $t[0] === T_VARIABLE) {
                $params[] = ['name' => substr($t[1], 1), 'type' => $type];
            }
        }

        return $params;
    }

    /** @return array{0: list<string>, 1: int} attribute short names, index of the closing ']' */
    private function readAttribute(array $tokens, int $i): array
    {
        $names = [];
        $nest = 1; // T_ATTRIBUTE is '#['
        $expectName = true;
        $count = count($tokens);
        for ($i++; $i < $count; $i++) {
            $t = $tokens[$i];
            $s = $this->text($t);
            if ($s === '[' || $s === '(') {
                $nest++;
                $expectName = false;
            } elseif ($s === ']' || $s === ')') {
                $nest--;
                if ($nest === 0) {
                    break;
                }
            } elseif ($nest === 1 && $s === ',') {
                $expectName = true;
            } elseif ($nest === 1 && $expectName && is_array($t) && in_array($t[0], [T_STRING, T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED], true)) {
                $parts = explode('\\', $t[1]);
                $names[] = end($parts);
                $expectName = false;
            }
        }

        return [$names, $i];
    }

    /** @param list<string> $modifiers */
    private function visibility(array $modifiers): string
    {
        foreach (['private', 'protected', 'public'] as $v) {
            if (in_array($v, $modifiers, true)) {
                return $v;
            }
        }

        return 'public'; // PHP's default
    }

    private function text(mixed $t): string
    {
        return is_array($t) ? $t[1] : $t;
    }

    private function prevSignificant(array $tokens, int $i): ?array
    {
        for ($j = $i - 1; $j >= 0; $j--) {
            $t = $tokens[$j];
            if (is_array($t) && in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }

            return is_array($t) ? $t : [0, $t, 0];
        }

        return null;
    }

    private function nextSignificant(array $tokens, int $i): ?array
    {
        $count = count($tokens);
        for ($j = $i + 1; $j < $count; $j++) {
            $t = $tokens[$j];
            if (is_array($t) && in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }

            return is_array($t) ? $t : [0, $t, 0];
        }

        return null;
    }

    private function lineOfToken(array $tokens, int $j): ?int
    {
        for (; $j >= 0; $j--) {
            if (is_array($tokens[$j])) {
                return $tokens[$j][2] + substr_count($tokens[$j][1], "\n");
            }
        }

        return null;
    }
}

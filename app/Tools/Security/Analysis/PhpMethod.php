<?php

namespace App\Tools\Security\Analysis;

/**
 * One method of a PhpSource: signature, attributes and a token-split view of
 * its body as statements (comments dropped, chains kept whole).
 */
final class PhpMethod
{
    /** @var list<array{text: string, line: int}>|null */
    private ?array $statements = null;

    /**
     * @param  list<array{name: string, type: ?string}>  $params
     * @param  list<string>  $attributes
     * @param  list<mixed>  $bodyTokens
     */
    public function __construct(
        public readonly string $name,
        public readonly string $visibility,
        public readonly bool $static,
        public readonly array $params,
        public readonly array $attributes,
        public readonly int $startLine,
        public readonly int $endLine,
        public readonly string $body,
        private readonly array $bodyTokens,
    ) {}

    public function hasAttribute(string $name): bool
    {
        return in_array($name, $this->attributes, true);
    }

    /**
     * Statements of the body: split on ';', '{' and '}' outside parentheses
     * and brackets, so `if (...) {` heads and the statements inside a block
     * come out separately while a multi-line query chain stays one statement.
     * Closures passed as arguments stay inside their enclosing statement.
     *
     * @return list<array{text: string, line: int}>
     */
    public function statements(): array
    {
        if ($this->statements !== null) {
            return $this->statements;
        }

        $out = [];
        $buf = '';
        $line = null;
        $nest = 0;
        // Skip the body's own outer braces.
        $tokens = array_slice($this->bodyTokens, 1, -1);

        $flush = function () use (&$out, &$buf, &$line) {
            $text = trim(preg_replace('/\s+/', ' ', $buf));
            if ($text !== '') {
                $out[] = ['text' => $text, 'line' => $line ?? $this->startLine];
            }
            $buf = '';
            $line = null;
        };

        foreach ($tokens as $t) {
            $id = is_array($t) ? $t[0] : null;
            $s = is_array($t) ? $t[1] : $t;

            if ($id === T_COMMENT || $id === T_DOC_COMMENT) {
                continue;
            }
            if ($line === null && $id !== T_WHITESPACE && trim($s) !== '') {
                $line = is_array($t) ? $t[2] : null;
            }

            if ($s === '(' || $s === '[') {
                $nest++;
            } elseif ($s === ')' || $s === ']') {
                $nest--;
            }

            if ($nest === 0 && ($s === ';' || $s === '{' || $s === '}')) {
                $buf .= $s === ';' ? '' : ' '.$s;
                $flush();

                continue;
            }

            $buf .= $s;
        }
        $flush();

        return $this->statements = $out;
    }

    /** Names of the parameters a caller supplies. @return list<string> */
    public function paramNames(): array
    {
        return array_column($this->params, 'name');
    }
}

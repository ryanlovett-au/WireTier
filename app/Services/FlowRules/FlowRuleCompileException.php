<?php

namespace App\Services\FlowRules;

/**
 * A rules script failed to compile. Line and column are 1-based; both are 0
 * for errors that are not tied to a source position (e.g. size limits).
 */
final class FlowRuleCompileException extends \RuntimeException
{
    public function __construct(string $message, public readonly int $sourceLine, public readonly int $sourceColumn)
    {
        parent::__construct($message);
    }

    /** Human-readable message including the position, when known, plus a hint for confusing cases. */
    public function describe(): string
    {
        $text = $this->sourceLine > 0
            ? "Line {$this->sourceLine}, column {$this->sourceColumn}: {$this->getMessage()}"
            : $this->getMessage();

        $hint = $this->hint();

        return $hint ? "{$text} {$hint}" : $text;
    }

    /**
     * Explain the language's most confusing error. A bare action such as
     * "accept;" leaves its block open, so the next rule is parsed as one of
     * its matches and is reported as an unknown match type.
     */
    public function hint(): ?string
    {
        if (preg_match('/^Unrecognized match type "(drop|accept|break|tee|watch|redirect|priority|include|cap|tag|macro)"\.$/', $this->getMessage())) {
            return 'A bare action like "accept;" or "drop;" must be the last rule; move it below this one.';
        }

        return null;
    }
}

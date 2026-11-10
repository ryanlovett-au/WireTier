<?php

namespace App\Services\FlowRules;

/**
 * Compiled rules that cannot be rebuilt into a script exactly: a rule type
 * or field the rules language cannot express, or malformed controller data.
 */
final class FlowRuleDecompileException extends \RuntimeException {}

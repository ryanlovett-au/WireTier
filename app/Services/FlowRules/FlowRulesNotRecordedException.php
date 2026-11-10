<?php

namespace App\Services\FlowRules;

/**
 * The controller accepted the new rules (they are live on the network), but
 * WireTier failed to store the script, fingerprint or history entry. The
 * network will read as changed outside WireTier until the rules are saved
 * again or loaded back from the controller.
 */
final class FlowRulesNotRecordedException extends \RuntimeException {}

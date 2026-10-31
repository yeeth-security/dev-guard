/**
 * FAKE test stub. It does NOTHING.
 *
 * Why this exists:
 *   The real `zhifeiya.copilot-model-config-assistant@0.1.2` was flagged as
 *   malicious by pkgscan.dev. This stub has the same ID and version so we can
 *   test that DevGuard detects it and removes it, without running any
 *   malicious code.
 *
 * Safety:
 *   - No network calls.
 *   - No file access.
 *   - No commands. No secrets. No child processes.
 */

function activate() {
    // Intentionally empty. Never runs anyway: `activationEvents` is empty.
}

function deactivate() {}

module.exports = { activate, deactivate };

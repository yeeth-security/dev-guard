/**
 * Background advisory polling scheduler (`monitor.js`).
 *
 * Why this file exists:
 *   Previously, DevGuard only checked for malicious extensions once on editor
 *   startup and when the extension list changed. A developer who leaves their
 *   editor open for days would not hear about a newly flagged extension in a
 *   timely manner.
 *
 * How it works (modelled after VS Code's 5-minute malicious check and Google
 * Safe Browsing's frequency rules):
 *   - Uses a `setTimeout` chain (never `setInterval`) so slow requests cannot
 *     stack up.
 *   - Initial startup poll waits a random 0–60s jitter so restarts across many
 *     machines do not all hit pkgscan.dev at the same instant.
 *   - Subsequent polls wait 5 minutes + 0–30s jitter, or longer if the server
 *     sent a `minimumWaitMs` / `X-Min-Poll-Seconds` hint.
 *   - On network errors, backs off exponentially: `min(2^n minutes, 30 minutes)`
 *     plus jitter, and resets back to 5 minutes on the next success.
 *   - Also runs a check when the editor window regains focus after >= 5 minutes
 *     of idle time, and debounces `extensions.onDidChange` by 5 seconds.
 */

const BASE_POLL_MS = 5 * 60 * 1000; // 5 minutes
const POLL_JITTER_MS = 30 * 1000; // up to 30 seconds
const STARTUP_JITTER_MS = 60 * 1000; // 0 to 60 seconds
const MAX_BACKOFF_MS = 30 * 60 * 1000; // 30 minutes cap
const FOCUS_IDLE_MS = 5 * 60 * 1000; // 5 minutes idle before focus wake poll
const CHANGE_DEBOUNCE_MS = 5 * 1000; // 5 seconds debounce on extension install/uninstall

/**
 * Computes the random initial delay (0 to 60 seconds) after activation.
 * @param {() => number} [random]
 * @returns {number}
 */
function computeStartupDelayMs(random = Math.random) {
    return Math.floor(Math.max(0, Math.min(0.999999, random())) * STARTUP_JITTER_MS);
}

/**
 * Computes the wait duration before the next background poll.
 * - On success (`failureCount === 0`): `max(5 min, minWaitMs) + 0..30s jitter`
 * - On failure (`failureCount > 0`): `min(2^n min, 30 min) + 0..30s jitter`
 * @param {{failureCount?: number, minWaitMs?: number, random?: () => number}} [options]
 * @returns {number}
 */
function computeNextDelayMs(options = {}) {
    const failureCount = Number(options.failureCount) || 0;
    const minWaitMs = Number(options.minWaitMs) || 0;
    const random = options.random || Math.random;
    const jitter = Math.floor(Math.max(0, Math.min(0.999999, random())) * POLL_JITTER_MS);

    if (failureCount > 0) {
        const expMinutesMs = Math.pow(2, failureCount) * 60 * 1000;
        const backoffBase = Math.min(expMinutesMs, MAX_BACKOFF_MS);
        return Math.max(backoffBase, minWaitMs) + jitter;
    }

    return Math.max(BASE_POLL_MS, minWaitMs) + jitter;
}

/**
 * Creates the background monitor loop and event listeners.
 * @param {{
 *   runAudit: (trigger: 'startup'|'poll'|'focus'|'change'|'install'|'manual') => Promise<{failureCount?: number, minWaitMs?: number}|void>,
 *   vscodeApi?: any,
 *   random?: () => number,
 *   now?: () => number,
 *   startupJitterMs?: number
 * }} options
 */
function createAdvisoryMonitor(options) {
    const runAudit = options.runAudit;
    const vscodeApi = options.vscodeApi;
    const random = options.random || Math.random;
    const now = options.now || Date.now;

    let pollTimer = null;
    let changeTimer = null;
    let disposed = false;
    let inFlight = null;
    let lastCompletedAt = 0;
    let lastResult = { failureCount: 0, minWaitMs: 0 };
    const disposables = [];

    function clearTimers() {
        if (pollTimer) {
            clearTimeout(pollTimer);
            pollTimer = null;
        }
        if (changeTimer) {
            clearTimeout(changeTimer);
            changeTimer = null;
        }
    }

    function scheduleNext(delayMs) {
        if (disposed) return;
        if (pollTimer) clearTimeout(pollTimer);
        pollTimer = setTimeout(() => {
            pollTimer = null;
            void executeCycle('poll');
        }, delayMs);
    }

    /**
     * Runs one audit cycle if none is currently running, then schedules the next
     * timer tick using the returned `{ failureCount, minWaitMs }`.
     * Resolves with whatever `runAudit` returned (e.g. `flaggedIds`), so callers
     * such as the post-install scan can act on the outcome.
     * @param {'startup'|'poll'|'focus'|'change'|'install'|'manual'} trigger
     */
    async function executeCycle(trigger) {
        if (disposed) return;
        if (inFlight) {
            return inFlight;
        }

        inFlight = (async () => {
            try {
                const result = await runAudit(trigger);
                if (result && typeof result === 'object') {
                    lastResult = {
                        failureCount: Number(result.failureCount) || 0,
                        minWaitMs: Number(result.minWaitMs) || 0
                    };
                } else {
                    lastResult = { failureCount: 0, minWaitMs: 0 };
                }
                return result;
            } catch (error) {
                console.warn(`Background audit (${trigger}) failed:`, error);
                lastResult = { failureCount: (lastResult.failureCount || 0) + 1, minWaitMs: 0 };
            } finally {
                lastCompletedAt = now();
                inFlight = null;
                const nextDelay = computeNextDelayMs({
                    failureCount: lastResult.failureCount,
                    minWaitMs: lastResult.minWaitMs,
                    random
                });
                scheduleNext(nextDelay);
            }
        })();

        return inFlight;
    }

    /**
     * Starts the startup jittered check and subscribes to window focus and
     * extension-change events.
     */
    function start() {
        if (disposed) return;
        const initialDelay = typeof options.startupJitterMs === 'number'
            ? options.startupJitterMs
            : computeStartupDelayMs(random);

        pollTimer = setTimeout(() => {
            pollTimer = null;
            void executeCycle('startup');
        }, initialDelay);

        if (vscodeApi && vscodeApi.extensions && typeof vscodeApi.extensions.onDidChange === 'function') {
            disposables.push(vscodeApi.extensions.onDidChange(() => {
                if (disposed) return;
                if (changeTimer) clearTimeout(changeTimer);
                changeTimer = setTimeout(() => {
                    changeTimer = null;
                    // Installs are scanned immediately by extension.js (trigger
                    // 'install'). If that scan finished inside the debounce
                    // window, this catch-all cycle would only duplicate it.
                    if (lastCompletedAt > 0 && (now() - lastCompletedAt) < CHANGE_DEBOUNCE_MS) return;
                    void executeCycle('change');
                }, CHANGE_DEBOUNCE_MS);
            }));
        }

        if (vscodeApi && vscodeApi.window && typeof vscodeApi.window.onDidChangeWindowState === 'function') {
            disposables.push(vscodeApi.window.onDidChangeWindowState(state => {
                if (disposed || !state || !state.focused) return;
                if (lastCompletedAt > 0 && (now() - lastCompletedAt) >= FOCUS_IDLE_MS) {
                    void executeCycle('focus');
                }
            }));
        }
    }

    function dispose() {
        disposed = true;
        clearTimers();
        while (disposables.length > 0) {
            const d = disposables.pop();
            try {
                if (d && typeof d.dispose === 'function') d.dispose();
            } catch (_error) {
                // Ignore disposal errors.
            }
        }
    }

    return { start, executeCycle, dispose };
}

module.exports = {
    BASE_POLL_MS,
    POLL_JITTER_MS,
    STARTUP_JITTER_MS,
    MAX_BACKOFF_MS,
    FOCUS_IDLE_MS,
    CHANGE_DEBOUNCE_MS,
    computeStartupDelayMs,
    computeNextDelayMs,
    createAdvisoryMonitor
};

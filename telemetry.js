/**
 * Anonymous usage and security telemetry for dev-guard.
 *
 * Why this file exists:
 *   Gives us aggregate, per-install (`installId`) insight into what protects
 *   users in the field — such as editor health check posture, blocked malicious
 *   downloads, unscanned extension warnings/refusals, and pkgscan.dev report
 *   views — without ever collecting file paths or machine identifiers, and
 *   without blasting duplicate state events to the server.
 *
 * Deduplication model:
 *   - `recordState(stateKey, name, props)`: Persists a hash of `props` in
 *     `globalState` and only queues an event when a user's state actually
 *     changes (e.g., when they fix a health check item or toggle the proxy).
 *   - `recordOnce(dedupKey, name, props, ttlMs)`: Suppresses repeat events
 *     within `ttlMs` (e.g., viewing the same flagged README or daily heartbeats)
 *     so open windows never flood the server.
 *   - `record(name, props)`: Queues discrete user actions and schedules a
 *     debounced background flush so interactive security decisions are sent
 *     promptly without waiting for the next 5-minute poll.
 */

const vscode = require('vscode');
const crypto = require('crypto');
const os = require('os');

const DEFAULT_ENDPOINT = 'https://www.pkgscan.dev/api/telemetry/dev-guard';
const INSTALL_ID_KEY = 'devGuard.installId';
const NOTICE_KEY = 'devGuard.telemetryNoticeVersion';
const STATE_HASHES_KEY = 'devGuard.telemetryStateHashes';
const COOLDOWNS_KEY = 'devGuard.telemetryCooldowns';
const NOTICE_VERSION = 1;
const MAX_QUEUE = 25;
const MAX_STRING = 64;
const MAX_PROPS = 12;
const FLUSH_TIMEOUT_MS = 5000;
const DEFAULT_AUTO_FLUSH_MS = 2000;
const DEFAULT_ONCE_TTL_MS = 24 * 60 * 60 * 1000;

/** Strict validators for identifier props so free-form text cannot leak. */
const PROP_VALUE_VALIDATORS = {
    extension_id: /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/,
    installed_version: /^[A-Za-z0-9][A-Za-z0-9._+-]{0,31}$/
};

/** Buckets an extension count so raw inventory sizes are not transmitted. */
function bucketCount(value) {
    if (value <= 0) return '0';
    if (value <= 10) return '1-10';
    if (value <= 25) return '11-25';
    if (value <= 50) return '26-50';
    if (value <= 100) return '51-100';
    return '100+';
}

/** Buckets an audit duration into coarse latency bands. */
function bucketDuration(ms) {
    if (ms < 250) return '<250ms';
    if (ms < 1000) return '250ms-1s';
    if (ms < 5000) return '1-5s';
    return '>5s';
}

/** Strips unknown types and enforces strict key/value bounds on event props. */
function sanitizeProps(props) {
    const cleaned = {};
    if (!props) return cleaned;
    let count = 0;
    for (const [key, value] of Object.entries(props)) {
        if (count >= MAX_PROPS) break;
        if (!/^[a-z0-9_]{1,40}$/.test(key)) continue;
        if (typeof value === 'boolean') {
            cleaned[key] = value;
        } else if (typeof value === 'number' && Number.isFinite(value)) {
            cleaned[key] = value;
        } else if (typeof value === 'string') {
            const text = value.slice(0, MAX_STRING);
            const validator = PROP_VALUE_VALIDATORS[key];
            if (validator && !validator.test(text)) continue;
            cleaned[key] = text;
        } else {
            continue;
        }
        count++;
    }
    return cleaned;
}

/** Builds a deterministic string fingerprint from sanitized props for state deduplication. */
function stateFingerprint(props) {
    const cleaned = sanitizeProps(props);
    return Object.keys(cleaned).sort().map(k => `${k}=${String(cleaned[k])}`).join('&');
}

function getOrCreateInstallId(context) {
    try {
        const existing = context.globalState.get(INSTALL_ID_KEY);
        if (typeof existing === 'string' && existing.length > 0) return existing;
    } catch (error) {
        console.warn('Could not read telemetry install ID:', error);
    }
    const installId = crypto.randomUUID();
    try { void context.globalState.update(INSTALL_ID_KEY, installId); }
    catch (error) { console.warn('Could not persist telemetry install ID:', error); }
    return installId;
}

function readStateMap(context, key) {
    try {
        const raw = context && context.globalState ? context.globalState.get(key) : null;
        return raw && typeof raw === 'object' ? { ...raw } : {};
    } catch (_error) {
        return {};
    }
}

function writeStateMap(context, key, value) {
    try {
        if (context && context.globalState) void context.globalState.update(key, value);
    } catch (_error) { /* ignore storage errors */ }
}

function createTelemetry(context, options = {}) {
    const vscodeApi = options.vscodeApi || vscode;
    const fetchImpl = options.fetchImpl || fetch;
    const nowFn = options.now || Date.now;
    const autoFlushMs = options.autoFlushMs !== undefined ? options.autoFlushMs : DEFAULT_AUTO_FLUSH_MS;
    const endpoint = process.env.DEV_GUARD_TELEMETRY_URL || DEFAULT_ENDPOINT;
    const installId = getOrCreateInstallId(context);
    const sessionId = crypto.randomUUID();
    const queue = [];
    const extensionPackage = (context.extension && context.extension.packageJSON) || {};

    let flushPromise = null;
    let noticePromise = null;
    let autoFlushTimer = null;
    let activeController = null;
    let disposed = false;

    function isEnabled() {
        if (disposed) return false;
        try {
            if (typeof vscodeApi.env.isTelemetryEnabled === 'boolean' && !vscodeApi.env.isTelemetryEnabled) return false;
            return vscodeApi.workspace.getConfiguration('devGuard').get('telemetry.enabled', true) !== false;
        } catch (error) {
            console.warn('Could not read telemetry setting:', error);
            return false;
        }
    }

    function scheduleAutoFlush() {
        if (autoFlushMs <= 0 || autoFlushTimer) return;
        autoFlushTimer = setTimeout(() => {
            autoFlushTimer = null;
            void flush();
        }, autoFlushMs);
        if (typeof autoFlushTimer.unref === 'function') autoFlushTimer.unref();
    }

    function record(name, props) {
        if (!isEnabled() || queue.length >= MAX_QUEUE) return false;
        queue.push({ name, props: sanitizeProps(props), ts: nowFn() });
        scheduleAutoFlush();
        return true;
    }

    /** Records an event only when the user's state for `stateKey` has changed since last reported. */
    function recordState(stateKey, name, props) {
        if (!isEnabled() || !stateKey) return false;
        const fp = stateFingerprint(props);
        const hashes = readStateMap(context, STATE_HASHES_KEY);
        if (hashes[stateKey] === fp) return false;
        if (!record(name, props)) return false;
        hashes[stateKey] = fp;
        writeStateMap(context, STATE_HASHES_KEY, hashes);
        return true;
    }

    /** Records an event at most once per `ttlMs` window for `dedupKey`. */
    function recordOnce(dedupKey, name, props, ttlMs = DEFAULT_ONCE_TTL_MS) {
        if (!isEnabled() || !dedupKey) return false;
        const now = nowFn();
        const cooldowns = readStateMap(context, COOLDOWNS_KEY);
        const lastAt = Number(cooldowns[dedupKey]) || 0;
        if (lastAt > 0 && (now - lastAt) < ttlMs) return false;
        if (!record(name, props)) return false;
        // Prune expired entries when the cooldown map grows beyond 100 keys.
        const keys = Object.keys(cooldowns);
        if (keys.length >= 100) {
            for (const k of keys) {
                if ((now - (Number(cooldowns[k]) || 0)) >= DEFAULT_ONCE_TTL_MS) delete cooldowns[k];
            }
        }
        cooldowns[dedupKey] = now;
        writeStateMap(context, COOLDOWNS_KEY, cooldowns);
        return true;
    }

    function flush() {
        if (autoFlushTimer) { clearTimeout(autoFlushTimer); autoFlushTimer = null; }
        if (!isEnabled()) { queue.length = 0; return Promise.resolve(); }
        if (flushPromise) return flushPromise;

        flushPromise = (async () => {
            if (queue.length === 0) return;

            const events = queue.splice(0, MAX_QUEUE);
            const payload = {
                v: 1, installId, sessionId,
                extension: {
                    version: extensionPackage.version || 'unknown',
                    appName: vscodeApi.env.appName || 'unknown',
                    appHost: vscodeApi.env.appHost || 'unknown',
                    uiKind: vscodeApi.UIKind && vscodeApi.env.uiKind === vscodeApi.UIKind.Web ? 'web' : 'desktop',
                    vscodeVersion: vscodeApi.version || 'unknown',
                    os: os.platform()
                },
                events
            };
            const controller = new AbortController();
            activeController = controller;
            const timer = setTimeout(() => controller.abort(), FLUSH_TIMEOUT_MS);
            if (typeof timer.unref === 'function') timer.unref();
            try {
                const response = await fetchImpl(endpoint, {
                    method: 'POST',
                    headers: { 'content-type': 'application/json' },
                    body: JSON.stringify(payload),
                    signal: controller.signal
                });
                if (!response.ok) console.warn(`Telemetry request failed: ${response.status}`);
            } catch (error) {
                if (!disposed) {
                    console.warn('Telemetry request failed:', error && error.name ? error.name : error);
                }
            } finally {
                clearTimeout(timer);
                if (activeController === controller) activeController = null;
            }
        })().finally(() => { flushPromise = null; });
        return flushPromise;
    }

    /** No-op: telemetry is documented in Settings (`devGuard.telemetry.enabled`) to avoid startup popup noise. */
    function showNoticeOnce() {}

    /**
     * Synchronously cancels pending timers and aborts any in-flight request so
     * telemetry never delays Extension Host shutdown or editor updates.
     */
    function dispose() {
        disposed = true;
        queue.length = 0;
        if (autoFlushTimer) { clearTimeout(autoFlushTimer); autoFlushTimer = null; }
        if (activeController) {
            try { activeController.abort(); } catch (_e) { /* ignore */ }
            activeController = null;
        }
    }

    return { record, recordState, recordOnce, flush, showNoticeOnce, dispose };
}

module.exports = { createTelemetry, bucketCount, bucketDuration, sanitizeProps, stateFingerprint };

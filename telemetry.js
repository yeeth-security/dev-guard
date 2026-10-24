/**
 * Anonymous usage telemetry for dev-guard.
 *
 * Enabled by default (opt-out), but every send is gated on both VS Code's
 * global telemetry setting and the `devGuard.telemetry.enabled` setting.
 * Only coarse counts, timing buckets, and source health are sent — never
 * extension IDs, publisher names, file paths, or machine identifiers.
 */

const vscode = require('vscode');
const crypto = require('crypto');
const os = require('os');

const DEFAULT_ENDPOINT = 'https://www.pkgscan.dev/api/telemetry/dev-guard';
const INSTALL_ID_KEY = 'devGuard.installId';
const NOTICE_KEY = 'devGuard.telemetryNoticeVersion';
const NOTICE_VERSION = 1;
const MAX_QUEUE = 25;
const MAX_STRING = 64;
const MAX_PROPS = 12;
const FLUSH_TIMEOUT_MS = 5000;

/**
 * Buckets a count so raw inventory sizes are not transmitted.
 * @param {number} value
 * @returns {string}
 */
function bucketCount(value) {
    if (value <= 0) return '0';
    if (value <= 10) return '1-10';
    if (value <= 25) return '11-25';
    if (value <= 50) return '26-50';
    if (value <= 100) return '51-100';
    return '100+';
}

/**
 * Buckets an audit duration.
 * @param {number} ms
 * @returns {string}
 */
function bucketDuration(ms) {
    if (ms < 250) return '<250ms';
    if (ms < 1000) return '250ms-1s';
    if (ms < 5000) return '1-5s';
    return '>5s';
}

/**
 * Drops anything that could leak free-form data.
 * @param {Record<string, unknown>|undefined} props
 * @returns {Record<string, string|number|boolean>}
 */
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
            cleaned[key] = value.slice(0, MAX_STRING);
        } else {
            continue;
        }
        count++;
    }
    return cleaned;
}

/**
 * @param {vscode.ExtensionContext} context
 * @returns {string} Stable pseudonymous install ID
 */
function getOrCreateInstallId(context) {
    try {
        const existing = context.globalState.get(INSTALL_ID_KEY);
        if (typeof existing === 'string' && existing.length > 0) {
            return existing;
        }
    } catch (error) {
        console.warn('Could not read telemetry install ID:', error);
    }

    const installId = crypto.randomUUID();
    try {
        void context.globalState.update(INSTALL_ID_KEY, installId);
    } catch (error) {
        console.warn('Could not persist telemetry install ID:', error);
    }
    return installId;
}

/**
 * @param {vscode.ExtensionContext} context
 * @returns {{record: Function, flush: Function, showNoticeOnce: Function}}
 */
function createTelemetry(context) {
    const endpoint = process.env.DEV_GUARD_TELEMETRY_URL || DEFAULT_ENDPOINT;
    const installId = getOrCreateInstallId(context);
    const sessionId = crypto.randomUUID();
    const queue = [];

    const extensionPackage = context.extension && context.extension.packageJSON
        ? context.extension.packageJSON
        : {};

    let flushPromise = null;
    let noticePromise = null;

    function isEnabled() {
        try {
            if (typeof vscode.env.isTelemetryEnabled === 'boolean' && !vscode.env.isTelemetryEnabled) {
                return false;
            }
            const configured = vscode.workspace
                .getConfiguration('devGuard')
                .get('telemetry.enabled', true);
            return configured !== false;
        } catch (error) {
            console.warn('Could not read telemetry setting:', error);
            return false;
        }
    }

    /**
     * @param {string} name
     * @param {Record<string, unknown>} [props]
     */
    function record(name, props) {
        if (!isEnabled() || queue.length >= MAX_QUEUE) {
            return;
        }
        queue.push({
            name,
            props: sanitizeProps(props),
            ts: Date.now()
        });
    }

    /**
     * Sends the queued events, if telemetry is enabled. Never throws and
     * never blocks the audit.
     * @returns {Promise<void>}
     */
    function flush() {
        if (!isEnabled()) {
            queue.length = 0;
            return Promise.resolve();
        }
        if (flushPromise) {
            return flushPromise;
        }

        flushPromise = (async () => {
            // On first run, give the user a few seconds to act on the
            // disclosure before the first batch leaves the machine.
            if (noticePromise) {
                const notice = noticePromise;
                noticePromise = null;
                await notice;
                if (!isEnabled()) {
                    queue.length = 0;
                    return;
                }
            }

            if (queue.length === 0) {
                return;
            }

            const events = queue.splice(0, MAX_QUEUE);
            const payload = {
                v: 1,
                installId,
                sessionId,
                extension: {
                    version: extensionPackage.version || 'unknown',
                    appName: vscode.env.appName || 'unknown',
                    appHost: vscode.env.appHost || 'unknown',
                    uiKind: vscode.UIKind && vscode.env.uiKind === vscode.UIKind.Web ? 'web' : 'desktop',
                    vscodeVersion: vscode.version || 'unknown',
                    os: os.platform()
                },
                events
            };

            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), FLUSH_TIMEOUT_MS);

            try {
                const response = await fetch(endpoint, {
                    method: 'POST',
                    headers: { 'content-type': 'application/json' },
                    body: JSON.stringify(payload),
                    signal: controller.signal
                });
                if (!response.ok) {
                    console.warn(`Telemetry request failed: ${response.status}`);
                }
            } catch (error) {
                console.warn('Telemetry request failed:', error && error.name ? error.name : error);
            } finally {
                clearTimeout(timer);
            }
        })().finally(() => {
            flushPromise = null;
        });

        return flushPromise;
    }

    /**
     * Shows the opt-out disclosure once. Never shown when telemetry is off.
     */
    function showNoticeOnce() {
        if (!isEnabled()) {
            return;
        }
        try {
            if (context.globalState.get(NOTICE_KEY) === NOTICE_VERSION) {
                return;
            }
            void context.globalState.update(NOTICE_KEY, NOTICE_VERSION);
        } catch (error) {
            console.warn('Could not read telemetry notice state:', error);
        }

        noticePromise = new Promise(resolve => {
            const timer = setTimeout(resolve, 5000);
            const settle = () => {
                clearTimeout(timer);
                resolve();
            };

            vscode.window.showInformationMessage(
                'dev-guard sends anonymous usage stats to improve the extension. No extension IDs or file paths are collected.',
                'Learn more',
                'Disable telemetry'
            ).then(selection => {
                if (selection === 'Disable telemetry') {
                    const target = vscode.ConfigurationTarget
                        ? vscode.ConfigurationTarget.Global
                        : true;
                    void vscode.workspace
                        .getConfiguration('devGuard')
                        .update('telemetry.enabled', false, target);
                } else if (selection === 'Learn more') {
                    void vscode.env.openExternal(
                        vscode.Uri.parse('https://github.com/yeeth-security/dev-guard#telemetry')
                    );
                }
                settle();
            }, settle);
        });
    }

    return { record, flush, showNoticeOnce };
}

module.exports = {
    createTelemetry,
    bucketCount,
    bucketDuration
};

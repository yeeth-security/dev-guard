/**
 * Opens https links inside the editor (`openUrl.js`).
 *
 * Why this file exists:
 *   Toasts, the side pane, and the marketplace proxy used to call
 *   `env.openExternal`, which leaves the IDE. Users want reports and
 *   guides to stay in an editor tab. This helper tries Simple Browser
 *   first (`simpleBrowser.show`) and only falls back to the system
 *   browser if that command is missing.
 *
 * Security: only `https://` URLs are accepted. http, javascript, and
 * other schemes are ignored.
 */

/** True when the string is a safe https URL we are willing to open. */
function isHttpsUrl(url) {
    return typeof url === 'string' && /^https:\/\//.test(url);
}

/** Last-resort: open in the system browser. Returns a Promise. */
function openExternal(vscodeApi, url) {
    if (!vscodeApi || !vscodeApi.env || typeof vscodeApi.env.openExternal !== 'function') {
        return Promise.resolve(false);
    }
    const uri = vscodeApi.Uri && typeof vscodeApi.Uri.parse === 'function'
        ? vscodeApi.Uri.parse(url)
        : url;
    return Promise.resolve(vscodeApi.env.openExternal(uri));
}

/**
 * Opens `url` in a Simple Browser editor tab.
 * Returns false if the URL is rejected. The open itself is fire-and-forget.
 */
function openInEditor(vscodeApi, url) {
    if (!isHttpsUrl(url)) return false;
    const run = () => {
        if (vscodeApi && vscodeApi.commands && typeof vscodeApi.commands.executeCommand === 'function') {
            // Simple Browser is built into VS Code and Cursor.
            return Promise.resolve(vscodeApi.commands.executeCommand('simpleBrowser.show', url))
                .catch(() => openExternal(vscodeApi, url));
        }
        return openExternal(vscodeApi, url);
    };
    void run();
    return true;
}

module.exports = { isHttpsUrl, openInEditor };

/**
 * Tests for opening https links inside the editor (`openUrl.js`).
 * Simple Browser is tried first; the system browser is the fallback.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { isHttpsUrl, openInEditor } = require('../openUrl');

test('isHttpsUrl only accepts https URLs', () => {
    assert.equal(isHttpsUrl('https://www.pkgscan.dev/'), true);
    assert.equal(isHttpsUrl('http://insecure.example'), false);
    assert.equal(isHttpsUrl('javascript:alert(1)'), false);
    assert.equal(isHttpsUrl(''), false);
    assert.equal(isHttpsUrl(null), false);
});

test('openInEditor uses Simple Browser and never calls the system browser when it works', async () => {
    const cmds = [];
    const ext = [];
    const vscodeApi = {
        commands: { executeCommand: async (cmd, url) => { cmds.push([cmd, url]); } },
        env: { openExternal: url => { ext.push(url); } },
        Uri: { parse: url => url }
    };

    assert.equal(openInEditor(vscodeApi, 'https://www.pkgscan.dev/'), true);
    await new Promise(r => setImmediate(r));
    assert.deepEqual(cmds, [['simpleBrowser.show', 'https://www.pkgscan.dev/']]);
    assert.deepEqual(ext, []);
});

test('openInEditor falls back to the system browser if Simple Browser is missing', async () => {
    const ext = [];
    const vscodeApi = {
        commands: { executeCommand: async () => { throw new Error('command not found'); } },
        env: { openExternal: url => { ext.push(url); } },
        Uri: { parse: url => url }
    };

    assert.equal(openInEditor(vscodeApi, 'https://yeethsecurity.com/guides/vscode-extension-malware/#remove'), true);
    await new Promise(r => setImmediate(r));
    assert.deepEqual(ext, ['https://yeethsecurity.com/guides/vscode-extension-malware/#remove']);

    // No commands API at all: still fall back.
    const ext2 = [];
    openInEditor({ env: { openExternal: url => ext2.push(url) }, Uri: { parse: url => url } }, 'https://example.com/a');
    await new Promise(r => setImmediate(r));
    assert.deepEqual(ext2, ['https://example.com/a']);
});

test('openInEditor rejects non-https URLs', () => {
    const cmds = [];
    assert.equal(openInEditor({ commands: { executeCommand: async (c, u) => cmds.push([c, u]) } }, 'http://evil.example'), false);
    assert.equal(cmds.length, 0);
});

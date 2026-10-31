// Tests for the pane's marketplace value validation (no vscode needed for this helper,
// but ui/pane.js requires 'vscode' at load time, so we stub the module).
const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('module');

// Stub the 'vscode' module so ui/pane.js can be required outside the editor.
const originalLoad = Module._load;
Module._load = function (request, ...rest) {
    if (request === 'vscode') return { window: {}, workspace: {}, commands: {}, env: {}, Uri: {} };
    return originalLoad.call(this, request, ...rest);
};
const { cleanMarketplaceValue } = require('../ui/pane');
Module._load = originalLoad;

test('cleanMarketplaceValue accepts default, custom placeholder, and http(s) URLs only', () => {
    assert.equal(cleanMarketplaceValue(''), '');
    assert.equal(cleanMarketplaceValue('  custom '), 'custom');
    assert.equal(cleanMarketplaceValue('https://open-vsx.org/vscode/gallery'), 'https://open-vsx.org/vscode/gallery');
    assert.equal(cleanMarketplaceValue('http://localhost:8080/gallery'), 'http://localhost:8080/gallery');
    assert.equal(cleanMarketplaceValue('ftp://nope'), null);
    assert.equal(cleanMarketplaceValue('javascript:alert(1)'), null);
    assert.equal(cleanMarketplaceValue('not a url'), null);
    assert.equal(cleanMarketplaceValue('https://' + 'a'.repeat(400)), null);
    assert.equal(cleanMarketplaceValue(42), null);
});

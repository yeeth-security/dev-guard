/**
 * Tests for the headless `devguard-scan` CLI (`bin/devguard-scan.js`).
 *
 * Covers the contract: text output, `--json` shape, and exit codes.
 * The detection rules themselves are covered by `scanner.test.js`.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'devguard-scan.js');
const SHAPE = path.join(ROOT, 'test-fixtures', 'graphtage-shape');
const CLEAN = path.join(ROOT, 'test-fixtures', 'clean-workspace');

function run(args) {
    return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
}

test('attack fixture exits 1 and names the folder-open task', () => {
    const result = run([SHAPE]);
    assert.equal(result.status, 1);
    assert.match(result.stdout, /^high C2_COMMUNICATION \.vscode\/tasks\.json/m);
    assert.match(result.stdout, /graphtage-format/);
    assert.match(result.stdout, /folderOpen/);
    assert.match(result.stdout, /summary: 0 critical, 1 high, 0 medium, 0 low/);
});

test('clean fixture exits 0 and prints no findings', () => {
    const result = run([CLEAN]);
    assert.equal(result.status, 0);
    assert.doesNotMatch(result.stdout, /\b(critical|high|medium|low) C2_/);
    assert.match(result.stdout, /summary: 0 critical, 0 high, 0 medium, 0 low/);
});

test('--json returns findings and a summary', () => {
    const result = run([SHAPE, '--json']);
    assert.equal(result.status, 1);
    const payload = JSON.parse(result.stdout);
    assert.ok(Array.isArray(payload.findings), 'findings is an array');
    assert.equal(payload.findings.length, 1);
    assert.equal(payload.findings[0].file, '.vscode/tasks.json');
    assert.equal(payload.findings[0].severity, 'high');
    assert.deepEqual(payload.summary, { critical: 0, high: 1, medium: 0, low: 0 });
});

test('a missing path exits 2', () => {
    const result = run([path.join(ROOT, 'test-fixtures', 'does-not-exist')]);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /no such path/);
});

test('no arguments exits 2 with usage', () => {
    const result = run([]);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /Usage: devguard-scan/);
});

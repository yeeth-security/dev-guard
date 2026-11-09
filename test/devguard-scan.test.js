/**
 * Tests for the headless `devguard-scan` CLI (`bin/devguard-scan.js`).
 *
 * Covers the ENG-40 contract: text output, stable `--json` shape, exit codes,
 * `--emit-hashes`, and joining a flagged file hash to a local verdict map.
 * The scanner itself is unchanged and already covered by `scanner.test.js`.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'devguard-scan.js');
const SHAPE = path.join(ROOT, 'test-fixtures', 'graphtage-shape');
const CLEAN = path.join(ROOT, 'test-fixtures', 'clean-workspace');

function run(args) {
    return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
}

function sha256File(filePath) {
    return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function withTempDir(fn) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'devguard-scan-'));
    try {
        return fn(dir);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
}

test('graphtage-shape fixture exits 1 and names the folder-open task', () => {
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
    assert.doesNotMatch(result.stdout, /\b(critical|high)\b C2_/);
    assert.match(result.stdout, /summary: 0 critical, 0 high, 0 medium, 0 low/);
});

test('--json returns the stable finding, hash, and summary shape', () => {
    const result = run(['--json', SHAPE]);
    assert.equal(result.status, 1);
    const payload = JSON.parse(result.stdout);
    assert.deepEqual(Object.keys(payload), ['findings', 'hashes', 'summary']);

    assert.equal(payload.findings.length, 1);
    const finding = payload.findings[0];
    assert.deepEqual(Object.keys(finding), ['rule', 'technique', 'severity', 'file', 'detail']);
    assert.equal(finding.rule, 'C2_COMMUNICATION');
    assert.equal(finding.technique, 'T1059');
    assert.equal(finding.severity, 'high');
    assert.equal(finding.file, '.vscode/tasks.json');

    const expectedHash = sha256File(path.join(SHAPE, '.vscode', 'tasks.json'));
    assert.deepEqual(payload.hashes, [expectedHash]);
    assert.deepEqual(payload.summary, { critical: 0, high: 1, medium: 0, low: 0 });
});

test('--emit-hashes prints the sha256 of every flagged file', () => {
    const expectedHash = sha256File(path.join(SHAPE, '.vscode', 'tasks.json'));
    const withHashes = run(['--emit-hashes', SHAPE]);
    assert.equal(withHashes.status, 1);
    assert.ok(withHashes.stdout.includes(`${expectedHash}  .vscode/tasks.json`));

    const withoutHashes = run([SHAPE]);
    assert.ok(!withoutHashes.stdout.includes(expectedHash));
});

test('--verdicts turns a flagged hash into a critical finding with the campaign name', () => {
    withTempDir(dir => {
        const hash = sha256File(path.join(SHAPE, '.vscode', 'tasks.json'));
        const verdictsFile = path.join(dir, 'verdicts.json');
        fs.writeFileSync(verdictsFile, JSON.stringify({
            [hash]: { verdict: 'malicious', campaign: 'graphtage-pr-190' }
        }));

        const result = run(['--verdicts', verdictsFile, SHAPE]);
        assert.equal(result.status, 1);
        assert.match(result.stdout, /^critical KNOWN_MALICIOUS_ARTIFACT \.vscode\/tasks\.json/m);
        assert.match(result.stdout, /graphtage-pr-190/);
        assert.match(result.stdout, /summary: 1 critical, 1 high, 0 medium, 0 low/);
    });
});

test('--verdicts leaves findings alone when no hash matches', () => {
    withTempDir(dir => {
        const verdictsFile = path.join(dir, 'verdicts.json');
        fs.writeFileSync(verdictsFile, JSON.stringify({
            ['0'.repeat(64)]: { verdict: 'malicious', campaign: 'unrelated' }
        }));

        const result = run(['--verdicts', verdictsFile, '--json', SHAPE]);
        assert.equal(result.status, 1);
        const payload = JSON.parse(result.stdout);
        assert.equal(payload.findings.length, 1);
        assert.equal(payload.summary.critical, 0);
    });
});

test('usage errors exit 2', () => {
    withTempDir(dir => {
        const badJson = path.join(dir, 'bad.json');
        fs.writeFileSync(badJson, 'not json');

        assert.equal(run([]).status, 2, 'no paths');
        assert.equal(run(['--nope', SHAPE]).status, 2, 'unknown option');
        assert.equal(run([path.join(dir, 'missing')]).status, 2, 'missing path');
        assert.equal(run(['--verdicts', path.join(dir, 'missing.json'), SHAPE]).status, 2, 'missing verdicts file');
        assert.equal(run(['--verdicts', badJson, SHAPE]).status, 2, 'malformed verdicts file');
    });
});

test('the CLI and the modules it calls import no vscode API', () => {
    const files = [
        CLI,
        ...fs.readdirSync(path.join(ROOT, 'scanner')).filter(name => name.endsWith('.js'))
            .map(name => path.join(ROOT, 'scanner', name))
    ];
    for (const file of files) {
        assert.doesNotMatch(fs.readFileSync(file, 'utf8'), /require\(['"]vscode['"]\)/, file);
    }
});

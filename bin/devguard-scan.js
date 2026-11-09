#!/usr/bin/env node
'use strict';

/**
 * Headless entry point for the workspace rules (`bin/devguard-scan.js`).
 *
 * Why this file exists:
 *   `scanner/workspace.js` is a pure module with no `vscode` import, so the
 *   same checks that protect the editor can run in CI, a pre-push hook, or on
 *   a server. This CLI only calls the existing scanner; it adds no detection
 *   logic of its own.
 *
 * Usage:
 *   devguard-scan <path...> [--json] [--verdicts FILE] [--emit-hashes]
 *
 * Output:
 *   Text: one `severity rule file detail` line per finding, then a summary.
 *   `--json`: { findings: [...], hashes: [...], summary: {...} }.
 *
 * Exit codes: 0 clean, 1 any critical/high finding, 2 usage error.
 *
 * `--verdicts FILE` loads a local `{ "<sha256>": { verdict, campaign } }` map.
 * A flagged file whose hash is present becomes a critical
 * `KNOWN_MALICIOUS_ARTIFACT` finding. There is no network access.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { scanWorkspaceFolder } = require('../scanner/workspace');

const USAGE = 'Usage: devguard-scan <path...> [--json] [--verdicts FILE] [--emit-hashes]';
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
const SEVERITIES = ['critical', 'high', 'medium', 'low'];

/** Prints a usage error and exits 2 (never returns). */
function usageError(message) {
    process.stderr.write(`devguard-scan: ${message}\n${USAGE}\n`);
    process.exit(2);
}

function parseArgs(argv) {
    const paths = [];
    const options = { json: false, emitHashes: false, verdictsFile: null };
    for (let i = 0; i < argv.length; i += 1) {
        const arg = argv[i];
        if (arg === '--json') {
            options.json = true;
        } else if (arg === '--emit-hashes') {
            options.emitHashes = true;
        } else if (arg === '--verdicts') {
            const value = argv[i + 1];
            if (!value || value.startsWith('-')) usageError('--verdicts needs a file');
            options.verdictsFile = value;
            i += 1;
        } else if (arg === '--help' || arg === '-h') {
            process.stdout.write(`${USAGE}\n`);
            process.exit(0);
        } else if (arg.startsWith('-')) {
            usageError(`unknown option ${arg}`);
        } else {
            paths.push(arg);
        }
    }
    if (paths.length === 0) usageError('no paths given');
    return { paths, options };
}

/** Reads the local hash -> verdict map. Invalid files are usage errors. */
function loadVerdicts(file) {
    let raw;
    try {
        raw = fs.readFileSync(file, 'utf8');
    } catch (err) {
        usageError(`cannot read verdicts file: ${err.message}`);
    }
    let parsed;
    try {
        parsed = JSON.parse(raw);
    } catch (err) {
        usageError(`verdicts file is not JSON: ${err.message}`);
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        usageError('verdicts file must be a JSON object mapping sha256 to a verdict');
    }
    const map = new Map();
    for (const [rawHash, entry] of Object.entries(parsed)) {
        const hash = String(rawHash).toLowerCase();
        if (!/^[a-f0-9]{64}$/.test(hash)) usageError(`verdicts key is not a sha256: ${rawHash}`);
        map.set(hash, entry && typeof entry === 'object' ? entry : {});
    }
    return map;
}

/** SHA-256 of the file's bytes, falling back to the scanner's content hash. */
function hashFile(filePath, fallback) {
    try {
        if (!fs.statSync(filePath).isFile()) return fallback;
        return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
    } catch (_err) {
        return fallback;
    }
}

function toPosix(value) {
    return String(value).split(path.sep).join('/');
}

/**
 * Runs `scanWorkspaceFolder` on every path and flattens its matches into one
 * finding per match. Returns findings plus the flagged files for hash output
 * and verdict lookup.
 */
function scanPaths(paths) {
    const findings = [];
    const flagged = [];
    for (const input of paths) {
        const root = path.resolve(input);
        let stat;
        try {
            stat = fs.statSync(root);
        } catch (_err) {
            usageError(`no such path: ${input}`);
        }
        if (!stat.isDirectory()) usageError(`not a directory: ${input}`);

        for (const result of scanWorkspaceFolder(root)) {
            const file = toPosix(path.relative(root, result.filePath)) || result.displayPath || result.fileName;
            flagged.push({ file, sha256: hashFile(result.filePath, result.sha256) });
            for (const match of result.matches || []) {
                findings.push({
                    rule: match.rule,
                    technique: match.technique || null,
                    severity: match.severity,
                    file,
                    detail: match.detail
                });
            }
        }
    }
    return { findings, flagged };
}

/** Adds a critical KNOWN_MALICIOUS_ARTIFACT finding for each flagged hash in the map. */
function applyVerdicts(findings, flagged, verdictMap) {
    if (!verdictMap) return;
    const seen = new Set();
    for (const item of flagged) {
        if (seen.has(item.sha256) || !verdictMap.has(item.sha256)) continue;
        seen.add(item.sha256);
        const entry = verdictMap.get(item.sha256);
        const campaign = entry.campaign ? ` Campaign: ${entry.campaign}.` : '';
        findings.push({
            rule: 'KNOWN_MALICIOUS_ARTIFACT',
            technique: null,
            severity: 'critical',
            file: item.file,
            detail: `File SHA-256 ${item.sha256} matches a local verdict (${entry.verdict || 'malicious'}).${campaign}`
        });
    }
}

function summarize(findings) {
    const summary = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const finding of findings) {
        const key = String(finding.severity || '').toLowerCase();
        if (key in summary) summary[key] += 1;
    }
    return summary;
}

function printText(findings, hashes, summary) {
    const lines = findings.map(f => `${f.severity} ${f.rule} ${f.file} ${f.detail}`);
    process.stdout.write(`${lines.length > 0 ? `${lines.join('\n')}\n` : ''}`);
    for (const entry of hashes) process.stdout.write(`${entry.sha256}  ${entry.file}\n`);
    process.stdout.write(`summary: ${SEVERITIES.map(k => `${summary[k]} ${k}`).join(', ')}\n`);
}

function main() {
    const { paths, options } = parseArgs(process.argv.slice(2));
    const verdictMap = options.verdictsFile ? loadVerdicts(options.verdictsFile) : null;

    const { findings, flagged } = scanPaths(paths);
    applyVerdicts(findings, flagged, verdictMap);
    findings.sort((a, b) => (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0)
        || a.file.localeCompare(b.file));

    const summary = summarize(findings);
    const hashes = [...new Map(flagged.map(f => [f.sha256, f])).values()]
        .sort((a, b) => a.file.localeCompare(b.file));

    if (options.json) {
        const payload = { findings, hashes: hashes.map(h => h.sha256), summary };
        process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
    } else {
        printText(findings, options.emitHashes ? hashes : [], summary);
    }

    process.exit(summary.critical + summary.high > 0 ? 1 : 0);
}

main();

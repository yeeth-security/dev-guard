/**
 * Static heuristic rules for `.vscode/` and workspace malware (`scanner/rules.js`).
 *
 * Why this file exists:
 *   Attackers stage multi-file payloads directly inside `~/.vscode/` or a
 *   repository's `.vscode/` directory (such as `vscode-bootstrap.sh`,
 *   `env-setup.js`, `package.json`, `.npmrc`, and `package-lock.json`).
 *   Because these files are not extensions, marketplace scanners never see them.
 *   This module inspects file names and contents for the exact behaviors seen
 *   in `.vscode` malware campaigns.
 *
 * Design:
 *   - Pure functions with no `vscode` import so rules are fast and easy to test.
 *   - Caps inspected text at 256 KB so large files never block the editor.
 *   - Maps every finding to its rule name, MITRE ATT&CK technique ID, and severity.
 */

const crypto = require('crypto');
const path = require('path');

// Maximum bytes read from any single file during static analysis.
const MAX_SCAN_BYTES = 256 * 1024;

// Severity ranking used to pick the highest severity across multiple matches.
const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };

// Packages commonly bundled in `.vscode/package.json` credential-theft toolkits.
// For example, `clipboardy` steals copied secrets, `sql.js` reads browser SQLite
// credential stores, and `socket.io-client` keeps a persistent C2 channel open.
const RISKY_VSCODE_PACKAGES = [
    'clipboardy',
    'sql.js',
    'better-sqlite3',
    'sqlite3',
    'socket.io-client',
    'keytar',
    'node-pty',
    'request',
    'axios',
    'ws'
];

/** Computes a SHA-256 hex digest for a string or buffer. */
function sha256Text(content) {
    return crypto.createHash('sha256').update(content || '').digest('hex');
}

/** Returns the highest severity string (`critical`, `high`, `medium`, `low`). */
function highestSeverity(matches) {
    let best = 'medium';
    let bestScore = 0;
    for (const m of Array.isArray(matches) ? matches : []) {
        const score = SEVERITY_ORDER[String(m && m.severity).toLowerCase()] || 0;
        if (score > bestScore) {
            bestScore = score;
            best = String(m.severity).toLowerCase();
        }
    }
    return best;
}

/**
 * Checks JavaScript or TypeScript code for `process.env` exfiltration (`T1041`)
 * and `eval()` command-and-control execution (`T1059`).
 */
function checkScriptHeuristics(text) {
    const matches = [];
    const hasProcessEnv = /\bprocess\.env\b/.test(text);
    const hasHttpCall = /\b(axios|request|fetch|https?\.request|socket\.io-client|XMLHttpRequest)\b/i.test(text);
    const hasC2Marker = /githook-encrypted|x-secret-header/i.test(text);

    // T1041: Posting process.env over the network or to a known C2 collection path.
    if ((hasProcessEnv && hasHttpCall) || hasC2Marker) {
        matches.push({
            rule: 'DATA_EXFILTRATION',
            technique: 'T1041',
            severity: 'high',
            detail: 'Reads process.env and sends environment variables over an outbound HTTP request.'
        });
    }

    // T1059: Passing network responses or dynamic payloads into eval() or Function().
    const hasEval = /\beval\s*\(\s*(response\.data|res\.data|res\.body|body|data|Buffer\.from\b)/i.test(text)
        || /\beval\s*\(/.test(text) && (hasHttpCall || hasProcessEnv)
        || /\bnew\s+Function\s*\(/.test(text) && hasHttpCall;
    if (hasEval) {
        matches.push({
            rule: 'C2_COMMUNICATION',
            technique: 'T1059',
            severity: 'critical',
            detail: 'Executes remote HTTP response data dynamically via eval() or Function().'
        });
    }

    // T1027: Base64 decoding combined with eval or hidden execution.
    if (/Buffer\.from\s*\([^)]+,\s*['"]base64['"]\s*\)/.test(text) && /\beval\s*\(/.test(text)) {
        matches.push({
            rule: 'OBFUSCATED_CODE',
            technique: 'T1027',
            severity: 'medium',
            detail: 'Decodes base64 payload and passes it to dynamic code execution.'
        });
    }

    return matches;
}

/**
 * Checks shell, batch, or PowerShell scripts for second-stage downloaders
 * and portable Node.js runtime bootstrapping (`T1105`).
 */
function checkShellBootstrapHeuristics(text) {
    const matches = [];
    const hasDownloader = /\b(curl|wget|Invoke-WebRequest|iwr)\b/i.test(text);
    const writesVscode = /(?:\$HOME|~|%USERPROFILE%)[/\\]\.vscode|\.vscode[/\\](?:env-setup|package\.json|\.npmrc)/i.test(text)
        || /\/settings\/(?:env|package|npmrc)\b/i.test(text);

    // T1105: Downloading second-stage scripts or manifests into .vscode.
    if (hasDownloader && (writesVscode || /\bnpm\s+install\b/i.test(text) || /\bnode\s+/i.test(text))) {
        matches.push({
            rule: 'REMOTE_PAYLOAD',
            technique: 'T1105',
            severity: 'critical',
            detail: 'Uses curl/wget to download remote scripts or manifests and execute them with Node/npm.'
        });
    }

    // T1105: Bootstrapping a portable Node.js binary from nodejs.org into .vscode.
    if (/nodejs\.org\/dist/i.test(text) || (/portable.*node/i.test(text) && /\.vscode/i.test(text))) {
        matches.push({
            rule: 'REMOTE_PAYLOAD',
            technique: 'T1105',
            severity: 'critical',
            detail: 'Downloads a portable Node.js runtime from nodejs.org into .vscode to run payloads silently.'
        });
    }

    return matches;
}

/**
 * Inspects a file's name and text content and returns all matched static rules.
 * @param {{fileName: string, content?: string, inVscodeDir?: boolean}} input
 */
function scanFileContent({ fileName, content = '', inVscodeDir = false }) {
    const base = path.basename(String(fileName || '')).toLowerCase();
    const text = String(content || '').slice(0, MAX_SCAN_BYTES);
    const matches = [];

    // 1. Check .npmrc for disabled strictness or script-shell hijacking (T1195.002).
    if (base === '.npmrc') {
        const disablesStrict = /engine-strict\s*=\s*false/i.test(text);
        const exactPin = /save-exact\s*=\s*true/i.test(text);
        const shellOverride = /script-shell\s*=/i.test(text);
        if (shellOverride || (inVscodeDir && (disablesStrict || exactPin))) {
            matches.push({
                rule: 'SUPPLY_CHAIN_ABUSE',
                technique: 'T1195.002',
                severity: shellOverride ? 'critical' : 'medium',
                detail: shellOverride
                    ? '.npmrc overrides script-shell to run a custom binary during npm commands.'
                    : '.vscode/.npmrc disables package-manager strictness (engine-strict=false) to hide payload installs.'
            });
        }
    }

    // 2. Check .vscode/package.json for credential-theft dependencies (T1552.001).
    if (base === 'package.json' && inVscodeDir) {
        try {
            const pkg = JSON.parse(text);
            const deps = { ...(pkg && pkg.dependencies), ...(pkg && pkg.devDependencies) };
            const found = RISKY_VSCODE_PACKAGES.filter(name => Object.prototype.hasOwnProperty.call(deps, name));
            matches.push({
                rule: 'ENV_HARVESTING',
                technique: 'T1552.001',
                severity: found.length >= 2 ? 'high' : 'medium',
                detail: found.length > 0
                    ? `Staged .vscode/package.json pulls high-risk packages (${found.join(', ')}).`
                    : 'Unexpected package.json staged inside .vscode/ directory.'
            });
        } catch (_e) {
            matches.push({
                rule: 'ENV_HARVESTING',
                technique: 'T1552.001',
                severity: 'medium',
                detail: 'Unexpected package.json staged inside .vscode/ directory.'
            });
        }
    }

    // 3. Check .vscode/package-lock.json for staged dependency trees (T1027).
    if (base === 'package-lock.json' && inVscodeDir) {
        matches.push({
            rule: 'OBFUSCATED_CODE',
            technique: 'T1027',
            severity: 'medium',
            detail: 'Staged .vscode/package-lock.json pins an operator-controlled dependency tree inside .vscode/.'
        });
    }

    // 4. Always run script & shell heuristics on scripts or files inside .vscode.
    matches.push(...checkScriptHeuristics(text));
    matches.push(...checkShellBootstrapHeuristics(text));

    return matches;
}

module.exports = {
    MAX_SCAN_BYTES,
    SEVERITY_ORDER,
    RISKY_VSCODE_PACKAGES,
    sha256Text,
    highestSeverity,
    checkScriptHeuristics,
    checkShellBootstrapHeuristics,
    scanFileContent
};

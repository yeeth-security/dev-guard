# Changelog

Notable changes to Dev-Guard, newest first. Dates are the Open VSX publish dates. 0.0.7 and 0.0.8 were never published. Their changes shipped in 0.1.0's predecessor, 0.0.9.

## [0.1.2] - 2026-11-04

### Added
- Local marketplace proxy on `127.0.0.1` (`devGuard.proxy.enabled`, on by default). It injects a pkgscan summary at the top of extension READMEs as a GitHub alert, blocks downloads of advised or engine-flagged packages, and asks before an unscanned install.
- **Dev-Guard: Toggle Local Marketplace Proxy** turns the proxy off and restores the previous gallery URL.
- Open VSX and Cursor's mirror are queried with `repository_url`. Visual Studio Marketplace assets are not.
- Workspace and profile file scan. Quarantine and allow are per file, stored as name plus SHA-256 in `devGuard.allowedFiles`.
- **Dev-Guard: Scan Workspace & Profile for File Threats**.
- The side pane lists live extension threats and file threats.
- After a removal in the last 24 hours, the Protected hero links to the security guide.
- Security links open in an editor tab.
- Revoking an allowlist entry for a package the advisory feed misses, such as Ackee, triggers a pkgscan engine lookup.

### Changed
- Activates in Restricted Mode so it can scan before a folder is trusted.
- Threat toasts stay up until Uninstall, Allow, Quarantine, or Allow file. Closing with the X brings the toast back. A later auto scan shows the notice again when it is not already on screen.
- A clean completed engine scan is remembered. An unfinished lookup is retried. A manual scan does not say "looking good" while a lookup is still in flight.

### Security
- The proxy rejects unsigned asset URLs, refuses loopback asset hosts outside tests, and matches publisher and name as whole path segments.
- The peer challenge no longer sends the proxy secret. HTTP peer decisions need a one-time token.
- A taken-over port moves the proxy and rewrites the gallery setting.
- Removed the VSIX SHA-256 check. pkgscan's digest is not platform-aware and was blocking legitimate platform-specific builds. Advisory and scan-verdict blocking are unchanged.

### Fixed
- A reload no longer logs the same extension version as uninstalled and then installed.
- `malicious_found` telemetry is sent once per `id@version` instead of every audit cycle.
- Advisory fetch timers no longer keep the process alive.
- Uninstall restores `product.json` only when the proxy actually patched it.

## [0.1.1] - 2026-10-31

### Fixed
- Advisories come from pkgscan.dev only. The GitHub blocklist keyed on `publisher.name` and matched every marketplace, so it told users to uninstall widely installed legitimate extensions.
- A failed advisory fetch skips the audit. It does not fall back to a bundled list.

## [0.1.0] - 2026-10-31

### Added
- Background advisory monitor. It polls pkgscan.dev about every 5 minutes, scans on install and update, and maps the editor gallery to a registry and platform.
- `devGuard.removalMode`: `auto` (default), `manual`, or `warn`. Auto mode removes a flagged extension again on every reinstall until its ID is on `devGuard.allowlist`.
- Activity Bar pane with a verdict ring, scan log, removed list, and an audit log of installs, removals, and allowlist changes.
- `devGuard.historyLimit` caps the scan and audit logs (default 200).
- Every removal links to the cleanup guide.

### Changed
- The pane keeps scroll position and collapsed sections across a scan.
- While a removed extension is still loaded, the verdict stays amber and asks for a reload.

## [0.0.9] - 2026-10-24

### Added
- pkgscan.dev advisories are layered on the GitHub blocklist. The first sync fetches the full feed. Later syncs are incremental, with a full resync once a day.
- Opt-out usage telemetry (`devGuard.telemetry.enabled`). One `malicious_found` event per blocked extension includes its ID, version, and severity.
- The malicious extension list in the repository was expanded, including Argus Open VSX scan hits.

### Changed
- Copy refers to VS Code-compatible editors, including Cursor, Windsurf, and VSCodium.
- Manual audit feedback dismisses on its own.

## [0.0.6] - 2025-12-11

### Fixed
- Republished with the extension icon. 0.0.5 shipped without it.

## [0.0.5] - 2025-12-11

### Changed
- Republished the extension auditor.

## [0.0.4] - 2025-08-28

### Added
- Malicious-extension signatures from the Eclipse Foundation extension-control list.
- Funding and marketplace metadata. The repository URL points at this GitHub repo.

## [0.0.3] - 2025-08-20

### Added
- README notes how to contribute new detections.

## [0.0.2] - 2025-08-20

### Added
- Extension icon.

## [0.0.1] - 2025-08-20

First release. GitHub tag `Alpha`.

### Added
- Scans installed extensions against a local list of known malicious IDs and fetches updates to that list.
- Uninstalls a flagged extension and asks to reload the window.
- Runs again after an extension is updated.

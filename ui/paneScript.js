/**
 * Client-side script for the DevGuard side pane. Runs inside the webview.
 *
 * Design:
 *   - Event delegation on `document`, so content swapped in by an update
 *     keeps working without re-binding listeners.
 *   - Incremental updates: the extension posts `{ type: 'update', parts }`
 *     and we replace only the inner HTML of each container. The page is not
 *     reloaded, so scroll position, focus, and which sections are open all
 *     survive a background scan.
 *   - Section open/closed state is saved with `vscode.setState`, so it also
 *     survives a full reload of the webview.
 *   - Two-click health check changes: clicking an unsatisfied check row (or its
 *     right-hand `!` icon) arms the row (`is-armed`), cycling/morphing the icon
 *     into the apply symbol (`→`). Clicking the morphed apply icon sends the
 *     `harden` message to apply the setting.
 *
 * Exported as a string so paneHtml.js can inline it under the CSP nonce.
 */

const PANE_SCRIPT = `
  const vscode = acquireVsCodeApi();
  const post = (type, extra) => vscode.postMessage(Object.assign({ type }, extra || {}));
  const $ = id => document.getElementById(id);

  // ── Remember which sections are open ─────────────────────────────
  const state = vscode.getState() || { open: {} };
  document.querySelectorAll('details[data-section]').forEach(d => {
    const key = d.dataset.section;
    if (key in state.open) d.open = state.open[key];
    d.addEventListener('toggle', () => { state.open[key] = d.open; vscode.setState(state); });
  });

  // ── Clicks (delegated) ───────────────────────────────────────────
  const disarmAll = () => document.querySelectorAll('.hc__row.is-armed').forEach(r => r.classList.remove('is-armed'));

  document.addEventListener('click', e => {
    if (e.target.closest('.hc__info')) return;
    const badge = e.target.closest('button[data-harden]');
    if (badge) {
      const row = badge.closest('.hc__row');
      if (row && !row.classList.contains('is-armed')) {
        disarmAll();
        row.classList.add('is-armed');
      } else {
        post('harden', { check: badge.dataset.harden });
      }
      e.preventDefault();
      return;
    }
    const armRow = e.target.closest('[data-harden-arm]');
    if (armRow) {
      const wasArmed = armRow.classList.contains('is-armed');
      disarmAll();
      if (!wasArmed) armRow.classList.add('is-armed');
      e.preventDefault();
      return;
    }
    disarmAll();
    const el = e.target.closest('button, a');
    if (!el) return;
    const d = el.dataset;
    if (el.id === 'scan') post('scan');
    else if (el.id === 'settings') post('settings');
    else if (el.id === 'reload' || d.reload) post('reload'); // finish unloading removed extensions or activate proxy
    else if (el.id === 'pkgscan') post('pkgscan');
    else if (d.url) post('openUrl', { url: d.url });
    else if (d.allow) post('allow', { id: d.allow });
    else if (d.unallow) post('unallow', { id: d.unallow });
    else if (d.copy) { post('copy', { text: d.copy }); el.classList.add('copied'); setTimeout(() => el.classList.remove('copied'), 1200); }
    else return;
    e.preventDefault();
  });

  // ── Setup controls (delegated so they survive updates) ───────────
  const saveUrl = box => post('setMarketplace', { value: box.value.trim() || 'custom' });
  document.addEventListener('change', e => {
    const t = e.target;
    if (t.id === 'mode') post('setMode', { value: t.value });
    else if (t.id === 'proxy') post('setProxy', { value: Boolean(t.checked) });
    else if (t.id === 'marketplace') {
      // "Default" saves ''. "Custom" shows the URL box right away; the URL is
      // saved when the user presses Enter or leaves the box.
      const box = $('marketplaceUrl');
      if (t.value === 'custom') { box.classList.remove('is-hidden'); box.focus(); post('setMarketplace', { value: 'custom' }); }
      else { box.classList.add('is-hidden'); post('setMarketplace', { value: '' }); }
    }
    else if (t.id === 'marketplaceUrl') saveUrl(t);
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Enter' && e.target.id === 'marketplaceUrl') { e.preventDefault(); saveUrl(e.target); }
  });

  // ── Incremental updates from the extension ───────────────────────
  window.addEventListener('message', e => {
    const msg = e.data;
    if (!msg || msg.type !== 'update' || !msg.parts) return;
    const typing = document.activeElement && document.activeElement.id === 'marketplaceUrl';
    for (const [id, html] of Object.entries(msg.parts)) {
      if (id === 'setup' && typing) continue; // never yank the URL box while the user types in it
      const el = $(id);
      if (el && el.innerHTML !== html) el.innerHTML = html;
    }
  });

  post('ready');
`;

module.exports = { PANE_SCRIPT };

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
 *   - "Show more" paging: each list section shows 5 rows at first. A button
 *     reveals 5 more per click. How many rows are shown is saved while the
 *     section stays open, so a background scan does not collapse the list.
 *     Closing the dropdown puts that section back to the first 5.
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
    d.addEventListener('toggle', () => {
      state.open[key] = d.open;
      // Closing the dropdown forgets "Show more". The next open starts at 5.
      if (!d.open && state.shown && state.shown[key]) {
        delete state.shown[key];
        paginate(key);
      }
      vscode.setState(state);
    });
  });

  // ── Clicks (delegated) ───────────────────────────────────────────
  const disarmAll = () => document.querySelectorAll('.hc__row.is-armed').forEach(r => r.classList.remove('is-armed'));

  // Opens a collapsed section, then flashes the card the user should act on.
  // The eye button carries data-threat-key. A jump with no key (the health
  // check) flashes every card in that section.
  function openSection(key, threatKey) {
    const details = document.querySelector('details[data-section="' + key + '"]');
    if (!details) return;
    details.open = true;
    state.open[key] = true;
    vscode.setState(state);
    const card = document.getElementById(key);
    const rows = card ? Array.prototype.slice.call(card.querySelectorAll('[data-threat-key]')) : [];
    const hits = threatKey ? rows.filter(row => row.getAttribute('data-threat-key') === threatKey) : rows;
    const targets = hits.length > 0 ? hits : (card ? [card] : []);
    targets.forEach(revealThreat);
    document.querySelectorAll('.is-flash').forEach(el => el.classList.remove('is-flash'));
    targets.forEach(row => {
      // Reading layout forces the class to restart if the same row is clicked again.
      void row.offsetWidth;
      row.classList.add('is-flash');
    });
    (targets[0] || details).scrollIntoView({ block: 'nearest' });
  }

  // If the action card is past the first page, show enough rows to uncover it.
  function revealThreat(row) {
    const card = row.closest && row.closest('.card');
    if (!card || !card.id || typeof paginate !== 'function') return;
    const rows = Array.prototype.slice.call(card.querySelectorAll('[data-row]'));
    const index = rows.indexOf(row);
    if (index < 0) return;
    if ((state.shown[card.id] || PAGE) < index + 1) {
      state.shown[card.id] = index + 1;
      vscode.setState(state);
    }
    paginate(card.id);
  }

  document.addEventListener('click', e => {
    if (e.target.closest('.hc__info')) return;
    const jump = e.target.closest('[data-open-section]');
    if (jump) {
      openSection(jump.dataset.openSection, jump.getAttribute('data-threat-key') || '');
      e.preventDefault();
      return;
    }
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
    else if (d.removeExtension) post('removeExtension', { id: d.removeExtension });
    else if (d.allow) post('allow', { id: d.allow });
    else if (d.unallow) post('unallow', { id: d.unallow });
    else if (d.quarantineFile) post('quarantineFile', { filePath: d.quarantineFile });
    else if (d.restoreFile) post('restoreFile', { key: d.restoreFile });
    else if (d.inspectFile) post('inspectFile', { filePath: d.inspectFile });
    else if (d.allowFile) post('allowFile', { sha256: d.allowFile });
    else if (d.unallowFile) post('unallowFile', { sha256: d.unallowFile, label: d.unallowLabel || '' });
    else if (d.more) { state.shown[d.more] = (state.shown[d.more] || PAGE) + PAGE; vscode.setState(state); paginate(d.more); }
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

  // ── "Show more" paging ───────────────────────────────────────────
  // Rows carry data-row. Rows past the limit get the hidden attribute.
  const PAGE = 5;
  const PAGED = ['ext-threats', 'threats', 'runs', 'allowed-extensions', 'allowed-files', 'audit'];
  state.shown = state.shown || {};
  const lastHtml = {}; // last HTML we rendered per section (hidden attrs change innerHTML)

  function paginate(key) {
    const card = $(key), more = $('more-' + key);
    if (!card || !more) return;
    const rows = card.querySelectorAll('[data-row]');
    const limit = state.shown[key] || PAGE;
    rows.forEach((row, i) => { row.hidden = i >= limit; });
    // A day divider is only useful when at least one row under it is visible.
    card.querySelectorAll('li.day').forEach(day => {
      let n = day.nextElementSibling, any = false;
      while (n && !n.classList.contains('day')) { if (!n.hidden) { any = true; break; } n = n.nextElementSibling; }
      day.hidden = !any;
    });
    const left = rows.length - limit;
    more.innerHTML = left > 0
      ? '<button type="button" class="link more__btn" data-more="' + key + '">Show ' + Math.min(PAGE, left) + ' more · ' + left + ' left</button>'
      : '';
  }
  PAGED.forEach(key => { const el = $(key); if (el) { lastHtml[key] = el.innerHTML; paginate(key); } });

  // ── Incremental updates from the extension ───────────────────────
  window.addEventListener('message', e => {
    const msg = e.data;
    if (!msg || msg.type !== 'update' || !msg.parts) return;
    const typing = document.activeElement && document.activeElement.id === 'marketplaceUrl';
    for (const [id, html] of Object.entries(msg.parts)) {
      if (id === 'setup' && typing) continue; // never yank the URL box while the user types in it
      const el = $(id);
      if (!el) continue;
      if (PAGED.includes(id)) {
        // Compare with the HTML we rendered, then re-apply the paging.
        if (lastHtml[id] !== html) { lastHtml[id] = html; el.innerHTML = html; paginate(id); }
      } else if (el.innerHTML !== html) el.innerHTML = html;
    }
  });

  post('ready');
`;

module.exports = { PANE_SCRIPT };

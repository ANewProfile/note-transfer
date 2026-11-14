import { api, ApiError, isConfigured } from './api.js';
import { cryptoAvailable, deriveSpaceKeys, importKey, encryptNote, decryptNote } from './crypto.js';

// ---------------------------------------------------------------------------
// Constants & state
// ---------------------------------------------------------------------------
const MAX_LIFESPAN = 5 * 24 * 3600;               // seconds
const MIN_LIFESPAN = 60;
const NAME_RE = /^[a-z0-9-]{1,64}$/;
const MIN_PASSWORD = 6;
const POLL_MS = 15_000;
const REMEMBER_KEY = 'nt:remembered';              // localStorage: { [name]: {name, keyHex, auth, expiresAt} }
const CURRENT_KEY = 'nt:current';                  // sessionStorage: {name, keyHex, auth}

const PRESETS = [
  ['10 min', 600],
  ['1 hour', 3600],
  ['1 day', 86400],
  ['3 days', 3 * 86400],
  ['5 days', 5 * 86400],
];

const state = {
  session: null,        // { name, keyHex, auth }
  key: null,            // CryptoKey
  space: null,          // { created_at, expires_at }
  notes: [],            // [{ id, title, body, created_at, updated_at, broken }]
  editingId: null,
  pollTimer: null,
  tickTimer: null,
  refreshing: false,
  gen: 0,               // bumps on every enter/leave so stale responses are ignored
};

// ---------------------------------------------------------------------------
// Small DOM helpers
// ---------------------------------------------------------------------------
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) if (c != null) node.append(c);
  return node;
}

function showView(id) {
  for (const v of $$('.view')) v.hidden = v.id !== id;
  window.scrollTo(0, 0);
}

function toast(message, { error = false, ms = 2600 } = {}) {
  const t = el('div', { class: `toast${error ? ' error' : ''}`, role: error ? 'alert' : 'status', text: message });
  $('#toasts').append(t);
  setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 300); }, ms);
}

function setBusy(btn, busy, label) {
  if (busy) {
    btn.dataset.label = btn.textContent;
    btn.disabled = true;
    btn.replaceChildren(el('span', { class: 'spinner', 'aria-hidden': 'true' }), document.createTextNode(label || 'Working…'));
  } else {
    btn.disabled = false;
    if (btn.dataset.label != null) btn.textContent = btn.dataset.label;
  }
}

function showFormError(form, message) {
  const p = $('.form-error', form);
  if (!p) return toast(message, { error: true });
  p.textContent = message || '';
  p.hidden = !message;
}

function errorMessage(err) {
  if (err instanceof ApiError) return err.message;
  console.error(err);
  return 'Something went wrong. Please try again.';
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = el('textarea');
    Object.assign(ta.style, { position: 'fixed', top: '-1000px', opacity: '0' });
    ta.value = text;
    document.body.append(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch { /* ignore */ }
    ta.remove();
    return ok;
  }
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------
function formatDuration(seconds) {
  seconds = Math.max(0, Math.floor(seconds));
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${s}s`;
  return `${s}s`;
}

function formatDurationWords(seconds) {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.round((seconds % 3600) / 60);
  const parts = [];
  if (d) parts.push(`${d} day${d === 1 ? '' : 's'}`);
  if (h) parts.push(`${h} hour${h === 1 ? '' : 's'}`);
  if (m || !parts.length) parts.push(`${m} minute${m === 1 ? '' : 's'}`);
  return parts.join(' ');
}

const dateFmt = new Intl.DateTimeFormat(undefined, { weekday: 'short', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
const formatDate = (d) => dateFmt.format(new Date(d));

function sanitizeName(value) {
  return value.toLowerCase().replace(/[\s_]+/g, '-').replace(/[^a-z0-9-]/g, '').slice(0, 64);
}

// ---------------------------------------------------------------------------
// Storage (wrapped: private mode / blocked storage must not break the app)
// ---------------------------------------------------------------------------
function storageGet(kind, key) {
  try { return JSON.parse((kind === 'local' ? localStorage : sessionStorage).getItem(key)); } catch { return null; }
}
function storageSet(kind, key, value) {
  try { (kind === 'local' ? localStorage : sessionStorage).setItem(key, JSON.stringify(value)); } catch { /* ignore */ }
}
function storageDel(kind, key) {
  try { (kind === 'local' ? localStorage : sessionStorage).removeItem(key); } catch { /* ignore */ }
}

function getRemembered() {
  const all = storageGet('local', REMEMBER_KEY) || {};
  let changed = false;
  for (const [name, v] of Object.entries(all)) {
    if (!v || !v.keyHex || !v.auth || !(Date.parse(v.expiresAt) > Date.now())) { delete all[name]; changed = true; }
  }
  if (changed) storageSet('local', REMEMBER_KEY, all);
  return all;
}
function rememberSpace(session, expiresAt) {
  const all = getRemembered();
  all[session.name] = { name: session.name, keyHex: session.keyHex, auth: session.auth, expiresAt };
  storageSet('local', REMEMBER_KEY, all);
}
function forgetSpace(name) {
  const all = getRemembered();
  if (all[name]) { delete all[name]; storageSet('local', REMEMBER_KEY, all); }
}
function isRemembered(name) {
  return !!getRemembered()[name];
}

// ---------------------------------------------------------------------------
// Lifespan picker (preset chips + custom d/h/m)
// ---------------------------------------------------------------------------
let pickerId = 0;
function createLifespanPicker(root, { defaultSeconds = 86400, includeMax = false } = {}) {
  const group = `lifespan-${++pickerId}`;
  let maxSeconds = MAX_LIFESPAN;

  const radios = [];
  const chip = (label, value) => {
    const input = el('input', { type: 'radio', name: group, value: String(value) });
    radios.push(input);
    return el('label', { class: 'chip' }, input, el('span', { text: label }));
  };

  const chips = el('div', { class: 'chips' },
    PRESETS.map(([label, secs]) => chip(label, secs)),
    includeMax ? chip('Maximum', 'max') : null,
    chip('Custom', 'custom'));

  const num = (label, max) => {
    const input = el('input', { type: 'number', min: '0', max: String(max), step: '1', inputmode: 'numeric', value: '0' });
    return [input, el('label', {}, input, label)];
  };
  const [dIn, dLabel] = num('days', 5);
  const [hIn, hLabel] = num('hours', 23);
  const [mIn, mLabel] = num('minutes', 59);
  const custom = el('div', { class: 'custom-duration', hidden: true }, dLabel, hLabel, mLabel);
  const summary = el('p', { class: 'picker-summary' });

  root.replaceChildren(chips, custom, summary);

  const selected = () => radios.find((r) => r.checked)?.value;

  function seconds() {
    const v = selected();
    if (v === 'custom') {
      const n = (i) => Math.max(0, Math.floor(Number(i.value) || 0));
      return n(dIn) * 86400 + n(hIn) * 3600 + n(mIn) * 60;
    }
    if (v === 'max') return maxSeconds;
    return Number(v) || 0;
  }

  function update() {
    custom.hidden = selected() !== 'custom';
    const secs = seconds();
    if (secs < MIN_LIFESPAN) summary.textContent = 'Pick at least 1 minute.';
    else if (secs > maxSeconds) summary.textContent = `Too long. The most you can pick is ${formatDurationWords(maxSeconds)}.`;
    else summary.textContent = `Deletes ${formatDate(Date.now() + secs * 1000)} (in ${formatDurationWords(secs)}).`;
  }

  function setMax(max) {
    maxSeconds = Math.max(0, Math.floor(max));
    for (const r of radios) {
      const n = Number(r.value);
      r.disabled = Number.isFinite(n) && n > maxSeconds;
      if (r.disabled && r.checked) r.checked = false;
    }
    if (!selected()) {
      const fallback = radios.find((r) => r.value === String(defaultSeconds) && !r.disabled)
        || (includeMax ? radios.find((r) => r.value === 'max') : radios.filter((r) => !r.disabled && Number(r.value)).pop())
        || radios.find((r) => r.value === 'custom');
      fallback.checked = true;
    }
    update();
  }

  root.addEventListener('change', update);
  root.addEventListener('input', update);
  radios.find((r) => r.value === String(defaultSeconds)).checked = true;
  setMax(MAX_LIFESPAN);

  return {
    setMax,
    refresh: update,
    reset() { for (const r of radios) r.checked = false; setMax(maxSeconds); },
    validate() {
      const secs = seconds();
      if (secs < MIN_LIFESPAN) return { error: 'Pick a lifespan of at least 1 minute.' };
      if (secs > maxSeconds) return { error: `The most you can pick is ${formatDurationWords(maxSeconds)}.` };
      return { seconds: secs };
    },
  };
}

// ---------------------------------------------------------------------------
// Home view
// ---------------------------------------------------------------------------
let createPicker;

function setupHome() {
  // Tabs
  const tabs = { join: $('#tab-join'), create: $('#tab-create') };
  const forms = { join: $('#form-join'), create: $('#form-create') };
  const selectTab = (which) => {
    for (const k of Object.keys(tabs)) {
      tabs[k].setAttribute('aria-selected', String(k === which));
      forms[k].hidden = k !== which;
    }
    // carry the typed name over to the other tab
    const other = which === 'join' ? 'create' : 'join';
    const src = forms[other].elements.name.value;
    if (src && !forms[which].elements.name.value) forms[which].elements.name.value = src;
    if (which === 'create') createPicker.refresh();
  };
  tabs.join.addEventListener('click', () => selectTab('join'));
  tabs.create.addEventListener('click', () => selectTab('create'));

  // Name sanitizing
  for (const input of $$('.space-name-input')) {
    input.addEventListener('input', () => {
      const clean = sanitizeName(input.value);
      if (clean !== input.value) {
        const pos = input.selectionStart - (input.value.length - clean.length);
        input.value = clean;
        try { input.setSelectionRange(pos, pos); } catch { /* ignore */ }
      }
      input.removeAttribute('aria-invalid');
    });
  }

  // Show/hide password
  for (const btn of $$('.pw-toggle')) {
    btn.addEventListener('click', () => {
      const input = btn.previousElementSibling;
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      btn.textContent = show ? 'Hide' : 'Show';
      btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    });
  }

  createPicker = createLifespanPicker($('[data-picker="create"]'), { defaultSeconds: 86400 });

  forms.join.addEventListener('submit', onJoin);
  forms.create.addEventListener('submit', onCreate);
}

function resetHomeForms() {
  for (const f of [$('#form-join'), $('#form-create')]) {
    f.elements.password.value = '';
    if (f.elements.confirm) f.elements.confirm.value = '';
    showFormError(f, '');
  }
}

function renderRemembered() {
  const all = Object.values(getRemembered()).sort((a, b) => a.name.localeCompare(b.name));
  const card = $('#remembered');
  card.hidden = all.length === 0;
  const list = $('.remembered-list', card);
  list.replaceChildren(...all.map((s) => el('li', {},
    el('div', {},
      el('div', { class: 'name', text: s.name }),
      el('div', { class: 'muted small', text: `Expires in ${formatDurationWords((Date.parse(s.expiresAt) - Date.now()) / 1000)}` })),
    el('div', { class: 'actions' },
      el('button', {
        type: 'button', class: 'btn small primary', text: 'Open',
        onclick: async (e) => {
          const btn = e.currentTarget;
          setBusy(btn, true, 'Opening…');
          try { await enterSpace({ name: s.name, keyHex: s.keyHex, auth: s.auth }, { remember: true }); }
          catch (err) { handleOpenFailure(s.name, err); }
          finally { setBusy(btn, false); }
        },
      }),
      el('button', {
        type: 'button', class: 'btn small ghost', text: 'Forget', title: 'Remove from this device',
        onclick: () => { forgetSpace(s.name); renderRemembered(); },
      })))));
}

function handleOpenFailure(name, err) {
  if (err instanceof ApiError && (err.code === 'not_found' || err.code === 'bad_password')) {
    forgetSpace(name);
    renderRemembered();
  }
  toast(errorMessage(err), { error: true, ms: 4000 });
}

async function onJoin(e) {
  e.preventDefault();
  const form = e.currentTarget;
  const name = form.elements.name.value.trim();
  const password = form.elements.password.value;
  const remember = form.elements.remember.checked;
  showFormError(form, '');

  if (!NAME_RE.test(name)) {
    form.elements.name.setAttribute('aria-invalid', 'true');
    return showFormError(form, 'Enter a space name (lowercase letters, numbers and "-").');
  }
  if (!password) return showFormError(form, 'Enter the space password.');

  const btn = $('button[type="submit"]', form);
  setBusy(btn, true, 'Unlocking…');
  try {
    const keys = await deriveSpaceKeys(name, password);
    await enterSpace({ name, ...keys }, { remember });
  } catch (err) {
    showFormError(form, errorMessage(err));
  } finally {
    setBusy(btn, false);
  }
}

async function onCreate(e) {
  e.preventDefault();
  const form = e.currentTarget;
  const name = form.elements.name.value.trim();
  const password = form.elements.password.value;
  const confirm = form.elements.confirm.value;
  const remember = form.elements.remember.checked;
  showFormError(form, '');

  if (!NAME_RE.test(name)) {
    form.elements.name.setAttribute('aria-invalid', 'true');
    return showFormError(form, 'Space names use lowercase letters, numbers and "-" (1–64 characters).');
  }
  if (password.length < MIN_PASSWORD) return showFormError(form, `Use a password of at least ${MIN_PASSWORD} characters.`);
  if (password !== confirm) return showFormError(form, 'The passwords don’t match.');
  const life = createPicker.validate();
  if (life.error) return showFormError(form, life.error);

  const btn = $('button[type="submit"]', form);
  setBusy(btn, true, 'Creating…');
  try {
    const keys = await deriveSpaceKeys(name, password);
    const data = await api.createSpace(name, keys.auth, life.seconds);
    await enterSpace({ name, ...keys }, { remember, data });
    toast('Space created');
  } catch (err) {
    showFormError(form, errorMessage(err));
  } finally {
    setBusy(btn, false);
  }
}

// ---------------------------------------------------------------------------
// Space view
// ---------------------------------------------------------------------------
async function enterSpace(session, { remember = false, data = null } = {}) {
  const key = await importKey(session.keyHex);
  if (!data) data = await api.openSpace(session.name, session.auth);

  const gen = ++state.gen;
  state.session = session;
  state.key = key;
  state.notes = [];
  state.editingId = null;
  $('#notes').replaceChildren();

  await applySpaceData(data, gen);

  storageSet('session', CURRENT_KEY, session);
  if (remember) rememberSpace(session, data.expires_at);
  else if (isRemembered(session.name)) rememberSpace(session, data.expires_at); // keep expiry fresh

  $('#space-name').textContent = session.name;
  document.title = `${session.name} · Note Transfer`;
  history.replaceState(null, '', `#${session.name}`);
  resetHomeForms();
  resetComposer();
  showView('view-space');
  startTimers();
}

async function applySpaceData(data, gen = state.gen) {
  const notes = await Promise.all((data.notes || []).map(async (n) => {
    const base = { id: n.id, created_at: n.created_at, updated_at: n.updated_at };
    // Reuse already-decrypted notes that haven't changed.
    const existing = state.notes.find((x) => x.id === n.id && x.updated_at === n.updated_at && !x.broken);
    if (existing) return existing;
    try {
      return { ...base, ...(await decryptNote(state.key, state.session.name, n.ciphertext, n.iv)) };
    } catch {
      return { ...base, title: '', body: '', broken: true };
    }
  }));
  if (gen !== state.gen) return; // user left or switched spaces meanwhile
  state.space = { created_at: data.created_at, expires_at: data.expires_at };
  state.notes = notes.sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
  renderNotes();
  updateExpiry();
}

function leaveSpace({ message } = {}) {
  state.gen++;
  stopTimers();
  state.session = null;
  state.key = null;
  state.space = null;
  state.notes = [];
  state.editingId = null;
  $('#notes').replaceChildren();
  resetComposer();
  storageDel('session', CURRENT_KEY);
  history.replaceState(null, '', location.pathname + location.search);
  document.title = 'Note Transfer';
  if ($('#dlg-expiry').open) $('#dlg-expiry').close();
  renderRemembered();
  showView('view-home');
  if (message) toast(message, { ms: 4000 });
}

function spaceGone(message = 'This space has expired or was deleted.') {
  if (state.session) forgetSpace(state.session.name);
  leaveSpace({ message });
}

// Handle API errors from inside a space consistently.
function handleSpaceError(err) {
  if (err instanceof ApiError) {
    if (err.code === 'not_found') return spaceGone();
    if (err.code === 'bad_password') {
      if (state.session) forgetSpace(state.session.name);
      return leaveSpace({ message: 'This space’s password no longer matches. It may have been deleted and re-created by someone else.' });
    }
  }
  toast(errorMessage(err), { error: true, ms: 4000 });
}

function startTimers() {
  stopTimers();
  state.tickTimer = setInterval(updateExpiry, 1000);
  state.pollTimer = setInterval(() => { if (!document.hidden) refresh({ silent: true }); }, POLL_MS);
}
function stopTimers() {
  clearInterval(state.tickTimer);
  clearInterval(state.pollTimer);
  state.tickTimer = state.pollTimer = null;
}

async function refresh({ silent = false } = {}) {
  if (!state.session || state.refreshing) return;
  state.refreshing = true;
  const gen = state.gen;
  const status = $('#sync-status');
  const btn = $('#btn-refresh');
  if (!silent) btn.disabled = true;
  try {
    const data = await api.openSpace(state.session.name, state.session.auth);
    if (gen !== state.gen) return;
    await applySpaceData(data, gen);
    if (isRemembered(state.session.name)) rememberSpace(state.session, data.expires_at);
    status.textContent = `Synced ${new Date().toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' })}`;
    if (!silent) toast('Up to date');
  } catch (err) {
    if (gen !== state.gen) return;
    if (err instanceof ApiError && err.code === 'network' && silent) {
      status.textContent = 'Offline, retrying…';
    } else {
      handleSpaceError(err);
    }
  } finally {
    state.refreshing = false;
    btn.disabled = false;
  }
}

function updateExpiry() {
  if (!state.space) return;
  const remaining = (Date.parse(state.space.expires_at) - Date.now()) / 1000;
  if (remaining <= 0) return spaceGone('This space has expired and was deleted.');
  const line = $('#space-expiry');
  line.textContent = `Deletes in ${formatDuration(remaining)} · ${formatDate(state.space.expires_at)}`;
  line.parentElement.classList.toggle('soon', remaining < 3600);
}

// ----- Notes rendering -----
function renderNotes() {
  const list = $('#notes');
  const existing = new Map($$('#notes > li').map((li) => [li.dataset.id, li]));
  const nodes = state.notes.map((note) => {
    const old = existing.get(note.id);
    // Keep the node when unchanged (preserves text selection) or being edited.
    if (old && (note.id === state.editingId || old.dataset.ver === note.updated_at)) return old;
    return buildNoteEl(note);
  });
  // Keep an open editor even if the note vanished remotely, so typed text isn't lost.
  if (state.editingId && !state.notes.some((n) => n.id === state.editingId)) {
    const old = existing.get(state.editingId);
    if (old) nodes.unshift(old);
  }
  list.replaceChildren(...nodes);
  $('#notes-empty').hidden = nodes.length > 0;
  const n = state.notes.length;
  $('#notes-count').textContent = n ? `${n} note${n === 1 ? '' : 's'}` : 'Notes';
}

function buildNoteEl(note) {
  const li = el('li', { class: `card note${note.broken ? ' broken' : ''}`, 'data-id': note.id, 'data-ver': note.updated_at });
  const edited = note.updated_at && Date.parse(note.updated_at) - Date.parse(note.created_at) > 1000;
  const time = `${formatDate(note.created_at)}${edited ? ` · edited ${formatDate(note.updated_at)}` : ''}`;

  if (note.broken) {
    li.append(
      el('div', { class: 'note-head' }, el('div', {},
        el('h3', { class: 'note-title untitled', text: 'Unreadable note' }),
        el('div', { class: 'note-time', text: time }))),
      el('pre', { class: 'note-body', text: 'This note couldn’t be decrypted with this password.' }),
      el('div', { class: 'note-actions' }, deleteButton(note)));
    return li;
  }

  const copyBtn = (label, getText, title) => el('button', {
    type: 'button', class: 'btn small', text: label, title,
    onclick: async (e) => {
      const btn = e.currentTarget;
      const ok = await copyText(getText());
      btn.textContent = ok ? 'Copied ✓' : 'Copy failed';
      btn.classList.toggle('success', ok);
      setTimeout(() => { btn.textContent = label; btn.classList.remove('success'); }, 1500);
    },
  });

  li.append(
    el('div', { class: 'note-head' }, el('div', {},
      el('h3', { class: `note-title${note.title ? '' : ' untitled'}`, text: note.title || 'Untitled' }),
      el('div', { class: 'note-time', text: time }))),
    el('pre', { class: `note-body${note.body ? '' : ' empty-body'}`, text: note.body || '(empty)' }),
    el('div', { class: 'note-actions' },
      note.body ? copyBtn('Copy', () => note.body, 'Copy the note body') : null,
      note.title ? copyBtn('Copy title', () => note.title, 'Copy the title') : null,
      el('button', { type: 'button', class: 'btn small', text: 'Edit', onclick: () => startEdit(note.id) }),
      deleteButton(note)));
  return li;
}

function deleteButton(note) {
  return el('button', {
    type: 'button', class: 'btn small danger', text: 'Delete',
    onclick: async (e) => {
      if (!confirm(`Delete "${note.title || 'Untitled'}"? This can’t be undone.`)) return;
      const btn = e.currentTarget;
      setBusy(btn, true, 'Deleting…');
      try {
        await api.deleteNote(state.session.name, state.session.auth, note.id);
        state.notes = state.notes.filter((n) => n.id !== note.id);
        renderNotes();
        toast('Note deleted');
      } catch (err) {
        setBusy(btn, false);
        handleSpaceError(err);
      }
    },
  });
}

function startEdit(id) {
  if (state.editingId && state.editingId !== id) {
    toast('Finish the note you’re already editing first.');
    return;
  }
  const note = state.notes.find((n) => n.id === id);
  const li = $(`#notes > li[data-id="${CSS.escape(id)}"]`);
  if (!note || !li) return;
  state.editingId = id;

  const title = el('input', { type: 'text', maxlength: '300', placeholder: 'Title (optional)', autocomplete: 'off' });
  title.value = note.title;
  const body = el('textarea', { rows: '6', autocomplete: 'off', autocapitalize: 'off', autocorrect: 'off', spellcheck: 'false' });
  body.value = note.body;
  const save = el('button', { type: 'submit', class: 'btn primary small', text: 'Save' });
  const cancel = el('button', { type: 'button', class: 'btn small', text: 'Cancel' });

  const form = el('form', { class: 'stack', novalidate: true }, title, body,
    el('div', { class: 'row end' }, cancel, save));

  const finish = () => {
    state.editingId = null;
    li.replaceWith(buildNoteEl(state.notes.find((n) => n.id === id) || note));
    renderNotes();
  };
  cancel.addEventListener('click', finish);
  body.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); form.requestSubmit(); }
    if (e.key === 'Escape') { e.preventDefault(); finish(); }
  });
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const t = title.value.trim();
    const b = body.value;
    if (!t && !b.trim()) return toast('A note needs a title or some text.', { error: true });
    setBusy(save, true, 'Saving…');
    try {
      const { ciphertext, iv } = await encryptNote(state.key, state.session.name, { title: t, body: b });
      const row = await api.updateNote(state.session.name, state.session.auth, id, ciphertext, iv);
      const idx = state.notes.findIndex((n) => n.id === id);
      const updated = { ...note, title: t, body: b, updated_at: row.updated_at, broken: false };
      if (idx >= 0) state.notes[idx] = updated;
      finish();
      toast('Note saved');
    } catch (err) {
      setBusy(save, false);
      if (err instanceof ApiError && err.code === 'note_not_found') {
        toast(err.message, { error: true, ms: 4500 });
        return;
      }
      handleSpaceError(err);
    }
  });

  li.classList.add('editing');
  li.replaceChildren(form);
  body.focus();
}

// ----- Composer -----
function resetComposer() {
  const f = $('#form-note');
  f.reset();
}

async function onAddNote(e) {
  e.preventDefault();
  const form = e.currentTarget;
  const title = form.elements.title.value.trim();
  const body = form.elements.body.value;
  if (!title && !body.trim()) {
    form.elements.body.focus();
    return toast('Write something first.', { error: true });
  }
  const btn = $('button[type="submit"]', form);
  const gen = state.gen;
  setBusy(btn, true, 'Saving…');
  try {
    const { ciphertext, iv } = await encryptNote(state.key, state.session.name, { title, body });
    const row = await api.addNote(state.session.name, state.session.auth, ciphertext, iv);
    if (gen !== state.gen) return;
    state.notes.unshift({ id: row.id, title, body, created_at: row.created_at, updated_at: row.updated_at });
    renderNotes();
    form.reset();
    $(`#notes > li[data-id="${CSS.escape(row.id)}"]`)?.classList.add('flash');
    toast('Note added');
  } catch (err) {
    handleSpaceError(err);
  } finally {
    setBusy(btn, false);
  }
}

// ----- Expiry dialog -----
let expiryPicker;

function openExpiryDialog() {
  if (!state.space) return;
  const dlg = $('#dlg-expiry');
  const form = $('#form-expiry');
  showFormError(form, '');
  const hardLimit = Date.parse(state.space.created_at) + MAX_LIFESPAN * 1000;
  const maxSecs = Math.floor((hardLimit - Date.now()) / 1000);
  $('#expiry-info').textContent =
    `Currently deletes ${formatDate(state.space.expires_at)}. Spaces can live at most 5 days from creation, `
    + `so the latest possible time is ${formatDate(hardLimit)}.`;
  expiryPicker.reset();
  expiryPicker.setMax(maxSecs);
  dlg.showModal();
}

async function onSaveExpiry(e) {
  e.preventDefault();
  const form = e.currentTarget;
  const dlg = $('#dlg-expiry');
  const hardLimit = Date.parse(state.space.created_at) + MAX_LIFESPAN * 1000;
  expiryPicker.setMax(Math.floor((hardLimit - Date.now()) / 1000));
  const v = expiryPicker.validate();
  if (v.error) return showFormError(form, v.error);
  const btn = $('button[type="submit"]', form);
  setBusy(btn, true, 'Saving…');
  try {
    const target = new Date(Math.min(Date.now() + v.seconds * 1000, hardLimit)).toISOString();
    const data = await api.setExpiry(state.session.name, state.session.auth, target);
    state.space.expires_at = data.expires_at;
    if (isRemembered(state.session.name)) rememberSpace(state.session, data.expires_at);
    updateExpiry();
    dlg.close();
    toast(`Now deletes ${formatDate(data.expires_at)}`);
  } catch (err) {
    if (err instanceof ApiError && err.code === 'invalid_expiry') showFormError(form, err.message);
    else { dlg.close(); handleSpaceError(err); }
  } finally {
    setBusy(btn, false);
  }
}

async function onDeleteSpace() {
  const name = state.session?.name;
  if (!name) return;
  if (!confirm(`Delete the space "${name}" and all of its notes for everyone? This can’t be undone.`)) return;
  const btn = $('#btn-delete-space');
  setBusy(btn, true, 'Deleting…');
  try {
    await api.deleteSpace(name, state.session.auth);
    forgetSpace(name);
    leaveSpace({ message: `Deleted "${name}". The name is free again.` });
  } catch (err) {
    handleSpaceError(err);
  } finally {
    setBusy(btn, false);
  }
}

function setupSpace() {
  $('#form-note').addEventListener('submit', onAddNote);
  $('#form-note').elements.body.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); $('#form-note').requestSubmit(); }
  });
  $('#btn-refresh').addEventListener('click', () => refresh());
  $('#btn-leave').addEventListener('click', () => leaveSpace());
  $('#btn-delete-space').addEventListener('click', onDeleteSpace);
  $('#btn-expiry').addEventListener('click', openExpiryDialog);
  expiryPicker = createLifespanPicker($('[data-picker="expiry"]'), { defaultSeconds: 86400, includeMax: true });
  $('#form-expiry').addEventListener('submit', onSaveExpiry);
  $('#btn-expiry-cancel').addEventListener('click', () => $('#dlg-expiry').close());

  // Refresh promptly when coming back to the tab (e.g. after adding a note on your phone).
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && state.session) { updateExpiry(); refresh({ silent: true }); }
  });
  $('#brand-link').addEventListener('click', (e) => {
    if (state.session) { e.preventDefault(); }
  });
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
async function boot() {
  if (!cryptoAvailable()) return showView('view-nocrypto');
  if (!isConfigured()) return showView('view-setup');

  setupHome();
  setupSpace();
  renderRemembered();

  let hashName = '';
  try { hashName = sanitizeName(decodeURIComponent(location.hash.slice(1))); } catch { /* ignore */ }
  const current = storageGet('session', CURRENT_KEY);
  const remembered = getRemembered();
  const candidate = (current && current.name && (!hashName || current.name === hashName))
    ? current
    : (hashName && remembered[hashName]) || null;

  if (candidate) {
    try {
      await enterSpace({ name: candidate.name, keyHex: candidate.keyHex, auth: candidate.auth });
      return;
    } catch (err) {
      storageDel('session', CURRENT_KEY);
      handleOpenFailure(candidate.name, err);
    }
  }

  showView('view-home');
  if (hashName) {
    const join = $('#form-join');
    join.elements.name.value = hashName;
    join.elements.password.focus();
    history.replaceState(null, '', location.pathname + location.search);
  }
}

boot();

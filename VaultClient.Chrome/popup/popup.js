// ============================================================
// Sentil · Midnight Ops — Popup UI Logic
// ============================================================

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// --- State ---
let currentVaultId = null;
let currentVaultName = null;
let allSecrets = [];

// --- Views ---
// popup.css: .view { display: none } / .view.active { display: flex }
function showView(id) {
  $$('.view').forEach((v) => v.classList.remove('active'));
  $(`#view-${id}`).classList.add('active');
}

function show(el) { if (el) el.style.display = ''; }
function hide(el) { if (el) el.style.display = 'none'; }

// --- Message to background ---
function send(msg) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(msg, (res) => {
      if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
      if (res?.error) return reject(new Error(res.error));
      resolve(res);
    });
  });
}

// --- Init ---
document.addEventListener('DOMContentLoaded', async () => {
  showView('splash');

  try {
    const state = await send({ action: 'getAuthState' });
    await new Promise((r) => setTimeout(r, 700));

    if (state.authenticated) {
      const userEl = $('#logged-user');
      if (userEl) userEl.textContent = state.domain
        ? `${state.domain}\\${state.username}`
        : state.username;
      showView('vaults');
      loadVaults();
    } else {
      // Pre-fill domain from config
      try {
        const config = await send({ action: 'getConfig' });
        const domainEl = $('#login-domain');
        if (domainEl && config.defaultDomain) domainEl.value = config.defaultDomain;
      } catch (_) { /* ignore */ }
      showView('login');
    }
  } catch {
    showView('login');
  }

  bindEvents();
});

// --- Event binding ---
function bindEvents() {
  // Login
  $('#form-login')?.addEventListener('submit', handleLogin);
  $('#btn-settings')?.addEventListener('click', () => chrome.runtime.openOptionsPage());

  // Vault list
  $('#btn-logout')?.addEventListener('click', handleLogout);
  $('#nav-settings')?.addEventListener('click', () => chrome.runtime.openOptionsPage());

  // Secret list
  $('#btn-back-vaults')?.addEventListener('click', () => showView('vaults'));
  $('#secret-search')?.addEventListener('input', handleSecretSearch);
  $('#btn-add-credential')?.addEventListener('click', openAddCredential);
  $$('.nav-settings-2').forEach((el) => el.addEventListener('click', () => chrome.runtime.openOptionsPage()));

  // Add credential
  $('#btn-back-from-add')?.addEventListener('click', () => showView('secrets'));
  $('#btn-cancel-add')?.addEventListener('click', () => showView('secrets'));
  $('#form-add-credential')?.addEventListener('submit', handleAddCredential);
}

// --- Login ---
async function handleLogin(e) {
  e.preventDefault();

  const btn = $('#btn-login');
  const errEl = $('#login-error');

  if (errEl) { errEl.textContent = ''; errEl.classList.remove('visible'); }
  if (btn) { btn.disabled = true; btn.textContent = '// autenticando…'; }

  try {
    let domain;
    try {
      const config = await send({ action: 'getConfig' });
      domain = config.defaultDomain || undefined;
    } catch (_) { /* ignore */ }

    // Prefer domain field if user typed something
    const domainField = $('#login-domain');
    if (domainField?.value.trim()) domain = domainField.value.trim();

    const result = await send({
      action: 'login',
      username: $('#login-user').value.trim(),
      password: $('#login-pass').value,
      domain,
    });

    const userEl = $('#logged-user');
    if (userEl) userEl.textContent = result.domain
      ? `${result.domain}\\${result.username}`
      : result.username;

    showView('vaults');
    loadVaults();
  } catch (err) {
    if (errEl) {
      errEl.textContent = err.message || 'falha na autenticacao';
      errEl.classList.add('visible');
    }
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '> auth.login()'; }
  }
}

async function handleLogout() {
  await send({ action: 'logout' });
  const passEl = $('#login-pass');
  if (passEl) passEl.value = '';
  showView('login');
}

// --- Vaults ---
async function loadVaults() {
  const listEl = $('#vault-list');
  const emptyEl = $('#vault-empty');
  const loadEl = $('#vault-loading');

  listEl.innerHTML = '';
  hide(emptyEl);
  show(loadEl);

  try {
    const data = await send({ action: 'listVaults' });
    const vaults = Array.isArray(data) ? data : data?.items || data?.vaults || [];

    hide(loadEl);

    if (vaults.length === 0) { show(emptyEl); return; }

    vaults.forEach((v) => {
      const initial = (v.name || '?')[0].toUpperCase();
      const card = document.createElement('div');
      card.className = 'vault-card';
      card.innerHTML = `
        <div class="vault-icon">${esc(initial)}</div>
        <div style="flex:1;min-width:0;">
          <div class="vault-name">${esc(v.name)}</div>
          <div class="vault-meta">${esc(v.environment || 'Production')} · ${esc(v.status || 'Active')}</div>
        </div>
      `;
      card.addEventListener('click', () => openVault(v.id, v.name));
      listEl.appendChild(card);
    });
  } catch (err) {
    hide(loadEl);
    listEl.innerHTML = `<div class="status-error">${esc(err.message)}</div>`;
  }
}

function openVault(vaultId, vaultName) {
  currentVaultId = vaultId;
  currentVaultName = vaultName;
  const nameEl = $('#vault-name');
  if (nameEl) nameEl.textContent = vaultName;
  const searchEl = $('#secret-search');
  if (searchEl) searchEl.value = '';
  showView('secrets');
  loadSecrets();
}

// --- Secrets ---
async function loadSecrets() {
  const listEl = $('#secret-list');
  const emptyEl = $('#secret-empty');
  const loadEl = $('#secret-loading');
  const errEl = $('#secret-error');

  listEl.innerHTML = '';
  hide(emptyEl);
  hide(errEl);
  show(loadEl);

  try {
    const data = await send({ action: 'listSecrets', vaultId: currentVaultId });
    allSecrets = Array.isArray(data) ? data : data?.items || data?.secrets || [];

    hide(loadEl);
    renderSecrets(allSecrets);
  } catch (err) {
    hide(loadEl);
    if (errEl) { errEl.textContent = err.message; show(errEl); }
  }
}

function renderSecrets(secrets) {
  const listEl = $('#secret-list');
  const emptyEl = $('#secret-empty');
  listEl.innerHTML = '';

  if (secrets.length === 0) { show(emptyEl); return; }
  hide(emptyEl);

  secrets.forEach((s) => {
    const name = s.name || s.Name || '';
    const ver = s.currentVersion || s.version || '';
    const expires = s.expires;
    const initial = (name || '?')[0].toUpperCase();

    const item = document.createElement('div');
    item.className = 'credential-item';
    item.innerHTML = `
      <div class="credential-icon">${esc(initial)}</div>
      <div style="flex:1;min-width:0;">
        <div class="credential-name">${esc(name)}</div>
        <div class="credential-meta">
          <span class="version-badge">v${esc(String(ver))}</span>
          ${expires ? '<span class="expiry-badge">EXPIRA</span>' : ''}
        </div>
      </div>
    `;
    item.addEventListener('click', () => doAutofill(name, item));
    listEl.appendChild(item);
  });
}

function handleSecretSearch() {
  const q = ($('#secret-search')?.value || '').trim().toLowerCase();
  if (!q) return renderSecrets(allSecrets);
  renderSecrets(allSecrets.filter((s) => (s.name || s.Name || '').toLowerCase().includes(q)));
}

// --- Autofill ---
async function doAutofill(secretName, itemEl) {
  if (itemEl.classList.contains('filling')) return;
  itemEl.classList.add('filling');

  const nameEl = itemEl.querySelector('.credential-name');
  const originalName = nameEl?.textContent;
  if (nameEl) nameEl.textContent = 'preenchendo…';

  try {
    await send({ action: 'autofillSecret', vaultId: currentVaultId, secretName });
    if (nameEl) nameEl.textContent = 'preenchido!';
    setTimeout(() => window.close(), 600);
  } catch (err) {
    if (nameEl) nameEl.textContent = originalName;
    itemEl.classList.remove('filling');

    let errEl = $('#secret-list-error');
    if (!errEl) {
      errEl = document.createElement('div');
      errEl.id = 'secret-list-error';
      errEl.className = 'status-error';
      $('#secret-list')?.parentElement?.appendChild(errEl);
    }
    errEl.textContent = err.message;
    show(errEl);
    setTimeout(() => hide(errEl), 4000);
  }
}

// --- Add Credential ---
function openAddCredential() {
  ['#add-url', '#add-login', '#add-secret-name'].forEach((sel) => {
    const el = $(sel);
    if (el) el.value = '';
  });
  const errEl = $('#add-error');
  if (errEl) { errEl.textContent = ''; errEl.classList.remove('visible'); }
  showView('add-credential');
}

async function handleAddCredential(e) {
  e.preventDefault();
  const btn = $('#btn-save-credential');
  const errEl = $('#add-error');
  if (errEl) { errEl.textContent = ''; errEl.classList.remove('visible'); }
  if (btn) { btn.disabled = true; btn.textContent = 'salvando…'; }

  try {
    await send({
      action: 'createAutofillRule',
      vaultId: currentVaultId,
      urlPattern: $('#add-url')?.value.trim(),
      login: $('#add-login')?.value.trim(),
      secretName: $('#add-secret-name')?.value.trim(),
    });

    if (btn) btn.textContent = 'salvo!';
    setTimeout(() => {
      showView('secrets');
      if (btn) { btn.textContent = 'salvar'; btn.disabled = false; }
    }, 800);
  } catch (err) {
    if (errEl) { errEl.textContent = err.message || 'erro ao salvar'; errEl.classList.add('visible'); }
    if (btn) { btn.disabled = false; btn.textContent = 'salvar'; }
  }
}

// --- Util ---
function esc(str) {
  const d = document.createElement('div');
  d.textContent = String(str ?? '');
  return d.innerHTML;
}

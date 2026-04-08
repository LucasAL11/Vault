// ============================================================
// Sentinel Vault - Popup UI Logic
// ============================================================

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// --- State ---
let currentVaultId = null;
let currentVaultName = null;
let allSecrets = [];

// --- Views ---

function showView(id) {
  $$('.view').forEach((v) => v.classList.add('hidden'));
  $(`#view-${id}`).classList.remove('hidden');
}

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
  // Show splash
  showView('splash');

  try {
    const state = await send({ action: 'getAuthState' });
    // Brief splash delay for polish
    await new Promise((r) => setTimeout(r, 800));

    if (state.authenticated) {
      $('#logged-user').textContent = state.domain
        ? `${state.domain}\\${state.username}`
        : state.username;
      showView('vaults');
      loadVaults();
    } else {
      // Pre-fill domain from config
      try {
        const config = await send({ action: 'getConfig' });
        if (config.defaultDomain) {
          // Store for AD login
          document.body.dataset.defaultDomain = config.defaultDomain;
        }
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
  $('#form-login').addEventListener('submit', handleLogin);
  $('#btn-ad-login').addEventListener('click', handleLogin);
  $('#btn-settings').addEventListener('click', () => chrome.runtime.openOptionsPage());
  $('#btn-toggle-pass').addEventListener('click', togglePasswordVisibility);

  // Vault list
  $('#btn-logout').addEventListener('click', handleLogout);
  $('#nav-settings').addEventListener('click', () => chrome.runtime.openOptionsPage());

  // Secret list
  $('#btn-back-vaults').addEventListener('click', () => showView('vaults'));
  $('#secret-search').addEventListener('input', handleSecretSearch);
  $('#btn-add-credential').addEventListener('click', openAddCredential);
  $$('.nav-settings-2').forEach((el) => el.addEventListener('click', () => chrome.runtime.openOptionsPage()));

  // Add credential
  $('#btn-back-from-add').addEventListener('click', () => showView('secrets'));
  $('#btn-cancel-add').addEventListener('click', () => showView('secrets'));
  $('#form-add-credential').addEventListener('submit', handleAddCredential);
}

// --- Password Toggle ---

function togglePasswordVisibility() {
  const input = $('#login-pass');
  const icon = $('#btn-toggle-pass .material-symbols-outlined');
  if (input.type === 'password') {
    input.type = 'text';
    icon.textContent = 'visibility_off';
  } else {
    input.type = 'password';
    icon.textContent = 'visibility';
  }
}

// --- Login ---

async function handleLogin(e) {
  e.preventDefault();
  const btn = $('#btn-login');
  const errEl = $('#login-error');
  errEl.classList.add('hidden');
  btn.disabled = true;
  btn.textContent = 'Authenticating...';

  try {
    // Always read domain fresh from config
    let domain;
    try {
      const config = await send({ action: 'getConfig' });
      domain = config.defaultDomain || undefined;
    } catch (_) {
      domain = document.body.dataset.defaultDomain || undefined;
    }

    const result = await send({
      action: 'login',
      username: $('#login-user').value.trim(),
      password: $('#login-pass').value,
      domain,
    });

    $('#logged-user').textContent = result.domain
      ? `${result.domain}\\${result.username}`
      : result.username;

    showView('vaults');
    loadVaults();
  } catch (err) {
    errEl.textContent = err.message || 'Authentication failed';
    errEl.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Login';
  }
}

async function handleLogout() {
  await send({ action: 'logout' });
  $('#login-pass').value = '';
  showView('login');
}

// --- Vaults ---

async function loadVaults() {
  const listEl = $('#vault-list');
  const emptyEl = $('#vault-empty');
  const loadEl = $('#vault-loading');
  const countEl = $('#vault-count');

  listEl.innerHTML = '';
  emptyEl.classList.add('hidden');
  loadEl.classList.remove('hidden');
  countEl.textContent = '';

  try {
    const data = await send({ action: 'listVaults' });
    const vaults = Array.isArray(data) ? data : data?.items || data?.vaults || [];

    loadEl.classList.add('hidden');

    if (vaults.length === 0) {
      emptyEl.classList.remove('hidden');
      return;
    }

    countEl.textContent = `${vaults.length} Secure Vault${vaults.length !== 1 ? 's' : ''}`;

    vaults.forEach((v, i) => {
      const item = document.createElement('div');
      item.className = 'vault-card';
      if (i === 0) item.classList.add('selected');

      const iconClass = i === 0 ? 'default' : 'neutral';
      const iconName = i === 0 ? 'lock' : 'corporate_fare';

      item.innerHTML = `
        <div class="vault-card-icon ${iconClass}">
          <span class="material-symbols-outlined filled">${iconName}</span>
        </div>
        <div class="vault-card-info">
          <div class="vault-card-name">
            ${esc(v.name)}
            ${i === 0 ? '<span class="badge-default">Default</span>' : ''}
          </div>
          <div class="vault-card-meta">${esc(v.environment || 'Production')} &middot; ${esc(v.status || 'Active')}</div>
        </div>
        <span class="material-symbols-outlined vault-card-arrow">chevron_right</span>
      `;
      item.addEventListener('click', () => openVault(v.id, v.name));
      listEl.appendChild(item);
    });
  } catch (err) {
    loadEl.classList.add('hidden');
    listEl.innerHTML = `<div class="alert-error">${esc(err.message)}</div>`;
  }
}

function openVault(vaultId, vaultName) {
  currentVaultId = vaultId;
  currentVaultName = vaultName;
  $('#vault-name').textContent = vaultName;
  $('#secret-search').value = '';
  showView('secrets');
  loadSecrets();
}

// --- Secrets ---

async function loadSecrets() {
  const listEl = $('#secret-list');
  const emptyEl = $('#secret-empty');
  const loadEl = $('#secret-loading');
  const countEl = $('#secret-count');

  listEl.innerHTML = '';
  emptyEl.classList.add('hidden');
  loadEl.classList.remove('hidden');
  countEl.textContent = '';

  try {
    const data = await send({ action: 'listSecrets', vaultId: currentVaultId });
    allSecrets = Array.isArray(data) ? data : data?.items || data?.secrets || [];

    loadEl.classList.add('hidden');
    countEl.textContent = `${allSecrets.length} Credential${allSecrets.length !== 1 ? 's' : ''}`;
    renderSecrets(allSecrets);
  } catch (err) {
    loadEl.classList.add('hidden');
    listEl.innerHTML = `<div class="alert-error">${esc(err.message)}</div>`;
  }
}

function renderSecrets(secrets) {
  const listEl = $('#secret-list');
  const emptyEl = $('#secret-empty');
  listEl.innerHTML = '';

  if (secrets.length === 0) {
    emptyEl.classList.remove('hidden');
    return;
  }
  emptyEl.classList.add('hidden');

  secrets.forEach((s) => {
    const name = s.name || s.Name;
    const ver = s.currentVersion || s.version || '';
    const status = s.status || '';
    const initial = (name || '?')[0].toUpperCase();

    const item = document.createElement('div');
    item.className = 'credential-item';
    item.innerHTML = `
      <div class="credential-icon">
        <div class="credential-icon-letter">${esc(initial)}</div>
      </div>
      <div class="credential-info">
        <div class="credential-name">${esc(name)}</div>
        <div class="credential-sub">v${esc(String(ver))} ${status ? '&middot; ' + esc(status) : ''}</div>
      </div>
      <span class="material-symbols-outlined credential-action">vpn_key</span>
    `;
    item.addEventListener('click', () => doAutofill(name, item));
    listEl.appendChild(item);
  });
}

function handleSecretSearch() {
  const q = $('#secret-search').value.trim().toLowerCase();
  if (!q) return renderSecrets(allSecrets);
  const filtered = allSecrets.filter((s) => {
    const name = (s.name || s.Name || '').toLowerCase();
    return name.includes(q);
  });
  renderSecrets(filtered);
}

// --- Autofill (direct on click) ---

async function doAutofill(secretName, itemEl) {
  // Prevent double-click
  if (itemEl.classList.contains('filling')) return;
  itemEl.classList.add('filling');

  const nameEl = itemEl.querySelector('.credential-name');
  const originalName = nameEl.textContent;
  nameEl.textContent = 'Filling...';

  try {
    await send({
      action: 'autofillSecret',
      vaultId: currentVaultId,
      secretName,
    });

    nameEl.textContent = 'Filled!';
    itemEl.style.background = 'rgba(99, 138, 255, 0.15)';
    setTimeout(() => window.close(), 600);
  } catch (err) {
    nameEl.textContent = originalName;
    itemEl.classList.remove('filling');
    // Show error inline
    let errEl = $('#secret-list-error');
    if (!errEl) {
      errEl = document.createElement('div');
      errEl.id = 'secret-list-error';
      errEl.className = 'alert-error';
      errEl.style.margin = '8px 0 0';
      $('#secret-list').parentElement.appendChild(errEl);
    }
    errEl.textContent = err.message;
    errEl.classList.remove('hidden');
    setTimeout(() => errEl.classList.add('hidden'), 4000);
  }
}

// --- Add Credential ---

function openAddCredential() {
  $('#add-url').value = '';
  $('#add-login').value = '';
  $('#add-secret-name').value = '';
  $('#add-error').classList.add('hidden');
  showView('add-credential');
}

async function handleAddCredential(e) {
  e.preventDefault();
  const btn = $('#btn-save-credential');
  const errEl = $('#add-error');
  errEl.classList.add('hidden');
  btn.disabled = true;
  btn.textContent = 'Saving...';

  try {
    await send({
      action: 'createAutofillRule',
      vaultId: currentVaultId,
      urlPattern: $('#add-url').value.trim(),
      login: $('#add-login').value.trim(),
      secretName: $('#add-secret-name').value.trim(),
    });

    btn.textContent = 'Saved!';
    setTimeout(() => {
      showView('secrets');
      btn.textContent = 'Save Credential';
      btn.disabled = false;
    }, 800);
  } catch (err) {
    errEl.textContent = err.message || 'Failed to save credential';
    errEl.classList.remove('hidden');
    btn.disabled = false;
    btn.textContent = 'Save Credential';
  }
}

// --- Util ---

function esc(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}

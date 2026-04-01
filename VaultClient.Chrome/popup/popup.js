// ============================================================
// Vault Password Manager - Popup UI Logic
// ============================================================

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// --- State ---
let currentVaultId = null;
let currentVaultName = null;
let currentSecretName = null;
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
  try {
    const state = await send({ action: 'getAuthState' });
    if (state.authenticated) {
      $('#logged-user').textContent = state.domain
        ? `${state.domain}\\${state.username}`
        : state.username;
      showView('vaults');
      loadVaults();
    } else {
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
  $('#btn-settings').addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
  });

  // Vault list
  $('#btn-logout').addEventListener('click', handleLogout);

  // Secret list
  $('#btn-back-vaults').addEventListener('click', () => showView('vaults'));
  $('#secret-search').addEventListener('input', handleSecretSearch);

  // Autofill
  $('#btn-back-secrets').addEventListener('click', () => showView('secrets'));
  $('#btn-autofill').addEventListener('click', handleAutofill);
  $('#btn-copy').addEventListener('click', handleCopy);
}

// --- Login ---

async function handleLogin(e) {
  e.preventDefault();
  const btn = $('#btn-login');
  const errEl = $('#login-error');
  errEl.classList.add('hidden');
  btn.disabled = true;
  btn.textContent = 'Autenticando...';

  try {
    const result = await send({
      action: 'login',
      username: $('#login-user').value.trim(),
      password: $('#login-pass').value,
    });

    $('#logged-user').textContent = result.domain
      ? `${result.domain}\\${result.username}`
      : result.username;

    showView('vaults');
    loadVaults();
  } catch (err) {
    errEl.textContent = err.message || 'Falha na autenticacao';
    errEl.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Entrar';
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

  listEl.innerHTML = '';
  emptyEl.classList.add('hidden');
  loadEl.classList.remove('hidden');

  try {
    const data = await send({ action: 'listVaults' });
    const vaults = Array.isArray(data) ? data : data?.items || data?.vaults || [];

    loadEl.classList.add('hidden');

    if (vaults.length === 0) {
      emptyEl.classList.remove('hidden');
      return;
    }

    vaults.forEach((v) => {
      const item = document.createElement('div');
      item.className = 'list-item';
      item.innerHTML = `
        <div class="list-item-icon">&#128274;</div>
        <div class="list-item-content">
          <div class="list-item-title">${esc(v.name)}</div>
          <div class="list-item-sub">${esc(v.environment || '')} ${v.status ? '&middot; ' + esc(v.status) : ''}</div>
        </div>
        <div class="list-item-arrow">&#x203A;</div>
      `;
      item.addEventListener('click', () => openVault(v.id, v.name));
      listEl.appendChild(item);
    });
  } catch (err) {
    loadEl.classList.add('hidden');
    listEl.innerHTML = `<div class="error">${esc(err.message)}</div>`;
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

  listEl.innerHTML = '';
  emptyEl.classList.add('hidden');
  loadEl.classList.remove('hidden');

  try {
    const data = await send({ action: 'listSecrets', vaultId: currentVaultId });
    allSecrets = Array.isArray(data) ? data : data?.items || data?.secrets || [];

    loadEl.classList.add('hidden');
    renderSecrets(allSecrets);
  } catch (err) {
    loadEl.classList.add('hidden');
    listEl.innerHTML = `<div class="error">${esc(err.message)}</div>`;
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

    const item = document.createElement('div');
    item.className = 'list-item';
    item.innerHTML = `
      <div class="list-item-icon">&#128273;</div>
      <div class="list-item-content">
        <div class="list-item-title">${esc(name)}</div>
        <div class="list-item-sub">v${esc(String(ver))} ${status ? '&middot; ' + esc(status) : ''}</div>
      </div>
      <div class="list-item-arrow">&#x203A;</div>
    `;
    item.addEventListener('click', () => openAutofill(name));
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

// --- Autofill ---

function openAutofill(secretName) {
  currentSecretName = secretName;
  $('#autofill-secret-name').textContent = `${currentVaultName} / ${secretName}`;
  $('#autofill-reason').value = '';
  $('#autofill-ticket').value = '';
  $('#autofill-error').classList.add('hidden');
  showView('autofill');
}

async function handleAutofill() {
  const reason = $('#autofill-reason').value.trim();
  if (!reason) {
    showAutofillError('Informe o motivo do acesso');
    return;
  }

  const btn = $('#btn-autofill');
  btn.disabled = true;
  btn.textContent = 'Preenchendo...';

  try {
    await send({
      action: 'autofillSecret',
      vaultId: currentVaultId,
      secretName: currentSecretName,
      reason,
      ticket: $('#autofill-ticket').value.trim() || '-',
    });

    btn.textContent = 'Preenchido!';
    setTimeout(() => window.close(), 800);
  } catch (err) {
    showAutofillError(err.message);
    btn.disabled = false;
    btn.textContent = 'Preencher no Site';
  }
}

async function handleCopy() {
  const reason = $('#autofill-reason').value.trim();
  if (!reason) {
    showAutofillError('Informe o motivo do acesso');
    return;
  }

  const btn = $('#btn-copy');
  btn.disabled = true;
  btn.textContent = 'Copiando...';

  try {
    const result = await send({
      action: 'requestSecret',
      vaultId: currentVaultId,
      secretName: currentSecretName,
      reason,
      ticket: $('#autofill-ticket').value.trim() || '-',
    });

    const value = result.value || result.Value || '';
    await navigator.clipboard.writeText(value);

    btn.textContent = 'Copiado!';

    // Auto-clear clipboard after 30s
    setTimeout(() => navigator.clipboard.writeText(''), 30000);
    setTimeout(() => {
      btn.textContent = 'Copiar';
      btn.disabled = false;
    }, 2000);
  } catch (err) {
    showAutofillError(err.message);
    btn.disabled = false;
    btn.textContent = 'Copiar';
  }
}

function showAutofillError(msg) {
  const el = $('#autofill-error');
  el.textContent = msg;
  el.classList.remove('hidden');
}

// --- Util ---

function esc(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}

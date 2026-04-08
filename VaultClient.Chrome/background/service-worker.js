// ============================================================
// Vault Password Manager - Background Service Worker
// Handles auth, API calls, and message routing
// ============================================================

const DEFAULT_CONFIG = {
  serverUrl: 'http://localhost:5065',
  clientId: 'local-dev-client',
  clientSecret: 'change-me-dev-shared-secret',
};

// --- Storage helpers ---

async function getConfig() {
  const { config } = await chrome.storage.local.get('config');
  return { ...DEFAULT_CONFIG, ...config };
}

async function getToken() {
  const { auth } = await chrome.storage.session.get('auth');
  return auth?.token || null;
}

async function setAuth(token, username, domain) {
  await chrome.storage.session.set({
    auth: { token, username, domain, ts: Date.now() },
  });
}

async function clearAuth() {
  await chrome.storage.session.remove('auth');
}

// --- Crypto: HMAC-SHA256 proof (mirrors ProofBuilder.cs) ---

// Normalize ISO timestamp to match C#'s DateTimeOffset.ToString("O")
// which always outputs exactly 7 fractional digits
function toRoundtripFormat(isoString) {
  // Match: date T time . fractional offset
  const m = isoString.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,7}))?([+-]\d{2}:\d{2}|Z)$/);
  if (!m) return isoString; // fallback: return as-is
  const base = m[1];
  const frac = (m[2] || '').padEnd(7, '0');
  const offset = m[3] === 'Z' ? '+00:00' : m[3];
  return `${base}.${frac}${offset}`;
}

async function buildProof(vaultId, secretName, clientId, subject, reason, ticket, nonce, issuedAt, clientSecret) {
  const normalizedTicket = (!ticket || !ticket.trim()) ? '-' : ticket.trim();
  const payload = [
    vaultId.toLowerCase(),
    secretName.trim(),
    clientId.trim(),
    subject.trim().toUpperCase(),
    reason.trim(),
    normalizedTicket,
    nonce.trim(),
    toRoundtripFormat(issuedAt),
  ].join('|');

  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(clientSecret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(payload));
  return base64url(new Uint8Array(sig));
}

function base64url(bytes) {
  const b64 = btoa(String.fromCharCode(...bytes));
  return b64.replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

// --- API client ---

async function apiFetch(path, options = {}) {
  const config = await getConfig();
  const token = await getToken();
  const url = `${config.serverUrl}${path}`;

  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...options.headers,
  };

  const res = await fetch(url, { ...options, headers });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`API ${res.status}: ${text || res.statusText}`);
  }

  const ct = res.headers.get('content-type') || '';
  if (ct.includes('application/json')) return res.json();
  return res.text();
}

// --- Auth ---

async function authenticate(username, password, domain) {
  const body = { username, password };
  if (domain) body.domain = domain;

  const result = await apiFetch('/users', {
    method: 'POST',
    body: JSON.stringify(body),
  });

  const token = typeof result === 'string' ? result : result.token || result.accessToken;
  if (!token) throw new Error('Token not returned');

  await setAuth(token, username, domain);
  return { success: true, username, domain };
}

async function challengeRespond(username, domain) {
  const config = await getConfig();
  const fullSubject = domain ? `${domain}\\${username}` : username;

  // 1. Get challenge
  const challenge = await apiFetch('/auth/challenge', {
    method: 'POST',
    body: JSON.stringify({
      clientId: config.clientId,
      subject: fullSubject,
      audience: 'vault.secret.request',
    }),
  });

  return challenge;
}

// --- Vaults ---

async function listVaults() {
  return apiFetch('/vaults');
}

// --- Secrets ---

async function listSecrets(vaultId, page = 1, pageSize = 50) {
  return apiFetch(`/vaults/${vaultId}/secrets?page=${page}&pageSize=${pageSize}`);
}

async function getSecretMetadata(vaultId, name) {
  return apiFetch(`/vaults/${vaultId}/secrets/${encodeURIComponent(name)}`);
}

async function requestSecretValue(vaultId, secretName) {
  const config = await getConfig();
  const { auth } = await chrome.storage.session.get('auth');
  if (!auth) throw new Error('Not authenticated');

  const reason = 'Autofill via Sentinel Vault Extension';

  // Build full subject matching JWT identity (DOMAIN\username)
  const fullSubject = auth.domain
    ? `${auth.domain}\\${auth.username}`
    : auth.username;

  // 1. Get nonce challenge
  const challenge = await apiFetch('/auth/challenge', {
    method: 'POST',
    body: JSON.stringify({
      clientId: config.clientId,
      subject: fullSubject,
      audience: 'vault.secret.request',
    }),
  });

  // 2. Build HMAC proof
  const proof = await buildProof(
    vaultId,
    secretName,
    config.clientId,
    challenge.subject || fullSubject,
    reason,
    '-',
    challenge.nonce,
    challenge.issuedAtUtc,
    config.clientSecret
  );

  // 3. Request secret with proof
  const result = await apiFetch(`/vaults/${vaultId}/secrets/${encodeURIComponent(secretName)}/request`, {
    method: 'POST',
    body: JSON.stringify({
      contractVersion: 'v1',
      reason,
      ticket: '-',
      clientId: config.clientId,
      nonce: challenge.nonce,
      issuedAtUtc: challenge.issuedAtUtc,
      proof,
    }),
  });

  return result;
}

// --- Message handler (popup & content script communication) ---

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  handleMessage(msg)
    .then(sendResponse)
    .catch((err) => sendResponse({ error: err.message }));
  return true; // async response
});

async function handleMessage(msg) {
  switch (msg.action) {
    case 'login':
      return authenticate(msg.username, msg.password, msg.domain);

    case 'logout':
      await clearAuth();
      return { success: true };

    case 'getAuthState': {
      const { auth } = await chrome.storage.session.get('auth');
      return { authenticated: !!auth, username: auth?.username, domain: auth?.domain };
    }

    case 'listVaults':
      return listVaults();

    case 'listSecrets':
      return listSecrets(msg.vaultId, msg.page, msg.pageSize);

    case 'requestSecret':
      return requestSecretValue(msg.vaultId, msg.secretName);

    case 'getConfig':
      return getConfig();

    case 'saveConfig':
      await chrome.storage.local.set({ config: msg.config });
      return { success: true };

    case 'autofillSecret': {
      // Get secret value and send to content script
      const secret = await requestSecretValue(msg.vaultId, msg.secretName);
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.id) {
        await chrome.tabs.sendMessage(tab.id, {
          action: 'fillPassword',
          value: secret.value,
          username: msg.username,
        });
      }
      return { success: true };
    }

    case 'createAutofillRule':
      return apiFetch(`/vaults/${msg.vaultId}/autofill-rules`, {
        method: 'POST',
        body: JSON.stringify({
          urlPattern: msg.urlPattern,
          login: msg.login,
          secretName: msg.secretName,
          isActive: true,
        }),
      });

    case 'matchAutofillRules':
      return apiFetch(`/autofill-rules/match?url=${encodeURIComponent(msg.url)}`);

    default:
      throw new Error(`Unknown action: ${msg.action}`);
  }
}

// --- Keyboard shortcut ---

chrome.commands.onCommand.addListener(async (command) => {
  if (command === 'autofill') {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id) {
      chrome.tabs.sendMessage(tab.id, { action: 'showAutofillMenu' });
    }
  }
});

// ============================================================
// Vault Password Manager - Background Service Worker
// Handles auth, API calls, and message routing
// ============================================================

const DEFAULT_CONFIG = {
  serverUrl: '',
  jwtAudience: 'WebApplication1',
  defaultDomain: '',
  clientId: '',
  clientSecret: '',
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

// --- JWT helpers (no crypto — decode only, server already validated) ---

/**
 * Decodes the payload of a JWT without verifying the signature.
 * Verification is performed by the server on every API call.
 */
function decodeJwtPayload(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    // Base64url → Base64 → JSON
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const json = atob(base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '='));
    return JSON.parse(json);
  } catch {
    return null;
  }
}

/**
 * Validates the 'aud' claim of a JWT against the expected audience.
 * Returns true if the claim matches (or if no expected audience is configured).
 */
function validateJwtAudience(token, expectedAudience) {
  if (!expectedAudience) return true; // not configured — skip check
  const payload = decodeJwtPayload(token);
  if (!payload) return false;
  const aud = payload.aud;
  if (Array.isArray(aud)) return aud.includes(expectedAudience);
  return aud === expectedAudience;
}

// --- Crypto: HMAC-SHA256 proof (mirrors ProofBuilder.cs) ---

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
    issuedAt,
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
  const config = await getConfig();
  const effectiveDomain = domain || config.defaultDomain || undefined;

  const body = { username, password };
  if (effectiveDomain) body.domain = effectiveDomain;

  const result = await apiFetch('/users', {
    method: 'POST',
    body: JSON.stringify(body),
  });

  const token = typeof result === 'string' ? result : result.token || result.accessToken;
  if (!token) throw new Error('Token nao retornado pelo servidor.');

  // Validate the 'aud' claim of the received JWT against the configured audience.
  // This ensures the extension is talking to the correct server / tenant.
  const expectedAudience = config.jwtAudience || DEFAULT_CONFIG.jwtAudience;
  if (!validateJwtAudience(token, expectedAudience)) {
    const payload = decodeJwtPayload(token);
    const received = payload?.aud ?? '(nao presente)';
    throw new Error(
      `Token invalido: audience incorreta. Esperado: "${expectedAudience}", recebido: "${received}". ` +
      `Verifica o campo "JWT Audience" nas Configuracoes.`
    );
  }

  await setAuth(token, username, effectiveDomain);
  return { success: true, username, domain: effectiveDomain };
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

async function requestSecretValue(vaultId, secretName, reason, ticket) {
  const config = await getConfig();
  const { auth } = await chrome.storage.session.get('auth');
  if (!auth) throw new Error('Nao autenticado');

  // 1. Get nonce challenge
  const challenge = await apiFetch('/auth/challenge', {
    method: 'POST',
    body: JSON.stringify({
      clientId: config.clientId,
      subject: auth.username,
      audience: config.jwtAudience || 'vault.secret.request',
    }),
  });

  // 2. Build HMAC proof
  const proof = await buildProof(
    vaultId,
    secretName,
    config.clientId,
    challenge.subject || auth.username,
    reason,
    ticket,
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
      ticket: ticket || '-',
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
      return requestSecretValue(msg.vaultId, msg.secretName, msg.reason, msg.ticket);

    case 'getConfig':
      return getConfig();

    case 'saveConfig':
      await chrome.storage.local.set({ config: msg.config });
      return { success: true };

    case 'autofillSecret': {
      const secret = await requestSecretValue(msg.vaultId, msg.secretName, 'Autofill via Chrome Extension', msg.ticket || '-');
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

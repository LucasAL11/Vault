// ============================================================
// Vault Password Manager — Background Service Worker v2.1
//
// Toda a configuracao vem de chrome.storage.local['config'].
// Sem defaults. O utilizador configura tudo na tela de settings.
// ============================================================

// --- Storage ---

async function getConfig() {
  const { config } = await chrome.storage.local.get('config');
  return config || {};
}

async function getAuth() {
  const { auth } = await chrome.storage.session.get('auth');
  return auth || null;
}

/** Returns true if the stored JWT is still within its lifetime (client-side fast check). */
function isTokenFresh(auth) {
  if (!auth?.token) return false;
  try {
    // JWT payload is the middle base64url segment
    const payload = JSON.parse(atob(auth.token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    if (!payload.exp) return true; // no expiry claim — assume fresh
    return Date.now() / 1000 < payload.exp;
  } catch {
    return true; // can't decode — optimistically assume valid
  }
}

async function setAuth(token, username, domain) {
  await chrome.storage.session.set({
    auth: { token, username, domain, ts: Date.now() },
  });
}

async function clearAuth() {
  await chrome.storage.session.remove('auth');
}

// ============================================================
// DateTimeOffset :O format
//
// C# DateTimeOffset.ToString("O") SEMPRE produz:
//   yyyy-MM-ddTHH:mm:ss.fffffff+HH:mm
//
// System.Text.Json serializa DateTime(Kind=Utc) como:
//   2026-04-01T15:30:45.123Z       (decimais truncados, "Z")
//
// Esta funcao converte para o formato :O exacto:
//   2026-04-01T15:30:45.1230000+00:00
// ============================================================

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

  // BuildProofPayload — campos separados por "|"
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

  // HMACSHA256(payload, clientSecret) → base64url (sem padding)
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

// Encode a secret name for use in a URL path segment.
function encodeName(name) {
  return encodeURIComponent(name);
}

// Build a secret name from hostname + login.
// Uses '--' as separator to avoid '/' which causes %2F encoding issues in route params.
function buildSecretName(hostname, login) {
  return `${hostname}--${login}`.replace(/[^\w.\-@]/g, '_').slice(0, 120);
}

function base64url(bytes) {
  const b64 = btoa(String.fromCharCode(...bytes));
  return b64.replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

// ============================================================
// API Client
// ============================================================

async function apiFetch(path, options = {}) {
  const config = await getConfig();

  if (!config.serverUrl) {
    throw new Error('Servidor nao configurado. Abra as Configuracoes da extensao e insira a URL do servidor.');
  }

  const auth = await getAuth();
  const url = `${config.serverUrl}${path}`;

  const headers = {
    'Content-Type': 'application/json',
    ...(auth?.token ? { Authorization: `Bearer ${auth.token}` } : {}),
    ...options.headers,
  };

  let res;
  try {
    res = await fetch(url, { ...options, headers });
  } catch (netErr) {
    // Network-level failure (DNS, refused, timeout, CORS preflight blocked)
    throw new Error(`Nao foi possivel conectar ao servidor (${config.serverUrl}). Verifique se o servidor esta a correr e se a URL esta correta.`);
  }

  if (res.status === 401) {
    // /secrets/{name}/request returns 401 for proof failures (not session expiry).
    // Only clear auth for endpoints that truly signal an invalid/expired token.
    const isProofEndpoint = path.includes('/request');
    if (!isProofEndpoint) {
      await clearAuth();
      throw new Error('SESSION_EXPIRED');
    }
    const body = await res.text().catch(() => '');
    throw new Error(`API 401: ${body || 'Unauthorized'}`);
  }

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`API ${res.status}: ${text || res.statusText}`);
  }

  const ct = res.headers.get('content-type') || '';
  if (ct.includes('application/json')) return res.json();
  return res.text();
}

// ============================================================
// Auth — POST /users
//
// C# Authenticate.Request:
//   record Request(string Username, string? Domain, string? Password)
// ============================================================

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

  await setAuth(token, username, effectiveDomain);
  return { success: true, username, domain: effectiveDomain };
}

// ============================================================
// Vaults & Secrets
// ============================================================

async function listVaults() {
  return apiFetch('/vaults');
}

async function listSecrets(vaultId, page = 1, pageSize = 50) {
  return apiFetch(`/vaults/${vaultId}/secrets?page=${page}&pageSize=${pageSize}`);
}

async function getSecretMetadata(vaultId, name) {
  return apiFetch(`/vaults/${vaultId}/secrets/${encodeName(name)}`);
}

async function requestSecretValue(vaultId, secretName) {
  const config = await getConfig();
  const { auth } = await chrome.storage.session.get('auth');
  if (!auth?.token) throw new Error('SESSION_EXPIRED');
  if (!isTokenFresh(auth)) {
    await clearAuth();
    throw new Error('SESSION_EXPIRED');
  }

  const reason = 'Autofill via Sentinel Vault Extension';

  // 1. Get nonce challenge — do NOT pass subject manually.
  //    The server resolves it from the JWT claims and returns the canonical form.
  //    This guarantees both sides build the HMAC proof with the exact same subject.
  const challenge = await apiFetch('/auth/challenge', {
    method: 'POST',
    body: JSON.stringify({
      clientId: config.clientId,
      audience: 'vault.secret.request',
    }),
  });

  // challenge.subject is the server-canonical subject derived from the JWT.
  const canonicalSubject = challenge.subject || challenge.Subject;
  if (!canonicalSubject) throw new Error('Challenge nao retornou subject.');

  // 2. Build HMAC proof
  const proof = await buildProof(
    vaultId,
    secretName,
    config.clientId,
    canonicalSubject,
    reason,
    '-',
    challenge.nonce || challenge.Nonce,
    challenge.issuedAtUtc || challenge.IssuedAtUtc,
    config.clientSecret
  );

  const nonce = challenge.nonce || challenge.Nonce;
  const issuedAtUtc = challenge.issuedAtUtc || challenge.IssuedAtUtc;

  // 3. Request secret with proof — name passed in body (supports slashes)
  const result = await apiFetch(`/vaults/${vaultId}/secrets/request`, {
    method: 'POST',
    body: JSON.stringify({
      secretName,
      contractVersion: 'v1',
      reason,
      ticket: '-',
      clientId: config.clientId,
      nonce,
      issuedAtUtc,
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
  return true;
});

async function handleMessage(msg) {
  switch (msg.action) {
    case 'login':
      return authenticate(msg.username, msg.password, msg.domain);

    case 'logout':
      await clearAuth();
      return { success: true };

    case 'getAuthState': {
      const auth = await getAuth();
      const fresh = isTokenFresh(auth);
      if (auth && !fresh) await clearAuth();
      return {
        authenticated: !!auth && fresh,
        username: auth?.username,
        domain: auth?.domain,
      };
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

    case 'saveCredentials': {
      // msg: { url, login, password, vaultId }
      const auth = await getAuth();
      if (!auth?.token || !isTokenFresh(auth)) {
        await clearAuth();
        throw new Error('SESSION_EXPIRED');
      }

      const parsedUrl = new URL(msg.url);
      const hostname = parsedUrl.hostname;
      const hostWithPort = parsedUrl.port ? `${parsedUrl.hostname}:${parsedUrl.port}` : parsedUrl.hostname;

      // ── Step 1: check for an existing rule for this host + login ─────
      let existingRule = null;
      try {
        const matchResp = await apiFetch(`/autofill-rules/match?url=${encodeURIComponent(msg.url)}`);
        const matches = Array.isArray(matchResp)
          ? matchResp
          : matchResp?.items ?? matchResp?.Items ?? [];
        // Find a rule whose login matches exactly
        existingRule = matches.find(
          (r) => (r.login ?? r.Login) === msg.login
        ) ?? null;
      } catch (_) {
        // match endpoint failure is non-fatal — treat as no existing rule
      }

      if (existingRule) {
        // ── UPDATE path ───────────────────────────────────────────────
        // Rule already exists for this login — just update the secret value.
        // The rule itself (urlPattern, login, secretName) stays unchanged.
        const vaultId    = existingRule.vaultId    ?? existingRule.VaultId;
        const secretName = existingRule.secretName ?? existingRule.SecretName;

        await apiFetch(`/vaults/${vaultId}/secrets/${encodeName(secretName)}`, {
          method: 'PUT',
          body: JSON.stringify({ value: msg.password, contentType: 'password' }),
        });

        return { success: true, updated: true, secretName };
      }

      // ── CREATE path ───────────────────────────────────────────────────
      // No rule found for this login — create secret + rule from scratch.
      const secretName = buildSecretName(hostname, msg.login);
      const urlPattern = `${parsedUrl.protocol}//${hostWithPort}/*`;

      // Step 2: upsert secret (PUT = create or overwrite)
      await apiFetch(`/vaults/${msg.vaultId}/secrets/${encodeName(secretName)}`, {
        method: 'PUT',
        body: JSON.stringify({ value: msg.password, contentType: 'password' }),
      });

      // Step 3: create autofill rule (ignore 409 = rule already exists)
      try {
        await apiFetch(`/vaults/${msg.vaultId}/autofill-rules`, {
          method: 'POST',
          body: JSON.stringify({ urlPattern, login: msg.login, secretName, isActive: true }),
        });
      } catch (err) {
        if (!err.message?.includes('409')) {
          console.error('[Vault] autofill rule creation failed:', err.message);
          throw err;
        }
      }

      return { success: true, updated: false, secretName };
    }

    case 'storePendingSave':
      // Content script delegates storage to the service worker because the
      // content script can be killed by navigation before the write completes.
      await chrome.storage.session.set({ vault_pending_save: msg.pending });
      return { success: true };

    case 'getPendingSave': {
      const data = await chrome.storage.session.get('vault_pending_save');
      return data.vault_pending_save || null;
    }

    case 'clearPendingSave':
      await chrome.storage.session.remove('vault_pending_save');
      return { success: true };

    case 'openPopup':
      // chrome.action.openPopup() requires user gesture; best-effort only
      try { await chrome.action.openPopup(); } catch { /* ignore if not supported */ }
      return { success: true };

    default:
      throw new Error(`Accao desconhecida: ${msg.action}`);
  }
}

// ============================================================
// Keyboard shortcut
// ============================================================

chrome.commands.onCommand.addListener(async (command) => {
  if (command === 'autofill') {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id) {
      chrome.tabs.sendMessage(tab.id, { action: 'showAutofillMenu' });
    }
  }
});

// ============================================================
// Vault Password Manager — Background Service Worker
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

function base64url(bytes) {
  const b64 = btoa(String.fromCharCode(...bytes));
  return b64.replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

// ============================================================
// API Client
// ============================================================

async function apiFetch(path, options = {}) {
  const config = await getConfig();
  const auth = await getAuth();
  const url = `${config.serverUrl}${path}`;

  const headers = {
    'Content-Type': 'application/json',
    ...(auth?.token ? { Authorization: `Bearer ${auth.token}` } : {}),
    ...options.headers,
  };

  const res = await fetch(url, { ...options, headers });

  if (res.status === 401) {
    // Clear stale session so getAuthState reflects the truth
    await clearAuth();
    throw new Error('SESSION_EXPIRED');
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
  return apiFetch(`/vaults/${vaultId}/secrets/${encodeURIComponent(name)}`);
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

      const hostname = new URL(msg.url).hostname;
      // Secret name: "hostname/login" — sanitized for API
      const secretName = `${hostname}/${msg.login}`
        .replace(/[^\w.\-/:@]/g, '_')
        .slice(0, 120);

      // URL pattern: wildcard for the whole host
      const urlPattern = `https://${hostname}/*`;

      // 1. Upsert secret (create or update if name already exists)
      await apiFetch(`/vaults/${msg.vaultId}/secrets`, {
        method: 'POST',
        body: JSON.stringify({
          name: secretName,
          value: msg.password,
          contentType: 'password',
        }),
      });

      // 2. Create autofill rule (ignore conflict — rule may already exist)
      try {
        await apiFetch(`/vaults/${msg.vaultId}/autofill-rules`, {
          method: 'POST',
          body: JSON.stringify({
            urlPattern,
            login: msg.login,
            secretName,
            isActive: true,
          }),
        });
      } catch (err) {
        // Conflict (rule already exists) is acceptable — secret was updated above
        if (!err.message?.includes('409')) throw err;
      }

      return { success: true, secretName };
    }

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

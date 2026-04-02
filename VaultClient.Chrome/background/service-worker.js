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

function formatDateTimeOffsetO(isoString) {
  const m = isoString.match(
    /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,7}))?(Z|[+-]\d{2}:\d{2})$/
  );
  if (!m) return isoString;
  const datetime = m[1];
  const frac = (m[2] || '').padEnd(7, '0');
  const offset = m[3] === 'Z' ? '+00:00' : m[3];
  return `${datetime}.${frac}${offset}`;
}

// ============================================================
// HMAC-SHA256 Proof
//
// Espelho exacto de SecretProofHelpers.BuildProofPayload (C#):
//
//   $"{vaultId:D}|{secretName.Trim()}|{clientId.Trim()}|
//     {subject.Trim().ToUpperInvariant()}|{reason.Trim()}|
//     {NormalizeTicketId(ticket)}|{nonce.Trim()}|{issuedAtUtc:O}"
//
// E de ProofBuilder.Build (Desktop):
//   HMACSHA256(payload, clientSecret) → base64url
// ============================================================

async function buildProof(vaultId, secretName, clientId, subject, reason, ticket, nonce, issuedAtUtc, clientSecret) {
  // NormalizeTicketId: string.IsNullOrWhiteSpace(ticket) ? "-" : ticket.Trim()
  const normalizedTicket = (!ticket || !ticket.trim()) ? '-' : ticket.trim();

  // BuildProofPayload — campos separados por "|"
  const payload = [
    vaultId.toLowerCase(),            // {vaultId:D}   → guid lowercase com hifens
    secretName.trim(),                // .Trim()
    clientId.trim(),                  // .Trim()
    subject.trim().toUpperCase(),     // .Trim().ToUpperInvariant()
    reason.trim(),                    // .Trim()
    normalizedTicket,                 // NormalizeTicketId()
    nonce.trim(),                     // .Trim()
    formatDateTimeOffsetO(issuedAtUtc), // {issuedAtUtc:O}
  ].join('|');

  // DEBUG: comparar com o log do servidor
  console.log('[PROOF DEBUG] payload:', payload);
  console.log('[PROOF DEBUG] fields:', {
    vaultId: vaultId.toLowerCase(),
    secretName: secretName.trim(),
    clientId: clientId.trim(),
    subject: subject.trim().toUpperCase(),
    reason: reason.trim(),
    ticket: normalizedTicket,
    nonce: nonce.trim(),
    issuedAtUtc: formatDateTimeOffsetO(issuedAtUtc),
    issuedAtUtcRaw: issuedAtUtc,
  });

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
// Request Secret Value
//
// Fluxo:
//   1. POST /auth/challenge  → { nonce, subject, issuedAtUtc }
//   2. buildProof(...)        → HMAC-SHA256 base64url
//   3. POST /vaults/{id}/secrets/{name}/request  → { value }
//
// C# NonceChallenge.Request:
//   record Request(string? ClientId, string? Subject, string? Audience)
//
// C# SecretRequestPayload:
//   ContractVersion, Reason, Ticket, TicketId, ClientId,
//   Nonce, IssuedAt, IssuedAtUtc, Proof
// ============================================================

async function requestSecretValue(vaultId, secretName, reason, ticket) {
  const config = await getConfig();
  const auth = await getAuth();
  if (!auth) throw new Error('Nao autenticado.');

  // 1. Nonce challenge
  //    - NÃO enviar subject (servidor resolve do JWT)
  //    - Audience DEVE ser "vault.secret.request" porque o endpoint
  //      /request hardcodeia NonceChallengeAudiences.VaultSecretRequest
  //      para consumir o nonce. Se o challenge usar outro audience,
  //      os scopes nao coincidem e nonceConsumed=false.
  const challenge = await apiFetch('/auth/challenge', {
    method: 'POST',
    body: JSON.stringify({
      clientId: config.clientId,
      audience: 'vault.secret.request',
    }),
  });

  // 2. HMAC proof — campos exactos do BuildProofPayload
  const proof = await buildProof(
    vaultId,                              // Guid do vault
    secretName,                           // nome do segredo
    config.clientId,                      // AuthChallenge:ClientSecrets key
    challenge.subject,                    // subject resolvido pelo servidor (do JWT)
    reason,                               // motivo do acesso
    ticket,                               // ticket/incidente
    challenge.nonce,                      // nonce base64url do challenge
    challenge.issuedAtUtc,                // timestamp do challenge
    config.clientSecret                   // AuthChallenge:ClientSecrets value
  );

  // 3. Request body — espelho de SecretRequestPayload
  const result = await apiFetch(
    `/vaults/${vaultId}/secrets/${encodeURIComponent(secretName)}/request`,
    {
      method: 'POST',
      body: JSON.stringify({
        contractVersion: 'v1',
        reason: reason,
        ticket: ticket || '-',
        clientId: config.clientId,
        nonce: challenge.nonce,
        issuedAtUtc: challenge.issuedAtUtc,
        proof: proof,
      }),
    }
  );

  return result;
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

// ============================================================
// Message Router (popup / content script → service worker)
// ============================================================

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
      return {
        authenticated: !!auth,
        username: auth?.username,
        domain: auth?.domain,
      };
    }

    case 'listVaults':
      return listVaults();

    case 'listSecrets':
      return listSecrets(msg.vaultId, msg.page, msg.pageSize);

    case 'requestSecret':
      return requestSecretValue(
        msg.vaultId, msg.secretName, msg.reason, msg.ticket
      );

    case 'getConfig':
      return getConfig();

    case 'saveConfig':
      await chrome.storage.local.set({ config: msg.config });
      return { success: true };

    case 'autofillSecret': {
      const secret = await requestSecretValue(
        msg.vaultId, msg.secretName,
        'Autofill via Chrome Extension',
        msg.ticket || '-'
      );
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

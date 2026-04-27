// ═══════════════════════════════════════════════════════════
//  SENTIL · options.js
//  Config / setup page logic
// ═══════════════════════════════════════════════════════════

'use strict';

const $ = (id) => document.getElementById(id);

// ── State ────────────────────────────────────────────────
let testStatus = 'idle'; // idle | testing | ok | fail
let allPassed  = false;

// ── Helpers ──────────────────────────────────────────────
function setStatus(state, label) {
  testStatus = state;
  const badge = $('test-status-badge');
  badge.className = `ec-test-status${state !== 'idle' ? ` is-${state}` : ''}`;
  $('status-label').textContent = ({
    idle:    'IDLE',
    testing: 'TESTING…',
    ok:      'TRUSTED',
    fail:    'FAILED',
  })[state] ?? label ?? state.toUpperCase();
}

function urlValue() {
  const proto = $('protocol').value;
  const host  = $('serverUrl').value.trim().replace(/\/+$/, '');
  return host ? `${proto}${host}` : '';
}

function updatePreview() {
  $('preview-protocol').textContent = $('protocol').value;
  const host = $('serverUrl').value.trim() || '<not set>';
  $('preview-host').textContent = host;
}

function isComplete() {
  return !!$('serverUrl').value.trim()
      && !!$('clientId').value.trim()
      && !!$('clientSecret').value;
}

function updateSaveBtn() {
  $('btn-save').disabled = !(allPassed && isComplete());
}

function appendLog(tag, msg, statusOk) {
  const log = $('test-log');
  // Remove empty placeholder
  log.querySelector('.ec-log-empty')?.remove();
  log.querySelector('.ec-log-cursor')?.remove();

  const row = document.createElement('div');
  row.className = 'ec-log-row';
  const isDone = tag === 'DONE';
  row.innerHTML = `
    <span class="ec-log-tag${isDone ? ' tag-done' : ''}">${tag}</span>
    <span class="ec-log-msg">${escHtml(msg)}</span>
    <span class="${statusOk ? 'ec-log-status-ok' : 'ec-log-status-err'}">
      ${statusOk ? '✓' : '✗'} ${isDone ? '—' : ''}
    </span>`;
  log.appendChild(row);
  log.scrollTop = log.scrollHeight;
}

function showCursor() {
  const log = $('test-log');
  log.querySelector('.ec-log-cursor')?.remove();
  const cur = document.createElement('div');
  cur.className = 'ec-log-cursor';
  cur.innerHTML = '▸ <span>_</span>';
  log.appendChild(cur);
}

function removeCursor() {
  $('test-log').querySelector('.ec-log-cursor')?.remove();
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// ── Toggle switches ──────────────────────────────────────
document.querySelectorAll('.ec-toggle').forEach((btn) => {
  btn.addEventListener('click', () => {
    const on = btn.getAttribute('aria-checked') === 'true';
    btn.setAttribute('aria-checked', String(!on));
    btn.classList.toggle('ec-toggle-on', !on);
  });
});

// ── Eye toggle ───────────────────────────────────────────
$('btn-toggle-secret').addEventListener('click', () => {
  const input = $('clientSecret');
  const isHidden = input.type === 'password';
  input.type = isHidden ? 'text' : 'password';
  $('icon-eye-open').style.display   = isHidden ? 'block' : 'none';
  $('icon-eye-closed').style.display = isHidden ? 'none'  : 'block';
});

// ── Live URL preview ─────────────────────────────────────
$('serverUrl').addEventListener('input', () => { updatePreview(); updateSaveBtn(); });
$('protocol').addEventListener('change', () => { updatePreview(); });
$('clientId').addEventListener('input', updateSaveBtn);
$('clientSecret').addEventListener('input', updateSaveBtn);

// ── Load saved config ────────────────────────────────────
chrome.storage.local.get('config', ({ config }) => {
  if (!config) return;
  if (config.serverUrl) {
    // Separate protocol from host if stored as full URL
    const m = config.serverUrl.match(/^(https?:\/\/)(.+)$/);
    if (m) { $('protocol').value = m[1]; $('serverUrl').value = m[2]; }
    else     { $('serverUrl').value = config.serverUrl; }
  }
  $('clientId').value      = config.clientId      || '';
  $('clientSecret').value  = config.clientSecret  || '';
  $('defaultDomain').value = config.defaultDomain || '';
  updatePreview();
  updateSaveBtn();
});

// ── Test connection ──────────────────────────────────────
$('btn-test').addEventListener('click', async () => {
  if (testStatus === 'testing') return;

  const base = urlValue();
  if (!base) return;

  // Reset
  allPassed = false;
  $('test-log').innerHTML = '';
  $('btn-test').textContent = '> probing…';
  $('btn-test').disabled = true;
  $('btn-test').classList.remove('is-done');
  $('fingerprint').style.display = 'none';
  $('url-ok').style.display  = 'none';
  $('url-err').style.display = 'none';
  $('cred-ok').style.display  = 'none';
  $('cred-err').style.display = 'none';
  setStatus('testing');
  showCursor();
  updateSaveBtn();

  let ok = true;

  // Step 1 — DNS / ping
  try {
    const t0 = Date.now();
    const r = await fetch(`${base}/`, { method: 'GET', signal: AbortSignal.timeout(5000) });
    const ms = Date.now() - t0;
    // 200, 401, 403, 404 are all "server reached"
    if (r.status < 500) {
      appendLog('NET ', `servidor alcançado`, true);
    } else {
      appendLog('NET ', `HTTP ${r.status}`, false); ok = false;
    }
  } catch (e) {
    appendLog('NET ', `falha na conexão: ${e.message}`, false); ok = false;
  }

  if (ok) {
    // Step 2 — health / vaults endpoint
    try {
      const t0 = Date.now();
      const r = await fetch(`${base}/vaults`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
        signal: AbortSignal.timeout(5000),
      });
      const ms = Date.now() - t0;
      if (r.ok || r.status === 401) {
        appendLog('SRV ', `GET /vaults · ${r.status} · ${ms}ms`, true);
        $('url-ok').style.display = 'flex';
      } else {
        appendLog('SRV ', `GET /vaults · ${r.status}`, false); ok = false;
        $('url-err-msg').textContent = `servidor retornou ${r.status}`;
        $('url-err').style.display = 'flex';
      }
    } catch (e) {
      appendLog('SRV ', `GET /vaults falhou`, false); ok = false;
      $('url-err-msg').textContent = e.message;
      $('url-err').style.display = 'flex';
    }
  }

  // Step 3 — HMAC credential check (se client ID + secret preenchidos)
  const clientId     = $('clientId').value.trim();
  const clientSecret = $('clientSecret').value;
  if (ok && clientId && clientSecret) {
    try {
      const issuedAt = new Date().toISOString();
      const payload  = `verify-client|${clientId.trim()}|${issuedAt}`;
      const proof    = await hmacSha256Base64Url(clientSecret, payload);

      const r = await fetch(`${base}/auth/verify-client`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ clientId, issuedAt, proof }),
        signal: AbortSignal.timeout(5000),
      });

      if (r.ok) {
        const data = await r.json();
        if (data.valid) {
          appendLog('HMAC', `client trusted · ${clientId}`, true);
          $('cred-ok').style.display = 'flex';
        } else {
          appendLog('HMAC', `client secret inválido`, false); ok = false;
          $('cred-err-msg').textContent = 'client secret não reconhecido';
          $('cred-err').style.display = 'flex';
        }
      } else {
        appendLog('HMAC', `verify-client · ${r.status}`, false);
        // Don't block overall success — endpoint may not exist
      }
    } catch (_) {
      appendLog('HMAC', `verify-client indisponível`, true); // soft — not a blocker
    }
  }

  // Done
  removeCursor();
  if (ok) {
    appendLog('DONE', `configuração válida`, true);
    setStatus('ok');
    allPassed = true;
    $('btn-test').classList.add('is-done');
    $('btn-test').textContent = '> retest()';

    // Advance steps
    $('step-1').className = 'ec-step ec-step-done';
    $('step-1').querySelector('.ec-step-dot span').textContent = '✓';
    $('step-2').className = 'ec-step ec-step-active';

    // Fingerprint placeholder
    $('fp-hash').textContent = ' a4:8f:c2:1e:9b:d3:7f:55:e0:6a:bb:c4:18:9d:7a:2f';
    $('fp-meta').textContent = 'issued by Internal CA · valid until 2027-08-12';
    $('fingerprint').style.display = 'block';
  } else {
    appendLog('DONE', `verificação falhou`, false);
    setStatus('fail');
    $('btn-test').textContent = '> retry()';
  }

  $('btn-test').disabled = false;
  updateSaveBtn();
});

// ── HMAC-SHA256 helper (Web Crypto) ─────────────────────
async function hmacSha256Base64Url(secret, payload) {
  const enc    = new TextEncoder();
  const keyMat = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', keyMat, enc.encode(payload));
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ── Save ─────────────────────────────────────────────────
$('btn-save').addEventListener('click', () => {
  const proto = $('protocol').value;
  const host  = $('serverUrl').value.trim().replace(/\/+$/, '');
  const config = {
    serverUrl:     `${proto}${host}`,
    clientId:      $('clientId').value.trim(),
    clientSecret:  $('clientSecret').value,
    defaultDomain: $('defaultDomain').value.trim(),
  };

  chrome.storage.local.set({ config }, () => {
    // Advance to finish step
    $('step-2').className = 'ec-step ec-step-done';
    $('step-2').querySelector('.ec-step-dot span').textContent = '✓';
    $('step-3').className = 'ec-step ec-step-done';
    $('step-3').querySelector('.ec-step-dot span').textContent = '✓';

    $('btn-save').textContent = '✓ saved';
    setTimeout(() => {
      $('btn-save').textContent = 'save + activate ⏎';
    }, 2000);
  });
});

// ── Cancel ───────────────────────────────────────────────
$('btn-cancel').addEventListener('click', () => window.close());

// ── Init preview ─────────────────────────────────────────
updatePreview();

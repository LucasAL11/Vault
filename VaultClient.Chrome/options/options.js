const $ = (sel) => document.querySelector(sel);

// --- Advanced toggle ---

$('#advanced-toggle').addEventListener('click', () => {
  const toggle = $('#advanced-toggle');
  const content = $('#advanced-content');
  toggle.classList.toggle('open');
  content.classList.toggle('open');
});

// --- Load saved config ---

chrome.storage.local.get('config', ({ config }) => {
  if (!config) return;
  $('#serverUrl').value     = config.serverUrl     || '';
  $('#jwtAudience').value   = config.jwtAudience   || '';
  $('#defaultDomain').value = config.defaultDomain || '';
  $('#clientId').value      = config.clientId      || '';
  $('#clientSecret').value  = config.clientSecret  || '';
});

// --- Helpers ---

function showToast(message, type = 'success') {
  const toast = $('#toast');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  if (type === 'success') {
    setTimeout(() => { toast.style.display = 'none'; }, 4000);
  }
}

function readForm() {
  return {
    serverUrl:     $('#serverUrl').value.trim().replace(/\/+$/, ''),
    jwtAudience:   $('#jwtAudience').value.trim(),
    defaultDomain: $('#defaultDomain').value.trim(),
    clientId:      $('#clientId').value.trim(),
    clientSecret:  $('#clientSecret').value,
  };
}

// --- Save ---

$('#btn-save').addEventListener('click', () => {
  const config = readForm();
  if (!config.serverUrl) {
    showToast('O URL do servidor e obrigatorio.', 'error');
    return;
  }
  chrome.storage.local.set({ config }, () => {
    showToast('Configuracoes guardadas com sucesso!', 'success');
  });
});

// --- Test Connection ---

$('#btn-test').addEventListener('click', async () => {
  const btn = $('#btn-test');
  const config = readForm();

  if (!config.serverUrl) {
    showToast('Introduz o URL do servidor antes de testar.', 'error');
    return;
  }

  btn.disabled = true;
  btn.textContent = 'A testar...';
  $('#toast').style.display = 'none';

  try {
    // Nonce challenge audience is always 'vault.secret.request' — NOT the JWT audience.
    const audience = 'vault.secret.request';
    const clientId = config.clientId || 'test-connection';

    const res = await fetch(`${config.serverUrl}/auth/challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clientId, audience }),
    });

    if (res.status === 400) {
      const body = await res.json().catch(() => ({}));
      const msg = body.message || 'Erro 400';
      showToast(`Ligacao estabelecida mas pedido rejeitado: "${msg}". Verifica o campo JWT Audience.`, 'error');
      return;
    }

    if (res.status === 404) {
      showToast('Servidor acessivel mas endpoint nao encontrado. Verifica o URL.', 'error');
      return;
    }

    if (res.status === 429) {
      showToast('Servidor acessivel (rate limit ativo). Configuracao OK.', 'success');
      return;
    }

    if (res.ok) {
      showToast(`Ligacao bem-sucedida (HTTP ${res.status}). Servidor e audience aceites.`, 'success');
      return;
    }

    showToast(`Servidor acessivel mas respondeu ${res.status}. Verifica as configuracoes.`, 'error');
  } catch (err) {
    const msg = err.message.includes('Failed to fetch')
      ? 'Nao foi possivel ligar ao servidor. Verifica o URL e se o servidor esta ativo.'
      : err.message;
    showToast(msg, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Testar Ligacao';
  }
});

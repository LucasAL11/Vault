const $ = (sel) => document.querySelector(sel);

// Toggle secret visibility
$('#btn-toggle-secret').addEventListener('click', () => {
  const input = $('#clientSecret');
  const icon = $('#btn-toggle-secret .material-symbols-outlined');
  if (input.type === 'password') {
    input.type = 'text';
    icon.textContent = 'visibility';
  } else {
    input.type = 'password';
    icon.textContent = 'visibility_off';
  }
});

// Load config
chrome.storage.local.get('config', ({ config }) => {
  if (!config) return;
  $('#serverUrl').value = config.serverUrl || '';
  $('#clientId').value = config.clientId || '';
  $('#clientSecret').value = config.clientSecret || '';
  $('#defaultDomain').value = config.defaultDomain || '';
});

// Save
$('#btn-save').addEventListener('click', () => {
  const config = {
    serverUrl: $('#serverUrl').value.trim().replace(/\/+$/, ''),
    clientId: $('#clientId').value.trim(),
    clientSecret: $('#clientSecret').value,
    defaultDomain: $('#defaultDomain').value.trim(),
  };

  chrome.storage.local.set({ config }, () => {
    showToast('Configuracoes salvas com sucesso!', 'success');
  });
});

// Test connection
$('#btn-test').addEventListener('click', async () => {
  const serverUrl = $('#serverUrl').value.trim().replace(/\/+$/, '');
  if (!serverUrl) {
    showToast('Insira a URL do servidor', 'error');
    return;
  }

  const btn = $('#btn-test');
  btn.textContent = 'Testando...';
  btn.disabled = true;

  try {
    const res = await fetch(`${serverUrl}/vaults`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    if (res.ok || res.status === 401) {
      showToast('Conexao estabelecida com sucesso!', 'success');
    } else {
      showToast(`Servidor respondeu com status ${res.status}`, 'error');
    }
  } catch (err) {
    showToast(`Falha na conexao: ${err.message}`, 'error');
  } finally {
    btn.textContent = 'Testar Ligacao';
    btn.disabled = false;
  }
});

function showToast(msg, type) {
  const toast = $('#toast');
  toast.className = `toast ${type}`;
  toast.textContent = msg;
  setTimeout(() => { toast.style.display = 'none'; toast.className = 'toast'; }, 4000);
}

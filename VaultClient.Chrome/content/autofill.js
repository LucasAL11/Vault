// ============================================================
// Vault Password Manager - Content Script
// Detects login fields and fills credentials
// ============================================================

(() => {
  'use strict';

  // --- Field detection ---

  const PASSWORD_SELECTORS = [
    'input[type="password"]',
    'input[autocomplete="current-password"]',
    'input[autocomplete="new-password"]',
  ];

  const USERNAME_SELECTORS = [
    'input[autocomplete="username"]',
    'input[autocomplete="email"]',
    'input[type="email"]',
    'input[name*="user" i]',
    'input[name*="login" i]',
    'input[name*="email" i]',
    'input[id*="user" i]',
    'input[id*="login" i]',
    'input[id*="email" i]',
    'input[name*="identificador" i]',
  ];

  function findPasswordFields() {
    const fields = [];
    for (const sel of PASSWORD_SELECTORS) {
      fields.push(...document.querySelectorAll(sel));
    }
    return [...new Set(fields)].filter((f) => isVisible(f));
  }

  function findUsernameField(passwordField) {
    // Look for the closest username field BEFORE the password field in DOM order
    const form = passwordField.closest('form');
    const scope = form || document;
    const allInputs = [...scope.querySelectorAll('input')].filter(isVisible);
    const pwIdx = allInputs.indexOf(passwordField);

    // Check inputs before the password field
    for (let i = pwIdx - 1; i >= 0; i--) {
      const input = allInputs[i];
      if (isUsernameField(input)) return input;
    }

    // Fallback: search by selectors
    for (const sel of USERNAME_SELECTORS) {
      const el = scope.querySelector(sel);
      if (el && isVisible(el)) return el;
    }
    return null;
  }

  function isUsernameField(input) {
    if (input.type === 'password' || input.type === 'hidden') return false;
    const attrs = `${input.name} ${input.id} ${input.autocomplete} ${input.placeholder}`.toLowerCase();
    return /user|email|login|identif|account|cpf/.test(attrs);
  }

  function isVisible(el) {
    if (!el) return false;
    const style = getComputedStyle(el);
    return style.display !== 'none' && style.visibility !== 'hidden' && el.offsetParent !== null;
  }

  // --- Fill field with proper event dispatch ---

  function fillField(el, value) {
    if (!el || !value) return;

    // Focus the element
    el.focus();
    el.dispatchEvent(new FocusEvent('focus', { bubbles: true }));

    // Set value via native setter (bypasses React/Angular overrides)
    const nativeSetter = Object.getOwnPropertyDescriptor(
      Object.getPrototypeOf(el), 'value'
    )?.set || Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;

    if (nativeSetter) {
      nativeSetter.call(el, value);
    } else {
      el.value = value;
    }

    // Dispatch events that frameworks listen to
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
    el.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true, key: 'a' }));
    el.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, key: 'a' }));

    // Mark as vault-filled (for copy/cut/drag protection)
    el.dataset.vaultFilled = 'true';

    // Blur
    el.dispatchEvent(new FocusEvent('blur', { bubbles: true }));
  }

  // --- Vault badge on password fields ---

  function addVaultBadges() {
    const pwFields = findPasswordFields();
    pwFields.forEach((field) => {
      if (field.dataset.vaultBadge) return;
      field.dataset.vaultBadge = 'true';

      const badge = document.createElement('div');
      badge.className = 'vault-autofill-badge';
      badge.innerHTML = '&#128272;';
      badge.title = 'Preencher com Vault (Ctrl+Shift+L)';

      badge.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        chrome.runtime.sendMessage({ action: 'getAuthState' }, (res) => {
          if (res?.authenticated) {
            // Open popup for vault/secret selection
            showInlineMenu(field);
          } else {
            // Open popup for login
            chrome.runtime.sendMessage({ action: 'openPopup' });
          }
        });
      });

      // Position badge inside the field
      const wrapper = field.parentElement;
      if (wrapper) {
        wrapper.style.position = wrapper.style.position || 'relative';
        badge.style.position = 'absolute';
        badge.style.right = '8px';
        badge.style.top = '50%';
        badge.style.transform = 'translateY(-50%)';
        badge.style.zIndex = '99999';
        wrapper.appendChild(badge);
      }
    });
  }

  // --- Inline quick menu ---

  let activeMenu = null;

  function showInlineMenu(passwordField) {
    removeInlineMenu();

    const menu = document.createElement('div');
    menu.className = 'vault-inline-menu';
    menu.innerHTML = `
      <div class="vault-inline-header">
        <span>&#128272; Vault</span>
      </div>
      <div class="vault-inline-body">
        <div class="vault-inline-loading">Carregando cofres...</div>
      </div>
    `;

    // Position below the field
    const rect = passwordField.getBoundingClientRect();
    menu.style.position = 'fixed';
    menu.style.left = `${rect.left}px`;
    menu.style.top = `${rect.bottom + 4}px`;
    menu.style.width = `${Math.max(rect.width, 280)}px`;
    menu.style.zIndex = '2147483647';

    document.body.appendChild(menu);
    activeMenu = { el: menu, passwordField };

    // Load vaults
    loadInlineVaults(menu, passwordField);

    // Close on outside click
    setTimeout(() => {
      document.addEventListener('click', closeMenuOnOutsideClick);
    }, 100);
  }

  function closeMenuOnOutsideClick(e) {
    if (activeMenu && !activeMenu.el.contains(e.target)) {
      removeInlineMenu();
    }
  }

  function removeInlineMenu() {
    if (activeMenu) {
      activeMenu.el.remove();
      activeMenu = null;
    }
    document.removeEventListener('click', closeMenuOnOutsideClick);
  }

  async function loadInlineVaults(menu, passwordField) {
    const body = menu.querySelector('.vault-inline-body');
    try {
      const data = await sendAsync({ action: 'listVaults' });
      const vaults = Array.isArray(data) ? data : data?.items || data?.vaults || [];

      if (vaults.length === 0) {
        body.innerHTML = '<div class="vault-inline-empty">Nenhum cofre disponivel</div>';
        return;
      }

      body.innerHTML = vaults.map((v) => `
        <div class="vault-inline-item" data-vault-id="${v.id}" data-vault-name="${esc(v.name)}">
          &#128274; ${esc(v.name)}
        </div>
      `).join('');

      body.querySelectorAll('.vault-inline-item').forEach((item) => {
        item.addEventListener('click', () => {
          loadInlineSecrets(menu, passwordField, item.dataset.vaultId, item.dataset.vaultName);
        });
      });
    } catch (err) {
      body.innerHTML = `<div class="vault-inline-error">${esc(err.message)}</div>`;
    }
  }

  async function loadInlineSecrets(menu, passwordField, vaultId, vaultName) {
    const body = menu.querySelector('.vault-inline-body');
    body.innerHTML = '<div class="vault-inline-loading">Carregando segredos...</div>';

    try {
      const data = await sendAsync({ action: 'listSecrets', vaultId });
      const secrets = Array.isArray(data) ? data : data?.items || data?.secrets || [];

      if (secrets.length === 0) {
        body.innerHTML = `
          <div class="vault-inline-back" data-action="back-vaults">&larr; ${esc(vaultName)}</div>
          <div class="vault-inline-empty">Nenhum segredo</div>
        `;
        body.querySelector('.vault-inline-back')?.addEventListener('click', () => loadInlineVaults(menu, passwordField));
        return;
      }

      // Filter secrets that look like they match the current site
      const hostname = location.hostname.replace('www.', '').split('.')[0].toLowerCase();
      const sorted = [...secrets].sort((a, b) => {
        const aName = (a.name || '').toLowerCase();
        const bName = (b.name || '').toLowerCase();
        const aMatch = aName.includes(hostname) ? -1 : 0;
        const bMatch = bName.includes(hostname) ? -1 : 0;
        return aMatch - bMatch;
      });

      body.innerHTML = `
        <div class="vault-inline-back" data-action="back-vaults">&larr; ${esc(vaultName)}</div>
        ${sorted.map((s) => {
          const name = s.name || s.Name;
          const highlight = name.toLowerCase().includes(hostname) ? ' vault-inline-match' : '';
          return `<div class="vault-inline-item vault-inline-secret${highlight}" data-vault-id="${vaultId}" data-secret-name="${esc(name)}">
            &#128273; ${esc(name)}
          </div>`;
        }).join('')}
      `;

      body.querySelector('.vault-inline-back')?.addEventListener('click', () => loadInlineVaults(menu, passwordField));

      body.querySelectorAll('.vault-inline-secret').forEach((item) => {
        item.addEventListener('click', async () => {
          item.textContent = 'Buscando...';
          try {
            const result = await sendAsync({
              action: 'requestSecret',
              vaultId: item.dataset.vaultId,
              secretName: item.dataset.secretName,
            });

            const value = result.value || result.Value || '';

            // Fill password
            fillField(passwordField, value);

            // Try to fill username if available
            const usernameField = findUsernameField(passwordField);
            if (usernameField && result.username) {
              fillField(usernameField, result.username);
            }

            removeInlineMenu();
          } catch (err) {
            item.textContent = `Erro: ${err.message}`;
            item.style.color = '#f87171';
          }
        });
      });
    } catch (err) {
      body.innerHTML = `<div class="vault-inline-error">${esc(err.message)}</div>`;
    }
  }

  // --- Message from background/popup ---

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === 'fillPassword') {
      const pwFields = findPasswordFields();
      if (pwFields.length > 0) {
        fillField(pwFields[0], msg.value);

        if (msg.username) {
          const userField = findUsernameField(pwFields[0]);
          if (userField) fillField(userField, msg.username);
        }
      }
      sendResponse({ success: true });
    }

    if (msg.action === 'showAutofillMenu') {
      const pwFields = findPasswordFields();
      if (pwFields.length > 0) {
        showInlineMenu(pwFields[0]);
      }
      sendResponse({ success: true });
    }
    return true;
  });

  // --- Helper ---

  function sendAsync(msg) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(msg, (res) => {
        if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
        if (res?.error) return reject(new Error(res.error));
        resolve(res);
      });
    });
  }

  function esc(str) {
    const d = document.createElement('span');
    d.textContent = str || '';
    return d.innerHTML;
  }

  // --- Auto-match autofill rules by URL ---

  let autoMatchDone = false;

  async function tryAutoMatch() {
    if (autoMatchDone) return;
    autoMatchDone = true;

    try {
      // Check if user is authenticated first
      const authState = await sendAsync({ action: 'getAuthState' });
      if (!authState?.authenticated) return;

      // Query API for autofill rules matching current URL
      const rules = await sendAsync({ action: 'matchAutofillRules', url: location.href });
      const matches = Array.isArray(rules) ? rules : rules?.items || [];
      if (matches.length === 0) return;

      // Use the first matching rule
      const rule = matches[0];

      // Wait briefly for fields to render (SPA pages)
      await new Promise((r) => setTimeout(r, 500));

      const pwFields = findPasswordFields();
      if (pwFields.length === 0) return;

      // Show a subtle notification bar instead of filling immediately
      showAutoMatchBar(rule, pwFields[0]);
    } catch (_) {
      // Silently ignore - user may not be logged in or API unavailable
    }
  }

  function showAutoMatchBar(rule, passwordField) {
    // Don't show if already visible
    if (document.querySelector('.vault-automatch-bar')) return;

    const bar = document.createElement('div');
    bar.className = 'vault-automatch-bar';
    bar.innerHTML = `
      <div class="vault-automatch-inner">
        <span class="vault-automatch-icon">&#128272;</span>
        <span class="vault-automatch-text">Sentinel Vault: <strong>${esc(rule.login)}</strong> disponivel para este site</span>
        <button class="vault-automatch-btn vault-automatch-fill">Autofill</button>
        <button class="vault-automatch-btn vault-automatch-dismiss">&times;</button>
      </div>
    `;

    document.body.appendChild(bar);

    // Animate in
    requestAnimationFrame(() => bar.classList.add('vault-automatch-visible'));

    bar.querySelector('.vault-automatch-dismiss').addEventListener('click', () => {
      bar.classList.remove('vault-automatch-visible');
      setTimeout(() => bar.remove(), 300);
    });

    bar.querySelector('.vault-automatch-fill').addEventListener('click', async () => {
      const btn = bar.querySelector('.vault-automatch-fill');
      btn.textContent = '...';
      btn.disabled = true;

      try {
        const secret = await sendAsync({
          action: 'requestSecret',
          vaultId: rule.vaultId,
          secretName: rule.secretName,
        });

        const value = secret.value || secret.Value || '';

        // Fill username
        const usernameField = findUsernameField(passwordField);
        if (usernameField && rule.login) {
          fillField(usernameField, rule.login);
        }

        // Fill password
        fillField(passwordField, value);

        // Remove bar
        bar.classList.remove('vault-automatch-visible');
        setTimeout(() => bar.remove(), 300);
      } catch (err) {
        btn.textContent = 'Error';
        btn.style.background = '#dc2626';
        setTimeout(() => {
          btn.textContent = 'Autofill';
          btn.style.background = '';
          btn.disabled = false;
        }, 2000);
      }
    });

    // Auto-dismiss after 15 seconds
    setTimeout(() => {
      if (bar.parentElement) {
        bar.classList.remove('vault-automatch-visible');
        setTimeout(() => bar.remove(), 300);
      }
    }, 15000);
  }

  // --- Password field protection (prevent copy/cut/drag of filled values) ---

  function lockPasswordField(field) {
    if (field.dataset.vaultLocked) return;
    field.dataset.vaultLocked = 'true';

    const block = (e) => {
      if (field.dataset.vaultFilled) {
        e.preventDefault();
        e.stopImmediatePropagation();
      }
    };

    field.addEventListener('copy', block, true);
    field.addEventListener('cut', block, true);
    field.addEventListener('dragstart', block, true);
  }

  // --- Init ---

  // Add badges to existing password fields
  addVaultBadges();

  // Lock all password fields
  findPasswordFields().forEach(lockPasswordField);

  // Try auto-match after a brief delay
  setTimeout(tryAutoMatch, 800);

  // Watch for dynamically added fields (SPAs)
  const observer = new MutationObserver(() => {
    addVaultBadges();
    findPasswordFields().forEach(lockPasswordField);

    // Retry auto-match if new password fields appear
    if (!autoMatchDone || findPasswordFields().length > 0) {
      tryAutoMatch();
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });
})();

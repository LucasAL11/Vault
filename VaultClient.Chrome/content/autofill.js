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

    // Mark as filling so our value getter doesn't block
    el.dataset.vaultFilling = 'true';

    // Focus the element
    el.focus();
    el.dispatchEvent(new FocusEvent('focus', { bubbles: true }));

    // Set value via native setter (bypasses React/Angular overrides)
    const nativeSetter = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype, 'value'
    )?.set;

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

    // Mark as vault-filled and remove filling flag
    delete el.dataset.vaultFilling;
    el.dataset.vaultFilled = 'true';

    // Ensure type stays as password
    if (el.type !== 'password') el.type = 'password';

    // Lock the field and suppress other password managers
    lockPasswordField(el);
    suppressExternalManagers(el);

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

            // Fill password and lock the field
            fillField(passwordField, value);
            lockPasswordField(passwordField);

            // Try to fill username if available
            const usernameField = findUsernameField(passwordField);
            if (usernameField && result.username) {
              fillField(usernameField, result.username);
            }

            removeInlineMenu();
          } catch (err) {
            if (err.message === 'SESSION_EXPIRED' || err.message?.includes('SESSION_EXPIRED')) {
              item.textContent = 'Sessao expirada — faça login';
              item.style.color = '#fbbf24';
              chrome.runtime.sendMessage({ action: 'openPopup' });
            } else {
              item.textContent = `Erro: ${err.message}`;
              item.style.color = '#f87171';
            }
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
        lockPasswordField(pwFields[0]);

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
      const authState = await sendAsync({ action: 'getAuthState' });
      if (!authState?.authenticated) return;

      const rules = await sendAsync({ action: 'matchAutofillRules', url: location.href });
      const matches = Array.isArray(rules) ? rules : rules?.items || [];
      if (matches.length === 0) return;

      // Wait briefly for fields to render (SPA pages)
      await new Promise((r) => setTimeout(r, 500));

      const pwFields = findPasswordFields();
      if (pwFields.length === 0) return;

      showAutoMatchBar(matches, pwFields[0]);
    } catch (_) {
      // Silently ignore — user may not be logged in or API unavailable
    }
  }

  // ----------------------------------------------------------------
  // showAutoMatchBar — handles 1 or multiple matching rules
  //
  // Single rule  → compact bar with one "Autofill" button
  // Multiple rules → bar expands to show each account as a row
  // ----------------------------------------------------------------
  function showAutoMatchBar(rules, passwordField) {
    if (document.querySelector('.vault-automatch-bar')) return;

    const single = rules.length === 1;

    const bar = document.createElement('div');
    bar.className = 'vault-automatch-bar';

    if (single) {
      // ── Single-rule compact bar ──────────────────────────────────
      bar.innerHTML = `
        <div class="vault-automatch-inner">
          <span class="vault-automatch-icon">&#128272;</span>
          <span class="vault-automatch-text">Sentinel Vault: <strong>${esc(rules[0].login)}</strong> disponivel para este site</span>
          <button class="vault-automatch-btn vault-automatch-fill" data-idx="0">Autofill</button>
          <button class="vault-automatch-btn vault-automatch-dismiss">&times;</button>
        </div>
      `;
    } else {
      // ── Multi-rule expanded bar ──────────────────────────────────
      const rows = rules.map((r, i) => `
        <div class="vault-automatch-rule-row">
          <span class="vault-automatch-rule-login">&#128100; ${esc(r.login)}</span>
          <button class="vault-automatch-btn vault-automatch-fill" data-idx="${i}">Autofill</button>
        </div>
      `).join('');

      bar.innerHTML = `
        <div class="vault-automatch-inner vault-automatch-multi">
          <div class="vault-automatch-multi-header">
            <span class="vault-automatch-icon">&#128272;</span>
            <span class="vault-automatch-text">Sentinel Vault: <strong>${rules.length} contas</strong> disponíveis</span>
            <button class="vault-automatch-btn vault-automatch-dismiss">&times;</button>
          </div>
          <div class="vault-automatch-rule-list">${rows}</div>
        </div>
      `;
    }

    document.body.appendChild(bar);
    requestAnimationFrame(() => bar.classList.add('vault-automatch-visible'));

    bar.querySelector('.vault-automatch-dismiss').addEventListener('click', () => {
      bar.classList.remove('vault-automatch-visible');
      setTimeout(() => bar.remove(), 300);
    });

    // Shared fill handler — same logic for single and multi
    bar.querySelectorAll('.vault-automatch-fill').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const rule = rules[parseInt(btn.dataset.idx, 10)];
        const originalText = btn.textContent;
        btn.textContent = '...';
        btn.disabled = true;

        try {
          const secret = await sendAsync({
            action: 'requestSecret',
            vaultId: rule.vaultId,
            secretName: rule.secretName,
          });

          const value = secret.value || secret.Value || '';

          const usernameField = findUsernameField(passwordField);
          if (usernameField && rule.login) fillField(usernameField, rule.login);
          fillField(passwordField, value);

          bar.classList.remove('vault-automatch-visible');
          setTimeout(() => bar.remove(), 300);
        } catch (err) {
          if (err.message === 'SESSION_EXPIRED' || err.message?.includes('SESSION_EXPIRED')) {
            btn.textContent = 'Login requerido';
            btn.style.background = '#d97706';
            chrome.runtime.sendMessage({ action: 'openPopup' });
            setTimeout(() => {
              btn.textContent = originalText;
              btn.style.background = '';
              btn.disabled = false;
            }, 3000);
          } else {
            btn.textContent = 'Erro';
            btn.style.background = '#dc2626';
            setTimeout(() => {
              btn.textContent = originalText;
              btn.style.background = '';
              btn.disabled = false;
            }, 2000);
          }
        }
      });
    });

    // Auto-dismiss after 20 seconds (longer for multi to give time to choose)
    setTimeout(() => {
      if (bar.parentElement) {
        bar.classList.remove('vault-automatch-visible');
        setTimeout(() => bar.remove(), 300);
      }
    }, single ? 15000 : 20000);
  }

  // --- Password field protection ---

  function lockPasswordField(field) {
    if (field.dataset.vaultLocked) return;
    field.dataset.vaultLocked = 'true';

    // Block copy, cut, drag, select-all
    const blockEvent = (e) => {
      if (field.dataset.vaultFilled) {
        e.preventDefault();
        e.stopImmediatePropagation();
        if (e.clipboardData) e.clipboardData.setData('text/plain', '');
      }
    };

    field.addEventListener('copy', blockEvent, true);
    field.addEventListener('cut', blockEvent, true);
    field.addEventListener('dragstart', blockEvent, true);
    field.addEventListener('selectstart', blockEvent, true);

    // Block show-password (type change from password → text)
    const typeDesc = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'type');
    if (typeDesc && typeDesc.set) {
      const originalSetter = typeDesc.set;
      Object.defineProperty(field, 'type', {
        get() { return typeDesc.get.call(this); },
        set(val) {
          if (this.dataset.vaultFilled && val !== 'password') return;
          originalSetter.call(this, val);
        },
        configurable: true,
      });
    }

    // Block setAttribute('type', 'text')
    const origSetAttribute = field.setAttribute.bind(field);
    field.setAttribute = function(name, value) {
      if (name === 'type' && this.dataset.vaultFilled && value !== 'password') return;
      origSetAttribute(name, value);
    };

    // Watch for attribute changes (external toggles via DOM)
    const attrObserver = new MutationObserver((mutations) => {
      for (const m of mutations) {
        if (m.attributeName === 'type' && field.dataset.vaultFilled && field.type !== 'password') {
          field.type = 'password';
        }
      }
    });
    attrObserver.observe(field, { attributes: true, attributeFilter: ['type'] });

    // Block reading AND writing the value by external scripts/extensions
    const valueDesc = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
    if (valueDesc && valueDesc.get) {
      const originalGetter = valueDesc.get;
      const originalValueSetter = valueDesc.set;
      Object.defineProperty(field, 'value', {
        get() {
          // Return '' to external scripts; our fillField sets vaultFilling before writing
          if (this.dataset.vaultFilled && !this.dataset.vaultFilling) return '';
          return originalGetter.call(this);
        },
        set(val) {
          // Block external writes once vault-filled (other autofill extensions)
          if (this.dataset.vaultFilled && !this.dataset.vaultFilling) return;
          if (originalValueSetter) originalValueSetter.call(this, val);
        },
        configurable: true,
      });
    }

    // Block context menu (right-click → inspect/copy)
    field.addEventListener('contextmenu', (e) => {
      if (field.dataset.vaultFilled) {
        e.preventDefault();
        e.stopImmediatePropagation();
      }
    }, true);
  }

  // --- Suppress other password managers on vault-filled fields ---

  // Attributes recognised by the main password manager extensions:
  //   data-lpignore        → LastPass
  //   data-1p-ignore       → 1Password
  //   data-bwignore        → Bitwarden
  //   data-dashlane-ignore → Dashlane
  //   autocomplete=off     → browser built-in + most extensions
  function suppressExternalManagers(field) {
    if (field.dataset.vaultSuppressed) return;
    field.dataset.vaultSuppressed = 'true';
    field.setAttribute('data-lpignore', 'true');
    field.setAttribute('data-1p-ignore', 'true');
    field.setAttribute('data-bwignore', 'true');
    field.setAttribute('data-dashlane-ignore', 'true');
    field.setAttribute('autocomplete', 'off');
  }

  // ============================================================
  // --- Save credentials (Chrome/Firefox/Edge pattern) ---
  //
  // Flow:
  //   1. Detect form submit on any form containing a password field
  //   2. Capture login + password values
  //   3. Persist as pendingSave in chrome.storage.session
  //   4. On NEXT page load, check for pendingSave → show save bar
  //      (matches Chrome's behaviour: bar appears after navigation)
  // ============================================================

  const PENDING_KEY = 'vault_pending_save';
  const SAVE_BAR_TTL_MS = 5 * 60 * 1000; // 5 minutes — discard stale pending

  // Attempt to show the save bar for a given pending credential.
  // Called both on page load (traditional navigation) and on same page (SPAs).
  async function tryShowSaveBar(pending) {
    if (!pending) return;
    if (document.querySelector('.vault-save-bar')) return;
    if (Date.now() - (pending.ts || 0) > SAVE_BAR_TTL_MS) return;

    try {
      const authState = await sendAsync({ action: 'getAuthState' });
      if (!authState?.authenticated) return; // silently skip — user not logged in

      const vaultResp = await sendAsync({ action: 'listVaults' });
      const vaults = Array.isArray(vaultResp) ? vaultResp
        : vaultResp?.items || vaultResp?.vaults || [];

      if (vaults.length === 0) return;

      showSaveBar(pending, vaults);
    } catch (_) {
      // Ignore errors (API unavailable, etc.)
    }
  }

  // On page load: check for pending save stored by a previous page (traditional navigation)
  async function checkPendingSave() {
    try {
      const data = await chrome.storage.session.get(PENDING_KEY);
      const pending = data[PENDING_KEY];
      if (!pending) return;

      // Clear immediately so it doesn't show twice on reload
      await chrome.storage.session.remove(PENDING_KEY);

      await tryShowSaveBar(pending);
    } catch (_) {}
  }

  function showSaveBar(pending, vaults) {
    if (document.querySelector('.vault-save-bar')) return;

    const vaultOptions = vaults.map((v, i) =>
      `<option value="${esc(v.id)}" ${i === 0 ? 'selected' : ''}>${esc(v.name)}</option>`
    ).join('');

    const bar = document.createElement('div');
    bar.className = 'vault-save-bar';
    bar.innerHTML = `
      <div class="vault-save-inner">
        <span class="vault-save-icon">&#128272;</span>
        <div class="vault-save-body">
          <span class="vault-save-title">Sentinel Vault: Salvar credenciais?</span>
          <span class="vault-save-login">&#128100; ${esc(pending.login)}</span>
        </div>
        <div class="vault-save-controls">
          <select class="vault-save-select">${vaultOptions}</select>
          <button class="vault-save-btn vault-save-confirm">Salvar</button>
          <button class="vault-save-btn vault-save-never">Nunca</button>
          <button class="vault-save-btn vault-save-dismiss">&times;</button>
        </div>
      </div>
    `;

    document.body.appendChild(bar);
    requestAnimationFrame(() => bar.classList.add('vault-save-visible'));

    const dismiss = () => {
      bar.classList.remove('vault-save-visible');
      setTimeout(() => bar.remove(), 300);
    };

    bar.querySelector('.vault-save-dismiss').addEventListener('click', dismiss);

    bar.querySelector('.vault-save-never').addEventListener('click', async () => {
      // Remember "never" for this host
      try {
        const { vault_never_hosts = [] } = await chrome.storage.local.get('vault_never_hosts');
        const host = new URL(pending.url).hostname;
        if (!vault_never_hosts.includes(host)) {
          await chrome.storage.local.set({ vault_never_hosts: [...vault_never_hosts, host] });
        }
      } catch (_) {}
      dismiss();
    });

    bar.querySelector('.vault-save-confirm').addEventListener('click', async () => {
      const btn = bar.querySelector('.vault-save-confirm');
      const vaultId = bar.querySelector('.vault-save-select').value;
      btn.textContent = '...';
      btn.disabled = true;

      try {
        const res = await sendAsync({
          action: 'saveCredentials',
          url: pending.url,
          login: pending.login,
          password: pending.password,
          vaultId,
        });

        btn.textContent = '✓ Salvo';
        btn.style.background = '#22c55e';
        setTimeout(dismiss, 1500);
      } catch (err) {
        if (err.message === 'SESSION_EXPIRED' || err.message?.includes('SESSION_EXPIRED')) {
          btn.textContent = 'Login requerido';
          btn.style.background = '#d97706';
          chrome.runtime.sendMessage({ action: 'openPopup' });
          setTimeout(() => {
            btn.textContent = 'Salvar';
            btn.style.background = '';
            btn.disabled = false;
          }, 3000);
        } else {
          btn.textContent = 'Erro';
          btn.style.background = '#dc2626';
          setTimeout(() => {
            btn.textContent = 'Salvar';
            btn.style.background = '';
            btn.disabled = false;
          }, 2000);
        }
      }
    });

    // Auto-dismiss after 25 seconds (longer — user needs time to pick vault)
    setTimeout(() => {
      if (bar.parentElement) dismiss();
    }, 25000);
  }

  // Attach submit listeners to any form containing a password field.
  // Handles: traditional submit, SPA button clicks, Enter-key submits.
  function attachSaveListeners() {
    document.querySelectorAll('form').forEach((form) => {
      if (form.dataset.vaultSaveAttached) return;
      const pw = form.querySelector('input[type="password"]');
      if (!pw) return;
      form.dataset.vaultSaveAttached = 'true';

      // Traditional form submit (navigation-based login pages)
      form.addEventListener('submit', () => onLoginFormSubmit(form));

      // Any button inside the form (SPAs often use plain <button> or <div role="button">)
      form.querySelectorAll('button, input[type="submit"], input[type="button"]').forEach((btn) => {
        btn.addEventListener('click', () => {
          // Small delay so the click handler can run first and populate fields
          setTimeout(() => onLoginFormSubmit(form), 150);
        });
      });
    });

    // Also catch Enter key on username/password fields (forms without explicit submit buttons)
    document.querySelectorAll('input[type="password"], input[type="email"], input[type="text"]')
      .forEach((input) => {
        if (input.dataset.vaultEnterAttached) return;
        input.dataset.vaultEnterAttached = 'true';
        input.addEventListener('keydown', (e) => {
          if (e.key !== 'Enter') return;
          const form = input.closest('form');
          if (form) setTimeout(() => onLoginFormSubmit(form), 150);
        });
      });
  }

  async function onLoginFormSubmit(form) {
    try {
      const pwField = form.querySelector('input[type="password"]');
      if (!pwField?.value) return;

      const usernameField = findUsernameField(pwField);
      const login = usernameField?.value?.trim();
      if (!login) return;

      const password = pwField.value;

      // Skip if vault already filled this field (credential already known)
      if (pwField.dataset.vaultFilled) return;

      // Skip if this host is on the "never" list
      const { vault_never_hosts = [] } = await chrome.storage.local.get('vault_never_hosts');
      if (vault_never_hosts.includes(location.hostname)) return;

      const pending = { url: location.href, login, password, ts: Date.now() };

      // Store for next-page navigation (traditional login pages)
      await chrome.storage.session.set({ [PENDING_KEY]: pending });

      // Also try showing on same page after a short delay (SPAs that don't navigate)
      setTimeout(() => tryShowSaveBar(pending), 1000);
    } catch (_) {
      // Never block form submission
    }
  }

  // --- Init ---

  // Add badges to existing password fields
  addVaultBadges();

  // Lock all password fields
  findPasswordFields().forEach(lockPasswordField);

  // Attach save-credential listeners to existing forms
  attachSaveListeners();

  // Check for a pending save from a previous page navigation
  checkPendingSave();

  // Try auto-match after a brief delay
  setTimeout(tryAutoMatch, 800);

  // Watch for dynamically added fields (SPAs)
  const observer = new MutationObserver(() => {
    addVaultBadges();
    findPasswordFields().forEach(lockPasswordField);
    attachSaveListeners(); // pick up new forms in SPAs

    // Retry auto-match if new password fields appear
    if (!autoMatchDone || findPasswordFields().length > 0) {
      tryAutoMatch();
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });
})();

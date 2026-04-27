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

    // Lift readonly set by suppress-native.js (MAIN world) before writing
    el.removeAttribute('readonly');
    el.dispatchEvent(new CustomEvent('sentil:unlock', { bubbles: false }));

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

      // Suppress native browser password manager & third-party managers immediately,
      // before the user even interacts with the field.
      suppressExternalManagers(field);

      // Also suppress the associated username/email field — Chrome triggers the
      // "Senhas salvas" dropdown when the *username* field receives focus.
      const userField = findUsernameField(field);
      if (userField) suppressExternalManagers(userField);

      const badge = document.createElement('div');
      badge.className = 'vault-autofill-badge';
      badge.title = 'Sentil autofill (Ctrl+Shift+L)';
      badge.innerHTML = `<svg viewBox="0 0 24 24" fill="none">
        <path d="M5 5 L19 5 L19 9 L9 9 L9 11 L19 11 L19 19 L5 19 L5 15 L15 15 L15 13 L5 13 Z" fill="#5BAD80"/>
      </svg>`;

      badge.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        chrome.runtime.sendMessage({ action: 'getAuthState' }, (res) => {
          if (res?.authenticated) {
            // Open picker — badge click has no pre-matched rules
            showInlineMenu(field, []);
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
  // Hierarchy: Site Matches → Vault → Secret

  let activeMenu = null;

  // siteMatches: array of autofill rules that matched the current URL
  function showInlineMenu(passwordField, siteMatches = []) {
    removeInlineMenu();

    const hostname = location.hostname.replace(/^www\./, '');
    const countLabel = siteMatches.length > 0
      ? `${siteMatches.length} conta${siteMatches.length > 1 ? 's' : ''} disponív${siteMatches.length > 1 ? 'eis' : 'el'}`
      : 'carregando…';

    const menu = document.createElement('div');
    menu.className = 'sentil-picker';
    menu.innerHTML = `
      <div class="sp-header">
        <svg class="sp-logo" viewBox="0 0 24 24" fill="none">
          <path d="M5 5 L19 5 L19 9 L9 9 L9 11 L19 11 L19 19 L5 19 L5 15 L15 15 L15 13 L5 13 Z" fill="#5BAD80"/>
        </svg>
        <span class="sp-chip">▸ AUTOFILL</span>
        <div class="sp-sealed">
          <span class="sp-sealed-dot"></span>
          SEALED
        </div>
        <button class="sp-close" aria-label="fechar">
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor"
               stroke-width="1.4" stroke-linecap="round">
            <path d="M3 3l6 6M9 3l-6 6"/>
          </svg>
        </button>
      </div>
      <div class="sp-host">
        <div class="sp-host-label">MATCHING HOST</div>
        <div class="sp-host-row">
          <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="#5BAD80" stroke-width="1.3">
            <rect x="2" y="4" width="6" height="4.5" rx="0.3"/>
            <path d="M3.3 4V3a1.7 1.7 0 013.4 0v1"/>
          </svg>
          <span class="sp-host-name">${esc(hostname)}</span>
          <span class="sp-host-count sp-host-count-label">${esc(countLabel)}</span>
        </div>
      </div>
      <div class="sp-list"></div>
      <div class="sp-footer">
        <button class="sp-footer-btn sp-btn-search">
          <svg width="11" height="11" viewBox="0 0 11 11" fill="none" stroke="currentColor" stroke-width="1.3">
            <circle cx="4.5" cy="4.5" r="3"/><path d="M7 7l3 3" stroke-linecap="round"/>
          </svg>
          search.all()
        </button>
      </div>
      <div class="sp-hints">
        <div class="sp-hints-keys">
          <span>↑↓ navegue</span>
          <span>⏎ preencher</span>
          <span>esc fechar</span>
        </div>
        <span id="sp-session-time"></span>
      </div>
    `;

    // Position below the field
    const rect = passwordField.getBoundingClientRect();
    menu.style.position = 'fixed';
    menu.style.left = `${Math.min(rect.left, window.innerWidth - 390)}px`;
    menu.style.top  = `${rect.bottom + 6}px`;
    menu.style.zIndex = '2147483647';

    document.body.appendChild(menu);
    activeMenu = { el: menu, passwordField, selectedIdx: 0, siteMatches };

    // Close button
    menu.querySelector('.sp-close').addEventListener('click', removeInlineMenu);

    // Load home screen (matches + vaults)
    loadInlineHome(menu, passwordField, siteMatches);

    // Keyboard navigation
    const onKey = (e) => {
      if (!activeMenu) return;
      const rows = [...menu.querySelectorAll('.sp-row')];
      if (!rows.length) return;
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        activeMenu.selectedIdx = Math.min(activeMenu.selectedIdx + 1, rows.length - 1);
        rows.forEach((r, i) => r.classList.toggle('sp-row-active', i === activeMenu.selectedIdx));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        activeMenu.selectedIdx = Math.max(activeMenu.selectedIdx - 1, 0);
        rows.forEach((r, i) => r.classList.toggle('sp-row-active', i === activeMenu.selectedIdx));
      } else if (e.key === 'Enter') {
        e.preventDefault();
        rows[activeMenu.selectedIdx]?.querySelector('.sp-fill-btn')?.click();
      } else if (e.key === 'Escape') {
        removeInlineMenu();
      }
    };
    document.addEventListener('keydown', onKey);
    activeMenu._keyHandler = onKey;

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
      if (activeMenu._keyHandler)
        document.removeEventListener('keydown', activeMenu._keyHandler);
      activeMenu.el.remove();
      activeMenu = null;
    }
    document.removeEventListener('click', closeMenuOnOutsideClick);
  }

  // ── Level 0: Home — site matches + vault list ────────────────
  async function loadInlineHome(menu, passwordField, siteMatches) {
    const list = menu.querySelector('.sp-list');
    list.innerHTML = '';

    // ── Site matches section ──
    if (siteMatches.length > 0) {
      const matchHeader = document.createElement('div');
      matchHeader.className = 'sp-section-label';
      matchHeader.textContent = 'MATCH DO SITE';
      list.appendChild(matchHeader);

      siteMatches.forEach((rule, i) => {
        const login = rule.login ?? rule.Login ?? '';
        const row = document.createElement('div');
        row.className = `sp-row${i === 0 ? ' sp-row-active' : ''}`;
        row.dataset.ruleIdx = i;
        row.innerHTML = `
          <div class="sp-avatar">${esc((login || '?')[0]).toUpperCase()}</div>
          <div class="sp-row-info">
            <div class="sp-row-name-line">
              <span class="sp-row-name">${esc(login)}</span>
              ${i === 0 ? '<span class="sp-primary-badge">PRIMARY</span>' : ''}
            </div>
            <div class="sp-row-meta">
              <span class="sp-row-vault">${esc(rule.secretName ?? rule.SecretName ?? '')}</span>
            </div>
          </div>
          <div class="sp-fill-col">
            <button class="sp-fill-btn">FILL ⏎</button>
          </div>
        `;

        const fillBtn = row.querySelector('.sp-fill-btn');
        const doMatchFill = async () => {
          fillBtn.textContent = '…'; fillBtn.disabled = true;
          try {
            const secret = await sendAsync({
              action: 'requestSecret',
              vaultId: rule.vaultId ?? rule.VaultId,
              secretName: rule.secretName ?? rule.SecretName,
            });
            const usernameField = findUsernameField(passwordField);
            if (usernameField && login) fillField(usernameField, login);
            fillField(passwordField, secret.value || secret.Value || '');
            removeInlineMenu();
          } catch (err) {
            if (err.message?.includes('SESSION_EXPIRED')) {
              fillBtn.textContent = 'login req.';
              fillBtn.style.background = '#B8903A';
              chrome.runtime.sendMessage({ action: 'openPopup' });
            } else {
              fillBtn.textContent = 'erro';
              fillBtn.style.background = '#C0523A';
            }
            setTimeout(() => { fillBtn.textContent = 'FILL ⏎'; fillBtn.style.background = ''; fillBtn.disabled = false; }, 3000);
          }
        };

        fillBtn.addEventListener('click', (e) => { e.stopPropagation(); doMatchFill(); });
        row.addEventListener('click', doMatchFill);
        list.appendChild(row);
      });
    }

    // ── Vault list section ──
    const vaultHeader = document.createElement('div');
    vaultHeader.className = 'sp-section-divider';
    vaultHeader.textContent = 'COFRES';
    list.appendChild(vaultHeader);

    const loadingEl = document.createElement('div');
    loadingEl.className = 'sp-list-status is-loading';
    loadingEl.textContent = 'carregando…';
    list.appendChild(loadingEl);

    try {
      const data = await sendAsync({ action: 'listVaults' });
      const vaults = Array.isArray(data) ? data : data?.items || data?.vaults || [];
      loadingEl.remove();

      if (vaults.length === 0) {
        const el = document.createElement('div');
        el.className = 'sp-list-status';
        el.textContent = 'nenhum cofre disponível';
        list.appendChild(el);
        return;
      }

      if (siteMatches.length === 0) {
        // Update count only when no site matches (otherwise count already set in header)
        menu.querySelector('.sp-host-count-label').textContent =
          `${vaults.length} cofre${vaults.length > 1 ? 's' : ''}`;
      }

      vaults.forEach((v) => {
        const row = document.createElement('div');
        row.className = 'sp-row';
        row.innerHTML = `
          <div class="sp-avatar">${esc((v.name || '?')[0]).toUpperCase()}</div>
          <div class="sp-row-info">
            <div class="sp-row-name-line">
              <span class="sp-row-name">${esc(v.name)}</span>
            </div>
            <div class="sp-row-meta">
              <span class="sp-row-vault">${esc(v.environment || v.group || '')}</span>
            </div>
          </div>
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="#737373" stroke-width="1.3">
            <path d="M5 2l5 4-5 4" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
        `;
        row.addEventListener('click', () => loadInlineSecrets(menu, passwordField, v.id, v.name));
        list.appendChild(row);
      });

      // Reset keyboard index
      if (activeMenu) activeMenu.selectedIdx = 0;

    } catch (err) {
      loadingEl.className = 'sp-list-status is-error';
      loadingEl.textContent = err.message;
    }
  }

  // ── Level 1: back to home ─────────────────────────────────
  function loadInlineVaults(menu, passwordField) {
    // Re-uses home with stored siteMatches
    loadInlineHome(menu, passwordField, activeMenu?.siteMatches ?? []);
  }

  async function loadInlineSecrets(menu, passwordField, vaultId, vaultName) {
    const list = menu.querySelector('.sp-list');
    list.innerHTML = '<div class="sp-list-status is-loading">carregando segredos…</div>';

    try {
      const data = await sendAsync({ action: 'listSecrets', vaultId });
      const secrets = Array.isArray(data) ? data : data?.items || data?.secrets || [];

      if (secrets.length === 0) {
        list.innerHTML = `
          <div class="sp-back">← ${esc(vaultName)}</div>
          <div class="sp-list-status">nenhum segredo neste cofre</div>
        `;
        list.querySelector('.sp-back').addEventListener('click', () => loadInlineHome(menu, passwordField, activeMenu?.siteMatches ?? []));
        return;
      }

      const hostname = location.hostname.replace(/^www\./, '').split('.')[0].toLowerCase();
      const sorted = [...secrets].sort((a, b) => {
        const am = (a.name || '').toLowerCase().includes(hostname) ? -1 : 0;
        const bm = (b.name || '').toLowerCase().includes(hostname) ? -1 : 0;
        return am - bm;
      });

      menu.querySelector('.sp-host-count-label').textContent = `${sorted.length} segredo${sorted.length !== 1 ? 's' : ''}`;

      list.innerHTML = `
        <div class="sp-back">← ${esc(vaultName)}</div>
        ${sorted.map((s, i) => {
          const name  = s.name || s.Name || '';
          const ver   = s.currentVersion ?? s.CurrentVersion ?? 1;
          const isPrimary = name.toLowerCase().includes(hostname) && i === 0;
          return `
          <div class="sp-row${i === 0 ? ' sp-row-active' : ''}"
               data-vault-id="${esc(vaultId)}" data-secret-name="${esc(name)}">
            <div class="sp-avatar">${esc(name[0] ?? '?').toUpperCase()}</div>
            <div class="sp-row-info">
              <div class="sp-row-name-line">
                <span class="sp-row-name">${esc(name)}</span>
                ${isPrimary ? '<span class="sp-primary-badge">PRIMARY</span>' : ''}
              </div>
              <div class="sp-row-meta">
                <span class="sp-row-vault">${esc(vaultName)}</span>
                <span class="sp-dot">·</span>
                <span class="sp-row-age">v${ver}</span>
              </div>
              <div class="sp-row-footer">
                <div class="sp-strength">
                  ${[1,2,3,4].map(p => `<div class="sp-strength-pip lit-hi"></div>`).join('')}
                </div>
              </div>
            </div>
            ${i === 0 ? `
            <div class="sp-fill-col">
              <button class="sp-fill-btn">FILL ⏎</button>
              <span class="sp-copy-hint">⌘C copy</span>
            </div>` : ''}
          </div>`;
        }).join('')}
      `;

      list.querySelector('.sp-back').addEventListener('click', () => loadInlineHome(menu, passwordField, activeMenu?.siteMatches ?? []));

      if (activeMenu) activeMenu.selectedIdx = 0;

      // Hover → activate row
      list.querySelectorAll('.sp-row[data-secret-name]').forEach((row, i) => {
        row.addEventListener('mouseenter', () => {
          list.querySelectorAll('.sp-row').forEach((r) => r.classList.remove('sp-row-active'));
          row.classList.add('sp-row-active');
          if (activeMenu) activeMenu.selectedIdx = i;
          // Show fill button on hover
          if (!row.querySelector('.sp-fill-btn')) {
            const col = document.createElement('div');
            col.className = 'sp-fill-col';
            col.innerHTML = `<button class="sp-fill-btn">FILL ⏎</button>`;
            col.querySelector('.sp-fill-btn').addEventListener('click', (e) => {
              e.stopPropagation();
              doFill(row, passwordField);
            });
            row.appendChild(col);
          }
        });

        row.addEventListener('click', () => doFill(row, passwordField));
      });

      // Existing fill btn on first row
      list.querySelector('.sp-fill-btn')?.addEventListener('click', (e) => {
        e.stopPropagation();
        const row = e.target.closest('.sp-row');
        if (row) doFill(row, passwordField);
      });

    } catch (err) {
      list.innerHTML = `<div class="sp-list-status is-error">${esc(err.message)}</div>`;
    }
  }

  async function doFill(row, passwordField) {
    const btn = row.querySelector('.sp-fill-btn');
    const originalText = btn?.textContent ?? 'FILL ⏎';
    if (btn) { btn.textContent = '…'; btn.disabled = true; }

    try {
      const result = await sendAsync({
        action: 'requestSecret',
        vaultId: row.dataset.vaultId,
        secretName: row.dataset.secretName,
      });

      const value = result.value || result.Value || '';
      fillField(passwordField, value);
      lockPasswordField(passwordField);

      const usernameField = findUsernameField(passwordField);
      if (usernameField && result.username) fillField(usernameField, result.username);

      removeInlineMenu();
    } catch (err) {
      if (btn) { btn.textContent = originalText; btn.disabled = false; }
      if (err.message === 'SESSION_EXPIRED' || err.message?.includes('SESSION_EXPIRED')) {
        if (btn) { btn.textContent = 'login requerido'; btn.style.background = '#B8903A'; btn.style.color = '#0A0A0A'; }
        chrome.runtime.sendMessage({ action: 'openPopup' });
      } else {
        if (btn) { btn.textContent = 'erro'; btn.style.background = '#C0523A'; }
      }
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
        showInlineMenu(pwFields[0], []);
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
      const matches = Array.isArray(rules)
        ? rules
        : rules?.items ?? rules?.Items ?? [];
      if (matches.length === 0) return;

      // Wait briefly for fields to render (SPA pages)
      await new Promise((r) => setTimeout(r, 500));

      const pwFields = findPasswordFields();
      if (pwFields.length === 0) return;

      // Open the inline picker with site matches pre-loaded at the top
      showInlineMenu(pwFields[0], matches);
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

    const sentilLogo = `<svg class="vault-automatch-logo" viewBox="0 0 24 24" fill="none">
      <path d="M5 5 L19 5 L19 9 L9 9 L9 11 L19 11 L19 19 L5 19 L5 15 L15 15 L15 13 L5 13 Z" fill="#5BAD80"/>
    </svg>`;

    if (single) {
      // ── Single-rule compact bar ──────────────────────────────────
      bar.innerHTML = `
        <div class="vault-automatch-inner">
          ${sentilLogo}
          <span class="vault-automatch-text">Sentil · <strong>${esc(rules[0].login)}</strong> disponível</span>
          <button class="vault-automatch-btn vault-automatch-fill" data-idx="0">FILL ⏎</button>
          <button class="vault-automatch-btn vault-automatch-dismiss">✕</button>
        </div>
      `;
    } else {
      // ── Multi-rule expanded bar ──────────────────────────────────
      const rows = rules.map((r, i) => `
        <div class="vault-automatch-rule-row">
          <span class="vault-automatch-rule-login">${esc(r.login)}</span>
          <button class="vault-automatch-btn vault-automatch-fill" data-idx="${i}">FILL ⏎</button>
        </div>
      `).join('');

      bar.innerHTML = `
        <div class="vault-automatch-inner vault-automatch-multi">
          <div class="vault-automatch-multi-header">
            ${sentilLogo}
            <span class="vault-automatch-text">Sentil · <strong>${rules.length} contas</strong> disponíveis</span>
            <button class="vault-automatch-btn vault-automatch-dismiss">✕</button>
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
          console.error('[Vault] requestSecret error:', err.message, { vaultId: rule.vaultId, secretName: rule.secretName, rule });
          if (err.message === 'SESSION_EXPIRED' || err.message?.includes('SESSION_EXPIRED')) {
            btn.textContent = 'Login requerido';
            btn.style.background = '#B8903A';
            chrome.runtime.sendMessage({ action: 'openPopup' });
            setTimeout(() => {
              btn.textContent = originalText;
              btn.style.background = '';
              btn.disabled = false;
            }, 3000);
          } else {
            btn.textContent = 'Erro';
            btn.title = err.message;
            btn.style.background = '#C0523A';
            setTimeout(() => {
              btn.textContent = originalText;
              btn.title = '';
              btn.style.background = '';
              btn.disabled = false;
            }, 4000);
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

  // Chrome/Edge deliberately ignore autocomplete="off" for credential fields
  // (since Chrome 34). We use a multi-layer approach:
  //
  //   1. autocomplete="new-password" on password fields  → Chrome respects this
  //      and skips the "Senhas salvas" dropdown entirely.
  //      For non-password fields a random unknown token is used.
  //
  //   2. readonly trick → browser skips field indexing for autofill while readonly.
  //      We remove the attribute the instant the user touches the field so typing
  //      still works normally.
  //
  //   3. Third-party extension suppression attributes (LastPass, 1Password, etc.)
  //
  function suppressExternalManagers(field) {
    if (field.dataset.vaultSuppressed) return;
    field.dataset.vaultSuppressed = 'true';

    // Third-party managers
    field.setAttribute('data-lpignore', 'true');
    field.setAttribute('data-1p-ignore', 'true');
    field.setAttribute('data-bwignore', 'true');
    field.setAttribute('data-dashlane-ignore', 'true');
    field.setAttribute('data-kwignore', 'true');      // Keeper
    field.setAttribute('data-roboform-ignore', 'true');

    // autocomplete values Chrome/Edge/Firefox actually respect:
    //   password field → "new-password"  (no saved-credential dropdown)
    //   username field → "one-time-code" (browser treats as OTP, not username)
    if (field.type === 'password') {
      field.setAttribute('autocomplete', 'new-password');
    } else {
      field.setAttribute('autocomplete', 'one-time-code');
    }

    // Readonly trick: Chrome won't show saved-credential dropdown on readonly fields.
    // Lift it immediately on first interaction so the user can still type.
    if (!field.readOnly && !field.dataset.vaultReadonlySet) {
      field.dataset.vaultReadonlySet = 'true';
      field.setAttribute('readonly', '');
      const unlock = () => {
        field.removeAttribute('readonly');
        field.removeEventListener('focus',      unlock);
        field.removeEventListener('mousedown',  unlock);
        field.removeEventListener('touchstart', unlock);
      };
      field.addEventListener('focus',      unlock);
      field.addEventListener('mousedown',  unlock);
      field.addEventListener('touchstart', unlock);
    }
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
    if (document.querySelector('.vault-save-popup')) return;
    if (Date.now() - (pending.ts || 0) > SAVE_BAR_TTL_MS) return;

    try {
      const hostname = new URL(pending.url).hostname;

      // Check "never" list
      const { vault_never_hosts = [] } = await chrome.storage.local.get('vault_never_hosts');
      if (vault_never_hosts.includes(hostname)) return;

      const authState = await sendAsync({ action: 'getAuthState' });
      if (!authState?.authenticated) return;

      const vaultResp = await sendAsync({ action: 'listVaults' });
      const vaults = Array.isArray(vaultResp) ? vaultResp
        : vaultResp?.items || vaultResp?.vaults || [];

      if (vaults.length === 0) return;

      // Check if a rule already exists for this host (show "Atualizar" instead of "Salvar")
      let existingRule = null;
      try {
        const matchResp = await sendAsync({ action: 'matchAutofillRules', url: pending.url });
        const matches = Array.isArray(matchResp)
          ? matchResp
          : matchResp?.items ?? matchResp?.Items ?? [];
        // Only treat as "update" if the exact same login already has a rule.
        // A different email on the same host → new rule (CREATE path).
        existingRule = matches.find((r) => (r.login ?? r.Login) === pending.login) ?? null;
      } catch (_) {}

      showSaveBar(pending, vaults, existingRule);
    } catch (_) {}
  }

  // On page load: check for pending save stored by a previous page (traditional navigation)
  async function checkPendingSave() {
    try {
      const pending = await sendAsync({ action: 'getPendingSave' });
      if (!pending) return;

      // Clear immediately so it doesn't show twice on reload
      sendAsync({ action: 'clearPendingSave' }).catch(() => {});

      await tryShowSaveBar(pending);
    } catch (_) {}
  }

  function showSaveBar(pending, vaults, existingRule) {
    if (document.querySelector('.vault-save-popup')) return;

    const isUpdate = !!existingRule;
    const title = isUpdate
      ? 'update.password()'
      : 'save.password()';
    const confirmLabel = isUpdate ? 'update' : 'seal';

    // When updating, lock the vault selector to the vault of the existing rule
    let vaultOptions;
    if (isUpdate) {
      // Show only the vault that owns the existing rule (no selector needed)
      vaultOptions = vaults
        .filter((v) => v.id === existingRule.vaultId)
        .map((v) => `<option value="${esc(v.id)}" selected>${esc(v.name)}</option>`)
        .join('');
      // Fallback: if rule's vault isn't in the list, show all
      if (!vaultOptions) {
        vaultOptions = vaults.map((v, i) =>
          `<option value="${esc(v.id)}" ${i === 0 ? 'selected' : ''}>${esc(v.name)}</option>`
        ).join('');
      }
    } else {
      vaultOptions = vaults.map((v, i) =>
        `<option value="${esc(v.id)}" ${i === 0 ? 'selected' : ''}>${esc(v.name)}</option>`
      ).join('');
    }

    // Build vault chip buttons
    let vaultChips;
    if (isUpdate) {
      vaultChips = vaults
        .filter((v) => v.id === existingRule.vaultId)
        .map((v) => `<button class="sp-vault-chip sp-vault-active" data-id="${esc(v.id)}">${esc(v.name)}</button>`)
        .join('');
      if (!vaultChips)
        vaultChips = vaults.map((v, i) =>
          `<button class="sp-vault-chip${i === 0 ? ' sp-vault-active' : ''}" data-id="${esc(v.id)}">${esc(v.name)}</button>`
        ).join('');
    } else {
      vaultChips = vaults.map((v, i) =>
        `<button class="sp-vault-chip${i === 0 ? ' sp-vault-active' : ''}" data-id="${esc(v.id)}">${esc(v.name)}</button>`
      ).join('');
    }

    const hostLabel = (() => { try { return new URL(pending.url).hostname; } catch { return pending.url; } })();

    const bar = document.createElement('div');
    bar.className = 'vault-save-popup';
    bar.innerHTML = `
      <div class="sp-save-header">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" style="flex-shrink:0">
          <path d="M5 5 L19 5 L19 9 L9 9 L9 11 L19 11 L19 19 L5 19 L5 15 L15 15 L15 13 L5 13 Z" fill="#5BAD80"/>
        </svg>
        <span class="sp-save-chip">▸ ${isUpdate ? 'UPDATE' : 'SAVE'}</span>
        <button class="sp-save-close" aria-label="fechar">
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor"
               stroke-width="1.4" stroke-linecap="round">
            <path d="M3 3l6 6M9 3l-6 6"/>
          </svg>
        </button>
      </div>
      <div class="sp-save-body">
        <div class="sp-save-tag">┌─ ${isUpdate ? 'CHANGE DETECTED' : 'NEW CREDENTIAL'} ─┐</div>
        <div class="sp-save-title">${isUpdate ? 'update.password()' : 'save.password()'}</div>
        <p class="sp-save-subtitle">${isUpdate
          ? '// Detectada alteração de senha para entrada existente.'
          : '// Sentil detectou uma nova credencial. Selar?'}</p>

        <div class="sp-save-host-row">
          <div class="sp-save-host-avatar">${esc(hostLabel[0] ?? '?').toUpperCase()}</div>
          <div class="sp-save-host-info">
            <div class="sp-save-host-name">${esc(hostLabel)}</div>
            <div class="sp-save-host-user">${esc(pending.login)}</div>
          </div>
          <span class="sp-save-badge">${isUpdate ? 'EXISTING' : 'NEW'}</span>
        </div>

        <label class="sp-save-label" for="sp-save-name">NAME</label>
        <input id="sp-save-name" class="sp-save-input" value="${esc(hostLabel)}">

        ${isUpdate ? `
        <label class="sp-save-label">OLD PASSWORD</label>
        <div class="sp-save-pwd-row is-old">
          <span class="sp-save-pwd-value is-old" id="sp-old-val">
            ${'•'.repeat(Math.min((pending.oldPassword || '').length || 14, 20))}
          </span>
        </div>` : ''}

        <label class="sp-save-label">${isUpdate ? 'NEW PASSWORD' : 'PASSWORD'}</label>
        <div class="sp-save-pwd-row is-new">
          <span class="sp-save-pwd-value" id="sp-new-val">
            ${'•'.repeat(Math.min(pending.password?.length || 14, 20))}
          </span>
          <button class="sp-save-pwd-eye" id="sp-eye-btn" title="Mostrar">
            <svg width="12" height="12" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.4">
              <path d="M1 7s2-4 6-4 6 4 6 4-2 4-6 4-6-4-6-4z"/><circle cx="7" cy="7" r="2"/>
            </svg>
          </button>
        </div>
        <div class="sp-save-strength">
          <div class="sp-save-strength-pips">
            ${[1,2,3,4].map(() => '<div class="sp-save-pip lit"></div>').join('')}
          </div>
          <span class="sp-save-strength-label">STRONG · ~118 bits</span>
        </div>

        <label class="sp-save-label">VAULT</label>
        <div class="sp-save-vault-grid" id="sp-vault-grid">
          ${vaultChips}
        </div>
      </div>

      <div class="sp-save-footer">
        <button class="sp-save-btn sp-never-btn">never.for.this()</button>
        <button class="sp-save-btn sp-dismiss-btn">not.now()</button>
        <button class="sp-save-btn-confirm ${isUpdate ? 'is-update' : ''} sp-confirm-btn">
          ${confirmLabel} ⏎
        </button>
      </div>
      <div class="sp-save-hint">
        <span id="sp-hint-vault">encriptado localmente · sincronizado</span>
        <span>⏎ confirmar  esc descartar</span>
      </div>
    `;

    document.body.appendChild(bar);
    requestAnimationFrame(() => bar.classList.add('sp-visible'));

    const dismiss = () => {
      bar.style.opacity = '0';
      bar.style.transform = 'translateY(-12px)';
      setTimeout(() => bar.remove(), 200);
    };

    // Close / dismiss
    bar.querySelector('.sp-save-close').addEventListener('click', dismiss);
    bar.querySelector('.sp-dismiss-btn').addEventListener('click', dismiss);

    // Eye toggle
    let pwVisible = false;
    bar.querySelector('#sp-eye-btn')?.addEventListener('click', () => {
      pwVisible = !pwVisible;
      const el = bar.querySelector('#sp-new-val');
      if (el) el.textContent = pwVisible ? pending.password : '•'.repeat(Math.min(pending.password?.length || 14, 20));
    });

    // Vault chip selection
    bar.querySelector('#sp-vault-grid')?.querySelectorAll('.sp-vault-chip').forEach((chip) => {
      chip.addEventListener('click', () => {
        bar.querySelectorAll('.sp-vault-chip').forEach((c) => c.classList.remove('sp-vault-active'));
        chip.classList.add('sp-vault-active');
        const hint = bar.querySelector('#sp-hint-vault');
        if (hint) hint.textContent = `encriptado localmente · sincronizado com ${chip.textContent}`;
      });
    });

    // Never
    bar.querySelector('.sp-never-btn').addEventListener('click', async () => {
      try {
        const { vault_never_hosts = [] } = await chrome.storage.local.get('vault_never_hosts');
        const host = new URL(pending.url).hostname;
        if (!vault_never_hosts.includes(host))
          await chrome.storage.local.set({ vault_never_hosts: [...vault_never_hosts, host] });
      } catch (_) {}
      dismiss();
    });

    // Confirm / save
    bar.querySelector('.sp-confirm-btn').addEventListener('click', async () => {
      const btn = bar.querySelector('.sp-confirm-btn');
      const activeChip = bar.querySelector('.sp-vault-chip.sp-vault-active');
      const vaultId = isUpdate
        ? (existingRule.vaultId ?? existingRule.VaultId)
        : (activeChip?.dataset.id ?? vaults[0]?.id);

      btn.textContent = '…';
      btn.disabled = true;

      try {
        await sendAsync({
          action: 'saveCredentials',
          url: pending.url,
          login: pending.login,
          password: pending.password,
          vaultId,
        });

        btn.textContent = isUpdate ? '✓ atualizado' : '✓ salvo';
        btn.style.background = '#5BAD80';
        btn.style.color = '#0A0A0A';
        setTimeout(dismiss, 1500);
      } catch (err) {
        btn.disabled = false;
        if (err.message === 'SESSION_EXPIRED' || err.message?.includes('SESSION_EXPIRED')) {
          btn.textContent = 'login requerido';
          btn.style.background = '#B8903A';
          btn.style.color = '#1a0e00';
          chrome.runtime.sendMessage({ action: 'openPopup' });
          setTimeout(() => { btn.textContent = confirmLabel + ' ⏎'; btn.style.background = ''; btn.style.color = ''; }, 3000);
        } else {
          btn.textContent = 'erro';
          btn.style.background = '#C0523A';
          setTimeout(() => { btn.textContent = confirmLabel + ' ⏎'; btn.style.background = ''; }, 2000);
        }
      }
    });

    // Keyboard dismiss
    const onEsc = (e) => { if (e.key === 'Escape') { dismiss(); document.removeEventListener('keydown', onEsc); } };
    document.addEventListener('keydown', onEsc);

    // Auto-dismiss after 30 s
    setTimeout(() => { if (bar.parentElement) dismiss(); }, 30000);
  }

  // Synchronously extract credentials from a form.
  // Returns null if credentials are incomplete or should be skipped.
  function captureCredentials(form) {
    const pwField = form.querySelector('input[type="password"]');
    if (!pwField?.value) return null;

    // Skip if vault itself filled this field (already known)
    if (pwField.dataset.vaultFilled) return null;

    const usernameField = findUsernameField(pwField);
    const login = usernameField?.value?.trim();
    if (!login) return null;

    return { url: location.href, login, password: pwField.value, ts: Date.now() };
  }

  // Called synchronously from submit/click/keydown handlers.
  // Does NOT use async/await so the page can navigate freely.
  function handleFormSubmit(form) {
    const pending = captureCredentials(form);
    if (!pending) return;

    // Delegate storage to the service worker — it survives page navigation.
    // The content script can be killed mid-write; the service worker cannot.
    chrome.runtime.sendMessage({ action: 'storePendingSave', pending }).catch(() => {});

    // For SPAs that don't navigate: show the bar after 1 s on the same page.
    setTimeout(() => tryShowSaveBar(pending), 1000);
  }

  // Attach submit listeners to any form containing a password field.
  // Handles: traditional submit event, any button click, Enter key.
  function attachSaveListeners() {
    document.querySelectorAll('form').forEach((form) => {
      if (form.dataset.vaultSaveAttached) return;
      const pw = form.querySelector('input[type="password"]');
      if (!pw) return;
      form.dataset.vaultSaveAttached = 'true';

      // Traditional form submit (catches keyboard Enter and programmatic submit())
      form.addEventListener('submit', () => handleFormSubmit(form));

      // Any clickable element that could trigger submit
      // (covers <button>, <input type="submit">, <input type="button">)
      form.querySelectorAll('button, input[type="submit"], input[type="button"]').forEach((btn) => {
        btn.addEventListener('click', () => handleFormSubmit(form));
      });
    });

    // Enter key on any field outside a form, or when no submit button is present
    document.querySelectorAll('input[type="password"], input[type="email"], input[type="text"]')
      .forEach((input) => {
        if (input.dataset.vaultEnterAttached) return;
        input.dataset.vaultEnterAttached = 'true';
        input.addEventListener('keydown', (e) => {
          if (e.key !== 'Enter') return;
          const form = input.closest('form');
          if (form) handleFormSubmit(form);
        });
      });
  }

  // --- Init ---

  // Add badges to existing password fields (also suppresses native manager inside)
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

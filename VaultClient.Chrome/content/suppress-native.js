// ============================================================
// Sentil · suppress-native.js
// Runs in MAIN world at document_start — before Blink's
// AutofillAgent scans the DOM for credential fields.
//
// Goal: prevent Chrome/Edge/Firefox from ever showing the
// "Senhas salvas" / "Saved Passwords" autofill dropdown.
//
// Strategy (layered):
//   1. Override HTMLInputElement.prototype so every future
//      password field gets autocomplete="new-password" + readonly
//      the instant it's created/typed.
//   2. Block navigator.credentials.get for password-type requests.
//   3. MutationObserver catches fields added after DOMContentLoaded.
//   4. DOMContentLoaded sweep for any fields we missed.
// ============================================================

(function () {
  'use strict';

  const MANAGED = 'data-sentil-managed';

  // ── 1. Block navigator.credentials (JS-level) ────────────
  // Does not block Blink's C++ autofill UI, but prevents
  // programmatic credential retrieval by the page itself.
  try {
    const _get = navigator.credentials.get.bind(navigator.credentials);
    navigator.credentials.get = function (opts) {
      if (opts && opts.password) return Promise.resolve(null);
      return _get(opts);
    };
    navigator.credentials.preventSilentAccess?.();
  } catch (_) {}

  // ── Helpers ───────────────────────────────────────────────

  function patchPasswordField(el) {
    if (el.getAttribute(MANAGED)) return;
    el.setAttribute(MANAGED, '1');

    // "new-password" tells Chrome/Edge: this is a create-password
    // field → do NOT offer saved credentials. Most respected value.
    el.setAttribute('autocomplete', 'new-password');

    // Readonly trick: Blink skips autofill indexing on readonly fields.
    // Lifted only on the first keydown so typing still works instantly.
    if (!el.readOnly) {
      el.setAttribute('readonly', '');
      el.addEventListener('keydown', function lift() {
        el.removeAttribute('readonly');
        el.removeEventListener('keydown', lift);
      }, { capture: true, once: true });

      // Also lift on explicit programmatic focus from Sentil content script
      el.addEventListener('sentil:unlock', function () {
        el.removeAttribute('readonly');
      }, { once: true });
    }

    // Extra: remove autofill-related name/id tokens that Blink uses
    // to heuristically classify a field as a credential input.
    // We store originals so the page still functions.
    const origName = el.name;
    const origId   = el.id;
    if (/pass|pwd|senha|contraseña/i.test(origName + origId)) {
      el.dataset.sentilOrigName = origName;
      el.dataset.sentilOrigId   = origId;
      // Prefix with sentil_ — Blink's classifier won't recognize it
      if (origName) el.setAttribute('name', 'sentil_' + origName);
      if (origId)   el.setAttribute('id',   'sentil_' + origId);
    }
  }

  function patchUsernameField(el) {
    if (el.getAttribute(MANAGED)) return;
    el.setAttribute(MANAGED, '1');

    // "one-time-code" → browser treats field as OTP, not username.
    // Most reliable hack to prevent saved-password dropdown on user fields.
    el.setAttribute('autocomplete', 'one-time-code');
    el.setAttribute('data-lpignore', 'true');
    el.setAttribute('data-1p-ignore', 'true');
    el.setAttribute('data-bwignore', 'true');

    if (!el.readOnly) {
      el.setAttribute('readonly', '');
      el.addEventListener('keydown', function lift() {
        el.removeAttribute('readonly');
        el.removeEventListener('keydown', lift);
      }, { capture: true, once: true });
    }
  }

  function isUsernameCandidate(el) {
    if (el.type === 'password' || el.type === 'hidden' || el.type === 'submit') return false;
    const hay = `${el.name} ${el.id} ${el.autocomplete} ${el.placeholder}`.toLowerCase();
    return /user|email|login|identif|account|cpf|usuario|usu/.test(hay);
  }

  function sweepAll() {
    document.querySelectorAll('input[type="password"]').forEach(patchPasswordField);
    document.querySelectorAll('input').forEach((el) => {
      if (isUsernameCandidate(el)) patchUsernameField(el);
    });
  }

  // ── 2. Intercept HTMLInputElement.type setter ─────────────
  // Fires the instant any script does input.type = 'password'
  // or the parser sets type="password" on a newly parsed element.
  const typeDesc = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'type');
  if (typeDesc?.set) {
    const _typeSet = typeDesc.set;
    Object.defineProperty(HTMLInputElement.prototype, 'type', {
      ...typeDesc,
      set(val) {
        _typeSet.call(this, val);
        if (val === 'password') patchPasswordField(this);
      },
    });
  }

  // Intercept setAttribute so dynamic changes are caught too
  const _setAttribute = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (name, value) {
    _setAttribute.call(this, name, value);
    if (
      name === 'type' &&
      value === 'password' &&
      this instanceof HTMLInputElement
    ) {
      patchPasswordField(this);
    }
  };

  // ── 3. MutationObserver ───────────────────────────────────
  // Catches fields added by SPA routers / dynamic forms.

  function observe(root) {
    new MutationObserver((mutations) => {
      for (const m of mutations) {
        for (const node of m.addedNodes) {
          if (node.nodeType !== 1) continue;
          if (node.matches?.('input[type="password"]')) {
            patchPasswordField(node);
          } else {
            node.querySelectorAll?.('input[type="password"]').forEach(patchPasswordField);
          }
          if (node.matches?.('input') && isUsernameCandidate(node)) {
            patchUsernameField(node);
          } else {
            node.querySelectorAll?.('input').forEach((el) => {
              if (isUsernameCandidate(el)) patchUsernameField(el);
            });
          }
        }
      }
    }).observe(root, { childList: true, subtree: true });
  }

  if (document.body) {
    observe(document.body);
  } else {
    const waitBody = new MutationObserver(() => {
      if (document.body) {
        waitBody.disconnect();
        observe(document.body);
      }
    });
    waitBody.observe(document.documentElement, { childList: true });
  }

  // ── 4. DOMContentLoaded sweep ─────────────────────────────
  document.addEventListener('DOMContentLoaded', sweepAll, { once: true });

  // ── 5. Restore name/id for form submit ───────────────────
  // When the form is submitted, restore original name/id so the
  // page's submit handler receives the right field names.
  document.addEventListener('submit', (e) => {
    const form = e.target;
    if (!(form instanceof HTMLFormElement)) return;
    form.querySelectorAll('[data-sentil-orig-name], [data-sentil-orig-id]').forEach((el) => {
      if (el.dataset.sentilOrigName) el.setAttribute('name', el.dataset.sentilOrigName);
      if (el.dataset.sentilOrigId)   el.setAttribute('id',   el.dataset.sentilOrigId);
    });
  }, true);

})();

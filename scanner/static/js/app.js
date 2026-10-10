/* Wi-Fi Radar Pro — shared application logic */
(() => {
  'use strict';

  const CFG = window.WIFI_CFG || {};
  const state = {
    timer: null,
    busy: false,
    lastPayload: null,
    refreshSeconds: Number(CFG.refreshSeconds) || 5,
  };

  /* ---------------------------------------------------------------- utils */

  function getCookie(name) {
    const match = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '=([^;]*)'));
    return match ? decodeURIComponent(match[1]) : '';
  }

  async function api(url, options = {}) {
    const opts = Object.assign({ credentials: 'same-origin', headers: {} }, options);
    opts.headers = Object.assign({
      'X-CSRFToken': getCookie('csrftoken') || CFG.csrfToken || '',
      'Content-Type': 'application/json',
    }, opts.headers);
    const response = await fetch(url, opts);
    let data = null;
    try { data = await response.json(); } catch (_) { data = {}; }
    if (!response.ok) {
      const error = new Error(data.detail || data.message || `Request failed (${response.status})`);
      error.status = response.status;
      error.data = data;
      throw error;
    }
    return data;
  }

  function toast(message, type = 'info', ttl = 4200) {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const el = document.createElement('div');
    el.className = `toast-notice ${type}`;
    const icons = { success: 'fa-circle-check', error: 'fa-circle-xmark', info: 'fa-circle-info' };
    el.innerHTML = `<i class="fa-solid ${icons[type] || icons.info}"></i><span></span>`;
    el.querySelector('span').textContent = message;
    container.appendChild(el);
    setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity .4s'; setTimeout(() => el.remove(), 400); }, ttl);
  }

  function setBadge(text, mode = '') {
    const badge = document.getElementById('scan-badge');
    if (!badge) return;
    badge.classList.remove('busy', 'error');
    if (mode) badge.classList.add(mode);
    badge.lastChild.textContent = ` ${text}`;
  }

  const classOf = (signal) => (signal >= 75 ? 'strong' : signal >= 40 ? 'medium' : 'weak');
  const colorOf = (signal) => (signal >= 75 ? '#3dff9a' : signal >= 40 ? '#ffd166' : '#ff5d73');
  const esc = (value) => String(value == null ? '' : value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

  /* -------------------------------------------------------------- scanner */

  async function scanOnce(force = false) {
    if (state.busy) return state.lastPayload;
    state.busy = true;
    setBadge('scanning', 'busy');
    try {
      const payload = await api(`${CFG.urls.scan}${force ? '?force=1' : ''}`);
      state.lastPayload = payload;
      setBadge(`updated ${new Date().toLocaleTimeString()}`);
      document.dispatchEvent(new CustomEvent('wifi:scan', { detail: payload }));
      return payload;
    } catch (error) {
      setBadge(error.status === 503 ? 'adapter unavailable' : 'scan failed', 'error');
      document.dispatchEvent(new CustomEvent('wifi:scan:error', { detail: error }));
      if (error.status !== 503) toast(error.message, 'error');
      return null;
    } finally {
      state.busy = false;
    }
  }

  function startPolling() {
    stopPolling();
    state.timer = setInterval(() => scanOnce(false), Math.max(1, state.refreshSeconds) * 1000);
  }

  function stopPolling() {
    if (state.timer) clearInterval(state.timer);
    state.timer = null;
  }

  /* ---------------------------------------------------------- agent status */

  async function checkAgent() {
    const pill = document.getElementById('agent-pill');
    try {
      const data = await api(CFG.urls.connected);
      const online = Boolean(data.agent && data.agent.reachable);
      if (pill) {
        pill.classList.toggle('online', online);
        pill.classList.toggle('offline', !online);
        pill.querySelector('span:last-child').textContent = online ? 'Agent online' : 'Agent offline';
      }
      document.dispatchEvent(new CustomEvent('wifi:agent', { detail: data.agent || {} }));
      return data.agent;
    } catch (_) {
      if (pill) {
        pill.classList.add('offline');
        pill.querySelector('span:last-child').textContent = 'Agent offline';
      }
      return { reachable: false };
    }
  }

  /* ----------------------------------------------------------- connect modal */

  const modal = {
    el: document.getElementById('connect-modal'),
    ssid: document.getElementById('cm-ssid'),
    meta: document.getElementById('cm-meta'),
    password: document.getElementById('cm-password'),
    result: document.getElementById('cm-result'),
    submit: document.getElementById('cm-submit'),
    warning: document.getElementById('cm-auth-warning'),
    current: null,
  };

  function openConnectModal(info) {
    if (!modal.el) return;
    modal.current = info;
    modal.ssid.textContent = info.ssid;
    modal.meta.textContent = `${info.security || 'Open'} · signal ${info.signal}% · ${info.bssid || 'BSSID unknown'}`;
    modal.password.value = '';
    modal.result.textContent = '';
    modal.result.className = 'mt-2 small';
    const secured = !/^(open|owe)$/i.test((info.security || '').trim()) && (info.security || '') !== '';
    const passwordLabel = document.getElementById('cm-password-label');
    const passwordGroup = modal.password.closest('.input-group');
    if (passwordLabel) passwordLabel.hidden = !secured;
    if (passwordGroup) passwordGroup.hidden = !secured;
    const unauthorized = !CFG.isAuthenticated;
    if (modal.warning) modal.warning.hidden = !unauthorized;
    modal.submit.disabled = unauthorized;
    modal.el.hidden = false;
    if (!unauthorized && secured) setTimeout(() => modal.password.focus(), 80);
  }

  function closeConnectModal() {
    if (modal.el) modal.el.hidden = true;
    modal.current = null;
  }

  async function submitConnect() {
    if (!modal.current || modal.submit.disabled) return;
    const info = modal.current;
    modal.submit.disabled = true;
    modal.result.textContent = 'Contacting local agent…';
    modal.result.className = 'mt-2 small text-info';
    try {
      const body = { ssid: info.ssid };
      const secured = !/^(open|owe)$/i.test((info.security || '').trim()) && (info.security || '') !== '';
      if (secured) body.password = modal.password.value;
      const data = await api(CFG.urls.connect, { method: 'POST', body: JSON.stringify(body) });
      modal.result.textContent = data.message || 'Connected.';
      modal.result.className = 'mt-2 small text-success';
      toast(data.message || `Connected to ${info.ssid}`, 'success');
      scanOnce(true);
      setTimeout(closeConnectModal, 1400);
    } catch (error) {
      const data = error.data || {};
      modal.result.textContent = data.message || error.message;
      modal.result.className = 'mt-2 small text-danger';
      if (data.password_required) modal.password.focus();
      toast(data.message || error.message, 'error');
    } finally {
      modal.submit.disabled = false;
    }
  }

  /* -------------------------------------------------------------- chrome */

  function initChrome() {
    const sidebar = document.getElementById('sidebar');
    const toggle = document.getElementById('sidebar-toggle');
    if (toggle && sidebar) {
      toggle.addEventListener('click', () => sidebar.classList.toggle('show'));
      document.addEventListener('click', (event) => {
        if (!sidebar.classList.contains('show')) return;
        if (sidebar.contains(event.target) || toggle.contains(event.target)) return;
        sidebar.classList.remove('show');
      });
    }

    const themeBtn = document.getElementById('theme-toggle');
    const savedTheme = localStorage.getItem('wifi-radar-theme') || 'dark';
    document.documentElement.setAttribute('data-bs-theme', savedTheme);
    const paintThemeIcon = () => {
      const icon = themeBtn && themeBtn.querySelector('i');
      if (icon) icon.className = document.documentElement.getAttribute('data-bs-theme') === 'dark' ? 'fa-solid fa-moon' : 'fa-solid fa-sun';
    };
    paintThemeIcon();
    if (themeBtn) {
      themeBtn.addEventListener('click', () => {
        const next = document.documentElement.getAttribute('data-bs-theme') === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-bs-theme', next);
        localStorage.setItem('wifi-radar-theme', next);
        paintThemeIcon();
        document.dispatchEvent(new CustomEvent('wifi:theme', { detail: next }));
      });
    }

    const refreshBtn = document.getElementById('refresh-now');
    if (refreshBtn) refreshBtn.addEventListener('click', () => { scanOnce(true); toast('Scanning…', 'info', 1800); });

    if (modal.el) {
      document.querySelectorAll('.js-connect').forEach((btn) => {
        btn.addEventListener('click', () => openConnectModal({
          ssid: btn.dataset.ssid,
          security: btn.dataset.security,
          signal: Number(btn.dataset.signal || 0),
          bssid: btn.dataset.bssid,
        }));
      });
      document.getElementById('cm-close').addEventListener('click', closeConnectModal);
      document.getElementById('cm-cancel').addEventListener('click', closeConnectModal);
      modal.el.addEventListener('click', (event) => { if (event.target === modal.el) closeConnectModal(); });
      document.getElementById('cm-submit').addEventListener('click', submitConnect);
      modal.password.addEventListener('keydown', (event) => { if (event.key === 'Enter') submitConnect(); });
      const reveal = document.getElementById('cm-reveal');
      reveal.addEventListener('click', () => {
        const showing = modal.password.type === 'text';
        modal.password.type = showing ? 'password' : 'text';
        reveal.querySelector('i').className = showing ? 'fa-solid fa-eye' : 'fa-solid fa-eye-slash';
      });
    }

    document.querySelectorAll('.toast-notice').forEach((el) => {
      setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity .5s'; setTimeout(() => el.remove(), 500); }, 5000);
    });
  }

  /* ----------------------------------------------------------------- boot */

  window.WifiRadar = {
    api, toast, scanOnce, startPolling, stopPolling, checkAgent,
    openConnectModal, closeConnectModal,
    classOf, colorOf, esc,
    get state() { return state; },
  };

  document.addEventListener('DOMContentLoaded', () => {
    initChrome();
    checkAgent();
    scanOnce(false).then(() => startPolling());
    setInterval(checkAgent, 20000);
  });
})();

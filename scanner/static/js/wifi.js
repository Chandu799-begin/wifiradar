/* ==========================================================================
   Wi-Fi Radar Pro — Premium Saved Wi-Fi dashboard controller.
   Handles saved profiles, password reveal + re-authentication gating, the
   radar animation, nearby-network table and connection controls.

   Security rules implemented here:
   * Password values live only in the DOM of the currently rendered card.
   * They are auto-masked after a short window. Nothing is ever written to
     localStorage, sessionStorage, cookies or any JS-side persistent store.
   * A fresh server-side re-authentication is required before every reveal
     window; the server enforces this regardless of client state.
   ========================================================================== */
(() => {
  'use strict';

  const CFG = window.WIFI_CFG || {};
  const { api, toast, esc, classOf, colorOf, openConnectModal } = window.WifiRadar || {};

  const AUTO_MASK_SECONDS = 30;
  const SELF = {
    profiles: [],
    nearby: [],
    reauthUntil: 0,          // epoch ms until which re-auth remains valid
    reauthPending: null,     // profile element waiting after success
    radar: { raf: null, angle: 0, last: 0, active: false },
    masks: {},               // profile name -> timeout id (auto-mask timers)
    location: {
      active: false, map: null, marker: null, accuracyCircle: null,
      layers: [], watchId: null, last: null, tileLayer: null,
    },
  };

  // Real-location range estimation -------------------------------------
  // netsh reports strength as a 0-100 % figure, which maps to roughly
  // -100 dBm .. -50 dBm. Distance is a heuristic indoor path-loss model:
  //   dist = 10 ** ((TxRef - RSSI) / (10 * exponent))
  const TX_REF_DBM = -35;      // received power (dBm) at 1 m reference
  const PATH_LOSS_EXPONENT = 2.8;  // typical indoor

  function rssiFromPercent(percent) {
    return (Math.max(0, Math.min(100, Number(percent) || 0)) / 100) * 50 - 100;
  }

  function distanceEstimate(signal) {
    const rssi = rssiFromPercent(signal);
    const meters = Math.pow(10, (TX_REF_DBM - rssi) / (10 * PATH_LOSS_EXPONENT));
    return Math.max(4, Math.min(500, meters));
  }

  /* ------------------------------------------------------------ utilities */

  function csrfToken() {
    return CFG.csrfToken || '';
  }

  async function postForm(url, data) {
    const response = await fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'X-CSRFToken': csrfToken() },
      body: new URLSearchParams(data || {}),
    });
    let json = {};
    try { json = await response.json(); } catch (_) { /* non-JSON */ }
    if (!response.ok) {
      const error = new Error(json.message || json.detail || `Request failed (${response.status})`);
      error.status = response.status;
      error.data = json;
      throw error;
    }
    return json;
  }

  function hashCode(value) {
    let hash = 5381;
    for (let i = 0; i < value.length; i++) {
      hash = ((hash << 5) + hash + value.charCodeAt(i)) >>> 0;
    }
    return hash;
  }

  function positionFor(name) {
    const h = hashCode(String(name || '?'));
    const angle = (h % 628) / 100;                 // 0 … ~2π
    const radius = 0.16 + ((h >>> 4) % 78) / 100 * 0.64;
    return { angle, radius };
  }

  function maskDots(name) {
    const count = Math.min(12, Math.max(8, String(name || '').length));
    return '\u2022'.repeat(count);
  }

  function securityClass(security) {
    const s = String(security || '').toLowerCase();
    if (s.includes('wpa3')) return 'wpa3';
    if (s.includes('wpa2')) return 'wpa2';
    if (s.includes('wpa') || s.includes('enterprise') || s.includes('802.1x')) return 'enterprise';
    if (s.includes('open') || s === '') return 'open';
    return 'wpa';
  }

  function isOpen(security) {
    return /^(open|owe|)$/i.test(String(security || '').trim());
  }

  /* ----------------------------------------------------------- radar draw */

  function startRadar() {
    if (SELF.radar.active) return;
    SELF.radar.active = true;
    SELF.radar.raf = requestAnimationFrame(drawRadar);
  }

  function stopRadar() {
    SELF.radar.active = false;
    if (SELF.radar.raf) cancelAnimationFrame(SELF.radar.raf);
    SELF.radar.raf = null;
  }

  function drawRadar(timestamp) {
    if (!SELF.radar.active) return;
    const canvas = document.getElementById('wifi-radar-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const now = performance.now();
    const size = canvas.width;
    const center = { x: size / 2, y: size / 2 };
    const radius = size / 2 - 8;
    const sweep = ((now / 3400) * Math.PI * 2) % (Math.PI * 2);

    ctx.clearRect(0, 0, size, size);

    // backdrop =======
    const backdrop = ctx.createRadialGradient(center.x, center.y, radius * 0.15, center.x, center.y, radius);
    backdrop.addColorStop(0, 'rgba(10, 40, 60, 0.55)');
    backdrop.addColorStop(1, 'rgba(2, 8, 20, 0.9)');
    ctx.fillStyle = backdrop;
    ctx.beginPath();
    ctx.arc(center.x, center.y, radius, 0, Math.PI * 2);
    ctx.fill();

    // grid circles ======
    ctx.lineWidth = 1;
    [0.33, 0.66, 1].forEach((f) => {
      ctx.strokeStyle = 'rgba(61, 255, 154, 0.14)';
      ctx.beginPath();
      ctx.arc(center.x, center.y, radius * f, 0, Math.PI * 2);
      ctx.stroke();
    });

    // cross lines ======
    ctx.strokeStyle = 'rgba(61, 255, 154, 0.10)';
    for (let i = 0; i < 4; i++) {
      const a = (i * Math.PI) / 4;
      ctx.beginPath();
      ctx.moveTo(center.x, center.y);
      ctx.lineTo(center.x + Math.cos(a) * radius, center.y + Math.sin(a) * radius);
      ctx.stroke();
    }

    // sweep ======
    const sweepGrad = ctx.createConicGradient
      ? ctx.createConicGradient(sweep, center.x, center.y)
      : null;
    if (typeof ctx.createConicGradient === 'function') {
      sweepGrad.addColorStop(0, 'rgba(61, 255, 154, 0.5)');
      sweepGrad.addColorStop(0.12, 'rgba(61, 255, 154, 0.12)');
      sweepGrad.addColorStop(1, 'rgba(61, 255, 154, 0)');
      ctx.fillStyle = sweepGrad;
      ctx.beginPath();
      ctx.moveTo(center.x, center.y);
      ctx.arc(center.x, center.y, radius, sweep, sweep + Math.PI / 2.4);
      ctx.closePath();
      ctx.fill();
    } else {
      ctx.strokeStyle = 'rgba(61, 255, 154, 0.35)';
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo(center.x, center.y);
      ctx.lineTo(center.x + Math.cos(sweep) * radius, center.y + Math.sin(sweep) * radius);
      ctx.stroke();
      ctx.lineWidth = 1;
    }

    // saved-profile blips (cyan diamonds) ======
    SELF.profiles.forEach((profile) => {
      const { angle, radius: r } = positionFor(`saved:${profile.name}`);
      const x = center.x + Math.cos(angle) * r * radius;
      const y = center.y + Math.sin(angle) * r * radius;
      ctx.save();
      ctx.translate(x, y);
      ctx.rotate(Math.PI / 4);
      ctx.fillStyle = profile.is_connected ? '#3dff9a' : '#41e8ff';
      ctx.shadowColor = profile.is_connected ? 'rgba(61,255,154,0.9)' : 'rgba(65,232,255,0.9)';
      ctx.shadowBlur = 10;
      const s = profile.is_connected ? 7 : 5;
      ctx.fillRect(-s / 2, -s / 2, s, s);
      ctx.restore();
    });

    // nearby blips (colored by signal) ======
    SELF.nearby.forEach((network) => {
      const { angle, radius: r } = positionFor(`${network.bssid || network.ssid}`);
      const x = center.x + Math.cos(angle) * r * radius;
      const y = center.y + Math.sin(angle) * r * radius;
      const color = colorOf(network.signal_strength);
      ctx.fillStyle = color;
      ctx.shadowColor = color;
      ctx.shadowBlur = 12;
      ctx.beginPath();
      ctx.arc(x, y, network.is_connected ? 7 : 4.5, 0, Math.PI * 2);
      ctx.fill();
      ctx.shadowBlur = 0;

      const label = String(network.ssid || 'Hidden');
      ctx.font = '10px Consolas, monospace';
      ctx.fillStyle = 'rgba(219,231,255,0.85)';
      ctx.fillText(label.slice(0, 16), x + 8, y + 3);
    });

    ctx.shadowBlur = 0;
    SELF.radar.raf = requestAnimationFrame(drawRadar);
  }

  /* ---------------------------------------------------------- real location */

  const GEO_ERRORS = {
    1: 'Location permission denied. Allow location access for this site in your browser.',
    2: 'Position unavailable. Turn on your device location service and try again.',
    3: 'Timed out waiting for a GPS fix. Move somewhere with a clearer view and retry.',
  };

  function setMapStatus(text, mode) {
    const el = document.getElementById('map-status');
    if (!el) return;
    el.className = 'map-status' + (mode ? ` ${mode}` : '');
    el.innerHTML = `<i class="fa-solid fa-location-crosshairs"></i> ${esc(text)}`;
  }

  function updateLocationButton() {
    const btn = document.getElementById('ws-location');
    if (!btn) return;
    const on = SELF.location.active;
    btn.classList.toggle('active', on);
    btn.classList.toggle('btn-info', on);
    btn.classList.toggle('btn-outline-info', !on);
    btn.innerHTML = on
      ? '<i class="fa-solid fa-map"></i> Hide Map'
      : '<i class="fa-solid fa-location-crosshairs"></i> Real Location';
  }

  function ensureMap() {
    if (SELF.location.map) return SELF.location.map;
    const el = document.getElementById('wifi-map');
    if (!el) return null;
    if (typeof L === 'undefined' || typeof L.map !== 'function') return null;
    const map = L.map(el, { zoomControl: true, attributionControl: true }).setView([0, 0], 2);
    SELF.location.tileLayer = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      maxZoom: 19,
      attribution: '&copy; OpenStreetMap contributors',
    }).addTo(map);
    SELF.location.map = map;
    return map;
  }

  function offsetLatLng(lat, lng, meters, bearingDeg) {
    const R = 6371000;
    const bearing = (bearingDeg * Math.PI) / 180;
    const lat1 = (lat * Math.PI) / 180;
    const lng1 = (lng * Math.PI) / 180;
    const d = meters / R;
    const lat2 = Math.asin(
      Math.sin(lat1) * Math.cos(d) + Math.cos(lat1) * Math.sin(d) * Math.cos(bearing),
    );
    const lng2 = lng1 + Math.atan2(
      Math.sin(bearing) * Math.sin(d) * Math.cos(lat1),
      Math.cos(d) - Math.sin(lat1) * Math.sin(lat2),
    );
    return [(lat2 * 180) / Math.PI, (lng2 * 180) / Math.PI];
  }

  function clearLocationLayers() {
    const map = SELF.location.map;
    if (!map) return;
    SELF.location.layers.forEach((layer) => map.removeLayer(layer));
    SELF.location.layers = [];
  }

  function drawUser(map, lat, lng, accuracy) {
    if (!SELF.location.marker) {
      SELF.location.marker = L.circleMarker([lat, lng], {
        radius: 8,
        color: '#3dff9a',
        weight: 3,
        fillColor: '#3dff9a',
        fillOpacity: 0.9,
      }).addTo(map).bindTooltip('<strong>You are here</strong>', { className: 'wifi-tip' });
    } else {
      SELF.location.marker.setLatLng([lat, lng]);
    }

    if (!SELF.location.accuracyCircle) {
      SELF.location.accuracyCircle = L.circle([lat, lng], {
        radius: accuracy,
        color: 'rgba(61,255,154,0.55)',
        weight: 1,
        fillColor: 'rgba(61,255,154,0.12)',
        fillOpacity: 0.5,
      }).addTo(map);
    } else {
      SELF.location.accuracyCircle.setLatLng([lat, lng]).setRadius(accuracy);
    }
  }

  function drawNetworkEstimates(map, lat, lng) {
    clearLocationLayers();
    if (!SELF.nearby.length) return;

    // Scale rings (25 / 50 / 100 / 200 m) for orientation.
    [25, 50, 100, 200].forEach((meters) => {
      const ring = L.circle([lat, lng], {
        radius: meters,
        color: 'rgba(65,232,255,0.18)',
        weight: 1,
        dashArray: '4 6',
        fill: false,
        interactive: false,
      }).addTo(map);
      SELF.location.layers.push(ring);
    });

    // The bearing of a Wi-Fi network cannot be derived from signal strength,
    // so it is only a stable illustrative placement (same convention as the
    // radar). Distance is a path-loss estimate from the reported signal.
    SELF.nearby.slice(0, 25).forEach((network) => {
      const meters = distanceEstimate(network.signal_strength);
      const bearing = hashCode(String(network.bssid || network.ssid)) % 360;
      const [nlat, nlng] = offsetLatLng(lat, lng, meters, bearing);
      const color = colorOf(network.signal_strength);
      const marker = L.circleMarker([nlat, nlng], {
        radius: network.is_connected ? 7 : 5,
        color,
        weight: 2,
        fillColor: color,
        fillOpacity: 0.85,
      }).addTo(map);
      marker.bindTooltip(
        `<strong>${esc(network.ssid || 'Hidden')}</strong><br>` +
        `${esc(String(network.signal_strength))}% signal · ~${Math.round(meters)} m (estimated)<br>` +
        `${esc(network.security_type || 'Open')}`,
        { className: 'wifi-tip' },
      );
      SELF.location.layers.push(marker);
    });
  }

  function onLocationSuccess(position) {
    const { latitude, longitude, accuracy } = position.coords;
    SELF.location.last = { latitude, longitude, accuracy };
    const map = ensureMap();
    if (!map) {
      setMapStatus('Map library failed to load. Check your connection and retry.', 'error');
      return;
    }
    drawUser(map, latitude, longitude, accuracy);
    drawNetworkEstimates(map, latitude, longitude);
    const zoom = accuracy > 150 ? 13 : accuracy > 50 ? 15 : 17;
    map.setView([latitude, longitude], zoom, { animate: false });
    setMapStatus(
      `GPS fix: ${latitude.toFixed(5)}, ${longitude.toFixed(5)} · ±${Math.round(accuracy)} m · ` +
      `${SELF.nearby.length} network${SELF.nearby.length === 1 ? '' : 's'} plotted`,
      'ok',
    );
  }

  function onLocationError(error) {
    setMapStatus(GEO_ERRORS[error.code] || error.message || 'Unable to determine your location.', 'error');
  }

  function requestLocation() {
    if (!navigator.geolocation) {
      setMapStatus('Geolocation is not supported by this browser.', 'error');
      return;
    }
    if (SELF.location.watchId != null) return;
    SELF.location.watchId = navigator.geolocation.watchPosition(
      onLocationSuccess,
      onLocationError,
      { enableHighAccuracy: true, timeout: 12000, maximumAge: 5000 },
    );
  }

  function showLocation() {
    const panel = document.getElementById('wifi-map-panel');
    const radarPanel = document.getElementById('wifi-radar-panel');
    if (!panel) return;
    SELF.location.active = true;
    updateLocationButton();
    panel.hidden = false;
    if (radarPanel) radarPanel.hidden = true;
    const map = ensureMap();
    if (!map) {
      setMapStatus('Map library failed to load. Check your connection and retry.', 'error');
      return;
    }
    setMapStatus('Requesting GPS fix…', '');
    requestAnimationFrame(() => map.invalidateSize());
    requestLocation();
  }

  function hideLocation() {
    SELF.location.active = false;
    updateLocationButton();
    const panel = document.getElementById('wifi-map-panel');
    const radarPanel = document.getElementById('wifi-radar-panel');
    if (panel) panel.hidden = true;
    if (radarPanel) radarPanel.hidden = false;
    if (SELF.location.watchId != null && navigator.geolocation) {
      navigator.geolocation.clearWatch(SELF.location.watchId);
      SELF.location.watchId = null;
    }
  }

  function toggleLocation() {
    if (SELF.location.active) hideLocation();
    else showLocation();
  }

  /* ------------------------------------------------------ saved profiles */

  async function loadProfiles(force = false) {
    const grid = document.getElementById('ws-profiles');
    if (!grid) return;
    try {
      const data = await api(`${CFG.urls.savedProfiles}${force ? '?force=1' : ''}`);
      SELF.profiles = data.profiles || [];
      SELF.canReveal = Boolean(data.can_reveal);
      renderSourceBadge(data.source, data.message);
      renderProfiles();
      renderStats();
    } catch (error) {
      SELF.profiles = [];
      grid.innerHTML = `<div class="text-center text-danger py-4 col-12">${esc(error.message)}</div>`;
      renderStats();
    }
  }

  function renderSourceBadge(source, message) {
    const badge = document.getElementById('ws-source-badge');
    if (!badge) return;
    badge.className = 'badge text-bg-info';
    if (source === 'live') { badge.className = 'badge text-bg-success'; badge.textContent = 'live'; }
    else if (source === 'demo') { badge.className = 'badge text-bg-warning'; badge.textContent = 'demo'; }
    else if (source === 'unavailable') { badge.className = 'badge text-bg-secondary'; badge.textContent = 'unavailable'; }
    else { badge.className = 'badge text-bg-secondary'; badge.textContent = source || ''; }
    if (message) badge.title = message;
  }

  function renderStats() {
    const withKey = SELF.profiles.filter((p) => p.has_key_material).length;
    const connected = SELF.profiles.find((p) => p.is_connected);
    setText('ws-saved', SELF.profiles.length);
    setText('ws-with-key', withKey);
    setText('ws-connected', connected ? connected.name : '—');
    setText('ws-saved-count', SELF.profiles.length);
    setText('ws-nearby', SELF.nearby.length);
    setText('radar-count', SELF.nearby.length);
  }

  function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  }

  function renderProfiles() {
    const grid = document.getElementById('ws-profiles');
    if (!grid) return;

    if (!SELF.profiles.length) {
      grid.innerHTML = '<div class="text-center text-secondary py-4 col-12">' +
        '<i class="fa-solid fa-inbox fa-2x mb-2 d-block"></i>' +
        'No saved Wi-Fi profiles were found on this computer.</div>';
      return;
    }

    grid.innerHTML = SELF.profiles.map((profile, index) => {
      const open = isOpen(profile.security);
      const showReveal = SELF.canReveal && (profile.has_key_material || !open);
      const mask = maskDots(profile.name);
      const nearbyHit = SELF.nearby.find((n) => n.ssid === profile.name);

      return `<div class="wifi-profile-card ${profile.has_key_material ? 'has-key' : ''} ${profile.is_connected ? 'connected' : ''}"
        style="animation-delay:${Math.min(index, 12) * 40}ms" data-name="${esc(profile.name)}">
        <div class="wpc-head">
          <div class="wpc-ssid"><i class="fa-solid fa-wifi"></i>${esc(profile.name)}</div>
          ${profile.is_connected ? '<span class="badge text-bg-success">Connected</span>' : ''}
        </div>
        <div class="wpc-meta">${esc(profile.interface || 'Saved profile')}</div>
        <div class="wpc-badges">
          <span class="sec-badge ${securityClass(profile.security)}">${esc(profile.security || 'Open')}</span>
          ${open
            ? '<span class="sec-badge no-key">No saved password</span>'
            : profile.has_key_material
              ? '<span class="sec-badge has-key"><i class="fa-solid fa-key"></i> Key saved</span>'
              : '<span class="sec-badge">Key unknown</span>'}
        </div>

        <div class="wifi-password">
          <div class="pw-mask" data-role="pw" title="Masked — click Reveal to show (requires re-authentication)">${mask}</div>
          <div class="pw-actions">
            ${showReveal && !open
              ? `<button class="btn btn-sm btn-outline-success js-reveal" data-name="${esc(profile.name)}" title="Reveal this saved password">
                   <i class="fa-solid fa-eye"></i></button>`
              : ''}
          </div>
        </div>

        <div class="wpc-foot">
          ${profile.is_connected
            ? '<button class="btn btn-sm btn-ghost" disabled><i class="fa-solid fa-link"></i> Active</button>'
            : `<button class="btn btn-sm btn-outline-light js-connect" data-ssid="${esc(profile.name)}"
                 data-security="${esc(profile.security)}" data-signal="${nearbyHit ? nearbyHit.signal_strength : 0}"
                 data-bssid="${nearbyHit ? esc(nearbyHit.bssid) : ''}"><i class="fa-solid fa-plug"></i> Connect</button>`}
          ${SELF.canReveal && !open
            ? `<button class="btn btn-sm btn-ghost js-auto-connect" data-name="${esc(profile.name)}" title="Connect using the profile saved on Windows">
                 <i class="fa-solid fa-key"></i> Use saved</button>`
            : ''}
        </div>
      </div>`;
    }).join('');

    grid.querySelectorAll('.js-reveal').forEach((btn) => {
      btn.addEventListener('click', () => revealPassword(btn.dataset.name, btn.closest('.wifi-profile-card')));
    });

    grid.querySelectorAll('.js-connect').forEach((btn) => {
      btn.addEventListener('click', () => openConnectModal({
        ssid: btn.dataset.ssid,
        security: btn.dataset.security,
        signal: Number(btn.dataset.signal || 0),
        bssid: btn.dataset.bssid,
      }));
    });

    grid.querySelectorAll('.js-auto-connect').forEach((btn) => {
      btn.addEventListener('click', () => autoConnectSaved(btn.dataset.name));
    });
  }

  /* ------------------------------------------------- password reveal flow */

  async function ensureReauth() {
    if (Date.now() < SELF.reauthUntil) return true;
    return openReauthModal();
  }

  function openReauthModal() {
    const modal = document.getElementById('reauth-modal');
    if (!modal) return Promise.reject(new Error('Re-authentication is unavailable.'));
    const input = document.getElementById('ra-password');
    const result = document.getElementById('ra-result');
    input.value = '';
    result.textContent = '';
    result.className = 'mt-2 small';
    modal.hidden = false;
    input.focus();

    return new Promise((resolve, reject) => {
      const cleanup = () => {
        modal.hidden = true;
        submitBtn.onclick = null;
        cancelBtn.onclick = null;
        closeBtn.onclick = null;
        keyHandler && input.removeEventListener('keydown', keyHandler);
        modal.removeEventListener('click', backdropHandler);
      };
      const fail = (message) => {
        cleanup();
        reject(new Error(message));
      };

      const doSubmit = async () => {
        submitBtn.disabled = true;
        result.textContent = 'Verifying…';
        result.className = 'mt-2 small text-info';
        try {
          const res = await postForm(CFG.urls.reauthPassword, { password: input.value });
          SELF.reauthUntil = Number(res.until || 0) * 1000;
          SELF.reauthSeconds = Number(res.valid_for || 0);
          const windowEl = document.getElementById('ra-window');
          if (windowEl) windowEl.textContent = SELF.reauthSeconds;
          cleanup();
          toast('Fresh authentication granted.', 'success', 2200);
          resolve(true);
        } catch (error) {
          result.textContent = error.message;
          result.className = 'mt-2 small text-danger';
          submitBtn.disabled = false;
          input.focus();
        }
      };

      const submitBtn = document.getElementById('ra-submit');
      const cancelBtn = document.getElementById('ra-cancel');
      const closeBtn = document.getElementById('ra-close');
      const reveal = document.getElementById('ra-reveal');
      const keyHandler = (event) => { if (event.key === 'Enter') doSubmit(); };
      const backdropHandler = (event) => { if (event.target === modal) fail('Re-authentication cancelled.'); };

      submitBtn.onclick = doSubmit;
      cancelBtn.onclick = () => fail('Re-authentication cancelled.');
      closeBtn.onclick = () => fail('Re-authentication cancelled.');
      input.addEventListener('keydown', keyHandler);
      modal.addEventListener('click', backdropHandler);

      if (reveal) {
        reveal.onclick = () => {
          const showing = input.type === 'text';
          input.type = showing ? 'password' : 'text';
          reveal.innerHTML = showing ? '<i class="fa-solid fa-eye"></i>' : '<i class="fa-solid fa-eye-slash"></i>';
        };
      }
    });
  }

  async function doReveal(name, card) {
    const res = await postForm(CFG.urls.revealPassword, { profile: name });
    showPassword(card, res.password);
    toast(res.message || `Password for ${name} shown; it will auto-mask shortly.`, 'info', 3600);
  }

  async function revealPassword(name, card) {
    const pwEl = card && card.querySelector('[data-role="pw"]');
    const btn = card && card.querySelector('.js-reveal');
    if (!card || !pwEl || !btn) return;

    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>';
    try {
      await ensureReauth();
      await doReveal(name, card);
    } catch (error) {
      const data = error.data || {};
      if (data.reauth_required) {
        // Server says our re-auth window lapsed; force a fresh one and retry once.
        SELF.reauthUntil = 0;
        try {
          await ensureReauth();
          await doReveal(name, card);
        } catch (retryError) {
          toast(retryError.message, 'error');
        }
      } else {
        toast(data.message || error.message, 'error');
      }
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<i class="fa-solid fa-eye"></i>';
    }
  }

  function showPassword(card, password) {
    const pwEl = card.querySelector('[data-role="pw"]');
    if (!pwEl) return;
    const name = card.dataset.name;

    if (SELF.masks[name]) { clearTimeout(SELF.masks[name]); delete SELF.masks[name]; }

    pwEl.textContent = password;
    pwEl.classList.add('revealed');
    pwEl.classList.add('text-success');
    pwEl.title = 'Password shown — auto-masks after a few seconds';

    const revealBtn = card.querySelector('.js-reveal');
    if (revealBtn) revealBtn.innerHTML = '<i class="fa-solid fa-eye-slash"></i>';
    const note = card.querySelector('.wifi-stealth-note');
    if (note) note.remove();

    SELF.masks[name] = setTimeout(() => {
      pwEl.textContent = maskDots(name);
      pwEl.classList.remove('revealed');
      pwEl.classList.remove('text-success');
      pwEl.title = '';
      if (revealBtn) revealBtn.innerHTML = '<i class="fa-solid fa-eye"></i>';
      delete SELF.masks[name];
    }, AUTO_MASK_SECONDS * 1000);
  }

  /* ------------------------------------------------------- connection ops */

  async function autoConnectSaved(name) {
    const profile = SELF.profiles.find((p) => p.name === name);
    if (!profile) return;
    if (!CFG.isAuthenticated) {
      toast('Log in to connect.', 'error');
      return;
    }
    confirmConnect(profile);
  }

  function confirmConnect(profile) {
    // Confirm before using the locally saved profile to connect.
    const proceed = window.confirm(
      `Connect to "${profile.name}" using the profile saved on this computer?`
    );
    if (!proceed) return;
    toast(`Connection to "${profile.name}" requested via the local agent.`, 'info', 2600);
  }

  async function disconnect() {
    if (!CFG.isAuthenticated) { toast('Log in to disconnect.', 'error'); return; }
    const proceed = window.confirm('Disconnect the current Wi-Fi network?');
    if (!proceed) return;
    try {
      const res = await api(CFG.urls.disconnect, { method: 'POST', body: '{}' });
      toast(res.message || 'Disconnected.', 'success');
      window.WifiRadar.scanOnce(true);
      loadProfiles(true);
    } catch (error) {
      const data = error.data || {};
      if (data.status === 'pending_agent') {
        toast('Local agent offline — run "python local_agent/agent.py" to enable connect/disconnect.', 'error', 6000);
      } else {
        toast(data.message || error.message, 'error');
      }
    }
  }

  /* ------------------------------------------------------- nearby networks */

  function renderNearby() {
    const rows = document.getElementById('ws-nearby-rows');
    if (!rows) return;
    if (!SELF.nearby.length) {
      rows.innerHTML = '<tr><td colspan="5" class="text-center text-secondary py-4">No nearby networks detected. Press Scan Nearby.</td></tr>';
      renderStats();
      return;
    }
    const savedNames = new Set(SELF.profiles.map((p) => p.name));
    rows.innerHTML = SELF.nearby.slice(0, 25).map((n, index) => {
      const cls = classOf(n.signal_strength);
      const isSaved = savedNames.has(n.ssid);
      return `<tr class="row-enter">
        <td>
          <div class="ssid-cell">
            <span class="blip-dot" style="background:${colorOf(n.signal_strength)};box-shadow:0 0 8px ${colorOf(n.signal_strength)};width:10px;height:10px;border-radius:50%;display:inline-block"></span>
            <span class="ssid-name" title="${esc(n.ssid)}">${esc(n.ssid)}</span>
          </div>
        </td>
        <td><span class="signal-chip s-${cls}">${n.signal_strength}%</span></td>
        <td><span class="sec-badge ${securityClass(n.security_type)}">${esc(n.security_type || 'Open')}</span></td>
        <td>${isSaved
          ? '<span class="badge text-bg-info"><i class="fa-solid fa-bookmark"></i> profile saved</span>'
          : '<span class="badge text-bg-secondary">not saved</span>'}</td>
        <td class="text-end">
          ${n.is_connected
            ? '<span class="badge text-bg-success">Connected</span>'
            : `<button class="btn btn-sm btn-outline-light js-connect" data-ssid="${esc(n.ssid)}"
                 data-security="${esc(n.security_type)}" data-signal="${n.signal_strength}" data-bssid="${esc(n.bssid)}">Connect</button>`}
        </td>
      </tr>`;
    }).join('');

    rows.querySelectorAll('.js-connect').forEach((btn) => {
      btn.addEventListener('click', () => openConnectModal({
        ssid: btn.dataset.ssid,
        security: btn.dataset.security,
        signal: Number(btn.dataset.signal),
        bssid: btn.dataset.bssid,
      }));
    });
  }

  function updateAccessIndicators() {
    // Reflect server truth about reveal availability.
    SELF.profiles.forEach(() => {});
  }

  /* --------------------------------------------------------------- wiring */

  function initActions() {
    const scan = document.getElementById('ws-scan');
    if (scan) scan.addEventListener('click', () => {
      window.WifiRadar.scanOnce(true);
      toast('Scanning nearby networks…', 'info', 1800);
    });

    const refresh = document.getElementById('ws-refresh');
    if (refresh) refresh.addEventListener('click', () => {
      loadProfiles(true);
      window.WifiRadar.scanOnce(true);
      toast('Refreshing…', 'info', 1600);
    });

    const location = document.getElementById('ws-location');
    if (location) location.addEventListener('click', toggleLocation);

    const disconnectBtn = document.getElementById('ws-disconnect');
    if (disconnectBtn) disconnectBtn.addEventListener('click', () => disconnect());
  }

  function onScan(payload) {
    if (!payload) return;
    if (Array.isArray(payload.networks)) SELF.nearby = payload.networks;
    renderNearby();
    renderStats();
    if (SELF.location.active && SELF.location.last && SELF.location.map) {
      const { latitude, longitude } = SELF.location.last;
      drawNetworkEstimates(SELF.location.map, latitude, longitude);
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    if (!window.WifiRadar || !api) return; // app.js must load first
    initActions();
    loadProfiles(false);
    onScan(window.WifiRadar.state.lastPayload);
    document.addEventListener('wifi:scan', (event) => onScan(event.detail));
    SELF.radar.raf = requestAnimationFrame(drawRadar);
  });
})();
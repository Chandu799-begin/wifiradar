/* Nearby networks table controller (server-side search / sort / filter) */
(() => {
  'use strict';
  const { api, classOf, esc, colorOf } = window.WifiRadar;

  const state = { search: '', signalClass: 'all', sort: '-signal_strength' };

  function queryString() {
    const params = new URLSearchParams();
    if (state.search) params.set('search', state.search);
    if (state.signalClass !== 'all') params.set('signal_class', state.signalClass);
    params.set('sort', state.sort);
    return params.toString();
  }

  function renderStrip(connected) {
    const strip = document.getElementById('connected-strip');
    if (!strip) return;
    if (!connected) { strip.hidden = true; return; }
    strip.hidden = false;
    document.getElementById('cs-ssid').textContent = connected.ssid;
    document.getElementById('cs-meta').textContent =
      `${connected.signal_strength}% · ${connected.security_type || 'Open'}${connected.frequency ? ' · ' + connected.frequency : ''}`;
  }

  function renderRows(results) {
    const tbody = document.getElementById('network-rows');
    const count = document.getElementById('table-count');
    if (!tbody) return;
    if (count) count.textContent = `${results.length} network${results.length === 1 ? '' : 's'} shown`;
    if (!results.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="text-center text-secondary py-4">No networks match your filters.</td></tr>';
      return;
    }
    tbody.innerHTML = results.map((n, index) => {
      const cls = classOf(n.signal_strength);
      const band = [n.frequency, n.channel ? `Ch ${n.channel}` : ''].filter(Boolean).join(' · ') || '—';
      return `<tr class="row-enter" style="animation-delay:${Math.min(index, 12) * 35}ms">
        <td>
          <div class="ssid-cell">
            <span class="blip-dot" style="background:${colorOf(n.signal_strength)};box-shadow:0 0 8px ${colorOf(n.signal_strength)};width:10px;height:10px;border-radius:50%;display:inline-block"></span>
            <span class="ssid-name" title="${esc(n.ssid)}">${esc(n.ssid)}${n.is_hidden ? ' <span class="badge text-bg-secondary">hidden</span>' : ''}</span>
          </div>
          <div class="small text-secondary" style="font-size:.7rem">${esc(n.bssid)}</div>
        </td>
        <td>
          <span class="signal-chip s-${cls}">${n.signal_strength}%</span>
          <span class="signal-bar i-${cls}"><i style="width:${n.signal_strength}%"></i></span>
        </td>
        <td class="d-none d-md-table-cell">${esc(n.security_type) || 'Open'}</td>
        <td class="d-none d-lg-table-cell small text-secondary">${esc(band)}</td>
        <td>${n.is_connected
          ? '<span class="badge text-bg-success">Connected</span>'
          : '<span class="badge text-bg-secondary">Available</span>'}</td>
        <td class="text-end">
          ${n.is_connected
            ? `<a href="${window.WIFI_CFG.urls.connectedPage}" class="btn btn-sm btn-outline-success">Details</a>`
            : `<button class="btn btn-sm btn-outline-light js-connect" data-ssid="${esc(n.ssid)}" data-security="${esc(n.security_type)}" data-signal="${n.signal_strength}" data-bssid="${esc(n.bssid)}">Connect</button>`}
        </td>
      </tr>`;
    }).join('');

    tbody.querySelectorAll('.js-connect').forEach((btn) => {
      btn.addEventListener('click', () => window.WifiRadar.openConnectModal({
        ssid: btn.dataset.ssid,
        security: btn.dataset.security,
        signal: Number(btn.dataset.signal),
        bssid: btn.dataset.bssid,
      }));
    });
  }

  async function refresh() {
    const tbody = document.getElementById('network-rows');
    try {
      const data = await api(`${window.WIFI_CFG.urls.networks}?${queryString()}`);
      renderRows(data.results || []);
      const connected = (data.results || []).find((n) => n.is_connected);
      renderStrip(connected || null);
    } catch (error) {
      if (tbody) tbody.innerHTML = `<tr><td colspan="6" class="text-center text-danger py-4">${esc(error.message)}</td></tr>`;
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    const search = document.getElementById('search-input');
    if (search) {
      let debounce = null;
      search.addEventListener('input', () => {
        clearTimeout(debounce);
        debounce = setTimeout(() => { state.search = search.value.trim(); refresh(); }, 250);
      });
    }

    const filter = document.getElementById('signal-filter');
    if (filter) {
      filter.querySelectorAll('button').forEach((btn) => {
        btn.addEventListener('click', () => {
          filter.querySelectorAll('button').forEach((b) => b.classList.remove('active'));
          btn.classList.add('active');
          state.signalClass = btn.dataset.filter;
          refresh();
        });
      });
    }

    const sort = document.getElementById('sort-select');
    if (sort) sort.addEventListener('change', () => { state.sort = sort.value; refresh(); });

    const button = document.getElementById('table-refresh');
    if (button) button.addEventListener('click', () => { window.WifiRadar.scanOnce(true); refresh(); });

    refresh();
  });

  document.addEventListener('wifi:scan', refresh);
})();

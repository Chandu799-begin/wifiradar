/* Dashboard page controller */
(() => {
  'use strict';
  const { api, classOf, esc, colorOf } = window.WifiRadar;
  let radar = null;
  let chart = null;

  function applyStats(payload) {
    const networks = payload.networks || [];
    const signals = networks.map((n) => Number(n.signal_strength) || 0);
    const connected = networks.find((n) => n.is_connected);
    const secured = networks.filter((n) => !/^(open|owe)$/i.test((n.security_type || '').trim()) && n.security_type);
    const set = (id, value) => {
      const el = document.getElementById(id);
      if (el) el.textContent = value;
    };
    set('stat-total', networks.length);
    set('stat-connected', connected ? connected.ssid : 'Not connected');
    set('stat-strongest', signals.length ? `${Math.max(...signals)}%` : '—');
    set('stat-weakest', signals.length ? `${Math.min(...signals)}%` : '—');
    set('stat-secured', secured.length);
    set('stat-open', networks.length - secured.length);
    set('stat-lastscan', payload.scan ? new Date(payload.scan.scan_time).toLocaleTimeString() : '—');
    set('stat-strong-n', signals.filter((s) => s >= 75).length);
    set('stat-medium-n', signals.filter((s) => s >= 40 && s < 75).length);
    set('stat-weak-n', networks.length - signals.filter((s) => s >= 75).length - signals.filter((s) => s >= 40 && s < 75).length);
  }

  function applyTopTable(payload) {
    const tbody = document.getElementById('dash-top-networks');
    if (!tbody) return;
    const rows = (payload.networks || []).slice(0, 6);
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="text-center text-secondary py-4">No networks detected.</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map((n, index) => {
      const cls = classOf(n.signal_strength);
      return `<tr class="row-enter" style="animation-delay:${index * 45}ms">
        <td><div class="ssid-cell">
          <span class="blip-dot" style="background:${colorOf(n.signal_strength)};box-shadow:0 0 8px ${colorOf(n.signal_strength)}"></span>
          <span class="ssid-name">${esc(n.ssid)}</span>
        </div></td>
        <td><span class="signal-chip s-${cls}">${n.signal_strength}%</span></td>
        <td>${esc(n.security_type) || 'Open'}</td>
        <td>${n.is_connected
          ? '<span class="badge text-bg-success">Connected</span>'
          : `<button class="btn btn-sm btn-outline-light js-connect" data-ssid="${esc(n.ssid)}" data-security="${esc(n.security_type)}" data-signal="${n.signal_strength}" data-bssid="${esc(n.bssid)}">Connect</button>`}</td>
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

  async function loadChart() {
    try {
      const data = await api(`${window.WIFI_CFG.urls.history}?limit=30`);
      const items = (data.results || []).slice().reverse();
      const labels = items.map((item) => new Date(item.scan_time).toLocaleTimeString());
      const strongest = items.map((item) => item.strongest_signal);
      const ctx = document.getElementById('dash-chart');
      if (!ctx || !window.Chart) return;
      if (chart) chart.destroy();
      chart = new Chart(ctx, {
        type: 'line',
        data: {
          labels,
          datasets: [{
            label: 'Strongest signal %',
            data: strongest,
            borderColor: '#3dff9a',
            backgroundColor: 'rgba(61, 255, 154, 0.12)',
            fill: true,
            tension: 0.38,
            pointRadius: 3,
            pointBackgroundColor: '#41e8ff',
          }],
        },
        options: chartOptions(0, 100),
      });
      const skeleton = document.getElementById('dash-chart-skeleton');
      if (skeleton) skeleton.hidden = true;
    } catch (error) {
      console.warn('chart load failed', error);
    }
  }

  function chartOptions(min, max) {
    return {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 700 },
      plugins: { legend: { labels: { color: '#7f92b5' } } },
      scales: {
        x: { ticks: { color: '#7f92b5', maxTicksLimit: 7 }, grid: { color: 'rgba(127,146,181,0.10)' } },
        y: { min, max, ticks: { color: '#7f92b5' }, grid: { color: 'rgba(127,146,181,0.10)' } },
      },
    };
  }

  document.addEventListener('DOMContentLoaded', () => {
    const canvas = document.getElementById('dash-radar-canvas');
    if (canvas && window.Radar) {
      radar = new window.Radar(canvas, {
        onSelect: (blip) => window.WifiRadar.openConnectModal({
          ssid: blip.ssid, security: blip.security_type, signal: blip.signal_strength, bssid: blip.bssid,
        }),
      });
      radar.start();
    }
    loadChart();
  });

  document.addEventListener('wifi:scan', (event) => {
    const payload = event.detail;
    applyStats(payload);
    applyTopTable(payload);
    if (radar) radar.update(payload.networks);
  });

  document.addEventListener('wifi:theme', () => { /* charts keep fixed colors */ });
})();

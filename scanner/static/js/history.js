/* Scan history page controller */
(() => {
  'use strict';
  const { esc } = window.WifiRadar;

  async function refresh() {
    const button = document.getElementById('history-refresh');
    const rows = document.getElementById('history-rows');
    if (button) button.disabled = true;
    try {
      const response = await fetch(`${window.WIFI_CFG.urls.history}?limit=200`, { credentials: 'same-origin' });
      const data = await response.json();
      if (!rows) return;
      const items = data.results || [];
      if (!items.length) {
        rows.innerHTML = '<tr><td colspan="6" class="text-center text-secondary py-4">No scans recorded yet. Open the radar page to run one.</td></tr>';
        return;
      }
      rows.innerHTML = items.map((item) => {
        const time = new Date(item.scan_time).toLocaleString();
        const strongClass = item.strongest_signal >= 75 ? 's-strong' : item.strongest_signal >= 40 ? 's-medium' : 's-weak';
        const weakClass = item.weakest_signal >= 75 ? 's-strong' : item.weakest_signal >= 40 ? 's-medium' : 's-weak';
        return `<tr class="row-enter">
          <td class="text-secondary">${esc(time)}</td>
          <td>${item.total_networks}</td>
          <td><span class="signal-chip ${strongClass}">${item.strongest_signal}%</span></td>
          <td><span class="signal-chip ${weakClass}">${item.weakest_signal}%</span></td>
          <td class="d-none d-md-table-cell">${esc(item.connected_ssid) || '—'}</td>
          <td><span class="badge text-bg-${item.source === 'demo' ? 'secondary' : 'info'}">${esc(item.source)}</span></td>
        </tr>`;
      }).join('');
    } catch (error) {
      window.WifiRadar.toast(error.message, 'error');
    } finally {
      if (button) button.disabled = false;
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    const button = document.getElementById('history-refresh');
    if (button) button.addEventListener('click', refresh);
  });
})();

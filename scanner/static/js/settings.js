/* Settings page controller */
(() => {
  'use strict';
  const { api } = window.WifiRadar;

  async function check() {
    const text = document.getElementById('agent-status-text');
    if (text) text.textContent = 'checking…';
    try {
      const data = await api(window.WIFI_CFG.urls.connected);
      const agent = data.agent || {};
      if (text) {
        text.innerHTML = agent.reachable
          ? `<span class="text-success">Online</span> <span class="small text-secondary">(${agent.platform || 'unknown'} · agent v1)</span>`
          : '<span class="text-danger">Offline</span> <span class="small text-secondary">python local_agent/agent.py</span>';
      }
    } catch (error) {
      if (text) text.innerHTML = `<span class="text-danger">Error: ${error.message}</span>`;
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    check();
    const button = document.getElementById('agent-check');
    if (button) button.addEventListener('click', check);

    const demoSwitch = document.getElementById('demo_mode');
    if (demoSwitch) {
      demoSwitch.addEventListener('change', () => {
        window.WifiRadar.toast(
          demoSwitch.checked ? 'Demo mode will apply after saving.' : 'Live scanning will resume after saving.',
          'info'
        );
      });
    }
  });
})();

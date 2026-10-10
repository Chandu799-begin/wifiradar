/* Connected page controller */
(() => {
  'use strict';
  const { api, toast } = window.WifiRadar;

  document.addEventListener('DOMContentLoaded', async () => {
    const agent = document.getElementById('agent-state');
    try {
      const data = await api(window.WIFI_CFG.urls.connected);
      if (agent) {
        agent.innerHTML = data.agent && data.agent.reachable
          ? '<span class="text-success">Online</span>'
          : '<span class="text-danger">Offline</span> <span class="small text-secondary">start local_agent/agent.py</span>';
      }
    } catch (_) {
      if (agent) agent.innerHTML = '<span class="text-danger">Unknown</span>';
    }

    const button = document.getElementById('disconnect-btn');
    const message = document.getElementById('disconnect-msg');
    if (button) {
      button.addEventListener('click', async () => {
        if (!window.confirm('Disconnect from the current Wi-Fi network?')) return;
        button.disabled = true;
        if (message) { message.textContent = 'Working…'; message.className = 'small text-info align-self-center'; }
        try {
          const data = await api(window.WIFI_CFG.urls.disconnect, { method: 'POST', body: '{}' });
          if (message) { message.textContent = data.message || 'Disconnected.'; message.className = 'small text-success align-self-center'; }
          toast(data.message || 'Disconnected.', 'success');
        } catch (error) {
          const detail = (error.data && error.data.message) || error.message;
          if (message) { message.textContent = detail; message.className = 'small text-danger align-self-center'; }
          toast(detail, 'error');
        } finally {
          button.disabled = false;
        }
      });
    }
  });
})();

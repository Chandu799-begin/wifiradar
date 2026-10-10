/* Live radar page controller */
(() => {
  'use strict';
  const { esc, classOf, colorOf } = window.WifiRadar;
  let radar = null;
  let selectedBssid = null;

  function renderList(networks) {
    const list = document.getElementById('blip-list');
    const badge = document.getElementById('radar-count-badge');
    const count = document.getElementById('rci-count');
    if (badge) badge.textContent = networks.length;
    if (count) count.textContent = networks.length;
    if (!list) return;
    if (!networks.length) {
      list.innerHTML = '<li class="blip-empty text-secondary small p-3">No networks detected.</li>';
      return;
    }
    list.innerHTML = networks.map((n) => `
      <li data-bssid="${esc(n.bssid)}" class="${n.bssid === selectedBssid ? 'active' : ''}">
        <span class="blip-dot" style="background:${colorOf(n.signal_strength)};box-shadow:0 0 8px ${colorOf(n.signal_strength)}"></span>
        <span class="blip-ssid">${esc(n.ssid)}${n.is_connected ? ' <span class="badge text-bg-success">on</span>' : ''}</span>
        <span class="blip-sig s-${classOf(n.signal_strength)}">${n.signal_strength}%</span>
      </li>`).join('');
    list.querySelectorAll('li[data-bssid]').forEach((item) => {
      item.addEventListener('click', () => {
        const blip = networks.find((n) => n.bssid === item.dataset.bssid);
        if (blip) showDetails(blip);
      });
    });
  }

  function showDetails(blip) {
    selectedBssid = blip.bssid;
    const body = document.getElementById('detail-body');
    if (!body) return;
    const cls = classOf(blip.signal_strength);
    body.innerHTML = `
      <h6 class="mb-2">${esc(blip.ssid)} ${blip.is_connected ? '<span class="badge text-bg-success">Connected</span>' : ''}</h6>
      <dl class="row mb-0 spec-list">
        <dt class="col-5">Signal</dt><dd class="col-7"><span class="signal-chip s-${cls}">${blip.signal_strength}%</span> <span class="s-${cls} small">${cls}</span></dd>
        <dt class="col-5">Security</dt><dd class="col-7">${esc(blip.security_type) || 'Open'}</dd>
        <dt class="col-5">BSSID</dt><dd class="col-7"><code>${esc(blip.bssid)}</code></dd>
        <dt class="col-5">Band / Channel</dt><dd class="col-7">${esc(blip.frequency) || '—'} ${blip.channel ? `· Ch ${blip.channel}` : ''}</dd>
        <dt class="col-5">Last seen</dt><dd class="col-7">${blip.last_seen ? new Date(blip.last_seen).toLocaleTimeString() : '—'}</dd>
      </dl>
      ${blip.is_connected ? '' : `<button class="btn btn-sm btn-accent mt-3 js-connect"
        data-ssid="${esc(blip.ssid)}" data-security="${esc(blip.security_type)}"
        data-signal="${blip.signal_strength}" data-bssid="${esc(blip.bssid)}">
        <i class="fa-solid fa-plug"></i> Connect</button>`}
      <p class="small text-secondary mt-3 mb-0">
        <i class="fa-solid fa-circle-info"></i> Radar placement is illustrative — derived from signal strength only.
      </p>`;
    const button = body.querySelector('.js-connect');
    if (button) {
      button.addEventListener('click', () => window.WifiRadar.openConnectModal({
        ssid: blip.ssid, security: blip.security_type, signal: blip.signal_strength, bssid: blip.bssid,
      }));
    }
    if (radar) radar.selected = radar.networks.find((n) => n.bssid === blip.bssid) || null;
    document.querySelectorAll('#blip-list li').forEach((li) => {
      li.classList.toggle('active', li.dataset.bssid === blip.bssid);
    });
  }

  function renderFeed(payload) {
    const feed = document.getElementById('scan-feed');
    const time = document.getElementById('feed-time');
    if (time) time.textContent = new Date(payload.scanned_at).toLocaleString();
    if (!feed) return;
    const line = document.createElement('div');
    line.className = 'feed-line';
    const names = (payload.networks || []).slice(0, 5).map((n) => `<b>${esc(n.ssid)}</b>`).join(', ');
    line.innerHTML = `&gt; ${payload.demo_mode ? '[demo] ' : ''}scan ok — ${payload.networks.length} network(s): ${names || 'none'}`;
    feed.prepend(line);
    while (feed.children.length > 12) feed.lastChild.remove();
  }

  document.addEventListener('DOMContentLoaded', () => {
    const canvas = document.getElementById('main-radar-canvas');
    if (canvas && window.Radar) {
      radar = new window.Radar(canvas, { onSelect: showDetails });
      radar.start();
    }
  });

  document.addEventListener('wifi:scan', (event) => {
    const payload = event.detail;
    const networks = payload.networks || [];
    if (radar) radar.update(networks);
    renderList(networks);
    renderFeed(payload);
    if (!selectedBssid && networks.length) showDetails(networks[0]);
    const stillThere = networks.some((n) => n.bssid === selectedBssid);
    if (selectedBssid && !stillThere) {
      selectedBssid = null;
      const body = document.getElementById('detail-body');
      if (body) body.innerHTML = '<p class="text-secondary small mb-0">Select a blip or a network from the list.</p>';
    }
  });
})();

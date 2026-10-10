/* Analytics page controller */
(() => {
  'use strict';

  const GRID = 'rgba(127,146,181,0.10)';
  const TICK = '#7f92b5';

  function baseOptions(yMin, yMax) {
    const options = {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 800 },
      plugins: { legend: { labels: { color: TICK } } },
      scales: {
        x: { ticks: { color: TICK, maxTicksLimit: 8 }, grid: { color: GRID } },
        y: { ticks: { color: TICK }, grid: { color: GRID } },
      },
    };
    if (yMin !== undefined) { options.scales.y.min = yMin; options.scales.y.max = yMax; }
    return options;
  }

  document.addEventListener('DOMContentLoaded', () => {
    if (!window.Chart) return;
    const data = window.CHART_DATA || { labels: [], strongest: [], totals: [] };

    const strongestCanvas = document.getElementById('chart-strongest');
    if (strongestCanvas) {
      new Chart(strongestCanvas, {
        type: 'line',
        data: {
          labels: data.labels,
          datasets: [{
            label: 'Strongest %',
            data: data.strongest,
            borderColor: '#3dff9a',
            backgroundColor: 'rgba(61,255,154,0.12)',
            fill: true,
            tension: 0.35,
            pointBackgroundColor: '#41e8ff',
          }],
        },
        options: baseOptions(0, 100),
      });
      const sk = document.getElementById('sk-strongest');
      if (sk) sk.hidden = true;
    }

    const totalsCanvas = document.getElementById('chart-totals');
    if (totalsCanvas) {
      new Chart(totalsCanvas, {
        type: 'bar',
        data: {
          labels: data.labels,
          datasets: [{
            label: 'Networks per scan',
            data: data.totals,
            backgroundColor: 'rgba(65,232,255,0.55)',
            borderColor: '#41e8ff',
            borderWidth: 1,
            borderRadius: 6,
          }],
        },
        options: baseOptions(),
      });
      const sk = document.getElementById('sk-totals');
      if (sk) sk.hidden = true;
    }

    const distCanvas = document.getElementById('chart-distribution');
    if (distCanvas) {
      const stats = window.DIST_STATS || null;
      const payload = stats || { strong: 0, medium: 0, weak: 0 };
      new Chart(distCanvas, {
        type: 'doughnut',
        data: {
          labels: ['Strong (75–100%)', 'Medium (40–74%)', 'Weak (0–39%)'],
          datasets: [{
            data: [payload.strong, payload.medium, payload.weak],
            backgroundColor: ['rgba(61,255,154,0.8)', 'rgba(255,209,102,0.8)', 'rgba(255,93,115,0.8)'],
            borderColor: 'rgba(0,0,0,0.25)',
            borderWidth: 2,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '62%',
          plugins: { legend: { position: 'bottom', labels: { color: TICK } } },
        },
      });
    }
  });

  document.addEventListener('wifi:scan', async (event) => {
    const canvas = document.getElementById('chart-distribution');
    if (!canvas || !window.Chart) return;
    const networks = (event.detail && event.detail.networks) || [];
    const strong = networks.filter((n) => n.signal_strength >= 75).length;
    const medium = networks.filter((n) => n.signal_strength >= 40 && n.signal_strength < 75).length;
    const weak = networks.length - strong - medium;
    const chart = Chart.getChart(canvas);
    if (chart) {
      chart.data.datasets[0].data = [strong, medium, weak];
      chart.update('none');
    }
  });
})();

/* Wi-Fi Radar Pro — canvas radar visualization.
 *
 * Blip position: angle comes from a stable hash of the BSSID and the radius
 * from the estimated signal strength. This is illustrative only — RSSI does
 * not encode real-world distance or direction.
 */
(() => {
  'use strict';

  const TAU = Math.PI * 2;

  function hashAngle(text) {
    let hash = 0;
    for (let i = 0; i < text.length; i += 1) {
      hash = (hash * 31 + text.charCodeAt(i)) >>> 0;
    }
    return (hash % 3600) / 10; // 0..359.9 degrees
  }

  const colorOf = (signal) => (signal >= 75 ? '#3dff9a' : signal >= 40 ? '#ffd166' : '#ff5d73');

  class Radar {
    constructor(canvas, options = {}) {
      this.canvas = canvas;
      this.ctx = canvas.getContext('2d');
      this.networks = [];
      this.sweep = 0;
      this.hovered = null;
      this.selected = null;
      this.onSelect = options.onSelect || null;
      this.running = false;
      this.dpr = window.devicePixelRatio || 1;

      this._resize = this._resize.bind(this);
      this._frame = this._frame.bind(this);
      this._onMove = this._onMove.bind(this);
      this._onClick = this._onClick.bind(this);

      this._resize();
      window.addEventListener('resize', this._resize);
      canvas.addEventListener('mousemove', this._onMove);
      canvas.addEventListener('mouseleave', () => { this.hovered = null; this.canvas.style.cursor = 'crosshair'; });
      canvas.addEventListener('click', this._onClick);
    }

    _resize() {
      const rect = this.canvas.getBoundingClientRect();
      const size = Math.max(240, Math.min(rect.width || this.canvas.width, 720));
      this.size = size;
      this.canvas.width = size * this.dpr;
      this.canvas.height = size * this.dpr;
      this.ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
      this.cx = size / 2;
      this.cy = size / 2;
      this.radius = size / 2 - 12;
    }

    update(networks) {
      const previous = new Map(this.networks.map((n) => [n.bssid, n]));
      this.networks = (networks || []).map((network) => {
        const angle = hashAngle(network.bssid || network.ssid || '?') * (Math.PI / 180);
        const signal = Math.max(0, Math.min(100, Number(network.signal_strength) || 0));
        const distance = (1 - signal / 100) * 0.82 + 0.1; // 0.1 .. 0.92 of radius
        const old = previous.get(network.bssid);
        return {
          ...network,
          angle,
          distance,
          color: colorOf(signal),
          x: 0,
          y: 0,
          born: old ? old.born : performance.now(),
          glow: old ? old.glow : 1,
        };
      });
    }

    _position(blip) {
      const r = blip.distance * this.radius;
      return { x: this.cx + Math.cos(blip.angle) * r, y: this.cy + Math.sin(blip.angle) * r };
    }

    _blipAt(px, py) {
      let best = null;
      let bestDist = 18;
      for (const blip of this.networks) {
        const { x, y } = this._position(blip);
        const d = Math.hypot(px - x, py - y);
        if (d < bestDist) { bestDist = d; best = blip; }
      }
      return best;
    }

    _eventPoint(event) {
      const rect = this.canvas.getBoundingClientRect();
      return {
        x: (event.clientX - rect.left) * (this.size / rect.width),
        y: (event.clientY - rect.top) * (this.size / rect.height),
      };
    }

    _onMove(event) {
      const { x, y } = this._eventPoint(event);
      this.hovered = this._blipAt(x, y);
      this.canvas.style.cursor = this.hovered ? 'pointer' : 'crosshair';
    }

    _onClick(event) {
      const { x, y } = this._eventPoint(event);
      const blip = this._blipAt(x, y);
      if (blip) {
        this.selected = blip;
        if (this.onSelect) this.onSelect(blip);
      }
    }

    start() {
      if (this.running) return;
      this.running = true;
      requestAnimationFrame(this._frame);
    }

    stop() { this.running = false; }

    destroy() {
      this.stop();
      window.removeEventListener('resize', this._resize);
      this.canvas.removeEventListener('mousemove', this._onMove);
      this.canvas.removeEventListener('click', this._onClick);
    }

    _frame(now) {
      if (!this.running) return;
      this.sweep = (this.sweep + 0.9) % 360;
      this._draw(now);
      requestAnimationFrame(this._frame);
    }

    _draw(now) {
      const { ctx, cx, cy, radius, size } = this;
      ctx.clearRect(0, 0, size, size);

      // background disc
      const bg = ctx.createRadialGradient(cx, cy * 0.7, radius * 0.1, cx, cy, radius);
      bg.addColorStop(0, 'rgba(8, 24, 30, 0.95)');
      bg.addColorStop(1, 'rgba(3, 10, 16, 0.98)');
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, TAU);
      ctx.fillStyle = bg;
      ctx.fill();

      // concentric rings
      ctx.strokeStyle = 'rgba(61, 255, 154, 0.22)';
      ctx.lineWidth = 1;
      for (let i = 1; i <= 4; i += 1) {
        ctx.beginPath();
        ctx.arc(cx, cy, (radius * i) / 4, 0, TAU);
        ctx.stroke();
      }

      // crosshair + diagonals
      ctx.strokeStyle = 'rgba(65, 232, 255, 0.18)';
      ctx.beginPath();
      ctx.moveTo(cx - radius, cy); ctx.lineTo(cx + radius, cy);
      ctx.moveTo(cx, cy - radius); ctx.lineTo(cx, cy + radius);
      ctx.stroke();

      ctx.strokeStyle = 'rgba(65, 232, 255, 0.09)';
      ctx.beginPath();
      for (let a = 45; a < 360; a += 45) {
        const rad = (a * Math.PI) / 180;
        ctx.moveTo(cx, cy);
        ctx.lineTo(cx + Math.cos(rad) * radius, cy + Math.sin(rad) * radius);
      }
      ctx.stroke();

      // degree ticks
      ctx.fillStyle = 'rgba(127, 146, 181, 0.75)';
      ctx.font = `${Math.max(8, size * 0.023)}px Segoe UI, sans-serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      for (let a = 0; a < 360; a += 30) {
        const rad = (a * Math.PI) / 180;
        const tx = cx + Math.cos(rad) * (radius + 0);
        const ty = cy + Math.sin(rad) * (radius + 0);
        const lx = cx + Math.cos(rad) * (radius - 9);
        const ly = cy + Math.sin(rad) * (radius - 9);
        ctx.strokeStyle = 'rgba(61, 255, 154, 0.45)';
        ctx.beginPath();
        ctx.moveTo(cx + Math.cos(rad) * radius, cy + Math.sin(rad) * radius);
        ctx.lineTo(cx + Math.cos(rad) * (radius - 6), cy + Math.sin(rad) * (radius - 6));
        ctx.stroke();
        if (size > 320) ctx.fillText(`${a}`, lx, ly);
        void tx; void ty;
      }

      // rotating sweep (comet trail)
      const sweepRad = (this.sweep * Math.PI) / 180;
      const trail = ctx.createConicGradient
        ? ctx.createConicGradient(sweepRad - 1.05, cx, cy)
        : null;
      if (trail) {
        trail.addColorStop(0, 'rgba(61, 255, 154, 0)');
        trail.addColorStop(0.16, 'rgba(61, 255, 154, 0.28)');
        trail.addColorStop(0.25, 'rgba(61, 255, 154, 0)');
        trail.addColorStop(1, 'rgba(61, 255, 154, 0)');
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.arc(cx, cy, radius, sweepRad - 1.05, sweepRad);
        ctx.closePath();
        ctx.fillStyle = trail;
        ctx.fill();
      } else {
        const grad = ctx.createLinearGradient(cx, cy, cx + Math.cos(sweepRad) * radius, cy + Math.sin(sweepRad) * radius);
        grad.addColorStop(0, 'rgba(61, 255, 154, 0)');
        grad.addColorStop(1, 'rgba(61, 255, 154, 0.25)');
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.arc(cx, cy, radius, sweepRad - 1.0, sweepRad);
        ctx.closePath();
        ctx.fillStyle = grad;
        ctx.fill();
      }

      // sweep line
      ctx.strokeStyle = 'rgba(61, 255, 154, 0.95)';
      ctx.lineWidth = 2;
      ctx.shadowColor = 'rgba(61, 255, 154, 0.9)';
      ctx.shadowBlur = 12;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(cx + Math.cos(sweepRad) * radius, cy + Math.sin(sweepRad) * radius);
      ctx.stroke();
      ctx.shadowBlur = 0;

      // blips
      for (const blip of this.networks) {
        const { x, y } = this._position(blip);
        blip.x = x; blip.y = y;

        const sweepAngle = ((sweepRad * 180) / Math.PI + 360) % 360;
        const blipAngle = ((blip.angle * 180) / Math.PI + 360) % 360;
        const delta = (sweepAngle - blipAngle + 360) % 360;
        if (delta < 8) blip.glow = 1;
        blip.glow = Math.max(0, blip.glow - 0.012);

        const pulse = 0.5 + 0.5 * Math.sin(now / 420 + blip.angle * 3);
        const baseR = Math.max(4, size * 0.011);
        const r = baseR * (1 + pulse * 0.35);

        // outer glow ring
        ctx.beginPath();
        ctx.arc(x, y, r + 6 + pulse * 5, 0, TAU);
        ctx.fillStyle = hexToRgba(blip.color, 0.06 + blip.glow * 0.10);
        ctx.fill();

        // halo
        ctx.beginPath();
        ctx.arc(x, y, r + 3, 0, TAU);
        ctx.fillStyle = hexToRgba(blip.color, 0.22);
        ctx.fill();

        // core
        ctx.beginPath();
        ctx.arc(x, y, r, 0, TAU);
        ctx.fillStyle = blip.color;
        ctx.shadowColor = blip.color;
        ctx.shadowBlur = 12 + blip.glow * 14;
        ctx.fill();
        ctx.shadowBlur = 0;

        if (blip.is_connected) {
          ctx.strokeStyle = '#41e8ff';
          ctx.lineWidth = 2;
          ctx.beginPath();
          ctx.arc(x, y, r + 7, 0, TAU);
          ctx.stroke();
        }

        const isHot = blip === this.hovered || blip === this.selected;
        if (isHot || size > 460) {
          ctx.font = `${Math.max(9, size * 0.026)}px Segoe UI, sans-serif`;
          ctx.fillStyle = isHot ? '#eaf7ff' : 'rgba(219, 231, 255, 0.68)';
          ctx.textAlign = 'left';
          ctx.textBaseline = 'bottom';
          const label = (blip.ssid || 'Hidden').slice(0, 22);
          ctx.fillText(label, x + r + 7, y - 2);
          if (isHot) {
            ctx.fillStyle = blip.color;
            ctx.font = `${Math.max(8, size * 0.022)}px Segoe UI, sans-serif`;
            ctx.textBaseline = 'top';
            ctx.fillText(`${blip.signal_strength}%`, x + r + 7, y + 1);
          }
        }
      }

      // center hub
      ctx.beginPath();
      ctx.arc(cx, cy, 5, 0, TAU);
      ctx.fillStyle = '#41e8ff';
      ctx.shadowColor = '#41e8ff';
      ctx.shadowBlur = 14;
      ctx.fill();
      ctx.shadowBlur = 0;
    }
  }

  function hexToRgba(hex, alpha) {
    const value = hex.replace('#', '');
    const bigint = parseInt(value, 16);
    const r = (bigint >> 16) & 255;
    const g = (bigint >> 8) & 255;
    const b = bigint & 255;
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
  }

  window.Radar = Radar;
  window.radarColorOf = colorOf;
})();

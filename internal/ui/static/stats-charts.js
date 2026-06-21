// stats-charts.js — time-series resource graphs using uPlot
(function() {
  'use strict';

  var DARK = {
    cpu: '#6366f1', mem: '#3b82f6',
    diskRd: '#22c55e', diskWr: '#f59e0b',
    netRx: '#06b6d4', netTx: '#ef4444',
    grid: '#2a2d3e', axis: '#64748b',
  };
  var LIGHT = {
    cpu: '#4f46e5', mem: '#2563eb',
    diskRd: '#16a34a', diskWr: '#d97706',
    netRx: '#0891b2', netTx: '#dc2626',
    grid: '#e2e8f0', axis: '#64748b',
  };

  function colors() {
    return document.documentElement.getAttribute('data-theme') === 'light' ? LIGHT : DARK;
  }

  function fmtRate(self, v) {
    if (v == null) return '--';
    if (v >= 1073741824) return (v / 1073741824).toFixed(1) + ' GiB/s';
    if (v >= 1048576) return (v / 1048576).toFixed(1) + ' MiB/s';
    if (v >= 1024) return (v / 1024).toFixed(1) + ' KiB/s';
    return v.toFixed(0) + ' B/s';
  }

  function fmtPct(self, v) {
    if (v == null) return '--';
    return v.toFixed(1) + '%';
  }

  function makeOpts(title, seriesDefs, width, c) {
    return {
      title: title,
      width: width,
      height: 160,
      cursor: { show: true, drag: { x: false, y: false } },
      scales: { x: { time: true }, y: { auto: true, range: function(u, min, max) { return [0, max || 1]; } } },
      axes: [
        { stroke: c.axis, grid: { stroke: c.grid, width: 1 }, ticks: { stroke: c.grid }, size: 35, font: '10px sans-serif' },
        { stroke: c.axis, grid: { stroke: c.grid, width: 1 }, ticks: { stroke: c.grid }, size: 55, font: '10px sans-serif',
          values: seriesDefs.valFmt || function(u, vals) { return vals.map(function(v) { return v == null ? '' : v.toFixed(1) + '%'; }); }
        },
      ],
      series: [{}].concat(seriesDefs.lines),
    };
  }

  function buildSeries(samples) {
    var ts = [], cpu = [], mem = [], drd = [], dwr = [], nrx = [], ntx = [];
    for (var i = 0; i < samples.length; i++) {
      var s = samples[i];
      ts.push(s.ts);
      cpu.push(s.cpu_pct);
      mem.push(s.mem_pct);
      drd.push(s.disk_rd_rate);
      dwr.push(s.disk_wr_rate);
      nrx.push(s.net_rx_rate);
      ntx.push(s.net_tx_rate);
    }
    return { ts: ts, cpu: cpu, mem: mem, drd: drd, dwr: dwr, nrx: nrx, ntx: ntx };
  }

  function initCharts(container, url) {
    var cpuEl = container.querySelector('.chart-cpu');
    var memEl = container.querySelector('.chart-mem');
    var ioEl = container.querySelector('.chart-io');
    var netEl = container.querySelector('.chart-net');
    var w = Math.floor((container.offsetWidth - 16) / 2) || 300;
    var c = colors();

    var cpuChart = null, memChart = null, ioChart = null, netChart = null;

    function render(samples) {
      if (!samples || !samples.length) return;
      var d = buildSeries(samples);
      var cNow = colors();

      if (!cpuChart && cpuEl) {
        cpuChart = new uPlot(makeOpts('CPU', {
          lines: [{ label: 'CPU', stroke: cNow.cpu, fill: cNow.cpu + '18', width: 2, value: fmtPct }],
        }, w, cNow), [d.ts, d.cpu], cpuEl);
      } else if (cpuChart) { cpuChart.setData([d.ts, d.cpu]); }

      if (!memChart && memEl) {
        memChart = new uPlot(makeOpts('Memory', {
          lines: [{ label: 'Mem', stroke: cNow.mem, fill: cNow.mem + '18', width: 2, value: fmtPct }],
        }, w, cNow), [d.ts, d.mem], memEl);
      } else if (memChart) { memChart.setData([d.ts, d.mem]); }

      if (!ioChart && ioEl) {
        ioChart = new uPlot(makeOpts('Disk I/O', {
          lines: [
            { label: 'Read', stroke: cNow.diskRd, width: 2, value: fmtRate },
            { label: 'Write', stroke: cNow.diskWr, width: 2, value: fmtRate },
          ],
          valFmt: function(u, vals) { return vals.map(function(v) { return v == null ? '' : fmtRate(null, v); }); },
        }, w, cNow), [d.ts, d.drd, d.dwr], ioEl);
      } else if (ioChart) { ioChart.setData([d.ts, d.drd, d.dwr]); }

      if (!netChart && netEl) {
        netChart = new uPlot(makeOpts('Network I/O', {
          lines: [
            { label: 'RX', stroke: cNow.netRx, width: 2, value: fmtRate },
            { label: 'TX', stroke: cNow.netTx, width: 2, value: fmtRate },
          ],
          valFmt: function(u, vals) { return vals.map(function(v) { return v == null ? '' : fmtRate(null, v); }); },
        }, w, cNow), [d.ts, d.nrx, d.ntx], netEl);
      } else if (netChart) { netChart.setData([d.ts, d.nrx, d.ntx]); }
    }

    // Rebuild charts on theme toggle.
    function rebuild() {
      [cpuChart, memChart, ioChart, netChart].forEach(function(ch) { if (ch) ch.destroy(); });
      cpuChart = memChart = ioChart = netChart = null;
      [cpuEl, memEl, ioEl, netEl].forEach(function(el) { if (el) el.innerHTML = ''; });
      fetch(url).then(function(r) { return r.json(); }).then(render);
    }

    var observer = new MutationObserver(function(mutations) {
      for (var i = 0; i < mutations.length; i++) {
        if (mutations[i].attributeName === 'data-theme') { rebuild(); break; }
      }
    });
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

    // Initial fetch.
    fetch(url).then(function(r) { return r.json(); }).then(render);

    // Poll every 5s.
    var interval = setInterval(function() {
      if (!document.body.contains(container)) {
        clearInterval(interval);
        observer.disconnect();
        return;
      }
      fetch(url).then(function(r) { return r.json(); }).then(render);
    }, 5000);

    container._chartsInit = true;
  }

  function initAll(root) {
    (root || document).querySelectorAll('[data-stats-chart]').forEach(function(el) {
      if (!el._chartsInit) initCharts(el, el.dataset.statsChart);
    });
  }

  document.addEventListener('DOMContentLoaded', function() { initAll(); });
  document.body.addEventListener('htmx:afterSettle', function(e) { initAll(e.detail.target); });
})();

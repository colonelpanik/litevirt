// Command palette + keyboard navigation.
//   ⌘K / Ctrl-K  open/close the palette
//   /            open the palette (when not typing in a field)
//   ↑ ↓          move selection,  ↵ open,  esc close
//   g then <key> jump directly to a section (vim-style): v=VMs h=Hosts s=Stacks
//                c=Containers n=Networks b=Backups d=Dashboard e=Events
//
// The palette fuzzy-matches a static page list (client-side) and live resources
// (VMs/hosts/stacks/networks/images/LBs) via the existing /ui/search endpoint.
(function () {
  "use strict";

  var PAGES = [
    { label: "Dashboard", href: "/", kw: "home overview cluster" },
    { label: "VMs", href: "/vms", kw: "virtual machines compute" },
    { label: "Stacks", href: "/stacks", kw: "compose deploy" },
    { label: "Containers", href: "/containers", kw: "lxc oci ct" },
    { label: "Hosts", href: "/hosts", kw: "nodes servers" },
    { label: "Rebalance", href: "/rebalance", kw: "drs placement" },
    { label: "Networks", href: "/networks", kw: "vxlan bridge sdn" },
    { label: "Load Balancers", href: "/lb", kw: "lb haproxy vip" },
    { label: "Security Groups", href: "/security-groups", kw: "firewall sg rules" },
    { label: "Topology", href: "/topology", kw: "map" },
    { label: "Storage Pools", href: "/storage", kw: "pools disks ceph zfs" },
    { label: "Images", href: "/images", kw: "templates cloud" },
    { label: "Backups", href: "/backups", kw: "snapshot restore pbs" },
    { label: "Schedules", href: "/schedules", kw: "cron backup" },
    { label: "Events", href: "/events", kw: "log activity" },
    { label: "Health", href: "/health", kw: "status quorum" },
    { label: "Metrics", href: "/metrics-viewer", kw: "prometheus charts" },
    { label: "Dashboards", href: "/dashboards", kw: "grafana" },
    { label: "RBAC", href: "/rbac", kw: "roles permissions" },
    { label: "Users", href: "/users", kw: "accounts tokens" },
    { label: "Projects", href: "/projects", kw: "tenancy quota" },
    { label: "Audit", href: "/audit", kw: "log compliance" },
    { label: "PCI Devices", href: "/pci", kw: "gpu passthrough" },
    { label: "Diagnostics", href: "/diagnostics", kw: "debug" },
    { label: "Account / 2FA", href: "/account/2fa", kw: "password security key" },
  ];

  // g-then-key jump targets.
  var GNAV = {
    v: "/vms", h: "/hosts", s: "/stacks", c: "/containers", n: "/networks",
    b: "/backups", d: "/", e: "/events", l: "/lb", i: "/images",
  };

  var overlay, input, results, hint;
  var items = [], sel = -1, searchTimer = null, reqSeq = 0, pendingG = 0;

  function isTyping() {
    var el = document.activeElement;
    return el && /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName) && el.id !== "cp-input";
  }
  function isOpen() { return overlay && overlay.style.display !== "none"; }
  function open() { overlay.style.display = "flex"; input.value = ""; render(""); input.focus(); }
  function close() { if (overlay) overlay.style.display = "none"; }

  function esc(s) { var d = document.createElement("div"); d.textContent = s; return d.innerHTML; }
  function group(name) { return '<div class="cp-group">' + esc(name) + "</div>"; }
  function pageRow(p) {
    return '<a class="search-result" href="' + p.href + '"><span>' + esc(p.label) + "</span></a>";
  }

  function render(q) {
    var qq = q.trim().toLowerCase();
    var html = "";
    var pages = PAGES.filter(function (p) {
      return !qq || p.label.toLowerCase().indexOf(qq) >= 0 || (p.kw || "").indexOf(qq) >= 0;
    });
    if (pages.length) { html += group("Pages"); pages.forEach(function (p) { html += pageRow(p); }); }
    results.innerHTML = html;
    collect();

    if (qq) {
      var mine = ++reqSeq;
      fetch("/ui/search?q=" + encodeURIComponent(q), { credentials: "same-origin" })
        .then(function (r) { return r.text(); })
        .then(function (t) {
          if (mine !== reqSeq || !isOpen()) return; // a newer keystroke won
          if (t.trim()) results.insertAdjacentHTML("beforeend", '<div class="cp-sep"></div>' + t);
          collect();
        })
        .catch(function () {});
    }
  }

  function collect() {
    items = Array.prototype.slice.call(results.querySelectorAll(".search-result"));
    if (sel < 0 || sel >= items.length) sel = items.length ? 0 : -1;
    highlight();
  }
  function highlight() {
    items.forEach(function (el, i) { el.classList.toggle("cp-selected", i === sel); });
    if (sel >= 0 && items[sel]) items[sel].scrollIntoView({ block: "nearest" });
  }
  function move(d) { if (items.length) { sel = (sel + d + items.length) % items.length; highlight(); } }
  function activate() {
    if (sel >= 0 && items[sel]) {
      var href = items[sel].getAttribute("href");
      if (href) window.location.href = href;
    }
  }

  document.addEventListener("keydown", function (e) {
    if ((e.metaKey || e.ctrlKey) && (e.key === "k" || e.key === "K")) {
      e.preventDefault(); isOpen() ? close() : open(); return;
    }
    if (isOpen()) {
      if (e.key === "Escape") { e.preventDefault(); close(); }
      else if (e.key === "ArrowDown") { e.preventDefault(); move(1); }
      else if (e.key === "ArrowUp") { e.preventDefault(); move(-1); }
      else if (e.key === "Enter") { e.preventDefault(); activate(); }
      return;
    }
    if (isTyping()) return;
    if (e.key === "/") { e.preventDefault(); open(); return; }
    // g-then-key navigation.
    var now = Date.now();
    if (e.key === "g") { pendingG = now; return; }
    if (pendingG && now - pendingG < 1000 && GNAV[e.key]) {
      e.preventDefault(); pendingG = 0; window.location.href = GNAV[e.key]; return;
    }
    pendingG = 0;
  });

  document.addEventListener("DOMContentLoaded", function () {
    overlay = document.getElementById("command-palette");
    if (!overlay) return;
    input = document.getElementById("cp-input");
    results = document.getElementById("cp-results");
    overlay.addEventListener("mousedown", function (e) { if (e.target === overlay) close(); });
    input.addEventListener("input", function () {
      clearTimeout(searchTimer);
      var q = input.value;
      searchTimer = setTimeout(function () { render(q); }, 120);
    });
    results.addEventListener("mousemove", function (e) {
      var a = e.target.closest(".search-result");
      if (!a) return;
      var i = items.indexOf(a);
      if (i >= 0 && i !== sel) { sel = i; highlight(); }
    });
  });
})();

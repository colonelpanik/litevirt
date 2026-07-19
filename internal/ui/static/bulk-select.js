// bulk-select.js — wires up multi-select toolbars on tables marked with
// `data-bulk-table`. Listens for changes on `.bulk-check` checkboxes,
// updates a counter + hidden input, and toggles the toolbar visibility.
// Re-runs after every HTMX swap so dynamically-replaced tables stay live.
(function () {
  function refresh(table) {
    if (!table) return;
    var toolbarSel = '[data-bulk-toolbar="' + table.id + '"]';
    var bar = document.querySelector(toolbarSel);
    if (!bar) return;
    var checks = table.querySelectorAll('input.bulk-check');
    var selected = [];
    checks.forEach(function (c) { if (c.checked) selected.push(c.dataset.bulkName); });
    var count = bar.querySelector('[data-bulk-count]');
    if (count) count.textContent = selected.length;
    var hidden = bar.querySelector('input[data-bulk-names]');
    if (hidden) hidden.value = selected.join(',');
    bar.style.display = selected.length > 0 ? '' : 'none';
    var master = table.querySelector('input[data-bulk-master]');
    if (master) {
      var total = checks.length;
      master.indeterminate = selected.length > 0 && selected.length < total;
      master.checked = selected.length > 0 && selected.length === total;
    }
  }

  function wire(root) {
    (root || document).querySelectorAll('table[data-bulk-table]').forEach(function (table) {
      // Master "select all" checkbox in the header.
      var master = table.querySelector('input[data-bulk-master]');
      if (master && !master.dataset.bound) {
        master.dataset.bound = 'true';
        master.addEventListener('change', function () {
          var on = master.checked;
          table.querySelectorAll('input.bulk-check').forEach(function (c) { c.checked = on; });
          refresh(table);
        });
      }
      table.querySelectorAll('input.bulk-check').forEach(function (c) {
        if (!c.dataset.bound) {
          c.dataset.bound = 'true';
          c.addEventListener('change', function () { refresh(table); });
        }
      });
      refresh(table);
    });
  }

  document.addEventListener('DOMContentLoaded', function () { wire(document); });
  // HTMX replaces sub-trees on every poll/post; rewire after each swap.
  document.addEventListener('htmx:afterSwap', function (e) { wire(e.target || document); });

  // Pause interval polling while a bulk selection is active — otherwise the
  // every-5s refresh swaps the table out and clears the user's checkboxes
  // mid-selection. Only gates the polling container (hx-trigger "every …")
  // that actually holds checked rows; filters, actions, and unrelated polls
  // (stats charts) are untouched. Polling resumes on the next tick once cleared.
  document.addEventListener('htmx:beforeRequest', function (e) {
    var elt = e.detail && e.detail.elt;
    if (!elt || !elt.getAttribute) return;
    var trig = elt.getAttribute('hx-trigger') || '';
    if (trig.indexOf('every') < 0) return;
    if (elt.querySelector && elt.querySelector('input.bulk-check:checked')) {
      e.preventDefault();
    }
  });
})();

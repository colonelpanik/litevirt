// Themed confirmation dialog. htmx's hx-confirm normally calls the browser's
// native confirm(); we intercept the global htmx:confirm event and show an
// in-theme modal instead, so every existing hx-confirm is styled with zero
// per-element changes. Falls back to window.confirm if the markup is absent.
(function () {
  "use strict";

  var overlay, msgEl, okBtn, cancelBtn, pending;

  function isOpen() { return overlay && overlay.style.display !== "none"; }

  function settle(ok) {
    if (!pending) return;
    var cb = pending;
    pending = null;
    if (overlay) overlay.style.display = "none";
    cb(ok);
  }

  function ask(question, danger, cb) {
    if (!overlay) { cb(window.confirm(question)); return; }
    pending = cb;
    msgEl.textContent = question;
    okBtn.className = "btn " + (danger ? "btn-danger" : "btn-primary");
    okBtn.textContent = danger ? "Delete" : "Confirm";
    overlay.style.display = "flex";
    okBtn.focus();
  }

  document.addEventListener("DOMContentLoaded", function () {
    overlay = document.getElementById("confirm-dialog");
    if (!overlay) return;
    msgEl = document.getElementById("cd-message");
    okBtn = document.getElementById("cd-confirm");
    cancelBtn = document.getElementById("cd-cancel");
    okBtn.addEventListener("click", function () { settle(true); });
    cancelBtn.addEventListener("click", function () { settle(false); });
    overlay.addEventListener("mousedown", function (e) { if (e.target === overlay) settle(false); });
  });

  document.addEventListener("keydown", function (e) {
    if (!isOpen()) return;
    if (e.key === "Escape") { e.preventDefault(); settle(false); }
    else if (e.key === "Enter") { e.preventDefault(); settle(true); }
  });

  // htmx fires htmx:confirm for every request; detail.question is set only when
  // the element carries hx-confirm. Take over just those.
  document.addEventListener("htmx:confirm", function (evt) {
    var q = evt.detail.question;
    if (!q) return; // no hx-confirm — let htmx proceed normally
    evt.preventDefault();
    var danger = /delete|remove|destroy|cannot be undone|force|revert|drain|fence/i.test(q);
    ask(q, danger, function (ok) {
      if (ok) evt.detail.issueRequest(true); // true: don't re-prompt
    });
  });
})();

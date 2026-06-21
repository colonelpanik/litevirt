// Drives the "move disk to another pool" modal with a live progress bar.
// Submits the form to the SSE streaming endpoint and reads MoveVolume progress
// frames (phase + percent + bytes) as they arrive, instead of blocking on a
// single request that only renders once the (potentially long) move finishes.
(function () {
  function fmtBytes(b) {
    b = Number(b) || 0;
    var u = ["B", "KiB", "MiB", "GiB", "TiB"], i = 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return b.toFixed(1) + " " + u[i];
  }
  function esc(s) {
    var d = document.createElement("div");
    d.textContent = s == null ? "" : String(s);
    return d.innerHTML;
  }

  // startMoveVolume is invoked from the Move button's onclick in the modal.
  window.startMoveVolume = async function (btn) {
    var form = btn.closest("form");
    if (!form) return;
    var vm = form.dataset.vm;
    var fd = new FormData(form);
    var disk = fd.get("disk"), pool = fd.get("target_pool");
    if (!pool) { form.reportValidity(); return; }

    var prog = document.getElementById("move-volume-progress");
    var bar = document.getElementById("move-volume-bar");
    var phaseEl = document.getElementById("move-volume-phase");
    var bytesEl = document.getElementById("move-volume-bytes");
    var resultEl = document.getElementById("move-volume-result");

    resultEl.innerHTML = "";
    prog.style.display = "block";
    bar.removeAttribute("value"); // indeterminate until the first percent
    phaseEl.textContent = "Starting…";
    bytesEl.textContent = "";
    btn.disabled = true;

    function finishSuccess(d) {
      prog.style.display = "none";
      var extra = d && d.cleanup ? '<p class="muted" style="font-size:12px;margin-top:4px">Source disk: ' + esc(d.cleanup) + "</p>" : "";
      resultEl.innerHTML =
        '<div class="bulk-result-dialog" style="border:1px solid var(--border);border-radius:6px;padding:1em;background:var(--bg-elev)">' +
        '<h3 style="margin-top:0;color:var(--ok)">Disk moved ✓</h3>' +
        "<p>" + esc(vm) + " / " + esc(disk) + " → pool <b>" + esc(pool) + "</b></p>" + extra +
        '<button class="btn btn-primary" onclick="window.location.href=\'/vms/' + esc(vm) + "'\">Refresh VM</button></div>";
      btn.disabled = false;
    }
    function finishError(msg) {
      prog.style.display = "none";
      resultEl.innerHTML =
        '<div class="bulk-result-dialog" style="border:1px solid var(--border);border-radius:6px;padding:1em;background:var(--bg-elev)">' +
        '<h3 style="margin-top:0;color:var(--err)">Move failed</h3>' +
        '<code style="word-break:break-all;font-size:12px">' + esc(msg) + "</code></div>";
      btn.disabled = false;
    }
    function onEvent(ev, data) {
      if (ev === "progress") {
        var p = {};
        try { p = JSON.parse(data); } catch (e) { return; }
        phaseEl.textContent = (p.phase || "Working") + (p.status ? " — " + p.status : "");
        if (typeof p.pct === "number" && p.pct > 0) bar.value = p.pct;
        if (Number(p.total) > 0) {
          bytesEl.textContent = fmtBytes(p.copied) + " / " + fmtBytes(p.total) + " (" + Math.round(p.pct || 0) + "%)";
        }
      } else if (ev === "done") {
        bar.value = 100; phaseEl.textContent = "Complete";
        var d = {}; try { d = JSON.parse(data); } catch (e) {}
        finishSuccess(d);
      } else if (ev === "error") {
        var msg = data; try { msg = JSON.parse(data); } catch (e) {}
        finishError(msg);
      }
    }

    try {
      // Send url-encoded (not multipart) so the server parses it with FormValue.
      var resp = await fetch("/ui/vms/" + encodeURIComponent(vm) + "/move-volume-stream", { method: "POST", body: new URLSearchParams(fd) });
      if (!resp.ok || !resp.body) throw new Error("HTTP " + resp.status);
      var reader = resp.body.getReader(), dec = new TextDecoder(), buf = "";
      while (true) {
        var r = await reader.read();
        if (r.done) break;
        buf += dec.decode(r.value, { stream: true });
        var blocks = buf.split("\n\n");
        buf = blocks.pop();
        for (var i = 0; i < blocks.length; i++) {
          var ev = "", data = "";
          blocks[i].split("\n").forEach(function (line) {
            if (line.indexOf("event:") === 0) ev = line.slice(6).trim();
            else if (line.indexOf("data:") === 0) data += line.slice(5).trim();
          });
          if (ev) onEvent(ev, data);
        }
      }
    } catch (err) {
      finishError(err && err.message ? err.message : String(err));
    }
  };
})();

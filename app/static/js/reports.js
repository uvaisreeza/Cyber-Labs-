/* Report Builder: pick saved runs, export JSON / CSV / HTML. */
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var tbody = document.querySelector("#hist tbody");

  function status(msg, bad) { var s = $("rstatus"); s.textContent = msg; s.className = "status" + (bad ? " err" : ""); }
  function td(text, cls) { var c = document.createElement("td"); c.textContent = text == null ? "" : text; if (cls) c.className = cls; return c; }
  function selected() { return [].slice.call(tbody.querySelectorAll("input:checked")).map(function (i) { return Number(i.value); }); }

  function load() {
    fetch("/api/history?limit=500").then(function (r) {
      if (r.status === 401) { location.href = "/login"; throw new Error("auth"); }
      return r.json();
    }).then(function (d) {
      tbody.textContent = "";
      if (!d.items.length) {
        var tr = document.createElement("tr"), c = td("No runs yet - use a tool from the dashboard first.");
        c.colSpan = 7; tr.appendChild(c); tbody.appendChild(tr); return;
      }
      d.items.forEach(function (it) {
        var tr = document.createElement("tr"), box = document.createElement("td"), cb = document.createElement("input");
        cb.type = "checkbox"; cb.value = it.id; cb.setAttribute("aria-label", "Select run " + it.id);
        box.appendChild(cb); tr.appendChild(box);
        tr.appendChild(td(it.id)); tr.appendChild(td(it.tool_name)); tr.appendChild(td(it.target, "wrap"));
        tr.appendChild(td(it.status, it.status === "ok" ? "" : "error"));
        tr.appendChild(td(it.duration_ms)); tr.appendChild(td(it.created_at.replace("T", " ").replace("Z", "")));
        tbody.appendChild(tr);
      });
    }).catch(function (e) { if (e.message !== "auth") status("Could not load history", true); });
  }

  $("all").addEventListener("change", function () {
    var on = this.checked; [].forEach.call(tbody.querySelectorAll("input"), function (i) { i.checked = on; });
  });

  [].forEach.call(document.querySelectorAll("[data-fmt]"), function (b) {
    b.addEventListener("click", function () {
      var ids = selected(); if (!ids.length) return status("Select at least one run.", true);
      var fmt = b.dataset.fmt; status("Building " + fmt.toUpperCase() + "...");
      fetch("/api/reports/export", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ids: ids, format: fmt, title: $("rtitle").value || "SecureCheck Report" })
      }).then(function (r) {
        if (!r.ok) return r.json().then(function (d) { throw new Error(typeof d.detail === "string" ? d.detail : "Export failed"); });
        var name = (/filename="([^"]+)"/.exec(r.headers.get("Content-Disposition") || "") || [])[1] || "report." + fmt;
        return r.blob().then(function (blob) {
          var a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = name;
          document.body.appendChild(a); a.click(); a.remove(); setTimeout(function () { URL.revokeObjectURL(a.href); }, 2000);
          status("Downloaded " + name);
        });
      }).catch(function (e) { status(e.message, true); });
    });
  });

  $("delsel").addEventListener("click", function () {
    var ids = selected(); if (!ids.length) return status("Select at least one run.", true);
    if (!confirm("Delete " + ids.length + " run(s) from your log?")) return;
    Promise.all(ids.map(function (id) { return fetch("/api/history/" + id, { method: "DELETE" }); }))
      .then(function () { status("Deleted " + ids.length + " run(s)."); $("all").checked = false; load(); });
  });

  load();
})();

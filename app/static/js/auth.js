(function () {
  "use strict";
  var box = document.getElementById("authbox"), form = document.getElementById("authform");
  if (!form) return;
  var mode = box.dataset.mode, err = document.getElementById("autherr");
  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    err.hidden = true;
    var fd = new FormData(form), btn = form.querySelector("button");
    btn.disabled = true;
    fetch("/api/auth/" + (mode === "register" ? "register" : "login"), {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: fd.get("username"), password: fd.get("password") })
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (d) { return { ok: r.ok, status: r.status, d: d }; });
    }).then(function (res) {
      if (res.ok) { location.href = "/dashboard"; return; }
      var msg = res.d.detail;
      if (Array.isArray(msg)) msg = msg.map(function (m) { return m.msg; }).join("; ");
      if (res.status === 429) msg = "Too many attempts - wait a minute and retry.";
      err.textContent = msg || "Request failed"; err.hidden = false; btn.disabled = false;
    }).catch(function () { err.textContent = "Network error"; err.hidden = false; btn.disabled = false; });
  });
})();

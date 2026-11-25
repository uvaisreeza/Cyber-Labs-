/* Dashboard: builds every tool form from /api/tools and renders results safely.
   All dynamic text goes through textContent (never HTML parsing), so hostile data from
   scanned targets (banners, WHOIS, DNS TXT...) cannot inject script. */
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var tools = [], cats = [], current = null, lastResult = null;

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }

  // ---- sidebar -----------------------------------------------------------
  function renderList(filter) {
    var list = $("toollist"); list.textContent = "";
    var f = (filter || "").toLowerCase(), n = 0;
    cats.forEach(function (c) {
      var inCat = tools.filter(function (t) {
        return t.category === c.id && (t.name + " " + t.description).toLowerCase().indexOf(f) !== -1;
      });
      if (!inCat.length) return;
      list.appendChild(el("h4", "", c.name));
      inCat.forEach(function (t) {
        n++;
        var b = el("button", "toolbtn" + (current && current.id === t.id ? " active" : ""), t.name);
        b.type = "button";
        b.addEventListener("click", function () { select(t.id); });
        list.appendChild(b);
      });
    });
    if (!n) list.appendChild(el("p", "hint", "No tools match."));
  }

  // ---- form --------------------------------------------------------------
  function select(id) {
    current = tools.filter(function (t) { return t.id === id; })[0];
    $("welcome").hidden = true; $("toolpanel").hidden = false;
    $("tp-name").textContent = current.name;
    $("tp-cat").textContent = (cats.filter(function (c) { return c.id === current.category; })[0] || {}).name;
    $("tp-desc").textContent = current.description;
    $("tp-out").hidden = true; setStatus("");
    var form = $("toolform"); form.textContent = "";
    current.fields.forEach(function (f) { form.appendChild(field(f)); });
    var go = el("button", "btn", "Run"); go.type = "submit"; go.id = "run"; form.appendChild(go);
    if (current.network) form.appendChild(el("span", "hint", "  contacts external services"));
    renderList($("filter").value);
    history.replaceState(null, "", "#" + id);
    var first = form.querySelector("input,textarea,select"); if (first) first.focus();
  }

  function field(f) {
    var wrap = el("label", f.type === "checkbox" ? "chk" : "");
    var inp;
    if (f.type === "textarea") inp = el("textarea");
    else if (f.type === "select") {
      inp = el("select");
      f.options.forEach(function (o) { var op = el("option", "", o); op.value = o; inp.appendChild(op); });
    } else {
      inp = el("input");
      inp.type = f.type === "number" ? "number" : f.type === "password" ? "password" :
                 f.type === "checkbox" ? "checkbox" : f.type === "file" ? "file" : "text";
    }
    inp.name = f.name;
    if (f.placeholder) inp.placeholder = f.placeholder;
    if (f.type === "checkbox") inp.checked = !!f.default;
    else if (f.default !== undefined && f.type !== "file") inp.value = f.default;
    if (f.type === "password" || f.sensitive) inp.autocomplete = "off";
    if (f.sensitive || f.type === "text") { inp.spellcheck = false; }
    if (f.type === "checkbox") { wrap.appendChild(inp); wrap.appendChild(document.createTextNode(f.label)); }
    else { wrap.appendChild(document.createTextNode(f.label)); wrap.appendChild(inp); }
    return wrap;
  }

  function readFile(file) {
    return new Promise(function (res, rej) {
      if (file.size > 5 * 1024 * 1024) return rej(new Error("File too large (max 5 MB)"));
      var r = new FileReader();
      r.onload = function () { res({ name: file.name, content_b64: String(r.result).split(",")[1] || "" }); };
      r.onerror = function () { rej(new Error("Could not read file")); };
      r.readAsDataURL(file);
    });
  }

  function collect() {
    var form = $("toolform"), params = {}, jobs = [];
    current.fields.forEach(function (f) {
      var i = form.elements[f.name];
      if (f.type === "checkbox") params[f.name] = i.checked;
      else if (f.type === "number") params[f.name] = i.value === "" ? null : Number(i.value);
      else if (f.type === "file") {
        if (!i.files.length) throw new Error("Choose a file first");
        jobs.push(readFile(i.files[0]).then(function (v) { params[f.name] = v; }));
      } else params[f.name] = i.value;
    });
    return Promise.all(jobs).then(function () { return params; });
  }

  function setStatus(msg, cls, busy) {
    var s = $("tp-status"); s.textContent = msg;
    s.className = "status" + (cls ? " " + cls : "") + (busy ? " spin" : "");
  }

  $("toolform").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var btn = $("run"); $("tp-out").hidden = true;
    var p;
    try { p = collect(); } catch (e) { setStatus(e.message, "err"); return; }
    btn.disabled = true; setStatus("Running " + current.name, "", true);
    p.then(function (params) {
      return fetch("/api/tools/" + current.id, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ params: params })
      });
    }).then(function (r) {
      if (r.status === 401) { location.href = "/login"; throw new Error("Session expired"); }
      return r.json().catch(function () { return {}; }).then(function (d) { return { r: r, d: d }; });
    }).then(function (x) {
      if (!x.r.ok) {
        var msg = x.d.detail;
        if (Array.isArray(msg)) msg = msg.map(function (m) { return m.msg; }).join("; ");
        if (x.r.status === 429) msg = "Rate limit reached - slow down and try again shortly.";
        setStatus((x.r.status === 403 ? "BLOCKED: " : "Error: ") + (msg || "request failed"),
                  x.r.status === 403 ? "blocked" : "err");
        return;
      }
      setStatus("");
      lastResult = x.d.result;
      $("tp-meta").textContent = "completed in " + x.d.duration_ms + " ms - saved to log #" + x.d.log_id;
      var v = $("tp-view"); v.textContent = ""; v.appendChild(render(lastResult, 0));
      $("tp-raw").textContent = JSON.stringify(lastResult, null, 2);
      $("tp-raw").hidden = true; $("tp-view").hidden = false; $("toggle-raw").textContent = "Raw JSON";
      $("tp-out").hidden = false;
    }).catch(function (e) { if (e.message !== "Session expired") setStatus("Error: " + e.message, "err"); })
      .finally(function () { btn.disabled = false; });
  });

  // ---- safe recursive renderer -------------------------------------------
  var GOOD = /^(true|clean|listed:false|ok|pass|a\+?)$/i;
  function cls(key, val) {
    var s = String(val).toLowerCase();
    if (key === "severity" && /^(critical|high|medium|low)$/.test(s)) return "sev-" + s;
    if (key === "status" || key === "verdict" || key === "grade") {
      if (/malicious|high risk|blocked|\bf\b|\bd\b|listed/.test(s)) return "v-bad";
      if (/suspicious|medium|unknown|\bc\b/.test(s)) return "v-warn";
      if (/clean|ok|\ba\b|\bb\b|low risk/.test(s)) return "v-ok";
    }
    return "";
  }
  function render(v, depth, key) {
    if (v === null || v === undefined) return el("span", "", "—");
    if (typeof v !== "object") {
      var c = cls(key || "", v);
      return el("span", c, typeof v === "boolean" ? (v ? "yes" : "no") : String(v));
    }
    var box = el("div", depth ? "nest" : "");
    if (Array.isArray(v)) {
      if (!v.length) return el("span", "", "(none)");
      if (v.every(function (x) { return x === null || typeof x !== "object"; })) {
        return el("span", "", v.join(", "));
      }
      v.forEach(function (x, i) {
        var row = el("div", "kv"); row.appendChild(el("div", "k", "[" + i + "]"));
        var val = el("div", "v"); val.appendChild(render(x, depth + 1)); row.appendChild(val); box.appendChild(row);
      });
      return box;
    }
    Object.keys(v).forEach(function (k) {
      var row = el("div", "kv"); row.appendChild(el("div", "k", k.replace(/_/g, " ")));
      var val = el("div", "v"); val.appendChild(render(v[k], depth + 1, k)); row.appendChild(val); box.appendChild(row);
    });
    return box;
  }

  $("toggle-raw").addEventListener("click", function () {
    var raw = $("tp-raw").hidden;
    $("tp-raw").hidden = !raw; $("tp-view").hidden = raw;
    this.textContent = raw ? "Formatted" : "Raw JSON";
  });
  $("copy").addEventListener("click", function () {
    var b = this;
    if (navigator.clipboard) navigator.clipboard.writeText(JSON.stringify(lastResult, null, 2)).then(function () {
      b.textContent = "Copied"; setTimeout(function () { b.textContent = "Copy"; }, 1200);
    });
  });
  $("filter").addEventListener("input", function () { renderList(this.value); });

  fetch("/api/tools").then(function (r) {
    if (r.status === 401) { location.href = "/login"; throw new Error("auth"); }
    return r.json();
  }).then(function (d) {
    tools = d.tools; cats = d.categories; renderList("");
    var h = location.hash.slice(1);
    if (h && tools.some(function (t) { return t.id === h; })) select(h);
  }).catch(function (e) { if (e.message !== "auth") $("toollist").textContent = "Could not load tools."; });
})();

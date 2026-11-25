/* Shared: matrix rain, one-time boot sequence, fail-safe scroll reveal, logout. */
(function () {
  "use strict";
  var reduce = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;

  // ---- matrix rain --------------------------------------------------------
  var cv = document.getElementById("matrix");
  if (cv && !reduce) {
    var ctx = cv.getContext("2d"), cols, drops, size = 16;
    var chars = "01ABCDEF<>/\\{}[]#$%=+*";
    var resize = function () {
      cv.width = innerWidth; cv.height = innerHeight;
      cols = Math.ceil(cv.width / size);
      drops = Array.from({ length: cols }, function () { return Math.random() * -50; });
    };
    resize(); addEventListener("resize", resize);
    setInterval(function () {
      if (document.hidden) return;
      ctx.fillStyle = "rgba(0,0,0,.09)"; ctx.fillRect(0, 0, cv.width, cv.height);
      ctx.fillStyle = "#00ff66"; ctx.font = size + "px monospace";
      for (var i = 0; i < cols; i++) {
        ctx.fillText(chars[(Math.random() * chars.length) | 0], i * size, drops[i] * size);
        if (drops[i] * size > cv.height && Math.random() > 0.975) drops[i] = 0;
        drops[i]++;
      }
    }, 60);
  }

  // ---- boot sequence (once per browser session, skippable) ----------------
  var boot = document.getElementById("boot");
  var seen = false;
  try { seen = sessionStorage.getItem("cl_boot") === "1"; } catch (e) {}
  if (boot && !seen && !reduce) {
    var lines = [
      "CYBERLABS BIOS v1.0 ........................ OK",
      "mounting /dev/recon ......................... OK",
      "mounting /dev/crypto ........................ OK",
      "mounting /dev/intel ......................... OK",
      "loading SSRF guard .......................... OK",
      "loading rate limiter ........................ OK",
      "28 tools online. authorised use only.",
      "> ready_"
    ];
    var pre = document.getElementById("boot-text"), i = 0, done = false;
    var finish = function () {
      if (done) return; done = true; boot.hidden = true;
      try { sessionStorage.setItem("cl_boot", "1"); } catch (e) {}
    };
    boot.hidden = false;
    boot.addEventListener("click", finish);
    addEventListener("keydown", finish, { once: true });
    (function next() {
      if (done) return;
      if (i >= lines.length) return setTimeout(finish, 350);
      pre.textContent += lines[i++] + "\n"; setTimeout(next, 130);
    })();
    setTimeout(finish, 3500);               // hard fail-safe: boot can never trap the page
  }

  // ---- scroll reveal (fail-safe: visible by default) -----------------------
  var items = [].slice.call(document.querySelectorAll(".reveal"));
  if (items.length && "IntersectionObserver" in window && !reduce) {
    var io = new IntersectionObserver(function (es) {
      es.forEach(function (e) {
        if (e.isIntersecting) { e.target.classList.remove("pending"); io.unobserve(e.target); }
      });
    }, { threshold: 0.05 });
    items.forEach(function (el) {
      if (el.getBoundingClientRect().top > innerHeight) { el.classList.add("pending"); io.observe(el); }
    });
    // whatever happens (observer never fires, inner route, print), reveal everything
    setTimeout(function () { items.forEach(function (el) { el.classList.remove("pending"); }); }, 1500);
  }

  // ---- logout ------------------------------------------------------------
  var lo = document.getElementById("logout");
  if (lo) lo.addEventListener("click", function () {
    fetch("/api/auth/logout", { method: "POST" }).finally(function () { location.href = "/login"; });
  });
})();

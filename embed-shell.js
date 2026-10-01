(function (win) {
  "use strict";
  const PROTOCOL = "aomen28.embed.v1";
  const KEY = "aomen28.embed.session.v1";
  const valid = auth => auth && /^emb_[a-f0-9]{64}$/.test(auth.token || "")
    && Number.isFinite(auth.expiresAt) && auth.expiresAt > Date.now()
    && auth.expiresAt <= Date.now() + 11 * 60 * 1000;
  function httpsOrigin(value) {
    try {
      const url = new URL(value);
      return url.protocol === "https:" && !url.username && !url.password ? url.origin : "";
    } catch (_) { return ""; }
  }
  win.createAomen28ShellBridge = function (frame) {
    let allowed = new Set();
    let activeOrigin = "";
    let nonce = "";
    let auth = null;
    let loggedOut = false;
    try {
      const saved = JSON.parse(win.sessionStorage.getItem(KEY) || "null");
      auth = valid(saved?.auth) ? saved.auth : null;
      loggedOut = Boolean(saved?.loggedOut || saved?.auth && !auth);
    } catch (_) {}
    function persist() {
      try { win.sessionStorage.setItem(KEY, JSON.stringify({ auth, loggedOut })); } catch (_) {}
    }
    function send(type, extra = {}) {
      if (activeOrigin && nonce) frame.contentWindow.postMessage({ protocol: PROTOCOL, type, nonce, ...extra }, activeOrigin);
    }
    win.addEventListener("message", event => {
      const data = event.data;
      if (!activeOrigin || !allowed.has(event.origin) || event.origin !== activeOrigin || event.source !== frame.contentWindow
        || !data || data.protocol !== PROTOCOL || !/^[a-f0-9]{32}$/.test(data.nonce || "")) return;
      if (data.type === "READY") {
        nonce = data.nonce;
        if (auth && !valid(auth)) { auth = null; loggedOut = true; persist(); }
        send("SYNC", { auth, loggedOut });
        return;
      }
      if (data.nonce !== nonce || !Number.isSafeInteger(data.id) || data.id <= 0) return;
      if (data.type === "LOGIN" && valid(data.auth)) {
        auth = { token: data.auth.token, expiresAt: data.auth.expiresAt };
        loggedOut = false;
        persist();
        send("ACK", { id: data.id });
      } else if (data.type === "LOGOUT") {
        auth = null;
        loggedOut = true;
        persist();
        send("ACK", { id: data.id });
      }
    });
    return {
      configure(routes) { allowed = new Set(routes.map(route => httpsOrigin(route.url)).filter(Boolean)); },
      select(url) {
        const origin = httpsOrigin(url);
        if (!allowed.has(origin)) throw new Error("线路来源不被允许");
        activeOrigin = origin;
        nonce = "";
      }
    };
  };
  win.aomen28HttpsOrigin = httpsOrigin;
})(window);

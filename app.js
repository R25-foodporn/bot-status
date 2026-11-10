"use strict";
/* Bot-Status v17: Daten nur verschluesselt (AES-GCM, Schluessel via PBKDF2-SHA256 aus dem Zugangscode). */
const REPO_API_LIVE = "https://api.github.com/repos/R25-foodporn/bot-status/contents/live.enc.json?ref=live";
const RAW_LIVE = "https://raw.githubusercontent.com/R25-foodporn/bot-status/live/live.enc.json";
const RAW_POLL_MS = 9000;
const STORE_KEY = "botstatus.auth.v1";
const VALID_MS = 180 * 24 * 60 * 60 * 1000;
const STATUS_POLL_MS = 6000;
const LIVE_POLL_MS = 3000;

let hasRendered = false;
let lastDataKey = "";
let lastLive = null;
let aesKey = null;
let statusTimer = null;
let liveTimer = null;
let liveEtag = null;
let running = false;

/* ---------- Krypto (auch in Node testbar) ---------- */
const subtle = (typeof crypto !== "undefined" && crypto.subtle) ? crypto.subtle : null;

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToB64(bytes) {
  let s = "";
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
  return btoa(s);
}
function normalizeCode(code) {
  return String(code || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
}
async function deriveRawKey(code, kdf) {
  const base = await subtle.importKey("raw", new TextEncoder().encode(normalizeCode(code)), "PBKDF2", false, ["deriveBits"]);
  return subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: b64ToBytes(kdf.salt), iterations: kdf.iter }, base, 256);
}
function importAesKey(raw) {
  return subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["decrypt"]);
}
async function decryptJson(key, env) {
  const plain = await subtle.decrypt({ name: "AES-GCM", iv: b64ToBytes(env.iv) }, key, b64ToBytes(env.ct));
  return JSON.parse(new TextDecoder().decode(plain));
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { normalizeCode, deriveRawKey, importAesKey, decryptJson, bytesToB64, b64ToBytes };
}

/* ---------- Gerät, Speicher ---------- */
function detectDevice() {
  const ua = navigator.userAgent || "";
  if (/Tesla|QtCarBrowser/i.test(ua)) return "Tesla";
  if (/iPhone/i.test(ua)) return "iPhone";
  if (/iPad/i.test(ua)) return "iPad";
  if (/Macintosh/i.test(ua)) return (navigator.maxTouchPoints > 1) ? "iPad" : "Mac";
  return "Andere";
}
function loadStored() {
  try {
    const s = JSON.parse(localStorage.getItem(STORE_KEY) || "null");
    if (s && s.k && s.exp && s.exp > Date.now()) return s;
  } catch (err) {}
  localStorage.removeItem(STORE_KEY);
  return null;
}
function logout() {
  stopTimers();
  running = false;
  aesKey = null;
  localStorage.removeItem(STORE_KEY);
  location.replace(location.pathname);
}

async function fetchEnc(url) {
  const sep = url.indexOf("?") >= 0 ? "&" : "?";
  const res = await fetch(url + sep + "ts=" + Date.now(), { cache: "no-store" });
  if (!res.ok) throw new Error("HTTP " + res.status);
  return res.json();
}

/* ---------- Anmeldung ---------- */
function showLogin(message) {
  stopTimers();
  running = false;
  document.getElementById("logout").hidden = true;
  const root = document.getElementById("app");
  root.innerHTML = `
    <div class="login">
      <form id="login-form" autocomplete="off">
        <label for="code">Zugangscode eingeben</label>
        <input id="code" name="code" inputmode="text" autocapitalize="characters" autocorrect="off" spellcheck="false" placeholder="XXXX-XXXX-XXXX" maxlength="20">
        <button type="submit">Anmelden</button>
        <p class="msg" id="login-msg"></p>
      </form>
    </div>`;
  const msg = document.getElementById("login-msg");
  if (message) msg.textContent = message;
  document.getElementById("login-form").onsubmit = async function (event) {
    event.preventDefault();
    const code = document.getElementById("code").value;
    msg.textContent = "Wird geprüft …";
    const ok = await tryCode(code);
    if (!ok) msg.textContent = "Code stimmt nicht. Bitte nochmals versuchen.";
  };
  const input = document.getElementById("code");
  if (input) input.focus();
}

async function tryCode(code) {
  if (normalizeCode(code).length < 8) return false;
  try {
    const kdf = await fetchEnc("kdf.json");
    const raw = await deriveRawKey(code, kdf);
    const key = await importAesKey(raw);
    const env = await fetchEnc("status.enc.json");
    const data = await decryptJson(key, env);
    localStorage.setItem(STORE_KEY, JSON.stringify({ k: bytesToB64(raw), exp: Date.now() + VALID_MS }));
    aesKey = key;
    startDashboard(data);
    return true;
  } catch (err) {
    return false;
  }
}

/* ---------- Laden ---------- */
async function loadStatus() {
  try {
    const env = await fetchEnc("status.enc.json");
    const data = await decryptJson(aesKey, env);
    render(document.getElementById("app"), data);
    hasRendered = true;
    if (lastLive) applyLive(lastLive);
  } catch (err) {
    if (err && err.name === "OperationError") { localStorage.removeItem(STORE_KEY); showLogin("Bitte Code neu eingeben."); return; }
    if (!hasRendered) {
      document.getElementById("app").innerHTML = '<div class="error">Status konnte nicht geladen werden. Seite neu laden oder später erneut versuchen.</div>';
    }
  }
}

let apiNextAt = 0;
let rawNextAt = 0;
let visibleSince = Date.now();

/* GitHub-API: schnell (Sekunden), aber ohne Login nur 60 Abfragen pro Stunde und IP, auch 304 zählt.
   Darum wird das Budget gleichmässig bis zum Reset verteilt; raw.githubusercontent (Zwischenspeicher bis 5 Min.) läuft als Ersatz mit. */
function scheduleApi(res) {
  const remaining = Number(res.headers.get("x-ratelimit-remaining"));
  const reset = Number(res.headers.get("x-ratelimit-reset")) * 1000;
  const now = Date.now();
  if (!Number.isFinite(remaining) || !reset) { apiNextAt = now + 60000; return; }
  if (remaining <= 3) { apiNextAt = Math.max(reset, now + 60000); return; }
  // Erste 2 Minuten nach dem Öffnen: alle 5 s, solange genug Budget da ist; danach gleichmässig verteilen.
  if (now - visibleSince < 120000 && remaining > 30) { apiNextAt = now + 5000; return; }
  apiNextAt = now + Math.max(LIVE_POLL_MS, (reset - now) / (remaining - 3));
}

async function loadLiveApi() {
  const headers = { "Accept": "application/vnd.github.raw" };
  if (liveEtag) headers["If-None-Match"] = liveEtag;
  const res = await fetch(REPO_API_LIVE, { cache: "no-store", headers: headers });
  if (res.status === 403 || res.status === 429) {
    const retry = Number(res.headers.get("retry-after")) * 1000;
    const reset = Number(res.headers.get("x-ratelimit-reset")) * 1000;
    apiNextAt = Math.max(Date.now() + 60000, retry ? Date.now() + retry : 0, reset || 0);
    throw new Error("rate");
  }
  scheduleApi(res);
  if (res.status === 304) return null;
  if (!res.ok) throw new Error("HTTP " + res.status);
  const tag = res.headers.get("ETag");
  if (tag) liveEtag = tag;
  return JSON.parse(await res.text());
}

async function takeLive(env) {
  if (!env) return;
  try {
    const data = await decryptJson(aesKey, env);
    if (!lastLive || String(data.updated || "") > String(lastLive.updated || "")) {
      lastLive = data;
      applyLive(data);
    } else if (lastLive && String(data.updated || "") === String(lastLive.updated || "")) {
      applyLive(lastLive);
    }
  } catch (err) {}
}

async function loadLive() {
  const jobs = [];
  if (Date.now() >= rawNextAt) {
    rawNextAt = Date.now() + RAW_POLL_MS;
    jobs.push(fetchEnc(RAW_LIVE).then(takeLive, function () {}));
  }
  if (Date.now() >= apiNextAt) {
    apiNextAt = Date.now() + LIVE_POLL_MS;
    jobs.push(loadLiveApi().then(takeLive, function () {
      // Fehler oder Sperre: nicht hämmern, mindestens 60 s warten
      apiNextAt = Math.max(apiNextAt, Date.now() + 60000);
    }));
  }
  await Promise.all(jobs);
}

/* ---------- Timer nur bei sichtbarer Seite ---------- */
function stopTimers() {
  if (statusTimer) clearTimeout(statusTimer);
  if (liveTimer) clearTimeout(liveTimer);
  statusTimer = liveTimer = null;
}
function startTimers() {
  stopTimers();
  rawNextAt = 0;
  visibleSince = Date.now();
  if (!running || !aesKey || document.visibilityState === "hidden") return;
  const statusLoop = function () {
    loadStatus().finally(function () {
      if (running && document.visibilityState !== "hidden") statusTimer = setTimeout(statusLoop, STATUS_POLL_MS);
    });
  };
  const liveLoop = function () {
    loadLive().finally(function () {
      if (running && document.visibilityState !== "hidden") liveTimer = setTimeout(liveLoop, LIVE_POLL_MS);
    });
  };
  liveLoop();
  statusTimer = setTimeout(statusLoop, hasRendered ? 0 : STATUS_POLL_MS);
}

function startDashboard(initialData) {
  running = true;
  document.getElementById("logout").hidden = false;
  if (initialData) {
    render(document.getElementById("app"), initialData);
    hasRendered = true;
  }
  startTimers();
}

function applyLive(live) {
  if (!live) return;
  const el = document.getElementById("call-status");
  if (el) {
    const call = live.currentCall;
    let text;
    let idle = false;
    if (call && call.bot) {
      text = "Am Telefon, " + call.bot + ", " + (call.note || "Gespräch läuft");
    } else {
      text = "Kein laufendes Gespräch";
      idle = true;
    }
    if (el.textContent !== text) {
      el.textContent = text;
      el.classList.toggle("idle", idle);
    }
  }
  const usageEl = document.getElementById("usage");
  if (usageEl && live.weeklyUsage && usageEl.textContent !== live.weeklyUsage) {
    usageEl.textContent = live.weeklyUsage;
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatTime(value) {
  const date = value instanceof Date ? value : new Date(value || Date.now());
  if (Number.isNaN(date.getTime())) return "unbekannt";
  try {
    const parts = new Intl.DateTimeFormat("de-CH", {
      timeZone: "Europe/Zurich",
      weekday: "short",
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
      hourCycle: "h23"
    }).formatToParts(date);
    const get = (type) => (parts.find((part) => part.type === type) || {}).value || "";
    const weekday = get("weekday").replace(/\.$/, "");
    return `${weekday} ${get("day")}.${get("month")}.${get("year")}, ${get("hour")}:${get("minute")}:${get("second")} Zurich`;
  } catch (err) {
    return date.toISOString();
  }
}

function contentKey(data) {
  return JSON.stringify({
    waitingOnMark: data.waitingOnMark,
    urgent: data.urgent,
    bots: data.bots,
    weeklyUsage: data.weeklyUsage
  });
}

function itemButton(key, title, detail, source) {
  const line = title || detail || "";
  const more = detail || title || "";
  const sourceHtml = source
    ? `<span class="need-source">${escapeHtml(source)}</span>`
    : "";
  return `<li><button type="button" class="need-item" data-drill data-key="${escapeHtml(key)}" data-title="${escapeHtml(line)}" data-detail="${escapeHtml(more)}" data-source="${escapeHtml(source || "")}"><span class="need-letter">${escapeHtml(key)}.</span>${sourceHtml}<span class="need-text">${escapeHtml(line)}</span></button></li>`;
}

function closeDrill(root) {
  const panel = root.querySelector("#drilldown");
  if (panel) panel.hidden = true;
}

function openDrill(root, key, title, detail, source) {
  const panel = root.querySelector("#drilldown");
  if (!panel) return;
  const keyText = key ? key + "." : "";
  panel.querySelector(".drilldown-key").textContent = source ? keyText + " · " + source : keyText;
  panel.querySelector(".drilldown-title").textContent = title || "";
  panel.querySelector(".drilldown-body").textContent = detail || title || "";
  panel.hidden = false;
}

function render(root, data) {
  const stamp = formatTime(new Date());
  const key = contentKey(data);
  if (hasRendered && key === lastDataKey) {
    const clock = document.getElementById("clock");
    if (clock) {
      clock.textContent = stamp;
      if (lastLive) applyLive(lastLive);
      return;
    }
  }
  lastDataKey = key;

  const call = (lastLive && lastLive.currentCall !== undefined) ? lastLive.currentCall : data.currentCall;
  const waiting = Array.isArray(data.waitingOnMark) ? data.waitingOnMark : [];
  const urgent = Array.isArray(data.urgent) ? data.urgent : [];
  const bots = Array.isArray(data.bots) ? data.bots : [];
  const usageText = (lastLive && lastLive.weeklyUsage) || data.weeklyUsage || "";

  let callDetail;
  let callLiveClass = "call-live";
  if (call && call.bot) {
    callDetail = "Am Telefon, " + call.bot + ", " + (call.note || "Gespräch läuft");
  } else {
    callDetail = "Kein laufendes Gespräch";
    callLiveClass += " idle";
  }

  const waitingHtml = waiting.length
    ? `<ol class="need-list">${waiting.map((item, i) => {
        const letter = String.fromCharCode(97 + i);
        return itemButton(letter, item.title || item.need, item.detail || item.need, item.source || item.bot || "");
      }).join("")}</ol>`
    : `<p class="empty">Gerade wartet niemand auf eine Entscheidung von dir.</p>`;

  const urgentHtml = urgent.length
    ? `<ol class="need-list">${urgent.map((item, i) => {
        return itemButton(String(i + 1), item.title || item.need, item.detail || item.need, item.source || "");
      }).join("")}</ol>`
    : `<p class="empty">Gerade nichts Dringendes.</p>`;

  const botsHtml = bots.map((bot) => {
    const status = (bot.status || "bereit").toLowerCase();
    const needed = bot.input || bot.task || "Keine Eingabe nötig";
    return `
      <article class="bot">
        <span class="badge ${escapeHtml(status)}">${escapeHtml(status)}</span>
        <p class="name">${escapeHtml(bot.name)}</p>
        <p class="input-label">Eingabe von dir</p>
        <p class="task">${escapeHtml(needed)}</p>
      </article>
    `;
  }).join("");

  root.innerHTML = `
    <p class="call-line">
      <span class="call-label">Aktuelles Gespräch</span>
      <span id="call-status" class="${callLiveClass}">${escapeHtml(callDetail)}</span>
    </p>
    <section class="section">
      <div class="top-grid">
        <article class="need need-tall need-wide">
          <h2>Was als Nächstes von mir gebraucht wird</h2>
          ${waitingHtml}
        </article>
        <article class="need need-tall urgent-tile">
          <h2>Dringendes</h2>
          ${urgentHtml}
        </article>
      </div>
    </section>
    <section class="section">
      <h2>Bots</h2>
      <div class="grid">${botsHtml}</div>
    </section>
    <div class="updated">
      <span>Aktualisiert: <span id="clock">${escapeHtml(stamp)}</span></span>
      <span id="usage">${escapeHtml(usageText)}</span>
    </div>
    <div id="drilldown" class="drilldown" hidden>
      <div class="drilldown-card">
        <p class="drilldown-key"></p>
        <h3 class="drilldown-title"></h3>
        <p class="drilldown-body"></p>
        <button type="button" class="drilldown-close" data-close-drill>Schliessen</button>
      </div>
    </div>
  `;

  root.onclick = function (event) {
    const item = event.target.closest("[data-drill]");
    if (item) {
      openDrill(root, item.getAttribute("data-key"), item.getAttribute("data-title"), item.getAttribute("data-detail"), item.getAttribute("data-source"));
      return;
    }
    if (event.target.closest("[data-close-drill]") || event.target.id === "drilldown") {
      closeDrill(root);
    }
  };
}


async function boot() {
  document.getElementById("device").textContent = "Gerät: " + detectDevice();
  try {
    if (!localStorage.getItem("botstatus-ua-ok")) {
      const ua = document.createElement("div");
      ua.id = "ua-raw";
      ua.textContent = "Kennung: " + (navigator.userAgent || "(leer)") + " · Antippen zum Ausblenden";
      ua.style.cssText = "font-size:11px;opacity:.75;word-break:break-all;margin-top:4px;cursor:pointer;";
      ua.addEventListener("click", () => { localStorage.setItem("botstatus-ua-ok", "1"); ua.remove(); });
      document.querySelector(".topbar").appendChild(ua);
    }
    console.log("User-Agent:", navigator.userAgent);
  } catch (err) {}
  document.getElementById("logout").onclick = function (e) { e.preventDefault(); logout(); };
  if (!subtle) { document.getElementById("app").innerHTML = '<div class="error">Dieser Browser unterstützt die nötige Verschlüsselung nicht.</div>'; return; }
  const m = /[#&]code=([^&]+)/.exec(location.hash || "");
  if (m) {
    history.replaceState(null, "", location.pathname + location.search);
    const ok = await tryCode(decodeURIComponent(m[1]));
    if (ok) return;
    showLogin("Code aus dem Link stimmt nicht.");
    return;
  }
  const stored = loadStored();
  if (!stored) { showLogin(); return; }
  try {
    aesKey = await importAesKey(b64ToBytes(stored.k));
  } catch (err) { showLogin(); return; }
  document.getElementById("app").innerHTML = '<p class="note">Status wird geladen …</p>';
  await loadStatus();
  if (aesKey && hasRendered) startDashboard(null);
}

if (typeof document !== "undefined") {
  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState === "hidden") stopTimers();
    else startTimers();
  });
  window.addEventListener("pageshow", function () { startTimers(); });
  boot();
}

"use strict";
/* Bot-Status v25: Daten nur verschluesselt (AES-GCM, Schluessel via PBKDF2-SHA256 aus dem Zugangscode).
   Gespraechsanzeige per Push (ntfy.sh, Topic nur in den verschluesselten Daten), Kachel-Reload alle 17 s nur im Gespraech. */
const RAW_LIVE = "https://raw.githubusercontent.com/R25-foodporn/bot-status/live/live.enc.json";
const NTFY = "https://ntfy.sh/";
const STORE_KEY = "botstatus.auth.v1";
const VALID_MS = 180 * 24 * 60 * 60 * 1000;
const CALL_RELOAD_MS = 17000;           // Kachel-Reload nur waehrend eines Gespraechs
const WINDOW_MS = 72 * 60 * 60 * 1000;  // Kacheln zeigen Eintraege der letzten 72 h
const RECONNECT_MS = [2000, 5000, 10000, 30000];

let hasRendered = false;
let lastDataKey = "";
let lastLive = null;
let lastStatus = null;
let aesKey = null;
let callTimer = null;
let running = false;
let pushTopic = "";
let es = null;
let esLastId = "";
let esRetry = 0;
let esRetryTimer = null;
let showOld = false;
let showMoreUrgent = false;

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
  let plain = await subtle.decrypt({ name: "AES-GCM", iv: b64ToBytes(env.iv) }, key, b64ToBytes(env.ct));
  if (env.z) {
    const stream = new Blob([plain]).stream().pipeThrough(new DecompressionStream("gzip"));
    plain = await new Response(stream).arrayBuffer();
  }
  return JSON.parse(new TextDecoder().decode(plain));
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { normalizeCode, deriveRawKey, importAesKey, decryptJson, bytesToB64, b64ToBytes };
}

/* ---------- Gerät, Speicher ---------- */
const DEVICE_NAME_KEY = "botstatus-device-name";
function detectDevice() {
  try { const n = localStorage.getItem(DEVICE_NAME_KEY); if (n) return n; } catch (err) {}
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
function stampOf(d) { return String((d && (d.published || d.updated)) || ""); }

function takeStatus(data) {
  if (!data) return;
  if (lastStatus && stampOf(data) < stampOf(lastStatus)) return; // aelter als das Angezeigte
  lastStatus = data;
  render(document.getElementById("app"), data);
  hasRendered = true;
  if (lastLive) applyLive(lastLive);
  const topic = data.push && data.push.topic;
  if (topic && topic !== pushTopic) { pushTopic = topic; connectPush(); }
}

function takeLiveData(data) {
  if (!data) return;
  if (lastLive && stampOf(data) < stampOf(lastLive)) return;
  lastLive = data;
  applyLive(data);
}

/* Status von GitHub Pages: ?ts= umgeht den Pages-Zwischenspeicher (max-age=600), kein API-Limit. */
async function loadStatus() {
  try {
    const env = await fetchEnc("status.enc.json");
    const data = await decryptJson(aesKey, env);
    takeStatus(data);
  } catch (err) {
    if (err && err.name === "OperationError") { localStorage.removeItem(STORE_KEY); showLogin("Bitte Code neu eingeben."); return; }
    if (!hasRendered) {
      document.getElementById("app").innerHTML = '<div class="error">Status konnte nicht geladen werden. Seite neu laden oder später erneut versuchen.</div>';
    }
  }
}

/* Ersatzweg fuer den Gespraechsstand: raw.githubusercontent (kein API-Limit, bis 5 Min. zwischengespeichert).
   Nur einmal beim (Wieder)Verbinden, nie periodisch. */
async function loadLiveOnce() {
  try { takeLiveData(await decryptJson(aesKey, await fetchEnc(RAW_LIVE))); } catch (err) {}
}

async function takePushMessage(text) {
  try {
    const payload = await decryptJson(aesKey, JSON.parse(text));
    if (payload.status) takeStatus(payload.status);
    if (payload.live) takeLiveData(payload.live);
  } catch (err) {}
}

/* ---------- Push-Kanal ntfy.sh (Topic steht nur verschluesselt in den Daten) ---------- */
function closePush() {
  if (esRetryTimer) { clearTimeout(esRetryTimer); esRetryTimer = null; }
  if (es) { es.close(); es = null; }
}
function connectPush() {
  closePush();
  if (!running || !pushTopic || document.visibilityState === "hidden" || typeof EventSource === "undefined") return;
  // since=: Verpasstes seit der letzten bekannten Nachricht (sonst der letzten 12 h) wird nachgeliefert.
  const since = esLastId || "12h";
  const src = new EventSource(NTFY + encodeURIComponent(pushTopic) + "/sse?since=" + encodeURIComponent(since));
  es = src;
  src.onopen = function () { esRetry = 0; };
  src.onmessage = function (ev) {
    try {
      const msg = JSON.parse(ev.data);
      if (msg.event !== "message" || !msg.message) return;
      if (msg.id) esLastId = msg.id;
      takePushMessage(msg.message);
    } catch (err) {}
  };
  src.onerror = function () {
    // Funkloch o. ae.: selbst neu verbinden (mit Pause), dabei Stand einmal nachfragen
    if (es !== src) return;
    src.close(); es = null;
    const wait = RECONNECT_MS[Math.min(esRetry, RECONNECT_MS.length - 1)];
    esRetry++;
    esRetryTimer = setTimeout(function () { esRetryTimer = null; resync(); }, wait);
  };
}
function pushOpen() { return !!(es && es.readyState === 1); }

/* Einmal nachfragen: Status + Gespraechsstand, dann Push (neu) verbinden. */
function resync() {
  if (!running || !aesKey || document.visibilityState === "hidden") return;
  loadStatus();
  loadLiveOnce();
  connectPush();
}

/* ---------- 17-s-Reload nur waehrend eines Gespraechs ---------- */
let callTicks = 0;
function inCall() { return !!(lastLive && lastLive.currentCall && lastLive.currentCall.bot); }
async function pollNtfyOnce() {
  if (!pushTopic) return;
  try {
    const r = await fetch(NTFY + encodeURIComponent(pushTopic) + "/json?poll=1&since=" + encodeURIComponent(esLastId || "12h"), { cache: "no-store" });
    if (!r.ok) return;
    for (const line of (await r.text()).split("\n")) {
      if (!line.trim()) continue;
      const msg = JSON.parse(line);
      if (msg.event === "message" && msg.message) { if (msg.id) esLastId = msg.id; await takePushMessage(msg.message); }
    }
  } catch (err) {}
}
async function callTick() {
  callTicks++;
  const jobs = [loadStatus()];
  // Ist der Push-Kanal offen, kommen neue Daten ohnehin in Sekunden; sonst bei ntfy nachfragen.
  if (!pushOpen()) jobs.push(pollNtfyOnce());
  await Promise.all(jobs);
}
function updateCallReload() {
  const want = running && inCall() && document.visibilityState !== "hidden";
  if (want && !callTimer) {
    callTimer = setInterval(callTick, CALL_RELOAD_MS);
  } else if (!want && callTimer) {
    clearInterval(callTimer); callTimer = null;
  }
  const ind = document.getElementById("reload-mode");
  const text = callTimer ? "· im Gespräch alle 17 s neu" : "";
  if (ind && ind.textContent !== text) ind.textContent = text;
}

/* ---------- Timer und Push nur bei sichtbarer Seite ---------- */
function stopTimers() {
  if (callTimer) { clearInterval(callTimer); callTimer = null; }
  closePush();
}
function startTimers() {
  stopTimers();
  if (!running || !aesKey || document.visibilityState === "hidden") return;
  resync();
  updateCallReload();
}

function startDashboard(initialData) {
  running = true;
  document.getElementById("logout").hidden = false;
  if (initialData) takeStatus(initialData);
  loadLiveOnce();
  connectPush();
  updateCallReload();
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
  updateCallReload();
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
    pending: data.pending,
    topics: data.topics,
    bots: data.bots,
    weeklyUsage: data.weeklyUsage,
    w: Math.floor(Date.now() / 600000)
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
  const pending = (Array.isArray(data.pending) ? data.pending : []).filter((p) => p && !p.done);
  const topics = Array.isArray(data.topics) ? data.topics : [];
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

  const now = Date.now();
  const isRecent = (item) => { const t = Date.parse(item && item.at); return !t || now - t <= WINDOW_MS; };
  const shortDate = (v) => { const t = new Date(v); return Number.isNaN(t.getTime()) ? "" : new Intl.DateTimeFormat("de-CH", { timeZone: "Europe/Zurich", day: "2-digit", month: "2-digit" }).format(t); };
  const fmtWhen = (v, withTime) => {
    const t = new Date(v);
    if (Number.isNaN(t.getTime())) return "";
    const o = { timeZone: "Europe/Zurich", day: "2-digit", month: "2-digit" };
    if (withTime) { o.hour = "2-digit"; o.minute = "2-digit"; o.hourCycle = "h23"; }
    return new Intl.DateTimeFormat("de-CH", o).format(t).replace(",", "");
  };
  const fristLabel = (p) => {
    if (!p.frist) return p.fristText || "";
    const t = new Date(p.frist);
    const hm = new Intl.DateTimeFormat("de-CH", { timeZone: "Europe/Zurich", hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).format(t);
    const base = fmtWhen(p.frist, hm !== "23:59" && hm !== "00:00");
    return p.fristText ? base + " " + p.fristText : base;
  };
  const fristMs = (p) => { const t = Date.parse(p.frist); return Number.isNaN(t) ? Infinity : t; };
  const prioOf = (p) => Number(p.prio) || 2;
  const urgentSort = (x, y) => (fristMs(x) - fristMs(y)) || (prioOf(x) - prioOf(y)) || String(x.since || "").localeCompare(String(y.since || ""));
  const dringend = pending.filter((p) => p.dringend).sort(urgentSort);
  const pendSorted = dringend.concat(pending.filter((p) => !p.dringend).sort((x, y) => String(y.since || "").localeCompare(String(x.since || ""))));
  const row = (cls, bot, when, text, extra, detail) =>
    `<li><button type="button" class="row ${cls}" data-drill data-key="${escapeHtml(bot)}" data-title="${escapeHtml(text)}" data-detail="${escapeHtml(detail || text)}" data-source="${escapeHtml(when)}"><span class="row-meta"><b>${escapeHtml(bot)}</b> ${escapeHtml(when)}${extra || ""}</span><span class="row-text">${escapeHtml(text)}</span></button></li>`;

  const pendHtml = pendSorted.length
    ? `<ol class="rows rows-big">${pendSorted.map((p) => {
        const overdue = p.dringend && fristMs(p) < now;
        const tag = p.dringend ? ` <span class="tag-urgent${overdue ? " overdue" : ""}">dringend${fristLabel(p) ? " bis " + escapeHtml(fristLabel(p)) : ""}</span>` : "";
        return row(p.dringend ? "is-urgent" : "", p.bot || "", "seit " + fmtWhen(p.since, false), p.title || "", tag, p.detail);
      }).join("")}</ol>`
    : `<p class="empty">Gerade ist nichts für dich pendent.</p>`;

  const URG_MAX = 6;
  const urgShown = showMoreUrgent ? dringend : dringend.slice(0, URG_MAX);
  const urgHtml = dringend.length
    ? `<ol class="rows rows-urgent">${urgShown.map((p) => {
        const overdue = fristMs(p) < now;
        return row("is-urgent" + (overdue ? " overdue" : ""), p.bot || "", fristLabel(p) || "ohne Frist", p.title || "", "", p.detail);
      }).join("")}</ol>` + (dringend.length > URG_MAX
        ? `<button type="button" class="more-toggle" data-toggle-urgent>${showMoreUrgent ? "Weniger" : "Weitere (" + (dringend.length - URG_MAX) + ")"}</button>`
        : "")
    : `<p class="empty">Nichts Zeitkritisches.</p>`;

  const topicsSorted = topics.slice().sort((x, y) => String(y.at || "").localeCompare(String(x.at || "")));
  const TOP_MAX = 8;
  const topicsRecent = topicsSorted.filter(isRecent);
  const topicsShown = showOld ? topicsSorted : topicsRecent.slice(0, TOP_MAX);
  const hiddenTopics = topicsSorted.length - topicsShown.length;
  const topicsHtml = (topicsShown.length
    ? `<ol class="rows rows-small">${topicsShown.map((t) => row("", t.bot || "", fmtWhen(t.at, true), t.title || "", "", t.detail)).join("")}</ol>`
    : `<p class="empty">In den letzten 72 Stunden nichts besprochen.</p>`) +
    ((showOld ? topicsSorted.length > Math.min(topicsRecent.length, TOP_MAX) : hiddenTopics > 0)
      ? `<button type="button" class="more-toggle" data-toggle-old>${showOld ? "Weniger" : "Ältere (" + hiddenTopics + ")"}</button>` : "");

  const botsHtml = bots.map((bot) => {
    const status = (bot.status || "bereit").toLowerCase();
    const needed = bot.input || bot.task || "Keine Eingabe nötig";
    const recent = isRecent(bot);
    const stale = recent ? "" : ` <span class="stale-note">(Stand ${escapeHtml(shortDate(bot.at))}, älter als 72 h)</span>`;
    return `
      <article class="bot${recent ? "" : " stale"}">
        <span class="badge ${escapeHtml(status)}">${escapeHtml(status)}</span>
        <p class="name">${escapeHtml(bot.name)}</p>
        <p class="input-label">Eingabe von dir</p>
        <p class="task">${escapeHtml(needed)}${stale}</p>
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
          <h2>Pendent für dich</h2>
          ${pendHtml}
        </article>
        <article class="need need-tall urgent-tile">
          <h2 class="h-urgent">Dringend</h2>
          ${urgHtml}
          <h2 class="h-recent">Zuletzt besprochen</h2>
          ${topicsHtml}
        </article>
      </div>
    </section>
    <section class="section">
      <h2>Bots</h2>
      <div class="grid">${botsHtml}</div>
    </section>
    <div class="updated">
      <span>Aktualisiert: <span id="clock">${escapeHtml(stamp)}</span> <span id="reload-mode"></span></span>
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
    if (event.target.closest("[data-toggle-urgent]")) {
      showMoreUrgent = !showMoreUrgent; lastDataKey = ""; render(root, lastStatus || data); if (lastLive) applyLive(lastLive);
      return;
    }
    if (event.target.closest("[data-toggle-old]")) {
      showOld = !showOld; lastDataKey = ""; render(root, lastStatus || data); if (lastLive) applyLive(lastLive);
      return;
    }
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
  const devEl = document.getElementById("device");
  devEl.textContent = "Gerät: " + detectDevice();
  devEl.style.cursor = "pointer";
  devEl.title = "Antippen, um den Gerätenamen festzulegen";
  devEl.addEventListener("click", function openEditor() {
    if (document.getElementById("device-edit")) return;
    const box = document.createElement("span");
    box.id = "device-edit";
    const inp = document.createElement("input");
    inp.type = "text"; inp.maxLength = 30; inp.placeholder = "z. B. Tesla";
    inp.value = localStorage.getItem(DEVICE_NAME_KEY) || "";
    inp.style.cssText = "font-size:16px;width:9em;margin-left:6px;";
    const ok = document.createElement("button");
    ok.type = "button"; ok.textContent = "Speichern";
    ok.style.cssText = "font-size:16px;margin-left:4px;";
    const save = () => {
      const v = inp.value.trim();
      if (v) localStorage.setItem(DEVICE_NAME_KEY, v); else localStorage.removeItem(DEVICE_NAME_KEY);
      devEl.textContent = "Gerät: " + detectDevice();
      box.remove();
    };
    ok.addEventListener("click", (e) => { e.stopPropagation(); save(); });
    inp.addEventListener("keydown", (e) => { if (e.key === "Enter") save(); });
    inp.addEventListener("click", (e) => e.stopPropagation());
    box.appendChild(inp); box.appendChild(ok);
    devEl.after(box);
    inp.focus();
  });
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

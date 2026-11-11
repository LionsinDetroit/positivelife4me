// positiveLife4me server helper for Cloudflare Pages (single-file "advanced mode").
// It answers the /api/... requests (sign-in, private data, sharing, workouts)
// and hands every other request to the site's normal files.
// Secrets live in the Cloudflare project settings, never in this file.
// Shared helpers for the positiveLife4me server functions (Cloudflare Pages).
// Secrets live in Cloudflare's project settings, never in these files:
//   ADAM_PASSCODE, ADAM_INTERVALS_ID, ADAM_INTERVALS_KEY
//   LAUREN_PASSCODE, LAUREN_INTERVALS_ID, LAUREN_INTERVALS_KEY
// Storage: a KV namespace bound to the project with the variable name PL4M.
// Scan workout: a Workers AI binding named AI, and a D1 database bound as DB (see schema.sql).
// Google sign-in (one-time): GOOGLE_CLIENT_ID and OWNER_EMAIL. People are then invited in Settings > People.

const USERS = { adam: "Adam", lauren: "Lauren" };
const up = (u) => u.toUpperCase();
const enc = new TextEncoder();
const b64u = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64uStr = (s) => b64u(enc.encode(s));
const unb64u = (s) => atob(s.replace(/-/g, "+").replace(/_/g, "/"));

const enabled = (env) => Object.keys(USERS).filter((u) => env[up(u) + "_PASSCODE"]);
const secret = (env, u) => (env[up(u) + "_PASSCODE"] || "") + "|pl4m|" + (env[up(u) + "_INTERVALS_KEY"] || "");

async function hmac(key, data) {
  const k = await crypto.subtle.importKey("raw", enc.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64u(await crypto.subtle.sign("HMAC", k, enc.encode(data)));
}
function sameText(a, b) { // constant-time comparison
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

async function sign(env, u, days = 180) {
  const p = b64uStr(JSON.stringify({ u, exp: Date.now() + days * 864e5 }));
  return p + "." + (await hmac(secret(env, u), p));
}

async function verify(env, request) {
  const t = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  const [p, s] = t.split(".");
  if (!p || !s) return null;
  let o;
  try { o = JSON.parse(unb64u(p)); } catch { return null; }
  if (!o || !(o.exp > Date.now())) return null;
  // Google sign-in: signed with the site's own secret, and the person must still be on the People list
  if (o.v === 2) {
    if (!env.DB || !sameText(s, await hmac(await siteSecret(env), p))) return null;
    return (await personById(env, o.u)) ? o.u : null;
  }
  // passcode sign-in (the original two profiles)
  if (!USERS[o.u] || !enabled(env).includes(o.u)) return null;
  return sameText(s, await hmac(secret(env, o.u), p)) ? o.u : null;
}

// ---------- Google sign-in and the People list ----------
// One-time setup in the Cloudflare project settings: GOOGLE_CLIENT_ID (from Google Cloud) and
// OWNER_EMAIL (the owner's Gmail). Everyone else is invited from Settings > People on the site:
// no per-person settings. People live in the D1 table "people"; tables are created automatically.
let peopleReady = null;
function peopleTables(db) {
  if (!peopleReady) peopleReady = db.batch([
    db.prepare("CREATE TABLE IF NOT EXISTS people (email TEXT PRIMARY KEY, user_id TEXT NOT NULL UNIQUE, name TEXT, role TEXT NOT NULL DEFAULT 'member', invited_by TEXT, created_at INTEGER NOT NULL, last_seen INTEGER)"),
    db.prepare("CREATE TABLE IF NOT EXISTS app_settings (k TEXT PRIMARY KEY, v TEXT NOT NULL)"),
  ]).catch((e) => { peopleReady = null; throw e; });
  return peopleReady;
}
// a random secret made once and kept in the database, used to sign Google sign-ins
let siteSecretCache = null;
async function siteSecret(env) {
  if (siteSecretCache) return siteSecretCache;
  const db = lifts(env); await peopleTables(db);
  const fresh = b64u(crypto.getRandomValues(new Uint8Array(32)));
  await db.prepare("INSERT OR IGNORE INTO app_settings (k, v) VALUES ('session_secret', ?1)").bind(fresh).run();
  const row = await db.prepare("SELECT v FROM app_settings WHERE k = 'session_secret'").first();
  return (siteSecretCache = row.v);
}
async function personById(env, id) {
  const db = lifts(env); await peopleTables(db);
  return db.prepare("SELECT email, user_id, name, role FROM people WHERE user_id = ?1").bind(id).first();
}
const ownerEmail = (env) => String(env.OWNER_EMAIL || "").trim().toLowerCase();
const ownerProfile = (env) => String(env.OWNER_PROFILE || "adam").trim().toLowerCase();
async function displayName(env, u) {
  if (USERS[u]) return USERS[u];
  const p = env.DB ? await personById(env, u).catch(() => null) : null;
  return (p && p.name) || "Friend";
}

// Google's public keys, to check that a sign-in really came from Google
let gKeys = null, gKeysAt = 0;
async function googleKeys() {
  if (gKeys && Date.now() - gKeysAt < 3600e3) return gKeys;
  const r = await fetch("https://www.googleapis.com/oauth2/v3/certs");
  if (!r.ok) throw new Error("Couldn't reach Google.");
  gKeys = (await r.json()).keys || []; gKeysAt = Date.now();
  return gKeys;
}
const b64uBytes = (s) => Uint8Array.from(unb64u(s), (c) => c.charCodeAt(0));
const b64uJSON = (s) => JSON.parse(new TextDecoder().decode(b64uBytes(s)));
async function googleIdentity(env, credential) {
  const [h, p, sig] = String(credential || "").split(".");
  if (!h || !p || !sig) return null;
  let head, pay;
  try { head = b64uJSON(h); pay = b64uJSON(p); } catch { return null; }
  if (head.alg !== "RS256") return null;
  const jwk = (await googleKeys()).find((k) => k.kid === head.kid);
  if (!jwk) return null;
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  if (!(await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64uBytes(sig), enc.encode(h + "." + p)))) return null;
  const okIss = pay.iss === "accounts.google.com" || pay.iss === "https://accounts.google.com";
  if (!okIss || pay.aud !== env.GOOGLE_CLIENT_ID || !(pay.exp * 1000 > Date.now()) || pay.email_verified !== true || !pay.email) return null;
  return { email: String(pay.email).toLowerCase(), name: String(pay.given_name || pay.name || "").slice(0, 40) };
}

async function authGoogle({ request, env }) {
  if (!env.GOOGLE_CLIENT_ID) return json({ error: "Google sign-in isn't set up yet." }, 409);
  let db;
  try { db = lifts(env); } catch (e) { return json({ error: e.message }, 500); }
  await peopleTables(db);
  let b = {};
  try { b = await request.json(); } catch {}
  const g = await googleIdentity(env, b.credential).catch(() => null);
  if (!g) return json({ error: "Google sign-in didn't go through. Please try again." }, 401);
  let person = await db.prepare("SELECT email, user_id, name, role FROM people WHERE email = ?1").bind(g.email).first();
  // the owner is added on their first Google sign-in, linked to their existing profile
  if (!person && g.email === ownerEmail(env)) {
    await db.prepare("INSERT OR IGNORE INTO people (email, user_id, name, role, invited_by, created_at) VALUES (?1, ?2, ?3, 'owner', NULL, ?4)")
      .bind(g.email, ownerProfile(env), USERS[ownerProfile(env)] || g.name || "Owner", Date.now()).run();
    person = await db.prepare("SELECT email, user_id, name, role FROM people WHERE email = ?1").bind(g.email).first();
  }
  if (!person) return json({ error: `${g.email} hasn't been invited yet. Ask the site's owner to add you under Settings > People.` }, 403);
  const name = person.name || g.name || "Friend";
  await db.prepare("UPDATE people SET last_seen = ?2, name = COALESCE(name, ?3) WHERE email = ?1").bind(g.email, Date.now(), g.name || null).run();
  const pl = b64uStr(JSON.stringify({ u: person.user_id, v: 2, exp: Date.now() + 180 * 864e5 }));
  return json({ token: pl + "." + (await hmac(await siteSecret(env), pl)), user: person.user_id, name, email: g.email, role: person.role });
}

// Settings > People: the owner invites and removes people by Gmail address
async function peopleAll({ request, env }) {
  const u = await verify(env, request);
  if (!u) return json({ error: "Please sign in again." }, 401);
  let db;
  try { db = lifts(env); } catch (e) { return json({ error: e.message }, 500); }
  await peopleTables(db);
  const me = await personById(env, u);
  if (!me || me.role !== "owner") return json({ error: "Only the site's owner can manage people." }, 403);
  const list = async () => {
    const { results } = await db.prepare("SELECT email, user_id, name, role, created_at, last_seen FROM people ORDER BY role DESC, created_at").all();
    const linked = new Set((results || []).map((r) => r.user_id));
    return json({ people: results || [], linkable: Object.keys(USERS).filter((id) => !linked.has(id)).map((id) => ({ id, name: USERS[id] })) });
  };
  if (request.method === "GET") return list();
  let b = {};
  try { b = await request.json(); } catch {}
  const email = String(b.email || "").trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 200) return json({ error: "Enter a full email address." }, 400);
  if (request.method === "POST") {
    if (await db.prepare("SELECT 1 FROM people WHERE email = ?1").bind(email).first()) return json({ error: "That person is already on the list." }, 409);
    // link to one of the original profiles (keeps its data), or start a new one
    let id = String(b.link || "");
    if (id) {
      if (!USERS[id]) return json({ error: "Unknown profile." }, 400);
      if (await db.prepare("SELECT 1 FROM people WHERE user_id = ?1").bind(id).first()) return json({ error: "That profile is already linked to someone." }, 409);
    } else id = "u" + [...crypto.getRandomValues(new Uint8Array(6))].map((x) => x.toString(16).padStart(2, "0")).join("");
    const name = String(b.name || "").trim().slice(0, 40) || (USERS[id] || null);
    await db.prepare("INSERT INTO people (email, user_id, name, role, invited_by, created_at) VALUES (?1, ?2, ?3, 'member', ?4, ?5)").bind(email, id, name, u, Date.now()).run();
    return list();
  }
  if (request.method === "DELETE") {
    const p = await db.prepare("SELECT role FROM people WHERE email = ?1").bind(email).first();
    if (!p) return json({ error: "That person isn't on the list." }, 404);
    if (p.role === "owner") return json({ error: "The owner can't be removed." }, 400);
    // removes sign-in access only; their saved data stays in case they're added back
    await db.prepare("DELETE FROM people WHERE email = ?1").bind(email).run();
    return list();
  }
  return json({ error: "Method not allowed" }, 405);
}

async function passOk(env, u, pc) {
  const real = env[up(u) + "_PASSCODE"];
  if (!real || typeof pc !== "string") return false;
  const h = async (x) => b64u(await crypto.subtle.digest("SHA-256", enc.encode(x)));
  return sameText(await h(pc), await h(real));
}

const intervals = (env, u) => ({ id: String(env[up(u) + "_INTERVALS_ID"] || "").trim(), key: String(env[up(u) + "_INTERVALS_KEY"] || "").trim() });

const json = (o, status = 200) =>
  new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });

const store = (env) => {
  if (!env.PL4M) throw new Error("Storage isn't connected. Add a KV binding named PL4M in the Cloudflare project settings.");
  return env.PL4M;
};

// Sign in to a profile with its passcode. GET lists which profiles are set up.

async function authGet({ env }) {
  return json({ users: enabled(env).map((u) => ({ id: u, name: USERS[u] })), googleClientId: env.GOOGLE_CLIENT_ID || "" });
}

async function authPost({ request, env }) {
  let b = {};
  try { b = await request.json(); } catch {}
  const u = String(b.user || "").toLowerCase();
  if (!enabled(env).includes(u) || !(await passOk(env, u, b.passcode))) {
    await new Promise((r) => setTimeout(r, 800)); // slow down guessing
    return json({ error: "That passcode didn't match." }, 401);
  }
  return json({ token: await sign(env, u), user: u, name: USERS[u] });
}

// Only what the person chose to share is stored where the other profile can see it.
// It's only rewritten when it actually changes, to stay well inside the free storage limits.
async function saveShare(kv, u, sh) {
  const share = sh && typeof sh === "object" && !Array.isArray(sh) && Object.keys(sh).length ? JSON.stringify(sh) : "";
  const prev = await kv.get("share/" + u);
  const prevShare = prev ? JSON.stringify((({ at, ...rest }) => rest)(JSON.parse(prev))) : "";
  if (share !== prevShare) {
    if (share) await kv.put("share/" + u, JSON.stringify({ at: Date.now(), ...sh }));
    else await kv.delete("share/" + u);
  }
}

// The old way profiles were saved: one copy of everything per profile. Devices now read it once,
// to bring what's in it into the new per-item sync (/api/sync).

async function dataAll({ request, env }) {
  const u = await verify(env, request);
  if (!u) return json({ error: "Please sign in again." }, 401);
  let kv;
  try { kv = store(env); } catch (e) { return json({ error: e.message }, 500); }

  if (request.method === "GET") {
    const d = await kv.get("profile/" + u, { type: "json" });
    return json(d || {});
  }
  if (request.method === "PUT") {
    let b;
    try { b = await request.json(); } catch { return json({ error: "Bad data" }, 400); }
    if (!b || typeof b.data !== "object" || Array.isArray(b.data)) return json({ error: "Bad data" }, 400);
    const body = JSON.stringify({ savedAt: Number(b.savedAt) || Date.now(), data: b.data });
    if (body.length > 20_000_000) return json({ error: "Too much data" }, 413);
    await kv.put("profile/" + u, body);
    await saveShare(kv, u, b.share);
    return json({ ok: true });
  }
  return json({ error: "Method not allowed" }, 405);
}

// Returns progress the other profiles have chosen to share.

async function sharedGet({ request, env }) {
  const u = await verify(env, request);
  if (!u) return json({ error: "Please sign in again." }, 401);
  let kv;
  try { kv = store(env); } catch (e) { return json({ error: e.message }, 500); }
  // everyone who can sign in: the passcode profiles plus people added in Settings > People
  const ids = new Set(enabled(env));
  if (env.DB) { try { await peopleTables(env.DB); const { results } = await env.DB.prepare("SELECT user_id FROM people").all(); (results || []).forEach((r) => ids.add(r.user_id)); } catch {} }
  const people = [];
  for (const other of ids) {
    if (other === u) continue;
    const s = await kv.get("share/" + other, { type: "json" });
    if (s) people.push({ name: await displayName(env, other), ...s });
  }
  return json({ people });
}

// Fetches the signed-in person's workouts from their own Intervals.icu account.

// ---------- Connect your apps: each profile links its own Intervals.icu account ----------
// The Athlete ID and API key are kept per profile in D1, the key encrypted with the site's secret.
// Older profiles set up through Cloudflare settings (ADAM_INTERVALS_ID/KEY) keep working as a fallback.
let connReady = null;
function connTables(db) {
  if (!connReady) connReady = db.prepare("CREATE TABLE IF NOT EXISTS connections (user TEXT NOT NULL, service TEXT NOT NULL, data TEXT NOT NULL, connected_at INTEGER NOT NULL, PRIMARY KEY (user, service))").run()
    .catch((e) => { connReady = null; throw e; });
  return connReady;
}
async function connKey(env) {
  const raw = await crypto.subtle.digest("SHA-256", enc.encode("pl4m-connections|" + (await siteSecret(env))));
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}
async function seal(env, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await connKey(env), enc.encode(JSON.stringify(obj)));
  return b64u(iv) + "." + b64u(ct);
}
async function unseal(env, s) {
  const [iv, ct] = String(s).split(".");
  return JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64uBytes(iv) }, await connKey(env), b64uBytes(ct))));
}
async function savedConn(env, u, service) {
  if (!env.DB) return null;
  const db = lifts(env); await peopleTables(db); await connTables(db);
  const row = await db.prepare("SELECT data, connected_at FROM connections WHERE user = ?1 AND service = ?2").bind(u, service).first();
  if (!row) return null;
  try { return { ...(await unseal(env, row.data)), connectedAt: row.connected_at }; } catch { return null; }
}
// the profile's own connection first, then the Cloudflare settings fallback
async function intervalsFor(env, u) {
  const c = await savedConn(env, u, "intervals").catch(() => null);
  if (c && c.id && c.key) return { id: c.id, key: c.key, from: "profile", name: c.name || "", connectedAt: c.connectedAt };
  const e = intervals(env, u);
  return e.id && e.key ? { ...e, from: "site" } : null;
}
const icu = (id, key, path) => fetch(`https://intervals.icu/api/v1/athlete/${encodeURIComponent(id)}${path}`, { headers: { authorization: "Basic " + btoa("API_KEY:" + key), accept: "application/json" } });

async function connectionsAll({ request, env }) {
  const u = await verify(env, request);
  if (!u) return json({ error: "Please sign in again." }, 401);
  let db;
  try { db = lifts(env); } catch (e) { return json({ error: e.message }, 500); }
  await peopleTables(db); await connTables(db);
  const view = async () => {
    const c = await intervalsFor(env, u);
    return json({ intervals: c ? { connected: true, athleteId: c.id, name: c.name || "", from: c.from, connectedAt: c.connectedAt || null } : { connected: false } });
  };
  if (request.method === "GET") return view();
  let b = {};
  try { b = await request.json(); } catch {}
  if (b.service !== "intervals") return json({ error: "Unknown app." }, 400);
  if (request.method === "DELETE") {
    await db.prepare("DELETE FROM connections WHERE user = ?1 AND service = 'intervals'").bind(u).run();
    return view();
  }
  if (request.method === "POST") {
    // accept "i12345", "12345", or a pasted intervals.icu link that contains the ID
    const m = String(b.athleteId || "").trim().match(/i?(\d{2,12})/i);
    const id = m ? "i" + m[1] : "";
    const key = String(b.apiKey || "").trim();
    if (!id) return json({ error: "Enter your Athlete ID. It looks like i12345." }, 400);
    if (key.length < 10 || key.length > 200 || /\s/.test(key)) return json({ error: "Paste the API key from Intervals.icu (Settings, Developer Settings)." }, 400);
    // test it before saving
    let r;
    try { r = await icu(id, key, ""); } catch { return json({ error: "Couldn't reach Intervals.icu right now. Try again in a minute." }, 502); }
    if (r.status === 401 || r.status === 403) return json({ error: "Intervals.icu didn't accept that API key for this Athlete ID. Check both and try again." }, 400);
    if (r.status === 404) return json({ error: "Intervals.icu doesn't know that Athlete ID. Check it and try again." }, 400);
    if (!r.ok) return json({ error: `Intervals.icu answered with an error (${r.status}). Try again in a minute.` }, 502);
    const ath = await r.json().catch(() => ({}));
    const name = String((ath && (ath.name || ath.firstname)) || "").slice(0, 60);
    let found = 0;
    try {
      const day = (n) => new Date(Date.now() - n * 864e5).toISOString().slice(0, 10);
      const a = await icu(id, key, `/activities?oldest=${day(30)}&newest=${day(-1)}`);
      if (a.ok) { const l = await a.json(); found = Array.isArray(l) ? l.length : 0; }
    } catch {}
    await db.prepare("INSERT INTO connections (user, service, data, connected_at) VALUES (?1, 'intervals', ?2, ?3) ON CONFLICT (user, service) DO UPDATE SET data = excluded.data, connected_at = excluded.connected_at")
      .bind(u, await seal(env, { id, key, name }), Date.now()).run();
    return json({ intervals: { connected: true, athleteId: id, name, from: "profile", connectedAt: Date.now() }, found });
  }
  return json({ error: "Method not allowed" }, 405);
}

// Wellness from Intervals.icu (filled by the person's watch or phone): sleep, resting heart rate, HRV.
// Used by the Flare forecast to fill in sleep and recovery on its own.
async function wellnessGet({ request, env }) {
  const u = await verify(env, request);
  if (!u) return json({ error: "Please sign in again." }, 401);
  const c = await intervalsFor(env, u);
  if (!c) return json({ error: "Not connected yet. Connect Intervals.icu in Settings." }, 409);
  const days = Math.min(90, Math.max(1, parseInt(new URL(request.url).searchParams.get("days")) || 35));
  const day = (n) => new Date(Date.now() - n * 864e5).toISOString().slice(0, 10);
  let r;
  try { r = await icu(c.id, c.key, `/wellness?oldest=${day(days)}&newest=${day(-1)}`); }
  catch { return json({ error: "Couldn't reach Intervals.icu right now." }, 502); }
  if (!r.ok) return json({ error: `Intervals.icu didn't accept the request (${r.status}).` }, 502);
  const list = await r.json().catch(() => []);
  const num = (v) => (typeof v === "number" && isFinite(v) && v > 0 ? v : null);
  const wellness = (Array.isArray(list) ? list : []).filter((w) => w && /^\d{4}-\d{2}-\d{2}$/.test(String(w.id)))
    .map((w) => ({ day: w.id, sleepSecs: num(w.sleepSecs), sleepScore: num(w.sleepScore), sleepQuality: num(w.sleepQuality), restingHR: num(w.restingHR), hrv: num(w.hrv) }));
  return json({ wellness, at: Date.now() });
}

async function actsGet({ request, env }) {
  const u = await verify(env, request);
  if (!u) return json({ error: "Please sign in again." }, 401);
  const c = await intervalsFor(env, u);
  if (!c) return json({ error: "Not connected yet. Connect Intervals.icu in Settings." }, 409);
  const { id, key } = c;
  const days = Math.min(365, Math.max(1, parseInt(new URL(request.url).searchParams.get("days")) || 30));
  const day = (n) => new Date(Date.now() - n * 864e5).toISOString().slice(0, 10);
  const url = `https://intervals.icu/api/v1/athlete/${encodeURIComponent(id)}/activities?oldest=${day(days)}&newest=${day(-1)}`;
  let r;
  try {
    r = await fetch(url, { headers: { authorization: "Basic " + btoa("API_KEY:" + key), accept: "application/json" } });
  } catch {
    return json({ error: "Couldn't reach Intervals.icu right now." }, 502);
  }
  if (!r.ok) return json({ error: `Intervals.icu didn't accept the request (${r.status}). Reconnect it in Settings.` }, 502);
  const list = await r.json();
  const activities = (Array.isArray(list) ? list : [])
    .filter((a) => a && a.id && (a.start_date_local || a.start_date))
    .map((a) => ({
      id: "icu-" + a.id, source: "intervals",
      type: String(a.type || ""), rawType: [a.type, a.sub_type].filter(Boolean).join(" · "),
      name: a.name || "", desc: a.description || "", dev: a.device_name || "", src: a.source || "", ext: a.external_id || "",
      startLocal: a.start_date_local || a.start_date,
      sec: a.moving_time || a.elapsed_time || 0, el: a.elapsed_time || 0, m: a.distance || 0, cal: a.calories || 0,
      hr: a.average_heartrate || 0, maxhr: a.max_heartrate || 0, w: a.icu_average_watts || a.average_watts || 0,
      kj: a.icu_joules ? a.icu_joules / 1000 : 0, cad: a.average_cadence || 0, elev: a.total_elevation_gain || 0, load: a.icu_training_load || 0,
    }));
  return json({ activities, at: Date.now() });
}

// ---------- Scan workout: read a logbook photo with Workers AI, save sessions in D1 ----------

// The Workers AI vision model that reads the logbook photo. Change it here to try another one.
// It must accept chat messages with an image_url part and support JSON mode (Llama 4 Scout does).
const SCAN_MODEL = "@cf/meta/llama-4-scout-17b-16e-instruct";

// The instructions the model gets with each photo. ${today} is filled in when the scan runs.
const scanPrompt = (today) => `You read a photo of one page of a handwritten weightlifting logbook and return JSON.

The printed page:
- Top line: "DATE" followed by a handwritten date in the form M·D·YY with dots between the numbers (11·5·26 means November 5, 2026; the year is always 20YY). Next to it the printed letters S M T W T F S, with the day of the week circled.
- "WORKOUT NAME" followed by a handwritten word such as Back, Chest, Legs, Shoulders, Biceps, Triceps.
- A table with rows numbered 1 to 12. Each row has a handwritten EXERCISE name on the left, then columns SET1 to SET6.
- Every numbered row is split into two lines across the set columns: the TOP line (shaded grey) is REPS, the BOTTOM line (white) is WEIGHT in pounds. Read the top number as reps and the number directly below it as weight for the same set.
- A weight with a small raised 2 after it, like 5², means that weight in EACH hand with two dumbbells or kettlebells: weight 5, implements 2. Without the raised 2, implements is 1. The raised 2 is not part of the number: 5² is weight 5, never 52 or 25.
- Below the table: CARDIO, NOTES, RATE WORKOUT. Copy anything handwritten under NOTES.

How to read:
- Most pages only use the first few rows and the first few set columns. Include ONLY rows that have a handwritten exercise name. Never make up exercises or sets for empty rows or empty columns.
- Copy exercise names as written. You may spell out obvious shorthand (for example "RE FLY" → "Rear fly", "KB" → "Kettlebell"), but never guess a different exercise.
- If a weight is blank or a dash/ditto, reuse the weight of the set before it in the same row. If a row has no weights at all (bodyweight), use null.
- The photo may be rotated or upside down; read it upright. Ignore any other page, partial page, or background at the edges.
- If any number is hard to read, give your best guess and set its "repsUnsure" or "weightUnsure" to true. Set "dateUnsure" to true if the date is hard to read.
- Today is ${today}. The page date is normally on or a little before today.`;

// The exact JSON shape the model must return. Workers AI enforces it (JSON mode), so the reply always parses.
const SCAN_SET = {
  type: "object",
  properties: {
    reps: { type: ["number", "null"] }, weight: { type: ["number", "null"] },
    implements: { type: "integer", enum: [1, 2] },
    repsUnsure: { type: "boolean" }, weightUnsure: { type: "boolean" },
  },
  required: ["reps", "weight", "implements", "repsUnsure", "weightUnsure"],
};
const SCAN_SCHEMA = {
  type: "object",
  properties: {
    date: { type: ["string", "null"] }, dateUnsure: { type: "boolean" }, dayOfWeek: { type: ["string", "null"] },
    workoutName: { type: "string" },
    exercises: { type: "array", items: { type: "object", properties: { name: { type: "string" }, sets: { type: "array", items: SCAN_SET } }, required: ["name", "sets"] } },
    notes: { type: "string" },
  },
  required: ["date", "dateUnsure", "workoutName", "exercises", "notes"],
};

const num = (v) => {
  if (v === null || v === undefined || v === "") return null;
  const n = typeof v === "number" ? v : parseFloat(String(v).replace(/[^\d.]/g, ""));
  return Number.isFinite(n) && n >= 0 && n < 10000 ? Math.round(n * 100) / 100 : null;
};
const txt = (v, max) => String(v ?? "").replace(/\s+/g, " ").trim().slice(0, max);

function scanDate(v) {
  const s = String(v || "").trim();
  let y, m, d, x;
  if ((x = s.match(/^(\d{4})-(\d{1,2})-(\d{1,2})$/))) [, y, m, d] = x.map(Number);
  else if ((x = s.match(/^(\d{1,2})\s*[·./\-\s]\s*(\d{1,2})\s*[·./\-\s]\s*(\d{2}|\d{4})$/))) { [, m, d, y] = x.map(Number); if (y < 100) y += 2000; }
  else return null;
  const dt = new Date(Date.UTC(y, m - 1, d));
  if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== m - 1 || dt.getUTCDate() !== d || y < 2000 || y > 2100) return null;
  return `${y}-${String(m).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
}

// Checks the model's answer and puts it in a tidy shape. Throws if it isn't usable.
function cleanScan(o, today) {
  if (!o || typeof o !== "object" || Array.isArray(o)) throw new Error("not an object");
  if (!Array.isArray(o.exercises)) throw new Error("no exercises list");
  const exercises = o.exercises.slice(0, 30).map((e) => ({
    name: txt(e && e.name, 80),
    sets: (Array.isArray(e && e.sets) ? e.sets : []).slice(0, 6).map((s) => ({
      reps: num(s && s.reps), weight: num(s && s.weight),
      implements: Number(s && s.implements) === 2 ? 2 : 1,
      repsUnsure: !!(s && s.repsUnsure), weightUnsure: !!(s && s.weightUnsure),
    })).filter((s) => s.reps !== null || s.weight !== null),
  })).filter((e) => e.name || e.sets.length);
  if (!exercises.length) throw new Error("no exercises found");
  const date = scanDate(o.date);
  // a date in the future or more than a year back is probably misread
  const far = date && today && (date > today || Date.parse(today) - Date.parse(date) > 366 * 864e5);
  return {
    date, dateUnsure: !!o.dateUnsure || !date || !!far,
    dayOfWeek: txt(o.dayOfWeek, 10), workoutName: txt(o.workoutName, 60),
    exercises, notes: txt(o.notes, 2000),
  };
}

// Pulls the JSON object out of the model's reply, even if it added words or code fences around it.
function pickJson(r) {
  const v = r && typeof r === "object" && "response" in r ? r.response : r;
  if (v && typeof v === "object") return v;
  const s = String(v || "");
  const a = s.indexOf("{"), b = s.lastIndexOf("}");
  if (a < 0 || b <= a) throw new Error("no JSON in reply");
  return JSON.parse(s.slice(a, b + 1));
}

function toB64(buf) {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

async function scanPost({ request, env }) {
  const u = await verify(env, request);
  if (!u) return json({ error: "Please sign in again." }, 401);
  if (request.method !== "POST") return json({ error: "Method not allowed" }, 405);
  if (!env.AI) return json({ error: "Scanning isn't connected. Add a Workers AI binding named AI in the Cloudflare project settings." }, 500);
  const type = (request.headers.get("content-type") || "").split(";")[0].trim();
  if (!/^image\/(jpeg|png|webp)$/.test(type)) return json({ error: "Send the photo as a JPEG." }, 415);
  const buf = await request.arrayBuffer();
  if (!buf.byteLength) return json({ error: "The photo was empty." }, 400);
  if (buf.byteLength > 4_000_000) return json({ error: "That photo is too large." }, 413);
  const image = `data:${type};base64,${toB64(buf)}`;

  // the person's local date from the browser (falls back to the server's date)
  const tz = new URL(request.url).searchParams.get("today") || "";
  const today = scanDate(tz) || new Date().toISOString().slice(0, 10);
  let lastErr = "";
  for (let attempt = 0; attempt < 2; attempt++) {
    const ask = attempt === 0
      ? "Read this logbook page and return the JSON."
      : `Your last answer could not be used (${lastErr}). Read the page again and return ONLY the JSON object in the exact shape described.`;
    let r;
    try {
      r = await env.AI.run(SCAN_MODEL, {
        messages: [
          { role: "system", content: scanPrompt(today) },
          { role: "user", content: [{ type: "text", text: ask }, { type: "image_url", image_url: { url: image } }] },
        ],
        response_format: { type: "json_schema", json_schema: SCAN_SCHEMA },
        max_tokens: 2500, temperature: 0,
      });
    } catch (e) {
      return json({ error: "The scanner couldn't read the photo right now. Try again in a minute." }, 502);
    }
    try {
      return json({ scan: cleanScan(pickJson(r), today), model: SCAN_MODEL });
    } catch (e) {
      lastErr = e.message || "invalid JSON";
    }
  }
  return json({ error: "Couldn't make sense of that page. Try a brighter, straighter photo of just the one page." }, 422);
}

const lifts = (env) => {
  if (!env.DB) throw new Error("Workout storage isn't connected. Add a D1 binding named DB in the Cloudflare project settings.");
  return env.DB;
};

// Scanned lifting sessions in D1. Every query is limited to the signed-in profile.
async function liftsAll({ request, env }) {
  const u = await verify(env, request);
  if (!u) return json({ error: "Please sign in again." }, 401);
  let db;
  try { db = lifts(env); } catch (e) { return json({ error: e.message }, 500); }

  if (request.method === "GET") {
    const { results } = await db.prepare(
      "SELECT id, date, workout_name, muscle_day, notes, exercises, created_at FROM lift_sessions WHERE user = ?1 ORDER BY date DESC, created_at DESC LIMIT 1000"
    ).bind(u).all();
    return json({ sessions: (results || []).map((r) => ({
      id: r.id, date: r.date, workoutName: r.workout_name, muscleDay: r.muscle_day, notes: r.notes,
      exercises: JSON.parse(r.exercises || "[]"), createdAt: r.created_at,
    })) });
  }
  if (request.method === "POST") {
    let b;
    try { b = await request.json(); } catch { return json({ error: "Bad data" }, 400); }
    const date = scanDate(b && b.date);
    if (!date) return json({ error: "Pick a valid date before saving." }, 400);
    const exercises = (Array.isArray(b.exercises) ? b.exercises : []).slice(0, 30).map((e) => ({
      name: txt(e && e.name, 80),
      sets: (Array.isArray(e && e.sets) ? e.sets : []).slice(0, 6)
        .map((s) => ({ reps: num(s && s.reps), weight: num(s && s.weight), implements: Number(s && s.implements) === 2 ? 2 : 1 }))
        .filter((s) => s.reps !== null && s.reps > 0),
    })).filter((e) => e.name && e.sets.length);
    if (!exercises.length) return json({ error: "Add at least one exercise with a name and reps." }, 400);
    const id = crypto.randomUUID();
    await db.prepare(
      "INSERT INTO lift_sessions (id, user, date, workout_name, muscle_day, notes, exercises, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
    ).bind(id, u, date, txt(b.workoutName, 60), txt(b.muscleDay, 30), txt(b.notes, 2000), JSON.stringify(exercises), Date.now()).run();
    return json({ ok: true, id, date, exercises });
  }
  if (request.method === "DELETE") {
    const id = new URL(request.url).searchParams.get("id") || "";
    await db.prepare("DELETE FROM lift_sessions WHERE id = ?1 AND user = ?2").bind(id, u).run();
    return json({ ok: true });
  }
  return json({ error: "Method not allowed" }, 405);
}

// ---------- Profile sync: the profile holds the data, one database row per saved item ----------
// Each change a device makes is sent as it happens. Devices ask for every change newer than the
// last one they saw (seq), so phone, tablet and computer always end up with the same data.
// The table is created automatically the first time it's needed.
let syncReady = null;
function syncTables(db) {
  if (!syncReady) syncReady = db.batch([
    db.prepare("CREATE TABLE IF NOT EXISTS profile_items (user TEXT NOT NULL, k TEXT NOT NULL, v TEXT, at INTEGER NOT NULL, seq INTEGER NOT NULL, PRIMARY KEY (user, k))"),
    db.prepare("CREATE INDEX IF NOT EXISTS profile_items_seq ON profile_items(user, seq)"),
  ]).catch((e) => { syncReady = null; throw e; });
  return syncReady;
}

const SYNC_PAGE = 2000;

async function syncAll({ request, env }) {
  const u = await verify(env, request);
  if (!u) return json({ error: "Please sign in again." }, 401);
  let db;
  try { db = lifts(env); } catch (e) { return json({ error: e.message }, 500); }
  await syncTables(db);

  // GET ?since=N: every item changed after change number N (v is null for a deleted item)
  if (request.method === "GET") {
    const since = Math.max(0, Math.floor(Number(new URL(request.url).searchParams.get("since")) || 0));
    const { results } = await db.prepare(
      "SELECT k, v, seq FROM profile_items WHERE user = ?1 AND seq > ?2 ORDER BY seq LIMIT " + SYNC_PAGE
    ).bind(u, since).all();
    const items = results || [];
    return json({ items, seq: items.length ? items[items.length - 1].seq : since, more: items.length === SYNC_PAGE });
  }

  // POST {items:[{k, v, at}]}: save changes. For each item the most recent edit wins.
  // Returns the profile's current value for any item where an edit made elsewhere was newer.
  if (request.method === "POST") {
    let b;
    try { b = await request.json(); } catch { return json({ error: "Bad data" }, 400); }
    const list = Array.isArray(b && b.items) ? b.items : [];
    if (list.length > SYNC_PAGE) return json({ error: "Too many changes at once." }, 413);
    const now = Date.now(), sent = new Map();
    for (const it of list) {
      const k = it && typeof it.k === "string" ? it.k : "";
      if (!k.startsWith("pl4m-") || k.length > 400) continue;
      const v = it.v === null ? null : typeof it.v === "string" ? it.v : undefined;
      if (v === undefined || (v && v.length > 1_000_000)) continue;
      sent.set(k, { k, v, at: Math.min(Math.floor(Number(it.at)) || now, now) });
    }
    const rows = [...sent.values()];
    const put = db.prepare(
      "INSERT INTO profile_items (user, k, v, at, seq) VALUES (?1, ?2, ?3, ?4, (SELECT COALESCE(MAX(seq), 0) + 1 FROM profile_items WHERE user = ?1)) " +
      "ON CONFLICT (user, k) DO UPDATE SET v = excluded.v, at = excluded.at, seq = excluded.seq " +
      "WHERE excluded.at >= profile_items.at AND profile_items.v IS NOT excluded.v"
    );
    for (let i = 0; i < rows.length; i += 100) await db.batch(rows.slice(i, i + 100).map((r) => put.bind(u, r.k, r.v, r.at)));
    const current = [];
    for (let i = 0; i < rows.length; i += 90) {
      const part = rows.slice(i, i + 90);
      const { results } = await db.prepare(
        "SELECT k, v FROM profile_items WHERE user = ?1 AND k IN (" + part.map((_, j) => "?" + (j + 2)).join(",") + ")"
      ).bind(u, ...part.map((r) => r.k)).all();
      for (const row of results || []) if (row.v !== sent.get(row.k).v) current.push({ k: row.k, v: row.v });
    }
    return json({ ok: true, current });
  }
  return json({ error: "Method not allowed" }, 405);
}

// POST {share}: what this profile chooses to show the other profile. Only rewritten when it changes.
async function sharePost({ request, env }) {
  const u = await verify(env, request);
  if (!u) return json({ error: "Please sign in again." }, 401);
  if (request.method !== "POST") return json({ error: "Method not allowed" }, 405);
  let kv;
  try { kv = store(env); } catch (e) { return json({ error: e.message }, 500); }
  let b = {};
  try { b = await request.json(); } catch {}
  await saveShare(kv, u, b && b.share);
  return json({ ok: true });
}

export default {
  async fetch(request, env) {
    const path = new URL(request.url).pathname;
    const ctx = { request, env };
    try {
      if (path === "/api/auth") return request.method === "POST" ? await authPost(ctx) : await authGet(ctx);
      if (path === "/api/auth/google") return await authGoogle(ctx);
      if (path === "/api/people") return await peopleAll(ctx);
      if (path === "/api/connections") return await connectionsAll(ctx);
      if (path === "/api/wellness") return await wellnessGet(ctx);
      if (path === "/api/data") return await dataAll(ctx);
      if (path === "/api/shared") return await sharedGet(ctx);
      if (path === "/api/activities") return await actsGet(ctx);
      if (path === "/api/scan") return await scanPost(ctx);
      if (path === "/api/lifts") return await liftsAll(ctx);
      if (path === "/api/sync") return await syncAll(ctx);
      if (path === "/api/share") return await sharePost(ctx);
      if (path.startsWith("/api/")) return json({ error: "Not found" }, 404);
    } catch (e) {
      return json({ error: "Something went wrong on the server." }, 500);
    }
    // /track/lifting style links: the app routes by #hash, so send them to /#track/lifting
    if (/^\/track(\/|$)/.test(path)) { const u = new URL(request.url); return Response.redirect(u.origin + "/#" + path.slice(1).replace(/\/+$/, ""), 302); }
    // Keep the old Netlify-only files private; serve everything else normally
    if (/^\/(netlify|functions|lib)\/|^\/(netlify\.toml|package\.json|_worker\.js|activities\.js|auth\.js|common\.js|data\.js|shared\.js|schema\.sql)$/.test(path)) return new Response("Not found", { status: 404 });
    return env.ASSETS.fetch(request);
  },
};

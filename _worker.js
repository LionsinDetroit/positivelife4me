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
  if (!o || !USERS[o.u] || !enabled(env).includes(o.u) || !(o.exp > Date.now())) return null;
  return sameText(s, await hmac(secret(env, o.u), p)) ? o.u : null;
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
  return json({ users: enabled(env).map((u) => ({ id: u, name: USERS[u] })) });
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

// Saves and loads each profile's private data so it matches on every device.

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
    // Only what the person chose to share is stored where the other profile can see it.
    // It's only rewritten when it actually changes, to stay well inside the free storage limits.
    const share = b.share && typeof b.share === "object" && Object.keys(b.share).length ? JSON.stringify(b.share) : "";
    const prev = await kv.get("share/" + u);
    const prevShare = prev ? JSON.stringify((({ at, ...rest }) => rest)(JSON.parse(prev))) : "";
    if (share !== prevShare) {
      if (share) await kv.put("share/" + u, JSON.stringify({ at: Date.now(), ...b.share }));
      else await kv.delete("share/" + u);
    }
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
  const people = [];
  for (const other of enabled(env)) {
    if (other === u) continue;
    const s = await kv.get("share/" + other, { type: "json" });
    if (s) people.push({ name: USERS[other], ...s });
  }
  return json({ people });
}

// Fetches the signed-in person's workouts from their own Intervals.icu account.

async function actsGet({ request, env }) {
  const u = await verify(env, request);
  if (!u) return json({ error: "Please sign in again." }, 401);
  const { id, key } = intervals(env, u);
  if (!id || !key) return json({ error: "Automatic sync isn't set up for this profile yet." }, 409);
  const days = Math.min(365, Math.max(1, parseInt(new URL(request.url).searchParams.get("days")) || 30));
  const day = (n) => new Date(Date.now() - n * 864e5).toISOString().slice(0, 10);
  const url = `https://intervals.icu/api/v1/athlete/${encodeURIComponent(id)}/activities?oldest=${day(days)}&newest=${day(-1)}`;
  let r;
  try {
    r = await fetch(url, { headers: { authorization: "Basic " + btoa("API_KEY:" + key), accept: "application/json" } });
  } catch {
    return json({ error: "Couldn't reach Intervals.icu right now." }, 502);
  }
  if (!r.ok) return json({ error: `Intervals.icu didn't accept the request (${r.status}). Check the Athlete ID and API key in Cloudflare.` }, 502);
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

export default {
  async fetch(request, env) {
    const path = new URL(request.url).pathname;
    const ctx = { request, env };
    try {
      if (path === "/api/auth") return request.method === "POST" ? await authPost(ctx) : await authGet(ctx);
      if (path === "/api/data") return await dataAll(ctx);
      if (path === "/api/shared") return await sharedGet(ctx);
      if (path === "/api/activities") return await actsGet(ctx);
      if (path === "/api/scan") return await scanPost(ctx);
      if (path === "/api/lifts") return await liftsAll(ctx);
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

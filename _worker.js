// positiveLife4me server helper for Cloudflare Pages (single-file "advanced mode").
// It answers the /api/... requests (sign-in, private data, sharing, workouts)
// and hands every other request to the site's normal files.
// Secrets live in the Cloudflare project settings, never in this file.
// Shared helpers for the positiveLife4me server functions (Cloudflare Pages).
// Secrets live in Cloudflare's project settings, never in these files:
//   ADAM_PASSCODE, ADAM_INTERVALS_ID, ADAM_INTERVALS_KEY
//   LAUREN_PASSCODE, LAUREN_INTERVALS_ID, LAUREN_INTERVALS_KEY
// Storage: a KV namespace bound to the project with the variable name PL4M.

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

export default {
  async fetch(request, env) {
    const path = new URL(request.url).pathname;
    const ctx = { request, env };
    try {
      if (path === "/api/auth") return request.method === "POST" ? await authPost(ctx) : await authGet(ctx);
      if (path === "/api/data") return await dataAll(ctx);
      if (path === "/api/shared") return await sharedGet(ctx);
      if (path === "/api/activities") return await actsGet(ctx);
      if (path.startsWith("/api/")) return json({ error: "Not found" }, 404);
    } catch (e) {
      return json({ error: "Something went wrong on the server." }, 500);
    }
    // Keep the old Netlify-only files private; serve everything else normally
    if (/^\/(netlify|functions|lib)\/|^\/(netlify\.toml|package\.json|_worker\.js|activities\.js|auth\.js|common\.js|data\.js|shared\.js)$/.test(path)) return new Response("Not found", { status: 404 });
    return env.ASSETS.fetch(request);
  },
};

// Shared helpers for the positiveLife4me server functions (Cloudflare Pages).
// Secrets live in Cloudflare's project settings, never in these files:
//   ADAM_PASSCODE, ADAM_INTERVALS_ID, ADAM_INTERVALS_KEY
//   LAUREN_PASSCODE, LAUREN_INTERVALS_ID, LAUREN_INTERVALS_KEY
// Storage: a KV namespace bound to the project with the variable name PL4M.

export const USERS = { adam: "Adam", lauren: "Lauren" };
const up = (u) => u.toUpperCase();
const enc = new TextEncoder();
const b64u = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64uStr = (s) => b64u(enc.encode(s));
const unb64u = (s) => atob(s.replace(/-/g, "+").replace(/_/g, "/"));

export const enabled = (env) => Object.keys(USERS).filter((u) => env[up(u) + "_PASSCODE"]);
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

export async function sign(env, u, days = 180) {
  const p = b64uStr(JSON.stringify({ u, exp: Date.now() + days * 864e5 }));
  return p + "." + (await hmac(secret(env, u), p));
}

export async function verify(env, request) {
  const t = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  const [p, s] = t.split(".");
  if (!p || !s) return null;
  let o;
  try { o = JSON.parse(unb64u(p)); } catch { return null; }
  if (!o || !USERS[o.u] || !enabled(env).includes(o.u) || !(o.exp > Date.now())) return null;
  return sameText(s, await hmac(secret(env, o.u), p)) ? o.u : null;
}

export async function passOk(env, u, pc) {
  const real = env[up(u) + "_PASSCODE"];
  if (!real || typeof pc !== "string") return false;
  const h = async (x) => b64u(await crypto.subtle.digest("SHA-256", enc.encode(x)));
  return sameText(await h(pc), await h(real));
}

export const intervals = (env, u) => ({ id: String(env[up(u) + "_INTERVALS_ID"] || "").trim(), key: String(env[up(u) + "_INTERVALS_KEY"] || "").trim() });

export const json = (o, status = 200) =>
  new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });

export const store = (env) => {
  if (!env.PL4M) throw new Error("Storage isn't connected. Add a KV binding named PL4M in the Cloudflare project settings.");
  return env.PL4M;
};

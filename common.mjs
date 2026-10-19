// Shared helpers for the positiveLife4me server functions.
// Secrets live in Netlify environment variables, never in these files:
//   ADAM_PASSCODE, ADAM_INTERVALS_ID, ADAM_INTERVALS_KEY
//   LAUREN_PASSCODE, LAUREN_INTERVALS_ID, LAUREN_INTERVALS_KEY
import crypto from "node:crypto";

export const USERS = { adam: "Adam", lauren: "Lauren" };

const env = (k) => (globalThis.Netlify?.env?.get?.(k)) || process.env[k] || "";
const up = (u) => u.toUpperCase();

// A profile is "on" once its passcode has been added in Netlify
export const enabled = () => Object.keys(USERS).filter((u) => env(up(u) + "_PASSCODE"));

const secret = (u) => env(up(u) + "_PASSCODE") + "|pl4m|" + env(up(u) + "_INTERVALS_KEY");

export function sign(u, days = 180) {
  const p = Buffer.from(JSON.stringify({ u, exp: Date.now() + days * 864e5 })).toString("base64url");
  const s = crypto.createHmac("sha256", secret(u)).update(p).digest("base64url");
  return p + "." + s;
}

export function verify(req) {
  const t = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  const [p, s] = t.split(".");
  if (!p || !s) return null;
  let o;
  try { o = JSON.parse(Buffer.from(p, "base64url").toString()); } catch { return null; }
  if (!o || !USERS[o.u] || !enabled().includes(o.u) || !(o.exp > Date.now())) return null;
  const good = crypto.createHmac("sha256", secret(o.u)).update(p).digest("base64url");
  const a = Buffer.from(s), b = Buffer.from(good);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  return o.u;
}

export function passOk(u, pc) {
  const real = env(up(u) + "_PASSCODE");
  if (!real || typeof pc !== "string") return false;
  const a = crypto.createHash("sha256").update(pc).digest();
  const b = crypto.createHash("sha256").update(real).digest();
  return crypto.timingSafeEqual(a, b);
}

export const intervals = (u) => ({ id: env(up(u) + "_INTERVALS_ID").trim(), key: env(up(u) + "_INTERVALS_KEY").trim() });

export const json = (o, status = 200) =>
  new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });

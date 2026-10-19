// Sign in to a profile with its passcode. GET lists which profiles are set up.
import { USERS, enabled, sign, passOk, json } from "../lib/common.mjs";

export default async (req) => {
  if (req.method === "GET") return json({ users: enabled().map((u) => ({ id: u, name: USERS[u] })) });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  let b = {};
  try { b = await req.json(); } catch {}
  const u = String(b.user || "").toLowerCase();
  if (!enabled().includes(u) || !passOk(u, b.passcode)) {
    await new Promise((r) => setTimeout(r, 800)); // slow down guessing
    return json({ error: "That passcode didn't match." }, 401);
  }
  return json({ token: sign(u), user: u, name: USERS[u] });
};

export const config = { path: "/api/auth" };

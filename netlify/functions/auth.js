// Sign in to a profile with its passcode. GET lists which profiles are set up.
import { USERS, enabled, sign, passOk, json } from "../../lib/common.js";

export async function onRequestGet({ env }) {
  return json({ users: enabled(env).map((u) => ({ id: u, name: USERS[u] })) });
}

export async function onRequestPost({ request, env }) {
  let b = {};
  try { b = await request.json(); } catch {}
  const u = String(b.user || "").toLowerCase();
  if (!enabled(env).includes(u) || !(await passOk(env, u, b.passcode))) {
    await new Promise((r) => setTimeout(r, 800)); // slow down guessing
    return json({ error: "That passcode didn't match." }, 401);
  }
  return json({ token: await sign(env, u), user: u, name: USERS[u] });
}

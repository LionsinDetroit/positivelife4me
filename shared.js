// Returns progress the other profiles have chosen to share.
import { USERS, enabled, verify, json, store } from "../../lib/common.js";

export async function onRequestGet({ request, env }) {
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

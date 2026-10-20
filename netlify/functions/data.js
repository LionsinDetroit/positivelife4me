// Saves and loads each profile's private data so it matches on every device.
import { verify, json, store } from "../../lib/common.js";

export async function onRequest({ request, env }) {
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

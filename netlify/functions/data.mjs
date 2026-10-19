// Saves and loads each profile's private data so it matches on every device.
import { getStore } from "@netlify/blobs";
import { verify, json } from "../lib/common.mjs";

export default async (req) => {
  const u = verify(req);
  if (!u) return json({ error: "Please sign in again." }, 401);
  const store = getStore({ name: "pl4m", consistency: "strong" });

  if (req.method === "GET") {
    const d = await store.get("profile/" + u, { type: "json" });
    return json(d || {});
  }
  if (req.method === "PUT") {
    let b;
    try { b = await req.json(); } catch { return json({ error: "Bad data" }, 400); }
    if (!b || typeof b.data !== "object" || Array.isArray(b.data)) return json({ error: "Bad data" }, 400);
    if (JSON.stringify(b.data).length > 4_000_000) return json({ error: "Too much data" }, 413);
    await store.setJSON("profile/" + u, { savedAt: Number(b.savedAt) || Date.now(), data: b.data });
    // Only what the person chose to share is stored where the other profile can see it
    if (b.share && typeof b.share === "object" && Object.keys(b.share).length) await store.setJSON("share/" + u, { at: Date.now(), ...b.share });
    else await store.delete("share/" + u);
    return json({ ok: true });
  }
  return json({ error: "Method not allowed" }, 405);
};

export const config = { path: "/api/data" };

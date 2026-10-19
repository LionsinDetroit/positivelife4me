// Returns progress the other profiles have chosen to share.
import { getStore } from "@netlify/blobs";
import { USERS, enabled, verify, json } from "../lib/common.mjs";

export default async (req) => {
  const u = verify(req);
  if (!u) return json({ error: "Please sign in again." }, 401);
  const store = getStore({ name: "pl4m", consistency: "strong" });
  const people = [];
  for (const other of enabled()) {
    if (other === u) continue;
    const s = await store.get("share/" + other, { type: "json" });
    if (s) people.push({ name: USERS[other], ...s });
  }
  return json({ people });
};

export const config = { path: "/api/shared" };

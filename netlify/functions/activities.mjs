// Fetches the signed-in person's workouts from their own Intervals.icu account.
import { verify, json, intervals } from "../lib/common.mjs";

export default async (req) => {
  const u = verify(req);
  if (!u) return json({ error: "Please sign in again." }, 401);
  const { id, key } = intervals(u);
  if (!id || !key) return json({ error: "Automatic sync isn't set up for this profile yet." }, 409);
  const days = Math.min(365, Math.max(1, parseInt(new URL(req.url).searchParams.get("days")) || 30));
  const day = (n) => new Date(Date.now() - n * 864e5).toISOString().slice(0, 10);
  const url = `https://intervals.icu/api/v1/athlete/${encodeURIComponent(id)}/activities?oldest=${day(days)}&newest=${day(-1)}`;
  let r;
  try {
    r = await fetch(url, { headers: { authorization: "Basic " + Buffer.from("API_KEY:" + key).toString("base64"), accept: "application/json" } });
  } catch {
    return json({ error: "Couldn't reach Intervals.icu right now." }, 502);
  }
  if (!r.ok) return json({ error: `Intervals.icu didn't accept the request (${r.status}). Check the Athlete ID and API key in Netlify.` }, 502);
  const list = await r.json();
  const activities = (Array.isArray(list) ? list : [])
    .filter((a) => a && a.id && (a.start_date_local || a.start_date))
    .map((a) => ({
      id: "icu-" + a.id,
      source: "intervals",
      type: String(a.type || ""),
      rawType: [a.type, a.sub_type].filter(Boolean).join(" · "),
      name: a.name || "",
      desc: a.description || "",
      dev: a.device_name || "",
      src: a.source || "",
      ext: a.external_id || "",
      startLocal: a.start_date_local || a.start_date,
      sec: a.moving_time || a.elapsed_time || 0,
      el: a.elapsed_time || 0,
      m: a.distance || 0,
      cal: a.calories || 0,
      hr: a.average_heartrate || 0,
      maxhr: a.max_heartrate || 0,
      w: a.icu_average_watts || a.average_watts || 0,
      kj: a.icu_joules ? a.icu_joules / 1000 : 0,
      cad: a.average_cadence || 0,
      elev: a.total_elevation_gain || 0,
      load: a.icu_training_load || 0,
    }));
  return json({ activities, at: Date.now() });
};

export const config = { path: "/api/activities" };

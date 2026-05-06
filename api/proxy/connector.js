const ALLOWED = new Set(["facebook", "google_ads", "instagram"]);
const BASE = "https://connectors.windsor.ai";

export default async function handler(req, res) {
  const { connector, ...rest } = req.query;
  if (!connector || !ALLOWED.has(connector)) {
    res.status(400).json({ error: "invalid_connector" });
    return;
  }
  const apiKey = process.env.WINDSOR_KEY;
  if (!apiKey) {
    res.status(500).json({ error: "server_misconfigured" });
    return;
  }

  const params = new URLSearchParams();
  params.set("api_key", apiKey);
  for (const [k, v] of Object.entries(rest)) {
    if (Array.isArray(v)) v.forEach(val => params.append(k, val));
    else if (v != null) params.set(k, String(v));
  }

  const url = `${BASE}/${connector}?${params}`;
  try {
    const r = await fetch(url, { headers: { "user-agent": "MesusPainel/1.0" } });
    const text = await r.text();
    res.setHeader("content-type", "application/json; charset=utf-8");
    res.setHeader("cache-control", "private, max-age=60");
    res.status(r.status).send(text);
  } catch (e) {
    res.status(502).json({ error: "upstream_failed", message: String(e) });
  }
}
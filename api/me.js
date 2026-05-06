import { createHmac } from "crypto";

function b64urlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return Buffer.from(str, "base64").toString("utf8");
}

function readToken(req) {
  const cookies = req.headers.cookie || "";
  const m = cookies.match(/mesus_session=([^;]+)/);
  if (!m) return null;
  try {
    const token = decodeURIComponent(m[1]);
    const [payload] = token.split(".");
    return JSON.parse(b64urlDecode(payload));
  } catch { return null; }
}

export default async function handler(req, res) {
  const u = readToken(req);
  if (!u) { res.status(401).json({ error: "unauthorized" }); return; }
  res.status(200).json({ email: u.email, name: u.name });
}
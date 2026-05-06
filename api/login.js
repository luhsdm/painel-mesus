import { pbkdf2Sync, createHmac, timingSafeEqual } from "crypto";

function b64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function signToken(payload, secret) {
  const data = b64url(JSON.stringify(payload));
  const sig = b64url(createHmac("sha256", secret).update(data).digest());
  return `${data}.${sig}`;
}

function verifyPassword(stored, supplied) {
  const [salt, hash] = (stored || "").split(":");
  if (!salt || !hash) return false;
  const test = pbkdf2Sync(supplied, salt, 100000, 32, "sha256").toString("hex");
  const a = Buffer.from(hash, "hex");
  const b = Buffer.from(test, "hex");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.status(405).json({ error: "method_not_allowed" });
    return;
  }
  let body = req.body;
  if (typeof body === "string") {
    try { body = JSON.parse(body); } catch { body = {}; }
  }
  const { email, password } = body || {};
  if (!email || !password) {
    res.status(400).json({ error: "missing_credentials" });
    return;
  }

  let users = [];
  try {
    users = JSON.parse(process.env.USERS || "[]");
  } catch {
    res.status(500).json({ error: "server_misconfigured" });
    return;
  }

  const user = users.find(u => (u.email || "").toLowerCase() === email.toLowerCase());
  if (!user || !verifyPassword(user.hash, password)) {
    res.status(401).json({ error: "invalid_credentials" });
    return;
  }

  const secret = process.env.AUTH_SECRET;
  if (!secret) {
    res.status(500).json({ error: "server_misconfigured" });
    return;
  }

  const hours = parseInt(process.env.SESSION_HOURS || "12", 10);
  const exp = Math.floor(Date.now() / 1000) + hours * 3600;
  const token = signToken(
    { email: user.email, name: user.name || user.email, exp, iat: Math.floor(Date.now() / 1000) },
    secret
  );

  const cookie = [
    `mesus_session=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${hours * 3600}`
  ].join("; ");

  res.setHeader("Set-Cookie", cookie);
  res.status(200).json({ ok: true, name: user.name || user.email });
}
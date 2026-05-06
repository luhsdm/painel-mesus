export const config = {
  matcher: ["/((?!_next|favicon|api/login|api/logout|login|public/login).*)"]
};

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64urlToBytes(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function verifyToken(token, secret) {
  if (!token || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [payloadB64, sigB64] = parts;
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const ok = await crypto.subtle.verify(
      "HMAC",
      key,
      b64urlToBytes(sigB64),
      enc.encode(payloadB64)
    );
    if (!ok) return null;
    const payload = JSON.parse(dec.decode(b64urlToBytes(payloadB64)));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

export default async function middleware(req) {
  const url = new URL(req.url);
  const cookies = req.headers.get("cookie") || "";
  const m = cookies.match(/mesus_session=([^;]+)/);
  const token = m ? decodeURIComponent(m[1]) : null;
  const secret = process.env.AUTH_SECRET;

  const payload = secret ? await verifyToken(token, secret) : null;
  if (payload) {
    return;
  }

  if (url.pathname.startsWith("/api/")) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "content-type": "application/json" }
    });
  }
  url.pathname = "/login";
  return Response.redirect(url, 302);
}
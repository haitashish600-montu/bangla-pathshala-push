/** Bangla Pathshala secure FCM topic-notification Worker.
 * Required Cloudflare secret: FIREBASE_SERVICE_ACCOUNT_JSON
 * Never put the service-account JSON/private key in GitHub or HTML.
 */
const ALLOWED_ORIGIN = "https://haitashish600-montu.github.io";
const FIREBASE_API_KEY = "AIzaSyDhpZJ1z2j74khtWMo9hIpo1WHgAaFzwCc";
const ADMIN_EMAIL = "haitashish600@gmail.com";
const TOPIC = "all_students";
// Preserve both scopes reported in the current deployed Worker.
const OAUTH_SCOPE = "https://www.googleapis.com/auth/firebase.messaging https://www.googleapis.com/auth/datastore";

function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": origin === ALLOWED_ORIGIN ? origin : ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin",
    "Content-Type": "application/json; charset=utf-8"
  };
}
function json(data, status, origin) {
  return new Response(JSON.stringify(data), { status, headers: corsHeaders(origin) });
}
function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function utf8B64url(value) { return b64url(new TextEncoder().encode(value)); }
function pemToBytes(pem) {
  const base64 = pem.replace(/-----BEGIN PRIVATE KEY-----/g, "").replace(/-----END PRIVATE KEY-----/g, "").replace(/\s/g, "");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
async function getAccessToken(serviceAccount) {
  const now = Math.floor(Date.now() / 1000);
  const header = utf8B64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claim = utf8B64url(JSON.stringify({
    iss: serviceAccount.client_email, scope: OAUTH_SCOPE,
    aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600
  }));
  const unsigned = `${header}.${claim}`;
  const privateKey = await crypto.subtle.importKey(
    "pkcs8", pemToBytes(serviceAccount.private_key),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]
  );
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, new TextEncoder().encode(unsigned));
  const assertion = `${unsigned}.${b64url(new Uint8Array(signature))}`;
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion })
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || !result.access_token) {
    throw new Error(`Google OAuth token request failed (${response.status}): ${result.error_description || result.error || "unknown error"}`);
  }
  return result.access_token;
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(origin) });
    if (origin !== ALLOWED_ORIGIN) return json({ ok: false, error: "Origin not allowed" }, 403, origin);
    if (request.method !== "POST") return json({ ok: false, error: "Method not allowed" }, 405, origin);

    try {
      const input = await request.json();
      const idToken = String(input.idToken || "");
      const title = String(input.title || "বাংলা পাঠশালা").slice(0, 100);
      const body = String(input.body || "").trim().slice(0, 1000);
      if (!idToken || !body) return json({ ok: false, error: "Missing authentication or notice text" }, 400, origin);

      const verifyResponse = await fetch(
        `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(FIREBASE_API_KEY)}`,
        { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ idToken }) }
      );
      const verified = await verifyResponse.json().catch(() => ({}));
      const user = verified.users && verified.users[0];
      if (!verifyResponse.ok || !user || String(user.email || "").trim().toLowerCase() !== ADMIN_EMAIL.toLowerCase()) {
        return json({ ok: false, error: "Admin authentication failed" }, 401, origin);
      }
      if (!env.FIREBASE_SERVICE_ACCOUNT_JSON) return json({ ok: false, error: "Server credential is not configured" }, 500, origin);
      let serviceAccount;
      try { serviceAccount = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT_JSON); }
      catch { return json({ ok: false, error: "Service-account secret is not valid JSON" }, 500, origin); }
      if (!serviceAccount.project_id || !serviceAccount.client_email || !serviceAccount.private_key) {
        return json({ ok: false, error: "Service-account secret is invalid" }, 500, origin);
      }

      const accessToken = await getAccessToken(serviceAccount);
      const fcmResponse = await fetch(
        `https://fcm.googleapis.com/v1/projects/${encodeURIComponent(serviceAccount.project_id)}/messages:send`,
        { method: "POST", headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
          body: JSON.stringify({ message: { topic: TOPIC, notification: { title, body }, android: { priority: "HIGH", notification: { sound: "default" } } } }) }
      );
      const fcmResult = await fcmResponse.json().catch(() => ({}));
      if (!fcmResponse.ok) return json({
        ok: false, error: "FCM send failed", status: fcmResponse.status,
        details: fcmResult.error?.message || "Unknown FCM error", errorCode: fcmResult.error?.status || ""
      }, 502, origin);
      return json({ ok: true }, 200, origin);
    } catch (error) {
      const details = String(error?.message || "Unknown server error").slice(0, 300);
      return json({ ok: false, error: "Notification server error", details }, 500, origin);
    }
  }
};

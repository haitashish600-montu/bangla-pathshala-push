/**
 * Bangla Pathshala — Cloudflare Worker
 * Sends an Admin-authenticated FCM notification to tokens saved in Firestore:
 * studentPushTokens/{token} with field token.
 *
 * Cloudflare Production Secret required:
 * FIREBASE_SERVICE_ACCOUNT_JSON = complete Firebase service-account JSON.
 */
const ALLOWED_ORIGIN = "https://haitashish600-montu.github.io";
const FIREBASE_API_KEY = "AIzaSyDhpZJ1z2j74khtWMo9hIpo1WHgAaFzwCc";
const ADMIN_EMAIL = "haitashish600@gmail.com";
const OAUTH_SCOPE = "https://www.googleapis.com/auth/firebase.messaging https://www.googleapis.com/auth/datastore";

function headers(origin) {
  return {
    "Access-Control-Allow-Origin": origin === ALLOWED_ORIGIN ? origin : ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin",
    "Content-Type": "application/json; charset=utf-8"
  };
}
function json(data, status, origin) {
  return new Response(JSON.stringify(data), { status, headers: headers(origin) });
}
function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function utf8B64url(value) {
  return b64url(new TextEncoder().encode(value));
}
function pemToBytes(pem) {
  const base64 = pem.replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "").replace(/\s/g, "");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
async function getAccessToken(sa) {
  const now = Math.floor(Date.now() / 1000);
  const unsigned = utf8B64url(JSON.stringify({ alg: "RS256", typ: "JWT" })) + "." +
    utf8B64url(JSON.stringify({
      iss: sa.client_email,
      scope: OAUTH_SCOPE,
      aud: "https://oauth2.googleapis.com/token",
      iat: now,
      exp: now + 3600
    }));
  const key = await crypto.subtle.importKey(
    "pkcs8", pemToBytes(sa.private_key),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]
  );
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(unsigned)
  );
  const assertion = unsigned + "." + b64url(new Uint8Array(signature));
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion
    })
  });
  const result = await response.json();
  if (!response.ok || !result.access_token) throw new Error("Google OAuth token request failed");
  return result.access_token;
}
async function verifyAdmin(idToken) {
  const response = await fetch(
    "https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=" + encodeURIComponent(FIREBASE_API_KEY),
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ idToken })
    }
  );
  const result = await response.json();
  const user = result.users && result.users[0];
  return response.ok && user &&
    String(user.email || "").trim().toLowerCase() === ADMIN_EMAIL.toLowerCase();
}
async function listTokens(projectId, accessToken) {
  const tokens = new Set();
  let pageToken = "";
  for (let page = 0; page < 20; page++) {
    const url = new URL(
      `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/databases/(default)/documents/studentPushTokens`
    );
    url.searchParams.set("pageSize", "1000");
    if (pageToken) url.searchParams.set("pageToken", pageToken);
    const response = await fetch(url.toString(), {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error?.message || "Could not read studentPushTokens");
    for (const doc of (data.documents || [])) {
      const token = doc.fields?.token?.stringValue;
      if (typeof token === "string" && token.trim()) tokens.add(token.trim());
    }
    pageToken = data.nextPageToken || "";
    if (!pageToken) break;
  }
  return [...tokens];
}
async function sendOne(projectId, accessToken, token, title, body) {
  const response = await fetch(
    `https://fcm.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/messages:send`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        message: {
          token,
          notification: { title, body },
          android: { priority: "HIGH", notification: { sound: "default" } }
        }
      })
    }
  );
  const result = await response.json().catch(() => ({}));
  return { ok: response.ok, error: result.error?.message || "", errorCode: result.error?.status || result.error?.details?.[0]?.errorCode || "" };
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: headers(origin) });
    if (origin !== ALLOWED_ORIGIN) return json({ ok: false, error: "Origin not allowed" }, 403, origin);
    if (request.method !== "POST") return json({ ok: false, error: "Method not allowed" }, 405, origin);

    try {
      const input = await request.json();
      const idToken = String(input.idToken || "");
      const title = String(input.title || "বাংলা পাঠশালা").trim().slice(0, 100);
      const body = String(input.body || "").trim().slice(0, 1000);
      if (!idToken || !body) return json({ ok: false, error: "Missing authentication or notice text" }, 400, origin);
      if (!(await verifyAdmin(idToken))) return json({ ok: false, error: "Admin authentication failed" }, 401, origin);
      if (!env.FIREBASE_SERVICE_ACCOUNT_JSON) return json({ ok: false, error: "Server credential is not configured" }, 500, origin);

      const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT_JSON);
      if (!sa.project_id || !sa.client_email || !sa.private_key) {
        return json({ ok: false, error: "Service-account secret is invalid" }, 500, origin);
      }
      const accessToken = await getAccessToken(sa);
      const tokens = await listTokens(sa.project_id, accessToken);
      if (!tokens.length) return json({
        ok: false,
        error: "No student FCM tokens found in Firestore studentPushTokens. No notification sent."
      }, 409, origin);

      let sent = 0, failed = 0;
      const failures = [];
      for (const token of tokens) {
        const result = await sendOne(sa.project_id, accessToken, token, title, body);
        if (result.ok) sent++;
        else {
          failed++;
          failures.push({
            token: token.length > 16 ? token.slice(0, 8) + "…" + token.slice(-6) : "[masked]",
            error: result.error || "FCM request failed without an error message",
            errorCode: result.errorCode || "UNKNOWN"
          });
        }
      }
      return json({ ok: failed === 0, total: tokens.length, sent, failed, failures: failures.slice(0, 20) }, failed ? 207 : 200, origin);
    } catch (error) {
      return json({ ok: false, error: String(error?.message || "Notification server error").slice(0, 300) }, 500, origin);
    }
  }
};

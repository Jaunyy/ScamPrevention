/**
 * Scam Coercion Detector — Cloudflare Worker
 *
 * Routes:
 *   POST /register          — register a new device token (first run)
 *   POST /events            — ingest a flagged event (requires Bearer token)
 *   GET  /events            — fetch events for a token (for the dashboard)
 *
 * Auth: every request that touches event data must include
 *   Authorization: Bearer <device_token>
 */

const ALLOWED_TACTICS = new Set([
  "URGENCY",
  "SECRECY",
  "FALSE_AUTHORITY",
  "RECIPROCITY",
  "CREDENTIAL_REQUEST",
  "PAYMENT_REQUEST",
]);

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}

function extractToken(request) {
  const auth = request.headers.get("Authorization") || "";
  const match = auth.match(/^Bearer\s+([A-Z0-9]{12})$/i);
  return match ? match[1].toUpperCase() : null;
}

async function getDevice(db, token) {
  const row = await db
    .prepare("SELECT token, name FROM devices WHERE token = ?")
    .bind(token)
    .first();
  return row;
}

// ---------------------------------------------------------------------------
// POST /register
// Body: { "token": "XXXXXXXXXXXX", "name": "optional device name" }
// ---------------------------------------------------------------------------
async function handleRegister(request, db) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid JSON" }, 400);
  }

  const token = (body.token || "").toUpperCase();
  if (!/^[A-Z0-9]{12}$/.test(token)) {
    return json({ error: "token must be 12 alphanumeric characters" }, 400);
  }

  const existing = await getDevice(db, token);
  if (existing) {
    return json({ ok: true, already_registered: true, name: existing.name });
  }

  const name = (body.name || "unnamed device").slice(0, 64);
  await db
    .prepare("INSERT INTO devices (token, name, created_at) VALUES (?, ?, ?)")
    .bind(token, name, Date.now())
    .run();

  return json({ ok: true, token, name });
}

// ---------------------------------------------------------------------------
// POST /events
// Body: { "timestamp": "ISO8601", "tactic": "URGENCY", "confidence": 0.8 }
// ---------------------------------------------------------------------------
async function handlePostEvent(request, db) {
  const token = extractToken(request);
  if (!token) return json({ error: "missing or malformed Bearer token" }, 401);

  const device = await getDevice(db, token);
  if (!device) return json({ error: "unknown device — register first" }, 403);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid JSON" }, 400);
  }

  const { timestamp, tactic, confidence } = body;

  if (!timestamp || typeof timestamp !== "string") {
    return json({ error: "timestamp required" }, 400);
  }
  if (!ALLOWED_TACTICS.has(tactic)) {
    return json({ error: "unknown tactic" }, 400);
  }
  if (typeof confidence !== "number" || confidence < 0 || confidence > 1) {
    return json({ error: "confidence must be 0.0–1.0" }, 400);
  }

  await db
    .prepare(
      "INSERT INTO events (token, tactic, confidence, timestamp, received_at) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(token, tactic, confidence, timestamp, Date.now())
    .run();

  return json({ ok: true });
}

// ---------------------------------------------------------------------------
// GET /events?limit=50
// ---------------------------------------------------------------------------
async function handleGetEvents(request, db) {
  const token = extractToken(request);
  if (!token) return json({ error: "missing or malformed Bearer token" }, 401);

  const device = await getDevice(db, token);
  if (!device) return json({ error: "unknown device" }, 403);

  const url = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "100"), 500);

  const { results } = await db
    .prepare(
      "SELECT tactic, confidence, timestamp FROM events WHERE token = ? ORDER BY received_at DESC LIMIT ?"
    )
    .bind(token, limit)
    .all();

  return json({ device: device.name, events: results });
}

// ---------------------------------------------------------------------------
// Main handler
// ---------------------------------------------------------------------------
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const method = request.method.toUpperCase();

    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    if (url.pathname === "/register" && method === "POST") {
      return handleRegister(request, env.DB);
    }
    if (url.pathname === "/events" && method === "POST") {
      return handlePostEvent(request, env.DB);
    }
    if (url.pathname === "/events" && method === "GET") {
      return handleGetEvents(request, env.DB);
    }

    return json({ error: "not found" }, 404);
  },
};

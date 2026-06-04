/**
 * Scam Coercion Detector — Cloudflare Worker
 *
 * Routes:
 *   POST /register          — register a new device token (first run)
 *   POST /events            — ingest a flagged event (requires Bearer token)
 *   GET  /events            — fetch events for a token (for the dashboard)
 *   POST /classify          — run Workers AI on a text snippet (no storage)
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
  "FREE_ITEM_LURE",
  "OFF_PLATFORM",
]);

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

// System prompt for the /classify LLM route.
// Instruct the model to return ONLY a JSON object — no prose, no fences.
const CLASSIFY_SYSTEM_PROMPT = `You are a child-safety classifier. You receive text extracted from a child's game screen (Roblox, Xbox, Fortnite, Minecraft, etc.) via OCR.

Determine whether the text contains a SCAM or COERCION TACTIC directed AT the child by another player or stranger.

CRITICAL INTENT RULE — identify who is speaking:
- A CHILD ASKING a question ("where can I get free skins?", "does anyone have robux?") → NONE
- A STRANGER TARGETING the child ("I'll give you free robux, DM me", "what's your password") → classify the tactic

Tactic definitions:
URGENCY           — time pressure to act before thinking ("only 3 minutes left", "act now or lose it")
SECRECY           — hiding activity from parents ("don't tell your parents", "keep this between us")
FALSE_AUTHORITY   — impersonating platform staff ("I'm a Roblox admin", "official Xbox support")
RECIPROCITY       — go-first trap ("trust trade, you send first", "send yours and I'll send mine")
CREDENTIAL_REQUEST — requesting account credentials ("what's your password", "send me your 2FA code")
PAYMENT_REQUEST   — money or gift card demands ("send me a gift card", "buy me V-Bucks", "scan this QR")
FREE_ITEM_LURE    — free item offer combined with an engagement hook ("free robux, DM me first", "giving away skins, add me on discord")
OFF_PLATFORM      — redirecting to an unmoderated channel ("let's move to Discord to trade", "add me on Telegram")
NONE              — normal game chat, benign content, or a child asking a question (not a threat)

Output exactly one JSON object — no markdown, no prose, nothing else:
{"tactic":"NONE","confidence":0.0,"reasoning":"one short sentence"}`;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
// POST /classify
// Body: { "text": "<snippet>" }
// Calls Workers AI; never stores the text or the result in D1.
// ---------------------------------------------------------------------------
async function handleClassify(request, env) {
  const token = extractToken(request);
  if (!token) return json({ error: "missing or malformed Bearer token" }, 401);

  const device = await getDevice(env.DB, token);
  if (!device) return json({ error: "unknown device" }, 403);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid JSON" }, 400);
  }

  const text = String(body.text || "").slice(0, 1000).trim();
  if (!text) {
    return json({ tactic: "NONE", confidence: 0, reasoning: "empty input" });
  }

  let raw = "";
  try {
    const response = await env.AI.run("@cf/meta/llama-3.1-8b-instruct", {
      messages: [
        { role: "system", content: CLASSIFY_SYSTEM_PROMPT },
        { role: "user", content: text },
      ],
      max_tokens: 256,
    });
    raw = (response.response || "").trim();
  } catch {
    return json({ tactic: "NONE", confidence: 0, reasoning: "ai_error" });
  }

  // Defensive parse: strip markdown fences, extract the first {...} object
  raw = raw.replace(/^```(?:json)?\s*/im, "").replace(/\s*```\s*$/im, "").trim();
  const jsonMatch = raw.match(/\{[\s\S]*\}/);
  if (jsonMatch) raw = jsonMatch[0];

  let result;
  try {
    result = JSON.parse(raw);
  } catch {
    return json({ tactic: "NONE", confidence: 0, reasoning: "parse_error" });
  }

  const tactic = ALLOWED_TACTICS.has(result.tactic) ? result.tactic : "NONE";
  const confidence =
    typeof result.confidence === "number"
      ? Math.min(1, Math.max(0, result.confidence))
      : 0;
  const reasoning =
    typeof result.reasoning === "string" ? result.reasoning.slice(0, 200) : "";

  return json({ tactic, confidence, reasoning });
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
    if (url.pathname === "/classify" && method === "POST") {
      return handleClassify(request, env);
    }

    return json({ error: "not found" }, 404);
  },
};

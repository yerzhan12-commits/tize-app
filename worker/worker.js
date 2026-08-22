/**
 * TIZE access-code gate.
 * KV "CODES": key = access code, value = JSON {"name": string, "token": string|null}.
 * token === null means the code has not been activated on any device yet.
 * First successful /verify call "burns" the code to that device's token;
 * subsequent calls from other devices (different/missing token) are rejected.
 */

const ALLOWED_ORIGIN = "https://yerzhan12-commits.github.io";

function json(obj, status, extra) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", ...(extra || {}) }
  });
}

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type"
  };
}

async function handleVerify(body, env, cors) {
  const code = String(body.code || "").trim().toUpperCase();
  const clientToken = body.token ? String(body.token) : null;
  if (!code) return json({ ok: false, error: "bad_request" }, 400, cors);

  const raw = await env.CODES.get(code);
  if (!raw) return json({ ok: false, error: "not_found" }, 404, cors);

  let entry;
  try {
    entry = JSON.parse(raw);
  } catch (e) {
    return json({ ok: false, error: "server_error" }, 500, cors);
  }

  if (!entry.token) {
    const newToken = crypto.randomUUID();
    entry.token = newToken;
    await env.CODES.put(code, JSON.stringify(entry));
    return json({ ok: true, name: entry.name, token: newToken }, 200, cors);
  }

  if (clientToken && clientToken === entry.token) {
    return json({ ok: true, name: entry.name, token: entry.token }, 200, cors);
  }

  return json({ ok: false, error: "used" }, 409, cors);
}

async function handleAdminAdd(body, env, cors) {
  if (!env.ADMIN_KEY || body.adminKey !== env.ADMIN_KEY) {
    return json({ ok: false, error: "forbidden" }, 403, cors);
  }
  const code = String(body.code || "").trim().toUpperCase();
  const name = String(body.name || "").trim();
  if (!code || !name) return json({ ok: false, error: "bad_request" }, 400, cors);
  await env.CODES.put(code, JSON.stringify({ name, token: null }));
  return json({ ok: true, code, name }, 200, cors);
}

async function handleAdminReset(body, env, cors) {
  if (!env.ADMIN_KEY || body.adminKey !== env.ADMIN_KEY) {
    return json({ ok: false, error: "forbidden" }, 403, cors);
  }
  const code = String(body.code || "").trim().toUpperCase();
  const raw = await env.CODES.get(code);
  if (!raw) return json({ ok: false, error: "not_found" }, 404, cors);
  const entry = JSON.parse(raw);
  entry.token = null;
  await env.CODES.put(code, JSON.stringify(entry));
  return json({ ok: true }, 200, cors);
}

export default {
  async fetch(request, env) {
    const cors = corsHeaders();
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: cors });
    }
    if (request.method !== "POST") {
      return json({ ok: false, error: "method_not_allowed" }, 405, cors);
    }

    let body;
    try {
      body = await request.json();
    } catch (e) {
      return json({ ok: false, error: "bad_request" }, 400, cors);
    }

    const { pathname } = new URL(request.url);
    if (pathname === "/verify") return handleVerify(body, env, cors);
    if (pathname === "/admin/add") return handleAdminAdd(body, env, cors);
    if (pathname === "/admin/reset") return handleAdminReset(body, env, cors);
    return json({ ok: false, error: "not_found" }, 404, cors);
  }
};

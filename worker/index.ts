import { json, error } from "./lib/responses";
import { randomId, randomToken, sha256 } from "./lib/ids";
import { validateCreate } from "./lib/validation";
import {
  SESSION_COOKIE,
  clearSessionCookie,
  createSessionToken,
  getCookie,
  safeStringEqual,
  sessionCookie,
  verifyPassword,
  verifySessionToken,
} from "./lib/auth";
import { DropAccessCoordinator } from "./durable/DropAccessCoordinator";
import { RateLimiter } from "./durable/RateLimiter";
import { STATIC_ASSETS } from "./generated/assets";

export interface Env {
  DB: D1Database;
  DROP_COORDINATOR: DurableObjectNamespace;
  RATE_LIMITER: DurableObjectNamespace;
  // Secrets (wrangler secret put ...)
  AUTH_USERNAME: string;
  AUTH_PASSWORD_HASH: string; // pbkdf2-sha256$iter$salt$hash
  SESSION_SECRET: string;
}

export { DropAccessCoordinator, RateLimiter };

/** Everything is served under this path prefix (Worker routes: host/moho and host/moho/*) */
const BASE = "/moho";

const SECURITY_HEADERS: Record<string, string> = {
  "content-security-policy":
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "permissions-policy": "clipboard-write=(self)",
};

function withSecurityHeaders(response: Response): Response {
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) {
    headers.set(k, v);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

/** Rate-limit key: IPv4 as is, IPv6 by its /64 prefix (one subscriber usually owns a whole /64) */
function clientKey(ip: string): string {
  if (!ip.includes(":")) return ip;
  const [head, tail = ""] = ip.split("::");
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  const full = ip.includes("::") ? [...h, ...Array(8 - h.length - t.length).fill("0"), ...t] : ip.split(":");
  return full.slice(0, 4).map((x) => x.toLowerCase().replace(/^0+(?=.)/, "")).join(":") + "::/64";
}

function redirect(location: string): Response {
  return new Response(null, {
    status: 302,
    headers: { location, "cache-control": "no-store" },
  });
}

function serveAsset(path: string): Response | null {
  const asset = STATIC_ASSETS[path];
  if (!asset) return null;
  const isHtml = path.endsWith(".html");
  return withSecurityHeaders(
    new Response(asset.body, {
      headers: {
        "content-type": asset.type,
        "cache-control": isHtml
          ? "no-store"
          : path.startsWith("/assets/")
            ? "public, max-age=31536000, immutable"
            : "public, max-age=3600",
      },
    })
  );
}

function serveApp(): Response {
  return serveAsset("/index.html") ?? new Response("index.html missing", { status: 500 });
}

async function isAuthenticated(request: Request, env: Env): Promise<boolean> {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token || !env.SESSION_SECRET) return false;
  return verifySessionToken(env.SESSION_SECRET, token);
}

function rateLimiter(env: Env): DurableObjectStub {
  // all IPs share one DO instance (singleton by fixed name)
  return env.RATE_LIMITER.get(env.RATE_LIMITER.idFromName("global"));
}

async function rlCall<T>(env: Env, path: string, ip: string): Promise<T> {
  const res = await rateLimiter(env).fetch(`http://rl${path}`, {
    method: "POST",
    body: JSON.stringify({ ip }),
  });
  return (await res.json()) as T;
}

async function handleLogin(request: Request, env: Env, ip: string): Promise<Response> {
  if (!env.AUTH_USERNAME || !env.AUTH_PASSWORD_HASH || !env.SESSION_SECRET) {
    return error("auth_not_configured", 500);
  }

  let username = "";
  let password = "";
  try {
    const body = (await request.json()) as { username?: unknown; password?: unknown };
    if (typeof body.username !== "string" || typeof body.password !== "string") {
      return error("invalid_request", 400);
    }
    username = body.username.trim();
    password = body.password;
  } catch {
    return error("invalid_request", 400);
  }
  if (username.length > 128 || password.length > 256) {
    return error("invalid_credentials", 401);
  }

  // Reserve an attempt atomically before checking the password
  const attempt = await rlCall<{ allowed: boolean; retry_after?: number }>(env, "/login-attempt", ip);
  if (!attempt.allowed) {
    return json({ error: "locked", retry_after: attempt.retry_after ?? 900 }, 429);
  }

  const userOk = await safeStringEqual(username.normalize("NFC"), env.AUTH_USERNAME.normalize("NFC"));
  const passOk = await verifyPassword(password, env.AUTH_PASSWORD_HASH);

  if (!(userOk && passOk)) {
    const fail = await rlCall<{ locked: boolean; retry_after?: number; remaining?: number }>(env, "/login-fail", ip);
    if (fail.locked) {
      return json({ error: "locked", retry_after: fail.retry_after ?? 900 }, 429);
    }
    return json({ error: "invalid_credentials", remaining: fail.remaining ?? 0 }, 401);
  }

  await rlCall(env, "/login-success", ip);
  const token = await createSessionToken(env.SESSION_SECRET);
  const res = json({ ok: true });
  res.headers.append("set-cookie", sessionCookie(token, BASE));
  return res;
}

async function handleApi(request: Request, env: Env, sub: string, ip: string): Promise<Response> {
  // RATE LIMIT — all API routes, keyed by IP
  const { allowed } = await rlCall<{ allowed: boolean }>(env, "/check", ip);
  if (!allowed) {
    return error("too many requests", 429);
  }

  // HEALTH (public)
  if (sub === "/api/health") {
    return json({ ok: true });
  }

  // LOGIN / LOGOUT / SESSION
  if (sub === "/api/login" && request.method === "POST") {
    return handleLogin(request, env, ip);
  }
  if (sub === "/api/logout" && request.method === "POST") {
    const res = json({ ok: true });
    res.headers.append("set-cookie", clearSessionCookie(BASE));
    return res;
  }
  if (sub === "/api/session" && request.method === "GET") {
    return json({ authenticated: await isAuthenticated(request, env) });
  }

  // GET drop (public, through DO) — friends with the link do not need to log in
  if (sub.startsWith("/api/drops/") && request.method === "GET") {
    const id = sub.slice("/api/drops/".length);
    if (!/^[A-Za-z0-9]{1,32}$/.test(id)) {
      return error("not_found", 404);
    }

    const stub = env.DROP_COORDINATOR.get(env.DROP_COORDINATOR.idFromName(id));
    const response = await stub.fetch("http://do/consume", {
      method: "POST",
      body: JSON.stringify({ id }),
    });
    const headers = new Headers(response.headers);
    headers.set("cache-control", "no-store");
    return new Response(response.body, { status: response.status, headers });
  }

  // Everything below requires a valid session (checked server-side)
  const authed = await isAuthenticated(request, env);

  // DELETE drop (revoke via delete token)
  if (sub.startsWith("/api/drops/") && request.method === "DELETE") {
    if (!authed) return error("unauthorized", 401);

    const id = sub.slice("/api/drops/".length);
    if (!/^[A-Za-z0-9]{1,32}$/.test(id)) {
      return error("missing drop id", 400);
    }

    let delete_token: string;
    try {
      const body = (await request.json()) as { delete_token?: string };
      if (typeof body.delete_token !== "string" || !body.delete_token) {
        return error("missing delete_token", 400);
      }
      delete_token = body.delete_token;
    } catch {
      return error("invalid request body", 400);
    }

    const stub = env.DROP_COORDINATOR.get(env.DROP_COORDINATOR.idFromName(id));
    return stub.fetch("http://do/revoke", {
      method: "POST",
      body: JSON.stringify({ id, delete_token }),
    });
  }

  // CREATE DROP
  if (sub === "/api/drops" && request.method === "POST") {
    if (!authed) return error("unauthorized", 401);

    try {
      const body = await request.json();
      const data = validateCreate(body);

      if (!data) {
        return error("invalid request", 400);
      }

      const id = randomId(10);
      const deleteToken = randomToken(32);
      const deleteTokenHash = await sha256(deleteToken);

      const expireAt = new Date(Date.now() + data.ttl_seconds * 1000).toISOString();

      // store ciphertext in the drop's Durable Object
      const stub = env.DROP_COORDINATOR.get(env.DROP_COORDINATOR.idFromName(id));
      const stored = await stub.fetch("http://do/store", {
        method: "POST",
        body: JSON.stringify({ ciphertext: data.ciphertext }),
      });
      if (!stored.ok) throw new Error("store failed");

      // store metadata in D1
      await env.DB.prepare(`
        INSERT INTO drops (
          id,
          r2_key,
          kind,
          size_bytes,
          views_left,
          expire_at,
          delete_token_hash,
          paranoid
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `)
        .bind(
          id,
          `do:${id}`,
          data.kind,
          data.size_bytes,
          data.views,
          expireAt,
          deleteTokenHash,
          data.paranoid ? 1 : 0
        )
        .run();

      return json({
        id,
        delete_token: deleteToken,
      });
    } catch {
      return error("internal_error", 500);
    }
  }

  return error("not_found", 404);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const pathname = url.pathname;

    // Only serve /moho and /moho/*; anything else is not ours
    if (pathname !== BASE && !pathname.startsWith(`${BASE}/`)) {
      return new Response("not found", { status: 404 });
    }
    const sub = pathname.slice(BASE.length) || "/";
    const ip = clientKey(request.headers.get("CF-Connecting-IP") ?? "unknown");

    if (sub.startsWith("/api/")) {
      return handleApi(request, env, sub, ip);
    }

    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("method not allowed", { status: 405 });
    }

    // Static files (hashed bundles, favicon) are public
    if (sub !== "/" && sub !== "/index.html") {
      const asset = serveAsset(sub);
      if (asset) return asset;
    }

    // Public pages: shared drop links, login, security explainer
    if (sub.startsWith("/d/") || sub === "/security" || sub === "/security/") {
      return serveApp();
    }
    if (sub === "/login" || sub === "/login/") {
      if (await isAuthenticated(request, env)) return redirect(`${BASE}/`);
      return serveApp();
    }

    // Create page (and anything else) requires login
    if (sub === "/" || sub === "/index.html") {
      if (!(await isAuthenticated(request, env))) return redirect(`${BASE}/login`);
      return serveApp();
    }

    return redirect(`${BASE}/`);
  },

  async scheduled(_event: ScheduledEvent, env: Env): Promise<void> {
    // find all expired drops and purge them (D1 row + DO storage)
    const expired = await env.DB.prepare(
      `SELECT id FROM drops WHERE expire_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`
    ).all();

    if (!expired.results?.length) return;

    for (const drop of expired.results as { id: string }[]) {
      const stub = env.DROP_COORDINATOR.get(env.DROP_COORDINATOR.idFromName(drop.id));
      await stub.fetch("http://do/purge", {
        method: "POST",
        body: JSON.stringify({ id: drop.id }),
      });
    }
  },
};

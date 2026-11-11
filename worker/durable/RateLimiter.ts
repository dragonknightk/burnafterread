// worker/durable/RateLimiter.ts
//
// 1) Sliding window API rate limiter: max N requests per IP per window.
//    State is in-memory, resets if the DO is evicted (acceptable for this).
// 2) Login lockout: max LOGIN_MAX_ATTEMPTS failed logins per IP, then the IP
//    is locked for LOGIN_LOCK_MS. Persisted in DO storage so it survives
//    eviction. Attempts are counted atomically *before* the password check,
//    so parallel bursts cannot exceed the limit; a successful login resets.

const LIMIT = 20;
const WINDOW_MS = 60_000;

export const LOGIN_MAX_ATTEMPTS = 5;
export const LOGIN_LOCK_MS = 15 * 60_000;
// Account-wide cap across all IPs (defends against attackers rotating IPs).
// Trade-off: when tripped, the real user is locked out for LOGIN_LOCK_MS too.
export const LOGIN_GLOBAL_MAX_FAILS = 20;
const GLOBAL_KEY = "login-global";

interface LoginRecord {
  count: number;
  windowStart: number;
  lockedUntil: number;
}

function json(data: unknown): Response {
  return new Response(JSON.stringify(data), {
    headers: { "content-type": "application/json" },
  });
}

export class RateLimiter {
  state: DurableObjectState;
  // ip -> array of request timestamps within the current window
  private hits: Map<string, number[]> = new Map();

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/check") {
      const { ip } = (await request.json()) as { ip: string };

      const now = Date.now();
      const windowStart = now - WINDOW_MS;

      const timestamps = (this.hits.get(ip) ?? []).filter(t => t > windowStart);
      timestamps.push(now);
      this.hits.set(ip, timestamps);

      return json({ allowed: timestamps.length <= LIMIT });
    }

    // Reserve one login attempt for this IP
    if (url.pathname === "/login-attempt") {
      const { ip } = (await request.json()) as { ip: string };
      const key = `login:${ip}`;
      const now = Date.now();
      const glob = await this.state.storage.get<LoginRecord>(GLOBAL_KEY);
      if (glob && glob.lockedUntil > now) {
        return json({ allowed: false, retry_after: Math.ceil((glob.lockedUntil - now) / 1000) });
      }
      let rec = (await this.state.storage.get<LoginRecord>(key)) ?? null;

      if (rec && rec.lockedUntil > now) {
        return json({ allowed: false, retry_after: Math.ceil((rec.lockedUntil - now) / 1000) });
      }
      if (!rec || rec.lockedUntil !== 0 || now - rec.windowStart > LOGIN_LOCK_MS) {
        rec = { count: 0, windowStart: now, lockedUntil: 0 };
      }
      if (rec.count >= LOGIN_MAX_ATTEMPTS) {
        rec.lockedUntil = now + LOGIN_LOCK_MS;
        await this.state.storage.put(key, rec);
        return json({ allowed: false, retry_after: Math.ceil(LOGIN_LOCK_MS / 1000) });
      }
      rec.count += 1;
      await this.state.storage.put(key, rec);
      return json({ allowed: true, remaining: LOGIN_MAX_ATTEMPTS - rec.count });
    }

    // Report a failed login; lock once the limit is reached
    if (url.pathname === "/login-fail") {
      const { ip } = (await request.json()) as { ip: string };
      const key = `login:${ip}`;
      const now = Date.now();
      const rec = await this.state.storage.get<LoginRecord>(key);

      // account-wide failure counter
      let glob = (await this.state.storage.get<LoginRecord>(GLOBAL_KEY)) ?? null;
      if (!glob || glob.lockedUntil !== 0 || now - glob.windowStart > LOGIN_LOCK_MS) {
        glob = { count: 0, windowStart: now, lockedUntil: 0 };
      }
      glob.count += 1;
      if (glob.count >= LOGIN_GLOBAL_MAX_FAILS) glob.lockedUntil = now + LOGIN_LOCK_MS;
      await this.state.storage.put(GLOBAL_KEY, glob);
      if (glob.lockedUntil > now) {
        return json({ locked: true, retry_after: Math.ceil(LOGIN_LOCK_MS / 1000) });
      }

      if (rec && rec.count >= LOGIN_MAX_ATTEMPTS && rec.lockedUntil <= now) {
        rec.lockedUntil = now + LOGIN_LOCK_MS;
        await this.state.storage.put(key, rec);
        return json({ locked: true, retry_after: Math.ceil(LOGIN_LOCK_MS / 1000) });
      }
      return json({ locked: false, remaining: rec ? Math.max(0, LOGIN_MAX_ATTEMPTS - rec.count) : LOGIN_MAX_ATTEMPTS });
    }

    if (url.pathname === "/login-success") {
      const { ip } = (await request.json()) as { ip: string };
      await this.state.storage.delete(`login:${ip}`);
      return json({ ok: true });
    }

    return new Response("not found", { status: 404 });
  }
}

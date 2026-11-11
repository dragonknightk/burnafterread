// worker/lib/auth.ts
//
// Single-account login for the private beta.
// - Username and password hash live in Worker secrets (never in the repo)
// - Password hash format: pbkdf2-sha256$<iterations>$<salt b64url>$<hash b64url>
// - Session cookie: <expiry ms>.<HMAC-SHA256 b64url>, signed with SESSION_SECRET

import { base64Url } from "./ids";

export const SESSION_COOKIE = "moho_session";
export const SESSION_TTL_SECONDS = 30 * 24 * 3600;

const enc = new TextEncoder();

function fromBase64Url(input: string): Uint8Array {
  const b64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64.padEnd(Math.ceil(b64.length / 4) * 4, "=");
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function sha256Bytes(input: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(input)));
}

/** Constant-time string compare (hash both sides first so length does not leak) */
export async function safeStringEqual(a: string, b: string): Promise<boolean> {
  const [ha, hb] = await Promise.all([sha256Bytes(a), sha256Bytes(b)]);
  return timingSafeEqualBytes(ha, hb);
}

export async function pbkdf2(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", enc.encode(password.normalize("NFC")), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations },
    key,
    256
  );
  return new Uint8Array(bits);
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2-sha256") return false;
  const iterations = Number(parts[1]);
  if (!Number.isInteger(iterations) || iterations < 1 || iterations > 100_000) return false;
  const salt = fromBase64Url(parts[2]);
  const expected = fromBase64Url(parts[3]);
  const actual = await pbkdf2(password, salt, iterations);
  return timingSafeEqualBytes(actual, expected);
}

async function hmac(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return base64Url(new Uint8Array(sig));
}

export async function createSessionToken(secret: string, now = Date.now()): Promise<string> {
  const exp = now + SESSION_TTL_SECONDS * 1000;
  const sig = await hmac(secret, `v1|${exp}`);
  return `${exp}.${sig}`;
}

export async function verifySessionToken(secret: string, token: string, now = Date.now()): Promise<boolean> {
  const dot = token.indexOf(".");
  if (dot <= 0) return false;
  const expStr = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  if (!/^\d{1,16}$/.test(expStr)) return false;
  const exp = Number(expStr);
  if (exp < now) return false;
  const expected = await hmac(secret, `v1|${exp}`);
  return safeStringEqual(sig, expected);
}

export function getCookie(request: Request, name: string): string | null {
  const header = request.headers.get("cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() === name) return part.slice(idx + 1).trim();
  }
  return null;
}

export function sessionCookie(token: string, basePath: string): string {
  return `${SESSION_COOKIE}=${token}; Path=${basePath}; Max-Age=${SESSION_TTL_SECONDS}; HttpOnly; Secure; SameSite=Strict`;
}

export function clearSessionCookie(basePath: string): string {
  return `${SESSION_COOKIE}=; Path=${basePath}; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
}

# moho deployment (dragonknightk.com/moho)

Fork of [casablanque-code/burnafterread](https://github.com/casablanque-code/burnafterread) deployed at
**https://dragonknightk.com/moho** as a private beta.

## Changes vs upstream

- **Path prefix**: everything (pages, `/api/*`, share links `/moho/d/<id>`) lives under `/moho`.
  Worker routes: `dragonknightk.com/moho` and `dragonknightk.com/moho/*`; other paths of the domain are untouched.
  The built frontend is embedded into the Worker (`scripts/embed-assets.mjs`), so no assets binding is needed.
- **Single-account login** (`worker/lib/auth.ts`):
  - Username and PBKDF2-SHA256 password hash are Worker secrets (`AUTH_USERNAME`, `AUTH_PASSWORD_HASH`), never in the repo.
    Generate the hash with `node scripts/hash-password.mjs` (reads the password from stdin).
  - Session cookie `moho_session` = expiry + HMAC-SHA256 (secret `SESSION_SECRET`), `HttpOnly; Secure; SameSite=Strict; Path=/moho`, 7 days.
  - Login required (checked in the Worker): create page `/moho/`, `POST /moho/api/drops`, `DELETE /moho/api/drops/:id`.
  - Public: `/moho/login`, `/moho/d/:id` (share links), `GET /moho/api/drops/:id`, `/moho/security`, static files.
- **Brute-force protection** (`worker/durable/RateLimiter.ts`): 5 failed logins per IP (IPv6 per /64) lock that IP for 15 min;
  20 failed logins account-wide within 15 min lock all logins for 15 min (defends against IP rotation).
- **No R2**: ciphertext is stored (chunked) in the per-drop `DropAccessCoordinator` Durable Object instead of an R2 bucket.
  Burn-after-reading, view limits, revoke and hourly expiry cleanup (cron) behave as upstream.
- **UI**: Chinese by default with a 中/EN toggle (top-right, remembered in `localStorage`).
- `workers_dev: false`, `preview_urls: false`.

## Deploy

```sh
npm ci
npm run build
npx wrangler secret put AUTH_USERNAME
node scripts/hash-password.mjs | npx wrangler secret put AUTH_PASSWORD_HASH
npx wrangler secret put SESSION_SECRET   # long random string; changing it logs everyone out
npx wrangler deploy
```

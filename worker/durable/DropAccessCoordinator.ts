// worker/durable/DropAccessCoordinator.ts

//
// Ciphertext is stored in this Durable Object's own storage (chunked), not in
// R2, so the deployment needs no R2 bucket. One DO instance per drop id.

interface Env {
  DB: D1Database;
}

// SQLite-backed DO storage allows values up to 2 MB; stay well below
const CHUNK_CHARS = 1_000_000;

interface DropRow {
  id: string;
  r2_key: string;
  kind: string;
  expire_at: string;
  views_left: number;
  paranoid: number; // 0 | 1 in SQLite
  delete_token_hash: string;
}

export class DropAccessCoordinator {
  state: DurableObjectState;
  env: Env;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/store") {
      const body = (await request.json()) as { ciphertext: string };
      const chunks: Record<string, string> = {};
      let n = 0;
      for (let i = 0; i < body.ciphertext.length; i += CHUNK_CHARS) {
        chunks[`c${n}`] = body.ciphertext.slice(i, i + CHUNK_CHARS);
        n++;
      }
      chunks.n = String(n);
      await this.state.storage.put(chunks);
      return new Response(JSON.stringify({ ok: true }), {
        headers: { "content-type": "application/json" },
      });
    }

    if (url.pathname === "/purge") {
      const body = (await request.json()) as { id: string };
      await this.env.DB.prepare(`DELETE FROM drops WHERE id = ?`).bind(body.id).run();
      await this.state.storage.deleteAll();
      return new Response(JSON.stringify({ ok: true }), {
        headers: { "content-type": "application/json" },
      });
    }

    if (url.pathname === "/consume") {
      const body = (await request.json()) as { id: string };
      const id = body.id;

      return this.state.blockConcurrencyWhile(async () => {
        const drop = await this.env.DB.prepare(
          `SELECT * FROM drops WHERE id = ?`
        )
          .bind(id)
          .first<DropRow>();

        if (!drop) {
          return new Response(JSON.stringify({ error: "not_found" }), {
            status: 404,
            headers: { "content-type": "application/json" },
          });
        }

        const expireTime = new Date(drop.expire_at).getTime();
        if (expireTime < Date.now()) {
          await this.deleteDrop(drop);

          if (drop.paranoid) {
            return new Response(JSON.stringify({ error: "not_found" }), { status: 404 });
          }

          return new Response(JSON.stringify({ error: "expired" }), { status: 410 });
        }

        if (drop.views_left <= 0) {
          if (drop.paranoid) {
            return new Response(JSON.stringify({ error: "not_found" }), { status: 404 });
          }

          return new Response(JSON.stringify({ error: "burned" }), { status: 410 });
        }

        const newViews = drop.views_left - 1;

        await this.env.DB.prepare(
          `UPDATE drops SET views_left = ? WHERE id = ?`
        )
          .bind(newViews, id)
          .run();

        const ciphertext = await this.readBlob();

        if (ciphertext === null) {
          return new Response(JSON.stringify({ error: "missing_blob" }), {
            status: 500,
            headers: { "content-type": "application/json" },
          });
        }

        if (drop.paranoid) {
          await this.deleteDrop(drop);
        } else if (newViews <= 0) {
          await this.deleteDrop(drop);
        }

        return new Response(
          JSON.stringify({ ciphertext, kind: drop.kind }),
          { headers: { "content-type": "application/json" } }
        );
      });
    }

    if (url.pathname === "/revoke") {
      const body = (await request.json()) as { id: string; delete_token: string };
      const { id, delete_token } = body;

      if (!id || !delete_token) {
        return new Response(JSON.stringify({ error: "invalid_request" }), {
          status: 400,
          headers: { "content-type": "application/json" },
        });
      }

      return this.state.blockConcurrencyWhile(async () => {
        const drop = await this.env.DB.prepare(
          `SELECT * FROM drops WHERE id = ?`
        )
          .bind(id)
          .first<DropRow>();

        if (!drop) {
          return new Response(JSON.stringify({ error: "not_found" }), {
            status: 404,
            headers: { "content-type": "application/json" },
          });
        }

        const providedHash = await this.sha256(delete_token);

        if (!this.timingSafeEqual(providedHash, drop.delete_token_hash)) {
          return new Response(JSON.stringify({ error: "forbidden" }), {
            status: 403,
            headers: { "content-type": "application/json" },
          });
        }

        await this.deleteDrop(drop);

        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      });
    }

    return new Response("not found", { status: 404 });
  }

  private async sha256(input: string): Promise<string> {
    const data = new TextEncoder().encode(input);
    const hash = await crypto.subtle.digest("SHA-256", data);
    return btoa(String.fromCharCode(...new Uint8Array(hash)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  private timingSafeEqual(a: string, b: string): boolean {
    const enc = new TextEncoder();
    const ab = enc.encode(a);
    const bb = enc.encode(b);
    if (ab.length !== bb.length) return false;
    let diff = 0;
    for (let i = 0; i < ab.length; i++) {
      diff |= ab[i] ^ bb[i];
    }
    return diff === 0;
  }

  private async readBlob(): Promise<string | null> {
    const nStr = await this.state.storage.get<string>("n");
    if (!nStr) return null;
    const n = Number(nStr);
    const keys = Array.from({ length: n }, (_, i) => `c${i}`);
    const map = await this.state.storage.get<string>(keys);
    let out = "";
    for (const k of keys) {
      const part = map.get(k);
      if (part === undefined) return null;
      out += part;
    }
    return out;
  }

  async deleteDrop(drop: DropRow): Promise<void> {
    await this.env.DB.prepare(`DELETE FROM drops WHERE id = ?`)
      .bind(drop.id)
      .run();

    await this.state.storage.deleteAll();
  }
}

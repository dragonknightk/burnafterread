// src/App.tsx

import { useMemo, useState } from "react";
import "./App.css";
import { BASE, errorText, useI18n } from "./i18n";
import {
  decodeKeyFromUrl,
  decryptBytes,
  decryptText,
  encodeKeyForUrl,
  encryptBytes,
  encryptText,
  generateKeyBytes,
  type EncryptedPayloadV1,
} from "./lib/crypto";

type Mode = "create" | "read";
type CreateKind = "text" | "file";

interface CreateResponse {
  id: string;
  delete_token: string;
}

interface ReadResponse {
  ciphertext: string;
  kind: "text" | "file";
}

interface FilePayloadV1 {
  v: 1;
  type: "file";
  filename: string;
  mime: string;
  iv: string;
  data: string;
}

function stripBase(pathname: string): string {
  return pathname.startsWith(BASE) ? pathname.slice(BASE.length) || "/" : pathname;
}

function getModeFromLocation(pathname: string): Mode {
  return stripBase(pathname).startsWith("/d/") ? "read" : "create";
}

function getDropIdFromPath(pathname: string): string | null {
  const parts = stripBase(pathname).split("/").filter(Boolean);
  if (parts.length === 2 && parts[0] === "d") {
    return parts[1];
  }
  return null;
}

function getKeyFromHash(hash: string): string | null {
  if (!hash.startsWith("#")) return null;

  const fragment = hash.slice(1);
  const params = new URLSearchParams(fragment);
  return params.get("k");
}

function App() {
  const { tr } = useI18n();
  const mode = useMemo(() => getModeFromLocation(window.location.pathname), []);
  const dropId = useMemo(() => getDropIdFromPath(window.location.pathname), []);
  const fragmentKey = useMemo(() => getKeyFromHash(window.location.hash), []);

  const [text, setText] = useState("");
  const [ttlSeconds, setTtlSeconds] = useState(86400);
  const [views, setViews] = useState(1);
  const [paranoid, setParanoid] = useState(true);
  const [file, setFile] = useState<File | null>(null);

  const [revoking, setRevoking] = useState(false);
  const [revokeError, setRevokeError] = useState("");
  const [revoked, setRevoked] = useState(false);
  const [creating, setCreating] = useState(false);

  async function handleRevoke() {
    if (!createdLink || !deleteToken) return;

    const id = createdLink.split("/d/")[1]?.split("#")[0];
    if (!id) return;

    setRevoking(true);
    setRevokeError("");

    try {
      const response = await fetch(`${BASE}/api/drops/${id}`, {
        method: "DELETE",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ delete_token: deleteToken }),
      });

      if (response.status === 401) {
        window.location.href = `${BASE}/login`;
        return;
      }
      if (!response.ok) {
        const maybeError = await response.json().catch(() => null);
        throw new Error(errorText(maybeError?.error, tr));
      }

      setRevoked(true);
      setCreatedLink("");
      setDeleteToken("");
    } catch (err) {
      setRevokeError(err instanceof Error ? err.message : tr("未知错误", "Unknown error"));
    } finally {
      setRevoking(false);
    }
  }
  const [createdLink, setCreatedLink] = useState("");
  const [deleteToken, setDeleteToken] = useState("");
  const [createError, setCreateError] = useState("");

  const [reading, setReading] = useState(false);
  const [readText, setReadText] = useState("");
  const [readError, setReadError] = useState("");
  const [readFileInfo, setReadFileInfo] = useState<string>("");

  async function handleCreate() {
    setCreateError("");
    setCreatedLink("");
    setDeleteToken("");

    if (!file && !text.trim()) {
      setCreateError(tr("请输入文字或选择一个文件", "Enter some text or select a file"));
      return;
    }

    try {
      setCreating(true);

      const rawKey = generateKeyBytes();

      let ciphertext = "";
      let kind: CreateKind = "text";
      let sizeBytes = 0;

      if (file) {
        kind = "file";

        const buffer = await file.arrayBuffer();
        const encrypted = await encryptBytes(buffer, rawKey);

        const payload: FilePayloadV1 = {
          v: 1,
          type: "file",
          filename: file.name,
          mime: file.type || "application/octet-stream",
          iv: encrypted.iv,
          data: encrypted.data,
        };

        ciphertext = JSON.stringify(payload);
        sizeBytes = buffer.byteLength;
      } else {
        kind = "text";

        const encryptedPayload = await encryptText(text, rawKey);

        ciphertext = JSON.stringify({
          ...encryptedPayload,
          type: "text",
        });

        sizeBytes = new TextEncoder().encode(text).length;
      }

      const response = await fetch(`${BASE}/api/drops`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          ciphertext,
          ttl_seconds: ttlSeconds,
          views,
          kind,
          size_bytes: sizeBytes,
          paranoid,
        }),
      });

      if (response.status === 401) {
        window.location.href = `${BASE}/login`;
        return;
      }
      if (!response.ok) {
        const maybeError = await response.json().catch(() => null);
        throw new Error(errorText(maybeError?.error, tr));
      }

      const data = (await response.json()) as CreateResponse;
      const encodedKey = encodeKeyForUrl(rawKey);
      const link = `${window.location.origin}${BASE}/d/${data.id}#k=${encodedKey}`;

      setCreatedLink(link);
      setDeleteToken(data.delete_token);

      try {
        await navigator.clipboard.writeText(link);
      } catch {
        // ignore clipboard errors
      }
    } catch (error) {
      setCreateError(error instanceof Error ? error.message : tr("未知错误", "Unknown error"));
    } finally {
      setCreating(false);
    }
  }

  async function handleLogout() {
    try {
      await fetch(`${BASE}/api/logout`, { method: "POST" });
    } finally {
      window.location.href = `${BASE}/login`;
    }
  }

  async function handleRead() {
    setReadError("");
    setReadText("");
    setReadFileInfo("");

    if (!dropId) {
      setReadError(tr("链接缺少 ID", "Missing drop id"));
      return;
    }

    if (!fragmentKey) {
      setReadError(tr("链接缺少解密密钥 (#k=...)", "Missing key in URL fragment"));
      return;
    }

    if (!/^[A-Za-z0-9_-]{43}$/.test(fragmentKey)) {
      setReadError(tr("链接里的密钥格式不对", "Invalid key format in URL"));
      return;
    }

    try {
      setReading(true);

      const response = await fetch(`${BASE}/api/drops/${dropId}`, {
        method: "GET",
        headers: {
          "cache-control": "no-store",
        },
      });

      if (!response.ok) {
        const maybeError = await response.json().catch(() => null);
        throw new Error(errorText(maybeError?.error, tr));
      }

      const data = (await response.json()) as ReadResponse;
      const payload = JSON.parse(data.ciphertext) as
        | (EncryptedPayloadV1 & { type?: "text" })
        | FilePayloadV1;

      const rawKey = decodeKeyFromUrl(fragmentKey);

      if (payload.type === "file") {
        const buffer = await decryptBytes(payload, rawKey);
        const blob = new Blob([buffer], {
          type: payload.mime || "application/octet-stream",
        });

        const fileUrl = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = fileUrl;
        a.download = payload.filename || "download";
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(fileUrl);

        setReadFileInfo(`${tr("已下载", "Downloaded")}: ${payload.filename}`);
      } else {
        const plaintext = await decryptText(payload as EncryptedPayloadV1, rawKey);
        setReadText(plaintext);
      }
    } catch (error) {
      setReadError(error instanceof Error && error.name !== "OperationError" ? error.message : tr("解密失败, 密钥不对或内容被篡改", "Decryption failed, wrong key or tampered data"));
    } finally {
      setReading(false);
    }
  }

  if (mode === "read") {
    return (
      <main className="page">
        <section className="card">
          <div className="eyebrow">BurnAfterRead</div>
          <h1>{tr("查看加密消息", "Read secure drop")}</h1>
          <p className="muted">
            {tr("解密密钥只在链接 # 后面, 服务器永远拿不到. 内容打开一次后即销毁", "The server never receives the decryption key. It stays in the URL fragment")}
          </p>

          <div className="meta">
            <div>
              <span className="metaLabel">{tr("消息 ID", "Drop ID")}</span>
              <code>{dropId ?? tr("缺失", "missing")}</code>
            </div>
            <div>
              <span className="metaLabel">{tr("链接内密钥", "Key in URL")}</span>
              <code>{fragmentKey ? tr("有", "present") : tr("缺失", "missing")}</code>
            </div>
          </div>

          <div className="actions">
            <button onClick={handleRead} disabled={reading}>
              {reading ? tr("解密中...", "Decrypting...") : tr("打开并解密", "Open and decrypt")}
            </button>
          </div>

          {readError ? <div className="error">{readError}</div> : null}

          {readText ? (
            <div className="resultBlock">
              <div className="resultLabel">{tr("解密后的内容", "Decrypted message")}</div>
              <pre className="plaintextBox">{readText}</pre>
            </div>
          ) : null}

          {readFileInfo ? (
            <div className="resultBlock">
              <div className="resultLabel">{tr("文件", "File")}</div>
              <div>{readFileInfo}</div>
            </div>
          ) : null}
        </section>
      </main>
    );
  }

  return (
    <main className="page">
      <section className="card">
        <div className="eyebrowRow">
          <div className="eyebrow">BurnAfterRead</div>
          <button type="button" className="linkButton" onClick={handleLogout}>{tr("退出登录", "Log out")}</button>
        </div>
        <h1>{tr("创建阅后即焚", "Create secure drop")}</h1>
        <p className="muted">
          {tr("文字和文件在你的浏览器里加密后才上传, 服务器看不到内容", "Text and files are encrypted in your browser before upload. We can't read them")}{' '}
          <a href={`${BASE}/security`} style={{ color: 'var(--accent)', textDecoration: 'none' }}>{tr("原理说明", "How it works")} &rarr;</a>
        </p>

        <label className="fieldLabel" htmlFor="secretText">
          {tr("秘密文字", "Secret text")}
        </label>
        <textarea
          id="secretText"
          className="textarea"
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder={tr("粘贴密码, 配置, 笔记或任何敏感内容...", "Paste a password, config, token, note, or anything sensitive...")}
          rows={6}
          disabled={!!file}
        />

        <label className="fieldLabel" style={{ marginTop: 18 }}>
          {tr("文件", "File")} <span style={{ color: "var(--muted)", fontWeight: 400 }}>{tr("(可选, 最大 5 MB)", "(optional, max 5 MB)")}</span>
        </label>
        <label
          className={`dropZone${file ? " dropZone--filled" : ""}${text.trim() ? " dropZone--disabled" : ""}`}
          onDragOver={(e) => { e.preventDefault(); e.currentTarget.classList.add("dropZone--over"); }}
          onDragLeave={(e) => { e.currentTarget.classList.remove("dropZone--over"); }}
          onDrop={(e) => {
            e.preventDefault();
            e.currentTarget.classList.remove("dropZone--over");
            if (text.trim()) return;
            const dropped = e.dataTransfer.files?.[0];
            if (!dropped) return;
            if (dropped.size > 5 * 1024 * 1024) { alert(tr("文件最大 5 MB", "Max file size is 5 MB")); return; }
            setFile(dropped);
            setText("");
          }}
        >
          <input
            id="fileInput"
            type="file"
            style={{ display: "none" }}
            disabled={text.trim().length > 0}
            onChange={(e) => {
              const selected = e.target.files?.[0] || null;
              if (!selected) { setFile(null); return; }
              if (selected.size > 5 * 1024 * 1024) {
                alert(tr("文件最大 5 MB", "Max file size is 5 MB"));
                e.currentTarget.value = "";
                setFile(null);
                return;
              }
              setFile(selected);
              setText("");
            }}
          />
          {file ? (
            <div className="dropZone__file">
              <span className="dropZone__icon">📄</span>
              <div className="dropZone__info">
                <span className="dropZone__name">{file.name}</span>
                <span className="dropZone__size">{(file.size / 1024).toFixed(1)} KB</span>
              </div>
              <button
                type="button"
                className="dropZone__remove"
                onClick={(e) => { e.preventDefault(); setFile(null); }}
                title={tr("移除文件", "Remove file")}
              >✕</button>
            </div>
          ) : (
            <div className="dropZone__empty">
              <span className="dropZone__icon">⬆</span>
              <span className="dropZone__hint">
                {text.trim() ? tr("清空文字后才能附加文件", "Clear text to attach a file") : tr("拖入文件或点击选择", "Drop file here or click to browse")}
              </span>
            </div>
          )}
        </label>

        <div className="grid">
          <div className="field">
            <label className="fieldLabel" htmlFor="ttl">
              {tr("有效期", "TTL")}
            </label>
            <select
              id="ttl"
              className="select"
              value={ttlSeconds}
              onChange={(e) => setTtlSeconds(Number(e.target.value))}
            >
              <option value={3600}>{tr("1 小时", "1 hour")}</option>
              <option value={86400}>{tr("24 小时", "24 hours")}</option>
              <option value={604800}>{tr("7 天", "7 days")}</option>
            </select>
          </div>

          <div className="field">
            <label className="fieldLabel" htmlFor="views">
              {tr("可查看次数", "Views")}
            </label>
            <select
              id="views"
              className="select"
              value={views}
              onChange={(e) => setViews(Number(e.target.value))}
            >
              <option value={1}>1</option>
              <option value={3}>3</option>
              <option value={10}>10</option>
            </select>
          </div>
        </div>

        <label className="toggleRow">
          <input
            type="checkbox"
            checked={paranoid}
            onChange={(e) => setParanoid(e.target.checked)}
          />
          <span>{tr("偏执模式 (首次打开即销毁, 不提示是否存在)", "Paranoid mode")}</span>
        </label>

        <div className="actions">
          <button onClick={handleCreate} disabled={creating}>
            {creating ? tr("加密中...", "Encrypting...") : tr("生成加密链接", "Create secure link")}
          </button>
        </div>

        {createError ? <div className="error">{createError}</div> : null}

        {createdLink ? (
          <div className="resultBlock">
            <div className="resultLabel">{tr("加密链接", "Secure link")}</div>
            <textarea className="linkBox" readOnly value={createdLink} rows={3} />

            <div className="inlineButtons">
              <button
                type="button"
                className="secondaryButton"
                onClick={async () => {
                  try {
                    await navigator.clipboard.writeText(createdLink);
                  } catch {
                    // ignore
                  }
                }}
              >
                {tr("复制链接", "Copy link")}
              </button>

              <button
                type="button"
                className="secondaryButton"
                onClick={() => {
                  window.open(createdLink, "_blank", "noopener,noreferrer");
                }}
              >
                {tr("打开链接", "Open link")}
              </button>
            </div>

            <div className="resultLabel">{tr("撤回凭证", "Delete token")}</div>
            <textarea className="linkBox" readOnly value={deleteToken} rows={2} />

            <div className="inlineButtons" style={{ marginTop: 12 }}>
              <button
                type="button"
                className="secondaryButton"
                onClick={handleRevoke}
                disabled={revoking}
                style={{ color: "var(--color-danger, #c0392b)" }}
              >
                {revoking ? tr("撤回中...", "Revoking...") : tr("撤回消息", "Revoke drop")}
              </button>
            </div>

            {revokeError ? <div className="error">{revokeError}</div> : null}
          </div>
        ) : null}

        {revoked ? (
          <div className="resultBlock">
            <div className="resultLabel">{tr("已撤回", "Drop revoked")}</div>
            <div className="muted">{tr("内容已删除, 链接已失效", "The drop has been deleted and the link is no longer valid")}</div>
          </div>
        ) : null}
      </section>
    </main>
  );
}

export default App;
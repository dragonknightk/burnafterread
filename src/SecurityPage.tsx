// src/SecurityPage.tsx
//
// Self-contained security verification page.
// All crypto runs in the browser via Web Crypto API.
// No network requests are made on this page.

import { useState, useCallback } from "react";
import "./App.css";
import "./SecurityPage.css";
import { BASE, useI18n } from "./i18n";

// ─── Inline crypto (copy of src/lib/crypto.ts core, visible to user) ──────────

function base64urlEncode(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64urlDecode(str: string): Uint8Array<ArrayBuffer> {
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64.padEnd(Math.ceil(b64.length / 4) * 4, "=");
  const binary = atob(padded);
  const buf = new ArrayBuffer(binary.length);
  const view = new Uint8Array(buf);
  for (let i = 0; i < binary.length; i++) view[i] = binary.charCodeAt(i);
  return view as Uint8Array<ArrayBuffer>;
}

async function generateKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt",
  ]);
}

async function exportKeyBase64url(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey("raw", key);
  return base64urlEncode(raw as ArrayBuffer);
}

interface DemoPayload {
  v: 1;
  alg: "AES-GCM";
  iv: string;
  data: string;
}

async function demoEncrypt(
  plaintext: string,
  key: CryptoKey
): Promise<DemoPayload> {
  const ivBuf = new ArrayBuffer(12);
  crypto.getRandomValues(new Uint8Array(ivBuf));
  const enc = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: ivBuf },
    key,
    enc.encode(plaintext)
  );
  return {
    v: 1,
    alg: "AES-GCM",
    iv: base64urlEncode(ivBuf),
    data: base64urlEncode(ciphertext as ArrayBuffer),
  };
}

async function demoDecrypt(
  payload: DemoPayload,
  key: CryptoKey
): Promise<string> {
  const iv = base64urlDecode(payload.iv);
  const data = base64urlDecode(payload.data);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv.buffer as ArrayBuffer },
    key,
    data.buffer as ArrayBuffer
  );
  return new TextDecoder().decode(plain);
}

// ─── Component ────────────────────────────────────────────────────────────────

type DemoState = "idle" | "encrypted" | "decrypted" | "error";

export default function SecurityPage() {
  const { tr } = useI18n();
  const [input, setInput] = useState("");
  const [keyB64, setKeyB64] = useState("");
  const [payload, setPayload] = useState<DemoPayload | null>(null);
  const [decrypted, setDecrypted] = useState("");
  const [demoState, setDemoState] = useState<DemoState>("idle");
  const [errorMsg, setErrorMsg] = useState("");
  const [currentKey, setCurrentKey] = useState<CryptoKey | null>(null);

  const handleEncrypt = useCallback(async () => {
    try {
      const key = await generateKey();
      const encoded = await exportKeyBase64url(key);
      const result = await demoEncrypt(input, key);
      setKeyB64(encoded);
      setPayload(result);
      setCurrentKey(key);
      setDecrypted("");
      setDemoState("encrypted");
      setErrorMsg("");
    } catch (e) {
      setErrorMsg(String(e));
      setDemoState("error");
    }
  }, [input]);

  const handleDecrypt = useCallback(async () => {
    if (!payload || !currentKey) return;
    try {
      const result = await demoDecrypt(payload, currentKey);
      setDecrypted(result);
      setDemoState("decrypted");
      setErrorMsg("");
    } catch {
      setErrorMsg(tr("GCM 校验失败, 密文已被篡改", "GCM authentication failed — ciphertext has been tampered with"));
      setDemoState("error");
    }
  }, [payload, currentKey, tr]);

  const handleTamper = useCallback(() => {
    if (!payload) return;
    const data = payload.data;
    const tampered = data.slice(0, -4) + (data.endsWith("AAAA") ? "ZZZZ" : "AAAA");
    setPayload({ ...payload, data: tampered });
    setDecrypted("");
    setDemoState("encrypted");
  }, [payload]);

  return (
    <div className="secPage">
      <div className="secContent">

        {/* Header */}
        <header className="secHeader">
          <a href={`${BASE}/`} className="secBack">← {tr("返回", "Back to app")}</a>
          <div className="eyebrow">{tr("安全", "Security")}</div>
          <h1>{tr("自己动手验证", "Verify it yourself")}</h1>
          <p className="secLead">
            {tr("本站是端到端加密的. 这一页用在你浏览器里实时运行的代码演示加密过程, 不发任何网络请求, 可以打开开发者工具的 Network 面板确认", "burnafterread is end-to-end encrypted. This page shows exactly how — with live code running in your browser. No network requests are made here. Open DevTools → Network tab to confirm.")}
          </p>
        </header>

        {/* How it works */}
        <section className="secSection">
          <h2>{tr("加密原理", "How the encryption works")}</h2>

          <div className="secSteps">
            <div className="secStep">
              <span className="secStepNum">1</span>
              <div>
                <strong>{tr("生成密钥", "Key generation")}</strong>
                <p>{tr("浏览器用 ", "A 256-bit random key is generated in your browser using ")}<code>crypto.subtle.generateKey</code>{tr(" 生成一把 256 位随机密钥, 它不会离开你的设备", ". It never leaves your device.")}</p>
              </div>
            </div>
            <div className="secStep">
              <span className="secStepNum">2</span>
              <div>
                <strong>{tr("加密", "Encryption")}</strong>
                <p>{tr("内容用 AES-GCM 256 加随机 12 字节 IV 加密. GCM 同时保证保密和完整, 被篡改的密文无法解密", "Your text is encrypted with AES-GCM 256 using a random 12-byte IV. GCM provides both confidentiality and authenticity — tampered ciphertext cannot be decrypted.")}</p>
              </div>
            </div>
            <div className="secStep">
              <span className="secStepNum">3</span>
              <div>
                <strong>{tr("上传", "Upload")}</strong>
                <p>{tr("只有密文会发给服务器. 密钥留在浏览器里, 作为链接的 # 片段 (", "Only the ciphertext is sent to the server. The key stays in your browser and is appended to the share link as a URL fragment (")}<code>#k=…</code>{tr(") 附在分享链接后面", ").")}</p>
              </div>
            </div>
            <div className="secStep">
              <span className="secStepNum">4</span>
              <div>
                <strong>{tr("为什么服务器拿不到密钥", "Why the server never sees the key")}</strong>
                <p>{tr("浏览器发 HTTP 请求时不会带上 # 后面的部分, 这是 ", "URL fragments are never sent in HTTP requests — this is defined in ")}<a href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.3" target="_blank" rel="noreferrer">RFC 9110 §4.2.3</a>{tr(" 规定的. 打开开发者工具的 Network 面板再打开链接, 可以看到每个请求里都没有 #k=…", ". Open DevTools → Network, open a drop link, and confirm: the #k=… part is absent from every request.")}</p>
              </div>
            </div>
            <div className="secStep">
              <span className="secStepNum">5</span>
              <div>
                <strong>{tr("自动销毁", "Self-destruct")}</strong>
                <p>{tr("达到查看次数后, D1 里的元数据和 Durable Object 里的密文都会被永久删除, 服务器想给也给不出来", "After the allowed number of views, both the D1 metadata record and the stored ciphertext are permanently deleted. The server cannot serve what it no longer has.")}</p>
              </div>
            </div>
          </div>
        </section>

        {/* Live demo */}
        <section className="secSection">
          <h2>{tr("实时加密演示", "Live encryption demo")}</h2>
          <p className="secSectionLead">
            {tr("演示完全在你的浏览器里运行, 代码就在这一页, 可以在开发者工具的 Sources 面板里查看", "This demo runs entirely in your browser. The code is on this page — view source or open DevTools → Sources.")}
          </p>

          <div className="demoCard">
            <label className="fieldLabel">{tr("明文", "Plaintext")}</label>
            <textarea
              className="textarea"
              rows={3}
              placeholder={tr("在这里输入一段秘密...", "Type something secret here...")}
              value={input}
              onChange={(e) => {
                setInput(e.target.value);
                setDemoState("idle");
                setPayload(null);
                setKeyB64("");
                setDecrypted("");
              }}
            />

            <div className="demoActions">
              <button onClick={handleEncrypt}>
                🔐 {tr("在浏览器里加密", "Encrypt in browser")}
              </button>
              {payload && (
                <>
                  <button className="secondaryButton" onClick={handleTamper}>
                    ✂️ {tr("篡改密文", "Tamper with ciphertext")}
                  </button>
                  <button className="secondaryButton" onClick={handleDecrypt}>
                    🔓 {tr("解密", "Decrypt")}
                  </button>
                </>
              )}
            </div>

            {demoState !== "idle" && (
              <div className="demoResults">
                {keyB64 && (
                  <div className="demoField">
                    <span className="demoLabel">{tr("AES-256 密钥 (Base64url, 32 字节)", "AES-256 key (Base64url, 32 bytes)")}</span>
                    <span className="demoNote">{tr("就是分享链接里 #k= 后面的值, 服务器永远看不到", "This is the value after #k= in the share URL. The server never sees this.")}</span>
                    <code className="demoCode demoKey">{keyB64}</code>
                  </div>
                )}

                {payload && (
                  <>
                    <div className="demoField">
                      <span className="demoLabel">{tr("IV (12 字节, 每次加密随机生成)", "IV (12 bytes, random per encryption)")}</span>
                      <code className="demoCode">{payload.iv}</code>
                    </div>
                    <div className="demoField">
                      <span className="demoLabel">{tr("密文 + GCM 校验标签 (服务器存的就是这个)", "Ciphertext + GCM auth tag (what the server stores)")}</span>
                      <span className="demoNote">{tr("点上面的「篡改密文」改掉最后 4 个字符, 看 GCM 校验如何拒绝它", "Click \"Tamper\" above to flip the last 4 bytes and see GCM authentication reject it.")}</span>
                      <code className="demoCode demoBreak">{payload.data}</code>
                    </div>
                  </>
                )}

                {demoState === "decrypted" && (
                  <div className="demoField demoSuccess">
                    <span className="demoLabel">✓ {tr("解密结果", "Decrypted plaintext")}</span>
                    <code className="demoCode">{decrypted}</code>
                  </div>
                )}

                {demoState === "error" && (
                  <div className="demoField demoError">
                    <span className="demoLabel">✗ {tr("校验失败", "Authentication failed")}</span>
                    <span className="demoNote">{errorMsg}</span>
                    <span className="demoNote">{tr("GCM 发现密文被改过, 拒绝解密. 也就是说传输或存储中被改动的数据谁都读不出来", "GCM detected the tampered ciphertext and refused to decrypt. This means no one can read data that has been modified in transit or in storage.")}</span>
                  </div>
                )}
              </div>
            )}
          </div>
        </section>

        {/* What the server sees */}
        <section className="secSection">
          <h2>{tr("服务器存了什么", "What the server stores")}</h2>
          <div className="secTable">
            <div className="secTableRow secTableHeader">
              <span>{tr("数据", "Data")}</span>
              <span>{tr("位置", "Where")}</span>
              <span>{tr("服务器能读吗", "Server can read?")}</span>
            </div>
            <div className="secTableRow">
              <span>{tr("密文", "Ciphertext")}</span>
              <span>Cloudflare Durable Object</span>
              <span className="secNo">{tr("不能, 已加密", "No — encrypted")}</span>
            </div>
            <div className="secTableRow">
              <span>{tr("消息 ID, 有效期, 查看次数", "Drop ID, TTL, view count")}</span>
              <span>Cloudflare D1</span>
              <span className="secNo">{tr("只有元数据", "Metadata only")}</span>
            </div>
            <div className="secTableRow">
              <span>{tr("解密密钥", "Decryption key")}</span>
              <span>{tr("只在链接 # 片段里", "URL fragment only")}</span>
              <span className="secNo">{tr("从不发给服务器", "Never sent to server")}</span>
            </div>
            <div className="secTableRow">
              <span>{tr("你的明文", "Your plaintext")}</span>
              <span>{tr("只在你的浏览器里", "Your browser only")}</span>
              <span className="secNo">{tr("从不离开你的设备", "Never leaves your device")}</span>
            </div>
          </div>
        </section>

        {/* Verify yourself */}
        <section className="secSection">
          <h2>{tr("一步步自己验证", "Verify it yourself — step by step")}</h2>

          <div className="secVerifySteps">
            <div className="secVerifyStep">
              <h3>{tr("1. 确认密钥没离开浏览器", "1. Confirm the key never leaves your browser")}</h3>
              <ol>
                <li>{tr("打开开发者工具的 Network 面板", "Open DevTools → Network tab")}</li>
                <li>{tr("在主页创建一条消息", "Create a drop on the main page")}</li>
                <li>{tr("打开分享链接", "Open the share link")}</li>
                <li>{tr("检查每个请求, 都不会出现 #k=… 这段", "Inspect every request — the #k=… fragment will be absent from all of them")}</li>
              </ol>
            </div>

            <div className="secVerifyStep">
              <h3>{tr("2. 在终端里解密", "2. Decrypt from the terminal")}</h3>
              <p>{tr("用命令行工具可以完全在本地接收并解密", "Using the CLI, you can receive and decrypt a drop entirely locally")}:</p>
              <pre className="secCode">{`npm install -g burnafter

burnafter receive "https://dragonknightk.com/moho/d/<id>#k=<key>"`}</pre>
            </div>

            <div className="secVerifyStep">
              <h3>{tr("3. 用 Node.js 手动解密", "3. Decrypt manually with Node.js")}</h3>
              <p>{tr("从接口取回原始密文, 自己解密", "Fetch the raw ciphertext from the API and decrypt it yourself")}:</p>
              <pre className="secCode">{`const crypto = require("crypto");

const KEY_B64 = "<paste #k= value here>";
const PAYLOAD = <paste ciphertext JSON here>;

function b64url(s) {
  return Buffer.from(s.replace(/-/g,"+").replace(/_/g,"/"), "base64");
}

const key  = b64url(KEY_B64);
const iv   = b64url(PAYLOAD.iv);
const raw  = b64url(PAYLOAD.data);
const data = raw.subarray(0, raw.length - 16);
const tag  = raw.subarray(raw.length - 16);

const d = crypto.createDecipheriv("aes-256-gcm", key, iv);
d.setAuthTag(tag);
console.log(Buffer.concat([d.update(data), d.final()]).toString("utf8"));`}</pre>
            </div>

            <div className="secVerifyStep">
              <h3>{tr("4. 读源码", "4. Read the source code")}</h3>
              <p>{tr("完整源码在 GitHub 上, 可以从加密模块看起", "The full source is open on GitHub. The crypto module is a good starting point")}:</p>
              <div className="secLinks">
                <a href="https://github.com/casablanque-code/burnafterread" target="_blank" rel="noreferrer">
                  github.com/casablanque-code/burnafterread
                </a>
                <a href="https://github.com/casablanque-code/burnafterread/blob/main/src/lib/crypto.ts" target="_blank" rel="noreferrer">
                  src/lib/crypto.ts — {tr("浏览器端加密", "browser encryption")}
                </a>
                <a href="https://github.com/casablanque-code/burnafterread/blob/main/worker/durable/DropAccessCoordinator.ts" target="_blank" rel="noreferrer">
                  worker/durable/DropAccessCoordinator.ts — {tr("服务端访问控制", "server-side access control")}
                </a>
              </div>
            </div>
          </div>
        </section>

        {/* Primitives */}
        <section className="secSection">
          <h2>{tr("密码学参数", "Cryptographic primitives")}</h2>
          <div className="secPrimitives">
            <div className="secPrimitive">
              <span className="secPrimName">{tr("算法", "Algorithm")}</span>
              <span className="secPrimValue">AES-GCM</span>
            </div>
            <div className="secPrimitive">
              <span className="secPrimName">{tr("密钥长度", "Key size")}</span>
              <span className="secPrimValue">{tr("256 位", "256 bits")}</span>
            </div>
            <div className="secPrimitive">
              <span className="secPrimName">{tr("IV 长度", "IV size")}</span>
              <span className="secPrimValue">{tr("96 位 (12 字节), 每条消息随机", "96 bits (12 bytes), random per message")}</span>
            </div>
            <div className="secPrimitive">
              <span className="secPrimName">{tr("校验标签", "Auth tag")}</span>
              <span className="secPrimValue">{tr("128 位 (16 字节), 附在密文后", "128 bits (16 bytes), appended to ciphertext")}</span>
            </div>
            <div className="secPrimitive">
              <span className="secPrimName">{tr("密钥编码", "Key encoding")}</span>
              <span className="secPrimValue">{tr("Base64url, 无填充, 只放在链接 # 片段里", "Base64url, no padding, URL fragment only")}</span>
            </div>
            <div className="secPrimitive">
              <span className="secPrimName">{tr("实现", "Implementation")}</span>
              <span className="secPrimValue">{tr("Web Crypto API (浏览器), node:crypto (命令行), 不用第三方加密库", "Web Crypto API (browser), node:crypto (CLI) — no third-party crypto libs")}</span>
            </div>
            <div className="secPrimitive">
              <span className="secPrimName">{tr("撤回凭证", "Delete token")}</span>
              <span className="secPrimValue">{tr("随机 32 字节凭证的 SHA-256, 常量时间比较", "SHA-256 of random 32-byte token, constant-time comparison")}</span>
            </div>
          </div>
        </section>

        <footer className="secFooter">
          <a href={`${BASE}/`}>← {tr("返回首页", "Back to burnafterread")}</a>
        </footer>

      </div>
    </div>
  );
}

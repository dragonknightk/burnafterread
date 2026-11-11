// src/LoginPage.tsx — single-account login for the private beta

import { useState, type FormEvent } from "react";
import "./App.css";
import { BASE, useI18n } from "./i18n";

export default function LoginPage() {
  const { tr } = useI18n();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setErr("");
    if (!username.trim() || !password) {
      setErr(tr("请输入账号和密码", "Enter username and password"));
      return;
    }
    setBusy(true);
    try {
      const res = await fetch(`${BASE}/api/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const data = (await res.json().catch(() => null)) as
        | { ok?: boolean; error?: string; retry_after?: number; remaining?: number }
        | null;
      if (res.ok && data?.ok) {
        window.location.href = `${BASE}/`;
        return;
      }
      if (data?.error === "locked") {
        const mins = Math.max(1, Math.ceil((data.retry_after ?? 900) / 60));
        setErr(tr(`失败次数过多, 已锁定, 请 ${mins} 分钟后再试`, `Too many failed attempts, locked for ${mins} min`));
      } else if (data?.error === "invalid_credentials") {
        setErr(
          tr(
            `账号或密码错误, 还可尝试 ${data.remaining ?? 0} 次`,
            `Wrong username or password, ${data.remaining ?? 0} attempts left`
          )
        );
      } else if (res.status === 429) {
        setErr(tr("请求太频繁, 请稍后再试", "Too many requests, try again later"));
      } else {
        setErr(tr("登录失败, 请稍后再试", "Login failed, try again later"));
      }
    } catch {
      setErr(tr("网络错误", "Network error"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="page">
      <section className="card loginCard">
        <div className="eyebrow">BurnAfterRead</div>
        <h1>{tr("登录", "Log in")}</h1>
        <p className="muted">{tr("内测中, 仅限受邀账号使用", "Private beta, invited account only")}</p>

        <form onSubmit={handleSubmit}>
          <label className="fieldLabel" htmlFor="username">
            {tr("账号", "Username")}
          </label>
          <input
            id="username"
            className="input"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />

          <label className="fieldLabel" htmlFor="password" style={{ marginTop: 14 }}>
            {tr("密码", "Password")}
          </label>
          <input
            id="password"
            className="input"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />

          <div className="actions">
            <button type="submit" disabled={busy}>
              {busy ? tr("登录中...", "Logging in...") : tr("登录", "Log in")}
            </button>
          </div>
        </form>

        {err ? <div className="error">{err}</div> : null}
      </section>
    </main>
  );
}

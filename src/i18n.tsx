// src/i18n.tsx — tiny zh/en switcher, default zh, choice kept in localStorage

import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";

export type Lang = "zh" | "en";
const STORAGE_KEY = "moho.lang";

/** App base path without trailing slash, e.g. "/moho" */
export const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

function initialLang(): Lang {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === "zh" || saved === "en") return saved;
  } catch {
    // ignore
  }
  return "zh";
}

interface I18nValue {
  lang: Lang;
  setLang: (l: Lang) => void;
  /** pick the string for the current language */
  tr: (zh: string, en: string) => string;
}

const I18nContext = createContext<I18nValue>({
  lang: "zh",
  setLang: () => {},
  tr: (zh) => zh,
});

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(initialLang);

  useEffect(() => {
    document.documentElement.lang = lang === "zh" ? "zh-CN" : "en";
  }, [lang]);

  const setLang = useCallback((l: Lang) => {
    setLangState(l);
    try {
      localStorage.setItem(STORAGE_KEY, l);
    } catch {
      // ignore
    }
  }, []);

  const tr = useCallback((zh: string, en: string) => (lang === "zh" ? zh : en), [lang]);

  return <I18nContext.Provider value={{ lang, setLang, tr }}>{children}</I18nContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useI18n(): I18nValue {
  return useContext(I18nContext);
}

export function LangToggle() {
  const { lang, setLang } = useI18n();
  return (
    <div className="langToggle" role="group" aria-label="Language">
      <button
        type="button"
        className={lang === "zh" ? "langBtn langBtn--active" : "langBtn"}
        onClick={() => setLang("zh")}
        aria-pressed={lang === "zh"}
      >
        中
      </button>
      <button
        type="button"
        className={lang === "en" ? "langBtn langBtn--active" : "langBtn"}
        onClick={() => setLang("en")}
        aria-pressed={lang === "en"}
      >
        EN
      </button>
    </div>
  );
}

/** Map server error codes to readable messages */
// eslint-disable-next-line react-refresh/only-export-components
export function errorText(code: string | undefined, tr: I18nValue["tr"]): string {
  switch (code) {
    case "not_found":
      return tr("链接不存在, 或已被阅读销毁", "Not found, or already burned");
    case "burned":
      return tr("已达到查看次数, 内容已销毁", "View limit reached, the drop is burned");
    case "expired":
      return tr("链接已过期", "This drop has expired");
    case "unauthorized":
      return tr("登录已失效, 请重新登录", "Session expired, please log in again");
    case "too many requests":
      return tr("请求太频繁, 请稍后再试", "Too many requests, try again later");
    case "invalid request":
    case "invalid_request":
      return tr("请求无效", "Invalid request");
    case "forbidden":
      return tr("撤回凭证不正确", "Invalid delete token");
    case "missing_blob":
      return tr("内容缺失", "Content missing");
    default:
      return code || tr("未知错误", "Unknown error");
  }
}

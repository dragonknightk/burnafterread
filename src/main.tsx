import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import SecurityPage from "./SecurityPage";
import LoginPage from "./LoginPage";
import { BASE, I18nProvider, LangToggle } from "./i18n";
import "./index.css";

const raw = window.location.pathname;
const path = (raw.startsWith(BASE) ? raw.slice(BASE.length) : raw).replace(/\/+$/, "") || "/";

const Page = path === "/security" ? SecurityPage : path === "/login" ? LoginPage : App;

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <I18nProvider>
      <LangToggle />
      <Page />
    </I18nProvider>
  </React.StrictMode>
);

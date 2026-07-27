import { StrictMode, useCallback, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";

import { translateExtensionText, type ExtensionLocale } from "./locale";
import type { PopupRequest, PopupState } from "./protocol";
import { useExtensionLocale } from "./use-extension-locale";
import "./popup.css";

function App() {
  const [state, setState] = useState<PopupState>({ kind: "loading" });
  const [busy, setBusy] = useState(false);
  const [locale, setLocale] = useExtensionLocale();
  const t = (source: string) => translateExtensionText(source, locale);

  const request = useCallback(async (message: PopupRequest) => {
    setBusy(true);
    try {
      setState(await sendMessage(message));
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    void request({ type: "popup_state" });
  }, [request]);

  useEffect(() => {
    if (state.kind !== "pairing") return;
    const timer = window.setInterval(
      () => void request({ type: "poll_pairing" }),
      1_500,
    );
    return () => window.clearInterval(timer);
  }, [request, state.kind]);

  return (
    <main className="popup-shell">
      <header>
        <div className="brand-mark" aria-hidden="true">
          <i />
          <i />
          <i />
          <span />
        </div>
        <div>
          <strong>StarAxis</strong>
          <small>{t("安全填充")}</small>
        </div>
        <StatusLight state={state} />
      </header>

      <section className="content" aria-live="polite">
        {state.kind === "loading" && <Loading locale={locale} />}
        {state.kind === "unpaired" && (
          <Message
            glyph="⌁"
            title={t("连接桌面端")}
            detail={t("首次使用需要在StarAxis桌面端确认一次配对。")}
          >
            <button
              className="primary"
              disabled={busy}
              onClick={() => void request({ type: "begin_pairing" })}
            >
              {t(busy ? "正在连接…" : "开始配对")}
            </button>
          </Message>
        )}
        {state.kind === "pairing" && (
          <Message
            glyph="✦"
            title={t("核对配对码")}
            detail={t("打开StarAxis → 浏览器扩展，确认两边显示相同数字。")}
          >
            <div className="pair-code" aria-label={t(`配对码 ${state.code}`)}>
              {state.code.slice(0, 3)} <span>{state.code.slice(3)}</span>
            </div>
            <small className="expiry">{t("配对请求将在一分钟内失效")}</small>
          </Message>
        )}
        {state.kind === "offline" && (
          <Message
            glyph="○"
            title={t("桌面端未连接")}
            detail={t(state.message)}
          >
            <button
              className="secondary"
              disabled={busy}
              onClick={() => void request({ type: "popup_state" })}
            >
              {t("重新连接")}
            </button>
          </Message>
        )}
        {state.kind === "locked" && (
          <Message
            glyph="⌑"
            title={t("保险库已锁定")}
            detail={t(
              "请在StarAxis桌面端输入主密码。扩展不会接收或保存主密码。",
            )}
          >
            <button
              className="secondary"
              disabled={busy}
              onClick={() => void request({ type: "popup_state" })}
            >
              {t("已解锁，刷新")}
            </button>
          </Message>
        )}
        {state.kind === "unsupported" && (
          <Message glyph="!" title={t("已阻止填充")} detail={t(state.message)}>
            <Origin value={state.origin} />
          </Message>
        )}
        {state.kind === "empty" && (
          <Message
            glyph="◇"
            title={t("没有匹配账号")}
            detail={t(
              "请检查条目网址及其“整个网站 / 精确主机 / 禁止填充”设置。",
            )}
          >
            <Origin value={state.origin} />
          </Message>
        )}
        {state.kind === "save_prompt" && (
          <Message
            glyph="✦"
            title={
              state.action === "update"
                ? t("更新StarAxis中的密码？")
                : t("保存到StarAxis？")
            }
            detail={
              state.action === "update"
                ? t(`${state.title ?? t("现有登录项")} 将使用刚提交的新密码。`)
                : t(
                    `${isHttp(state.origin) ? "这是未加密的 HTTP 网站；" : ""}为 ${displayHost(state.origin)} 保存这个新账号。`,
                  )
            }
          >
            <div className="capture-account">
              <span>{state.username || t("未设置用户名")}</span>
              <Origin value={state.origin} />
            </div>
            <div className="capture-actions">
              <button
                className="secondary"
                disabled={busy}
                onClick={() =>
                  void request({
                    type: "dismiss_capture",
                    captureId: state.captureId,
                  })
                }
              >
                {t("暂不")}
              </button>
              <button
                className="primary"
                disabled={busy}
                onClick={() =>
                  void request({
                    type: "save_capture",
                    captureId: state.captureId,
                  })
                }
              >
                {busy
                  ? t("正在保存…")
                  : state.action === "update"
                    ? t("更新密码")
                    : t("保存账号")}
              </button>
            </div>
          </Message>
        )}
        {state.kind === "saved" && (
          <Message
            glyph="✓"
            title={
              state.action === "unchanged"
                ? t("密码已是最新")
                : state.action === "update"
                  ? t("密码已更新")
                  : t("账号已保存")
            }
            detail={
              state.action === "unchanged"
                ? t(`${state.title} 无需更新。`)
                : t(`${state.title} 已加密写入StarAxis保险库。`)
            }
          >
            <Origin value={state.origin} />
          </Message>
        )}
        {state.kind === "error" && (
          <Message
            glyph="!"
            title={t("暂时无法填充")}
            detail={t(state.message)}
          >
            <button
              className="secondary"
              disabled={busy}
              onClick={() => void request({ type: "popup_state" })}
            >
              {t("重试")}
            </button>
          </Message>
        )}
        {state.kind === "success" && (
          <Message
            glyph="✓"
            title={t("已经填入")}
            detail={t(`${state.title} 的账号密码已发送到当前登录表单。`)}
          >
            <Origin value={state.origin} />
          </Message>
        )}
        {state.kind === "candidates" && (
          <CandidateList
            state={state}
            busy={busy}
            request={request}
            locale={locale}
          />
        )}
      </section>

      <footer>
        <span>{t("仅连接本机StarAxis")}</span>
        <div className="popup-language" role="group" aria-label={t("语言")}>
          <button
            type="button"
            className={locale === "en" ? "active" : ""}
            aria-pressed={locale === "en"}
            onClick={() => setLocale("en")}
          >
            English
          </button>
          <button
            type="button"
            className={locale === "zh-CN" ? "active" : ""}
            aria-pressed={locale === "zh-CN"}
            onClick={() => setLocale("zh-CN")}
          >
            简体中文
          </button>
        </div>
        <button
          className="refresh-button"
          aria-label={t("刷新")}
          title={t("刷新")}
          disabled={busy}
          onClick={() => void request({ type: "refresh_candidates" })}
        >
          ↻
        </button>
      </footer>
    </main>
  );
}

function CandidateList({
  state,
  busy,
  request,
  locale,
}: {
  state: Extract<PopupState, { kind: "candidates" }>;
  busy: boolean;
  request: (message: PopupRequest) => Promise<void>;
  locale: ExtensionLocale;
}) {
  const t = (source: string) => translateExtensionText(source, locale);
  return (
    <div className="candidate-view">
      <div className="site-heading">
        <div>
          <span
            className={
              isHttp(state.origin) ? "secure-dot insecure" : "secure-dot"
            }
          />
          <strong>{displayHost(state.origin)}</strong>
        </div>
        <small>
          {isHttp(state.origin)
            ? t(`HTTP 网站 · ${state.candidates.length} 个可用账号`)
            : t(`${state.candidates.length} 个可用账号`)}
        </small>
      </div>
      <div className="candidate-list">
        {state.candidates.flatMap((candidate) => {
          const usernames = candidate.usernames.length
            ? candidate.usernames
            : [""];
          return usernames.map((username, index) => (
            <button
              className="candidate"
              key={`${candidate.item_id}-${index}`}
              disabled={busy}
              onClick={() =>
                void request({
                  type: "fill",
                  origin: state.origin,
                  requestToken: state.requestToken,
                  itemId: candidate.item_id,
                  usernameIndex: index,
                  title: candidate.title,
                })
              }
            >
              <span className="credential-icon">
                {candidate.title.trim().slice(0, 1).toUpperCase() || "•"}
              </span>
              <span className="candidate-copy">
                <strong>{candidate.title}</strong>
                <small>{username || t("未设置用户名")}</small>
                <em className={`match-badge ${candidate.match_type}`}>
                  {t(matchLabel(candidate.match_type))}
                </em>
              </span>
              <span className="fill-arrow">↗</span>
            </button>
          ));
        })}
      </div>
      <p className="privacy-note">
        {t(
          "密码只在点击账号后解密，不会写入扩展存储；填充前会再次核对页面来源。",
        )}
      </p>
    </div>
  );
}

function Message({
  glyph,
  title,
  detail,
  children,
}: {
  glyph: string;
  title: string;
  detail: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="message-view">
      <span className="message-glyph">{glyph}</span>
      <h1>{title}</h1>
      <p>{detail}</p>
      {children}
    </div>
  );
}

function Loading({ locale }: { locale: ExtensionLocale }) {
  return (
    <div
      className="loading-view"
      aria-label={translateExtensionText("正在连接StarAxis", locale)}
    >
      <span />
      <span />
      <span />
    </div>
  );
}

function StatusLight({ state }: { state: PopupState }) {
  const connected = [
    "locked",
    "empty",
    "candidates",
    "success",
    "save_prompt",
    "saved",
  ].includes(state.kind);
  return <span className={connected ? "status online" : "status"} />;
}

function Origin({ value }: { value: string }) {
  return <code className="origin-chip">{value}</code>;
}

function displayHost(origin: string) {
  try {
    return new URL(origin).host;
  } catch {
    return origin;
  }
}

function isHttp(origin: string) {
  return origin.startsWith("http://");
}

function matchLabel(match: "exact_host" | "website" | "https_upgrade") {
  switch (match) {
    case "exact_host":
      return "精确主机";
    case "website":
      return "同一网站";
    case "https_upgrade":
      return "HTTPS 安全升级";
  }
}

function sendMessage(message: PopupRequest): Promise<PopupState> {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(message, (response) => {
      const error = chrome.runtime.lastError;
      resolve(
        error
          ? { kind: "error", message: error.message || "扩展后台未响应" }
          : (response as PopupState),
      );
    });
  });
}

const root = document.getElementById("root");
if (!root) throw new Error("missing popup root");
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);

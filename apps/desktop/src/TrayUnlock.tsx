import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";

import appIconUrl from "../assets/icon.svg";
import { command, type SessionState } from "./api";
import { useDocumentLocalization } from "./i18n";

type TrayUnlockContext = {
  state: SessionState;
  vault_name?: string;
};

export function TrayUnlock() {
  useDocumentLocalization();
  const [context, setContext] = useState<TrayUnlockContext>();
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string>();
  const passwordRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    void command<TrayUnlockContext>("tray_unlock_context")
      .then((next) => {
        setContext(next);
        window.setTimeout(() => passwordRef.current?.focus(), 0);
      })
      .catch((cause) =>
        setError(cause instanceof Error ? cause.message : String(cause)),
      );
  }, []);

  const close = async () => {
    setPassword("");
    await command("hide_tray_unlock").catch(() => undefined);
  };

  const openMain = async () => {
    setPassword("");
    await command("open_main_from_tray").catch((cause) =>
      setError(cause instanceof Error ? cause.message : String(cause)),
    );
  };

  const unlock = async (event: FormEvent) => {
    event.preventDefault();
    if (!password || submitting) return;
    setSubmitting(true);
    setError(undefined);
    try {
      await command("unlock_vault_from_tray", { password });
      setPassword("");
      await command("hide_tray_unlock");
    } catch (cause) {
      setPassword("");
      setError(cause instanceof Error ? cause.message : String(cause));
      window.setTimeout(() => passwordRef.current?.focus(), 0);
    } finally {
      setSubmitting(false);
    }
  };

  const unlocked = context?.state === "unlocked" || context?.state === "dirty";
  const unavailable = context !== undefined && !context.vault_name;

  return (
    <main className="tray-unlock-shell">
      <header className="tray-unlock-header">
        <img src={appIconUrl} alt="" />
        <div>
          <span>STARAXIS</span>
          <h1>{unlocked ? "保险库已解锁" : "解锁保险库"}</h1>
        </div>
        <button
          className="tray-close"
          type="button"
          aria-label="关闭"
          onClick={() => void close()}
        >
          ×
        </button>
      </header>

      <div className="tray-vault">
        <span className={unlocked ? "vault-dot ready" : "vault-dot"} />
        <strong>{context?.vault_name ?? "尚未选择保险库"}</strong>
        {unlocked && <small>已连接</small>}
      </div>

      {unavailable ? (
        <button
          className="tray-primary full"
          type="button"
          onClick={() => void openMain()}
        >
          打开 StarAxis 选择保险库
        </button>
      ) : unlocked ? (
        <button
          className="tray-primary full"
          type="button"
          onClick={() => void close()}
        >
          完成
        </button>
      ) : (
        <form onSubmit={(event) => void unlock(event)}>
          <label htmlFor="tray-main-password">主密码</label>
          <div className="tray-unlock-row">
            <input
              ref={passwordRef}
              id="tray-main-password"
              type="password"
              autoComplete="current-password"
              placeholder="输入主密码"
              value={password}
              disabled={submitting}
              onChange={(event) => setPassword(event.target.value)}
            />
            <button
              className="tray-primary"
              type="submit"
              disabled={!password || submitting}
            >
              {submitting ? "解锁中…" : "解锁"}
            </button>
          </div>
        </form>
      )}

      <footer className={error ? "tray-message error" : "tray-message"}>
        {error ?? "密码只在本机内存中用于本次解锁"}
      </footer>
    </main>
  );
}

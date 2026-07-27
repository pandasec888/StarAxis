import type { ContentRequest, ContentResponse } from "./protocol";
import {
  CONTENT_LOCALE_KEY,
  DEFAULT_CONTENT_LOCALE,
  parseContentLocale,
  readContentLocale,
  translateContentText,
  type ContentLocale,
} from "./content-locale";

type FillMessage = {
  type: "staraxis_fill";
  origin: string;
  username: string;
  password: string;
  expiresAt: number;
};

export {};

type FillResponse = { ok: boolean; message: string };

const marker = "__staraxisContentListenerV1";
const scope = globalThis as typeof globalThis & { [marker]?: boolean };
const submittedForms = new WeakSet<HTMLFormElement>();
const documentId = crypto.randomUUID();
const LOGIN_OUTCOME_TIMEOUT_MS = 15_000;
let contentLocale: ContentLocale = DEFAULT_CONTENT_LOCALE;

readContentLocale((locale) => {
  contentLocale = locale;
});
if (chrome.storage?.onChanged) {
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName !== "local" || !changes[CONTENT_LOCALE_KEY]) return;
    contentLocale = parseContentLocale(changes[CONTENT_LOCALE_KEY].newValue);
  });
}

const t = (source: string) => translateContentText(source, contentLocale);

if (!scope[marker]) {
  scope[marker] = true;
  chrome.runtime.onMessage.addListener(
    (message: FillMessage, _sender, respond: (value: FillResponse) => void) => {
      if (message.type !== "staraxis_fill") return;
      respond(fill(message));
      message.username = "";
      message.password = "";
    },
  );
  if (
    window.top === window &&
    ["http:", "https:"].includes(location.protocol)
  ) {
    document.addEventListener("submit", captureSubmittedLogin, true);
    document.addEventListener("click", captureLoginControlClick, true);
    document.addEventListener("keydown", captureLoginEnter, true);
    window.addEventListener("pageshow", requestPendingPrompt);
    requestPendingPrompt();
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", reportObservedPage, {
        once: true,
      });
    } else {
      reportObservedPage();
    }
  }
}

function fill(message: FillMessage): FillResponse {
  if (window.top !== window) {
    return {
      ok: false,
      message: t("StarAxis不在 iframe 中填充密码"),
    };
  }
  if (
    !["http:", "https:"].includes(location.protocol) ||
    location.origin !== message.origin ||
    message.expiresAt <= Date.now()
  ) {
    return {
      ok: false,
      message: t("页面地址已变化或填充数据已过期"),
    };
  }
  const passwords = visibleInputs('input[type="password"]');
  if (passwords.length !== 1) {
    return {
      ok: false,
      message:
        passwords.length === 0
          ? t("当前页面没有可见密码框")
          : t("页面包含多个密码框，请先聚焦登录表单后重试"),
    };
  }
  const username = chooseUsernameField(passwords[0]);
  if (message.username && !username) {
    return {
      ok: false,
      message: t("当前登录表单没有可确认的用户名输入框"),
    };
  }
  if (username) setInputValue(username, message.username);
  setInputValue(passwords[0], message.password);
  passwords[0].focus({ preventScroll: true });
  return { ok: true, message: t("账号密码已填入当前页面") };
}

function chooseUsernameField(password: HTMLInputElement) {
  const form = password.form ?? document;
  const candidates = Array.from(
    form.querySelectorAll<HTMLInputElement>(
      'input[type="email"], input[type="text"], input:not([type])',
    ),
  ).filter(isVisibleAndWritable);
  const beforePassword = candidates.filter((field) =>
    Boolean(
      field.compareDocumentPosition(password) &
      Node.DOCUMENT_POSITION_FOLLOWING,
    ),
  );
  const autocomplete = beforePassword.find((field) =>
    ["username", "email"].includes(field.autocomplete),
  );
  return autocomplete ?? beforePassword.at(-1) ?? candidates.at(0);
}

function visibleInputs(selector: string) {
  return Array.from(
    document.querySelectorAll<HTMLInputElement>(selector),
  ).filter(isVisibleAndWritable);
}

function isVisibleAndWritable(input: HTMLInputElement) {
  if (input.disabled || input.readOnly || input.type === "hidden") return false;
  const style = getComputedStyle(input);
  const rect = input.getBoundingClientRect();
  const geometricallyVisible =
    rect.width >= 2 &&
    rect.height >= 2 &&
    rect.bottom > 0 &&
    rect.right > 0 &&
    rect.top < window.innerHeight &&
    rect.left < window.innerWidth &&
    style.display !== "none" &&
    style.visibility !== "hidden" &&
    Number(style.opacity || "1") > 0;
  if (!geometricallyVisible) return false;
  const centerX = Math.min(
    window.innerWidth - 1,
    Math.max(0, rect.left + rect.width / 2),
  );
  const centerY = Math.min(
    window.innerHeight - 1,
    Math.max(0, rect.top + rect.height / 2),
  );
  const topmost = document.elementFromPoint?.(centerX, centerY);
  return !topmost || topmost === input || input.contains(topmost);
}

function setInputValue(input: HTMLInputElement, value: string) {
  const descriptor = Object.getOwnPropertyDescriptor(
    HTMLInputElement.prototype,
    "value",
  );
  if (!descriptor?.set) throw new Error("input value setter is unavailable");
  descriptor.set.call(input, value);
  input.dispatchEvent(
    new InputEvent("input", { bubbles: true, inputType: "insertText" }),
  );
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

function captureSubmittedLogin(event: SubmitEvent) {
  const form = event.target;
  if (form instanceof HTMLFormElement) captureLoginForm(form);
}

function captureLoginControlClick(event: MouseEvent) {
  if (
    event.button !== 0 ||
    event.metaKey ||
    event.ctrlKey ||
    event.altKey ||
    event.shiftKey
  ) {
    return;
  }
  const target = event.target;
  if (!(target instanceof Element)) return;
  const control = target.closest<HTMLElement>(
    'button, input[type="submit"], input[type="button"], a, [role="button"]',
  );
  if (!control || !isLoginControl(control)) return;
  const form = control.closest("form");
  if (form) captureLoginForm(form);
}

function captureLoginEnter(event: KeyboardEvent) {
  if (
    event.key !== "Enter" ||
    event.isComposing ||
    event.repeat ||
    event.metaKey ||
    event.ctrlKey ||
    event.altKey ||
    event.shiftKey
  ) {
    return;
  }
  const target = event.target;
  if (!(target instanceof HTMLInputElement)) return;
  const form = target.form;
  if (form) captureLoginForm(form);
}

function isLoginControl(control: HTMLElement) {
  if (
    (control instanceof HTMLButtonElement && control.type === "submit") ||
    (control instanceof HTMLInputElement && control.type === "submit")
  ) {
    return true;
  }
  const label = (
    control.getAttribute("aria-label") ??
    (control instanceof HTMLInputElement
      ? control.value
      : control.textContent) ??
    ""
  )
    .replace(/\s+/g, " ")
    .trim();
  return /^(?:登录|登陆|login|log in|sign in)$/i.test(label);
}

function captureLoginForm(form: HTMLFormElement) {
  if (submittedForms.has(form)) return;
  const passwords = Array.from(
    form.querySelectorAll<HTMLInputElement>('input[type="password"]'),
  ).filter(isVisibleAndWritable);
  const password = chooseSubmittedPassword(passwords);
  if (!password) return;
  const username = chooseUsernameField(password);
  const signature = loginFormSignature(form);
  submittedForms.add(form);
  window.setTimeout(() => submittedForms.delete(form), 2_000);
  const request: ContentRequest = {
    type: "staraxis_login_submitted",
    origin: location.origin,
    title: document.title,
    username: username?.value ?? "",
    password: password.value,
    documentId,
    formSignature: signature,
  };
  sendContentRequest(request, (response) => {
    request.password = "";
    if (response.kind === "none") {
      observeLoginOutcome(form, signature);
    } else {
      renderCapturePrompt(response);
    }
  });
}

function chooseSubmittedPassword(passwords: HTMLInputElement[]) {
  const valued = passwords.filter((field) => field.value);
  if (valued.length === 0) return undefined;
  if (valued.length === 1) return valued[0];

  const newPasswords = valued.filter(
    (field) =>
      field.autocomplete === "new-password" ||
      /(?:\b(?:new|confirm|repeat)\b|新|确认|重复)/i.test(
        passwordFieldHint(field),
      ),
  );
  if (newPasswords.length > 0) {
    const distinct = new Set(newPasswords.map((field) => field.value));
    return distinct.size === 1 ? newPasswords[0] : undefined;
  }

  if (valued.length === 2 && valued[0].value === valued[1].value) {
    return valued[0];
  }
  if (valued.length >= 3 && valued.at(-1)?.value === valued.at(-2)?.value) {
    return valued.at(-2);
  }
  return undefined;
}

function passwordFieldHint(field: HTMLInputElement) {
  return [
    field.name,
    field.id,
    field.getAttribute("aria-label"),
    field.placeholder,
  ]
    .filter(Boolean)
    .join(" ");
}

function loginFormSignature(form: HTMLFormElement) {
  let action = location.origin + location.pathname;
  try {
    const url = new URL(form.getAttribute("action") || location.href);
    action = `${url.origin}${url.pathname}`;
  } catch {
    // Keep the current page as the stable fallback.
  }
  const fields = Array.from(form.elements)
    .filter(
      (element): element is HTMLInputElement =>
        element instanceof HTMLInputElement &&
        ["email", "text", "password"].includes(element.type),
    )
    .map((field) => `${field.type}:${field.autocomplete || field.name || "-"}`)
    .join("|");
  return `${form.method.toUpperCase()}:${action}:${fields}`;
}

function reportObservedPage() {
  const formSignatures = Array.from(document.forms)
    .filter((form) =>
      Array.from(
        form.querySelectorAll<HTMLInputElement>('input[type="password"]'),
      ).some(isRenderedAndWritable),
    )
    .map(loginFormSignature);
  sendContentRequest(
    {
      type: "staraxis_page_observed",
      origin: location.origin,
      documentId,
      formSignatures,
    },
    (response) => {
      if (response.kind !== "none") renderCapturePrompt(response);
    },
  );
}

function observeLoginOutcome(form: HTMLFormElement, formSignature: string) {
  const view = window;
  const pageDocument = document;
  let settled = false;
  let stabilizationTimer: number | undefined;
  const finish = (outcome: "success" | "failure") => {
    if (settled) return;
    settled = true;
    observer.disconnect();
    view.clearTimeout(timeout);
    view.clearTimeout(stabilizationTimer);
    sendContentRequest(
      {
        type: "staraxis_login_outcome",
        origin: location.origin,
        documentId,
        formSignature,
        outcome,
      },
      (response) => {
        if (response.kind !== "none") renderCapturePrompt(response);
      },
    );
  };
  const check = () => {
    if (form.isConnected && formHasRenderedPassword(form)) return;
    view.clearTimeout(stabilizationTimer);
    stabilizationTimer = view.setTimeout(() => {
      const sameFormStillVisible = Array.from(pageDocument.forms).some(
        (candidate) =>
          loginFormSignature(candidate) === formSignature &&
          formHasRenderedPassword(candidate),
      );
      finish(sameFormStillVisible ? "failure" : "success");
    }, 900);
  };
  const observer = new MutationObserver(check);
  observer.observe(pageDocument.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ["class", "hidden", "style", "aria-invalid"],
  });
  const timeout = view.setTimeout(
    () => finish("failure"),
    LOGIN_OUTCOME_TIMEOUT_MS,
  );
}

function formHasRenderedPassword(form: HTMLFormElement) {
  return Array.from(
    form.querySelectorAll<HTMLInputElement>('input[type="password"]'),
  ).some(isRenderedAndWritable);
}

function isRenderedAndWritable(input: HTMLInputElement) {
  if (input.disabled || input.readOnly || input.type === "hidden") return false;
  const style = getComputedStyle(input);
  const rect = input.getBoundingClientRect();
  return (
    input.isConnected &&
    rect.width >= 2 &&
    rect.height >= 2 &&
    style.display !== "none" &&
    style.visibility !== "hidden" &&
    Number(style.opacity || "1") > 0
  );
}

function requestPendingPrompt() {
  sendContentRequest(
    { type: "staraxis_prompt_state", origin: location.origin },
    (response) => {
      if (response.kind !== "none") renderCapturePrompt(response);
    },
  );
}

function sendContentRequest(
  request: ContentRequest,
  callback: (response: ContentResponse) => void,
) {
  try {
    chrome.runtime.sendMessage(request, (response: ContentResponse) => {
      if (chrome.runtime.lastError || !response) return;
      callback(response);
    });
  } catch {
    // The page may be unloading while a login submission is being processed.
  }
}

function renderCapturePrompt(
  response: Exclude<ContentResponse, { kind: "none" }>,
) {
  document.getElementById("staraxis-save-prompt")?.remove();
  const host = document.createElement("div");
  host.id = "staraxis-save-prompt";
  const shadow = host.attachShadow({ mode: "closed" });
  const panel = document.createElement("section");
  const mark = document.createElement("span");
  mark.className = "mark";
  mark.textContent = "✦";
  const copy = document.createElement("div");
  copy.className = "copy";
  const heading = document.createElement("strong");
  const detail = document.createElement("small");
  const actions = document.createElement("div");
  actions.className = "actions";

  if (response.kind === "save_prompt") {
    heading.textContent =
      response.action === "update"
        ? t("更新StarAxis中的密码？")
        : t("是否将该账号密码保存到StarAxis？");
    detail.textContent =
      response.action === "update"
        ? `${response.title ?? t("现有登录项")} · ${response.username || t("未设置用户名")}`
        : `${response.origin.startsWith("http://") ? t("不安全的 HTTP 网站 · ") : ""}${displayHost(response.origin)} · ${response.username || t("未设置用户名")}`;
    const dismiss = promptButton(t("暂不"), "secondary");
    dismiss.addEventListener("click", () => {
      sendContentRequest(
        {
          type: "staraxis_capture_decision",
          captureId: response.captureId,
          decision: "dismiss",
        },
        () => undefined,
      );
      host.remove();
    });
    const save = promptButton(
      response.action === "update" ? t("更新") : t("保存"),
      "primary",
    );
    save.addEventListener("click", () => {
      save.disabled = true;
      save.textContent = t("处理中…");
      sendContentRequest(
        {
          type: "staraxis_capture_decision",
          captureId: response.captureId,
          decision: "save",
        },
        (result) => {
          if (result.kind === "none") {
            host.remove();
          } else {
            renderCapturePrompt(result);
          }
        },
      );
    });
    actions.append(dismiss, save);
  } else if (response.kind === "saved") {
    heading.textContent =
      response.action === "unchanged"
        ? t("密码已是最新")
        : response.action === "update"
          ? t("密码已更新")
          : t("账号已保存");
    detail.textContent =
      response.action === "unchanged"
        ? t(`${response.title} 无需更新`)
        : t(`${response.title} 已加密写入StarAxis保险库`);
    mark.textContent = "✓";
    window.setTimeout(() => host.remove(), 3_200);
  } else {
    heading.textContent =
      response.kind === "locked" ? t("请先解锁StarAxis") : t("暂时无法保存");
    detail.textContent =
      response.kind === "locked"
        ? t("解锁桌面端后，点击扩展图标继续保存。")
        : t(response.message);
    const close = promptButton(t("关闭"), "secondary");
    close.addEventListener("click", () => host.remove());
    actions.append(close);
  }

  copy.append(heading, detail);
  panel.append(mark, copy, actions);
  const style = document.createElement("style");
  style.textContent = `
    :host { all: initial; }
    section {
      position: fixed; top: max(18px, env(safe-area-inset-top)); left: 50%; z-index: 2147483647;
      display: grid; width: min(500px, calc(100vw - 32px));
      grid-template-columns: 42px minmax(0, 1fr) auto; align-items: center; gap: 13px;
      box-sizing: border-box; overflow: hidden;
      border: 1px solid rgba(0,113,227,.24); border-radius: 17px;
      background: rgba(255,255,255,.97);
      box-shadow: 0 18px 50px rgba(27,47,79,.22), 0 2px 10px rgba(27,47,79,.10);
      padding: 14px 15px; color: #1d1d1f;
      font: 13px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
      backdrop-filter: blur(24px) saturate(1.25);
      transform: translateX(-50%);
      animation: staraxis-arrive 220ms cubic-bezier(.2,.8,.2,1) both;
    }
    section::before {
      content:""; position:absolute; inset:0 auto 0 0; width:4px;
      background:linear-gradient(180deg,#36a7ff 0%,#0071e3 100%);
    }
    .mark { display:grid; width:42px; height:42px; place-items:center; border-radius:13px;
      background:linear-gradient(145deg,#edf7ff,#dceeff); color:#0066cc;
      box-shadow:inset 0 0 0 1px rgba(0,113,227,.10);
      font-size:20px; font-weight:750; }
    .copy { display:grid; min-width:0; gap:4px; }
    strong, small { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    strong { color:#101114; font-size:15px; font-weight:700; letter-spacing:-.2px; }
    small { color:#66676c; font-size:11px; line-height:1.35; }
    .actions { display:flex; gap:7px; }
    button {
      min-height:32px; border:0; border-radius:9px; padding:7px 12px;
      font:650 12px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
      cursor:pointer; transition:transform 120ms ease,filter 120ms ease,background 120ms ease;
    }
    button:hover { filter:brightness(.97); }
    button:active { transform:scale(.97); }
    button:focus-visible { outline:3px solid rgba(0,113,227,.25); outline-offset:2px; }
    button:disabled { cursor:default; opacity:.55; }
    .secondary { background:#f0f1f3; color:#45464a; }
    .primary { background:#0071e3; color:#fff; box-shadow:0 4px 12px rgba(0,113,227,.24); }
    @keyframes staraxis-arrive {
      from { opacity:0; transform:translate(-50%,-14px) scale(.985); }
      to { opacity:1; transform:translate(-50%,0) scale(1); }
    }
    @media (max-width: 480px) {
      section { grid-template-columns:38px minmax(0,1fr); gap:10px 12px; padding:12px 13px; }
      .mark { width:38px; height:38px; border-radius:12px; }
      .actions { grid-column:2; }
    }
    @media (prefers-reduced-motion: reduce) {
      section { animation:none; }
      button { transition:none; }
    }
  `;
  shadow.append(style, panel);
  (document.documentElement ?? document.body)?.append(host);
}

function promptButton(label: string, className: string) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = className;
  button.textContent = label;
  return button;
}

function displayHost(origin: string) {
  try {
    return new URL(origin).host;
  } catch {
    return origin;
  }
}

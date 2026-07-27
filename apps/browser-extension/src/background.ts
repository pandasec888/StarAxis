import {
  BridgeError,
  beginPairing,
  pollPairing,
  secureCommand,
  storedPair,
  storedPendingPair,
} from "./crypto";
import type {
  ContentRequest,
  ContentResponse,
  CredentialSaveAction,
  PopupRequest,
  PopupState,
  SecureReply,
} from "./protocol";

let operationQueue: Promise<unknown> = Promise.resolve();
const CAPTURE_TTL_MS = 2 * 60 * 1_000;
const SUBMISSION_TTL_MS = 30 * 1_000;
const MAX_CAPTURE_USERNAME_LENGTH = 16 * 1_024;
const MAX_CAPTURE_PASSWORD_LENGTH = 64 * 1_024;

interface PendingCapture {
  id: string;
  tabId: number;
  origin: string;
  title: string;
  username: string;
  password: string;
  action: Exclude<CredentialSaveAction, "unchanged">;
  existingTitle?: string;
  expiresAt: number;
}

interface PendingSubmission {
  tabId: number;
  origin: string;
  title: string;
  username: string;
  password: string;
  documentId: string;
  formSignature: string;
  expiresAt: number;
}

const pendingCaptures = new Map<number, PendingCapture>();
const pendingSubmissions = new Map<number, PendingSubmission>();
const recentFillFingerprints = new Map<
  number,
  { fingerprint: string; expiresAt: number }
>();

chrome.runtime.onMessage.addListener(
  (
    message: PopupRequest | ContentRequest,
    sender,
    respond: (value: PopupState | ContentResponse) => void,
  ) => {
    operationQueue = operationQueue
      .catch(() => undefined)
      .then(() => handleRuntimeRequest(message, sender));
    operationQueue
      .then((value) => respond(value as PopupState | ContentResponse))
      .catch((cause: unknown) => {
        respond({
          kind: "error",
          message: messageOf(cause),
        } satisfies PopupState);
      });
    return true;
  },
);

chrome.tabs.onRemoved.addListener((tabId) => {
  clearCapture(tabId, false);
  clearSubmission(tabId);
  recentFillFingerprints.delete(tabId);
});

async function handleRuntimeRequest(
  request: PopupRequest | ContentRequest,
  sender: chrome.runtime.MessageSender,
): Promise<PopupState | ContentResponse> {
  expireCaptures();
  if (request.type.startsWith("staraxis_")) {
    return handleContentRequest(request as ContentRequest, sender);
  }
  return handlePopupRequest(request as PopupRequest);
}

async function handlePopupRequest(request: PopupRequest): Promise<PopupState> {
  switch (request.type) {
    case "popup_state":
    case "refresh_candidates":
      return loadCurrentState();
    case "begin_pairing": {
      try {
        const pending = await beginPairing();
        return {
          kind: "pairing",
          code: pending.verificationCode,
          expiresAt: pending.expiresAt,
        };
      } catch (cause) {
        return classifyError(cause);
      }
    }
    case "poll_pairing": {
      try {
        const status = await pollPairing();
        if (status === "approved") return loadCurrentState();
        if (status === "rejected") {
          return { kind: "error", message: "桌面端已拒绝这次配对" };
        }
        if (status === "expired") return { kind: "unpaired" };
        const pending = await storedPendingPair();
        return pending
          ? {
              kind: "pairing",
              code: pending.verificationCode,
              expiresAt: pending.expiresAt,
            }
          : { kind: "unpaired" };
      } catch (cause) {
        return classifyError(cause);
      }
    }
    case "fill":
      return fillSelected(request);
    case "save_capture":
      return saveCapture(request.captureId);
    case "dismiss_capture":
      return dismissPopupCapture(request.captureId);
  }
}

async function loadCurrentState(): Promise<PopupState> {
  const pending = await storedPendingPair();
  if (pending && pending.expiresAt > Date.now()) {
    return {
      kind: "pairing",
      code: pending.verificationCode,
      expiresAt: pending.expiresAt,
    };
  }
  if (!(await storedPair())) return { kind: "unpaired" };
  const active = await activeTabContext();
  if (active.tabId !== undefined) {
    const capture = pendingCaptures.get(active.tabId);
    if (capture) return promptState(capture);
  }
  if (!active.origin) {
    return {
      kind: "unsupported",
      origin: active.display,
      message: active.message,
    };
  }
  try {
    const status = await secureCommand({ type: "status" });
    if (status.type === "error") return replyError(status, active.origin);
    if (status.type !== "status") {
      return { kind: "error", message: "桌面端返回了意外状态" };
    }
    if (status.vault_state === "locked") return { kind: "locked" };
    const reply = await secureCommand({
      type: "candidates",
      origin: active.origin,
    });
    if (reply.type === "error") return replyError(reply, active.origin);
    if (reply.type !== "candidates") {
      return { kind: "error", message: "候选账号响应格式不正确" };
    }
    return {
      kind: "candidates",
      origin: reply.origin,
      requestToken: reply.request_token,
      candidates: reply.candidates,
    };
  } catch (cause) {
    return classifyError(cause);
  }
}

async function handleContentRequest(
  request: ContentRequest,
  sender: chrome.runtime.MessageSender,
): Promise<ContentResponse> {
  const tabId = trustedContentTab(
    sender,
    "origin" in request ? request.origin : undefined,
  );
  if (tabId === undefined) {
    return { kind: "error", message: "登录页面来源无法确认" };
  }
  switch (request.type) {
    case "staraxis_login_submitted":
      return captureSubmittedCredential(tabId, request);
    case "staraxis_login_outcome":
      return resolveLoginOutcome(tabId, request);
    case "staraxis_page_observed":
      return observeLoginPage(tabId, request);
    case "staraxis_prompt_state": {
      const capture = pendingCaptures.get(tabId);
      return capture && capture.origin === request.origin
        ? promptState(capture)
        : { kind: "none" };
    }
    case "staraxis_capture_decision":
      return request.decision === "save"
        ? saveCapture(request.captureId, tabId)
        : dismissContentCapture(request.captureId, tabId);
  }
}

async function captureSubmittedCredential(
  tabId: number,
  request: Extract<ContentRequest, { type: "staraxis_login_submitted" }>,
): Promise<ContentResponse> {
  if (
    request.username.length > MAX_CAPTURE_USERNAME_LENGTH ||
    !request.password ||
    request.password.length > MAX_CAPTURE_PASSWORD_LENGTH ||
    !(await storedPair())
  ) {
    request.password = "";
    return { kind: "none" };
  }
  try {
    const fingerprint = await credentialFingerprint(
      request.origin,
      request.username,
      request.password,
    );
    const recentFill = recentFillFingerprints.get(tabId);
    if (
      recentFill &&
      recentFill.expiresAt > Date.now() &&
      recentFill.fingerprint === fingerprint
    ) {
      recentFillFingerprints.delete(tabId);
      request.password = "";
      return { kind: "none" };
    }
    clearSubmission(tabId);
    pendingSubmissions.set(tabId, {
      tabId,
      origin: request.origin,
      title: request.title,
      username: request.username,
      password: request.password,
      documentId: request.documentId,
      formSignature: request.formSignature,
      expiresAt: Date.now() + SUBMISSION_TTL_MS,
    });
    request.password = "";
    return { kind: "none" };
  } catch (cause) {
    request.password = "";
    return contentError(cause);
  }
}

async function resolveLoginOutcome(
  tabId: number,
  request: Extract<ContentRequest, { type: "staraxis_login_outcome" }>,
): Promise<ContentResponse> {
  const submission = pendingSubmissions.get(tabId);
  if (
    !submission ||
    submission.origin !== request.origin ||
    submission.documentId !== request.documentId ||
    submission.formSignature !== request.formSignature
  ) {
    return { kind: "none" };
  }
  if (request.outcome === "failure") {
    clearSubmission(tabId);
    return { kind: "none" };
  }
  return finalizeSubmittedCredential(tabId, submission);
}

async function observeLoginPage(
  tabId: number,
  request: Extract<ContentRequest, { type: "staraxis_page_observed" }>,
): Promise<ContentResponse> {
  const submission = pendingSubmissions.get(tabId);
  if (
    !submission ||
    submission.origin !== request.origin ||
    submission.documentId === request.documentId
  ) {
    return { kind: "none" };
  }
  if (request.formSignatures.includes(submission.formSignature)) {
    clearSubmission(tabId);
    return { kind: "none" };
  }
  return finalizeSubmittedCredential(tabId, submission);
}

async function finalizeSubmittedCredential(
  tabId: number,
  submission: PendingSubmission,
): Promise<ContentResponse> {
  pendingSubmissions.delete(tabId);
  try {
    const reply = await secureCommand({
      type: "credential_status",
      origin: submission.origin,
      username: submission.username,
      password: submission.password,
    });
    if (reply.type === "error") {
      clearSubmissionSecret(submission);
      return reply.code === "VAULT_LOCKED"
        ? { kind: "locked" }
        : { kind: "error", message: reply.message };
    }
    if (reply.type !== "credential_status") {
      clearSubmissionSecret(submission);
      return { kind: "error", message: "桌面端返回了意外的凭据状态" };
    }
    if (reply.action === "unchanged") {
      clearSubmissionSecret(submission);
      return { kind: "none" };
    }
    clearCapture(tabId);
    const capture: PendingCapture = {
      id: crypto.randomUUID(),
      tabId,
      origin: submission.origin,
      title: submission.title,
      username: submission.username,
      password: submission.password,
      action: reply.action,
      existingTitle: reply.title,
      expiresAt: Date.now() + CAPTURE_TTL_MS,
    };
    submission.password = "";
    submission.username = "";
    pendingCaptures.set(tabId, capture);
    if (!(await setCaptureBadge(tabId, true))) {
      clearCapture(tabId, false);
      return { kind: "none" };
    }
    return promptState(capture);
  } catch (cause) {
    clearSubmissionSecret(submission);
    return contentError(cause);
  }
}

async function saveCapture(
  captureId: string,
  expectedTabId?: number,
): Promise<PopupState & ContentResponse> {
  const capture = findCapture(captureId, expectedTabId);
  if (!capture) return { kind: "error", message: "待保存的登录信息已经过期" };
  try {
    const reply = await secureCommand({
      type: "save_credential",
      origin: capture.origin,
      title: capture.title,
      username: capture.username,
      password: capture.password,
    });
    if (reply.type === "error") {
      return reply.code === "VAULT_LOCKED"
        ? { kind: "locked" }
        : { kind: "error", message: reply.message };
    }
    if (reply.type !== "credential_saved") {
      return { kind: "error", message: "桌面端没有确认保存结果" };
    }
    const result = {
      kind: "saved" as const,
      origin: capture.origin,
      title: reply.title,
      action: reply.action,
    };
    clearCapture(capture.tabId);
    return result;
  } catch (cause) {
    return contentError(cause);
  }
}

async function dismissPopupCapture(captureId: string): Promise<PopupState> {
  const capture = findCapture(captureId);
  if (capture) clearCapture(capture.tabId);
  return loadCurrentState();
}

function dismissContentCapture(
  captureId: string,
  expectedTabId?: number,
): ContentResponse {
  const capture = findCapture(captureId, expectedTabId);
  if (capture) clearCapture(capture.tabId);
  return { kind: "none" };
}

function promptState(
  capture: PendingCapture,
): Extract<PopupState, { kind: "save_prompt" }> {
  return {
    kind: "save_prompt",
    captureId: capture.id,
    origin: capture.origin,
    username: capture.username,
    action: capture.action,
    title: capture.existingTitle,
  };
}

function findCapture(captureId: string, expectedTabId?: number) {
  for (const capture of pendingCaptures.values()) {
    if (
      capture.id === captureId &&
      (expectedTabId === undefined || capture.tabId === expectedTabId)
    ) {
      return capture;
    }
  }
  return undefined;
}

function trustedContentTab(
  sender: chrome.runtime.MessageSender,
  claimedOrigin?: string,
) {
  if (sender.frameId !== 0 || sender.tab?.id === undefined || !sender.url) {
    return undefined;
  }
  try {
    const senderUrl = new URL(sender.url);
    if (
      !["http:", "https:"].includes(senderUrl.protocol) ||
      (claimedOrigin && senderUrl.origin !== claimedOrigin)
    ) {
      return undefined;
    }
    return sender.tab.id;
  } catch {
    return undefined;
  }
}

function expireCaptures() {
  const now = Date.now();
  for (const [tabId, capture] of pendingCaptures) {
    if (capture.expiresAt <= now) clearCapture(tabId);
  }
  for (const [tabId, submission] of pendingSubmissions) {
    if (submission.expiresAt <= now) clearSubmission(tabId);
  }
  for (const [tabId, recentFill] of recentFillFingerprints) {
    if (recentFill.expiresAt <= now) recentFillFingerprints.delete(tabId);
  }
}

function clearCapture(tabId: number, updateBadge = true) {
  const capture = pendingCaptures.get(tabId);
  if (capture) {
    capture.password = "";
    capture.username = "";
    pendingCaptures.delete(tabId);
  }
  if (updateBadge) void setCaptureBadge(tabId, false);
}

function clearSubmission(tabId: number) {
  const submission = pendingSubmissions.get(tabId);
  if (submission) clearSubmissionSecret(submission);
  pendingSubmissions.delete(tabId);
}

function clearSubmissionSecret(submission: PendingSubmission) {
  submission.password = "";
  submission.username = "";
}

function setCaptureBadge(tabId: number, visible: boolean): Promise<boolean> {
  return new Promise((resolve) => {
    const setText = () => {
      chrome.action.setBadgeText({ tabId, text: visible ? "1" : "" }, () => {
        const error = chrome.runtime.lastError;
        resolve(!error);
      });
    };
    if (!visible) {
      setText();
      return;
    }
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#0071e3" }, () => {
      const error = chrome.runtime.lastError;
      if (error) {
        resolve(false);
        return;
      }
      setText();
    });
  });
}

function contentError(
  cause: unknown,
): Extract<ContentResponse, { kind: "error" }> {
  const state = classifyError(cause);
  if (state.kind === "locked") {
    return { kind: "error", message: "请先解锁StarAxis桌面端" };
  }
  return {
    kind: "error",
    message:
      state.kind === "offline"
        ? state.message
        : state.kind === "error"
          ? state.message
          : "StarAxis暂时无法处理登录信息",
  };
}

async function fillSelected(
  request: Extract<PopupRequest, { type: "fill" }>,
): Promise<PopupState> {
  const active = await activeTabContext();
  if (
    !active.origin ||
    active.origin !== request.origin ||
    active.tabId === undefined
  ) {
    return { kind: "error", message: "页面地址已经变化，请重新选择账号" };
  }
  try {
    const reply = await secureCommand({
      type: "fill",
      origin: request.origin,
      request_token: request.requestToken,
      item_id: request.itemId,
      username_index: request.usernameIndex,
    });
    if (reply.type === "error") return replyError(reply, request.origin);
    if (reply.type !== "fill" || reply.expires_at <= Date.now()) {
      return { kind: "error", message: "一次性填充数据已经过期" };
    }
    const fingerprint = await credentialFingerprint(
      reply.origin,
      reply.username,
      reply.password,
    );
    await executeContentScript(active.tabId);
    const result = await sendToTab(active.tabId, {
      type: "staraxis_fill",
      origin: reply.origin,
      username: reply.username,
      password: reply.password,
      expiresAt: reply.expires_at,
    });
    reply.username = "";
    reply.password = "";
    if (!result.ok) return { kind: "error", message: result.message };
    recentFillFingerprints.set(active.tabId, {
      fingerprint,
      expiresAt: Date.now() + CAPTURE_TTL_MS,
    });
    return { kind: "success", origin: request.origin, title: request.title };
  } catch (cause) {
    return classifyError(cause);
  }
}

async function credentialFingerprint(
  origin: string,
  username: string,
  password: string,
) {
  const bytes = new TextEncoder().encode(
    JSON.stringify([origin, username, password]),
  );
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  bytes.fill(0);
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

function replyError(
  reply: Extract<SecureReply, { type: "error" }>,
  origin: string,
): PopupState {
  if (reply.code === "VAULT_LOCKED") return { kind: "locked" };
  if (reply.code === "NO_MATCH") return { kind: "empty", origin };
  if (reply.code === "ORIGIN_NOT_ALLOWED") {
    return { kind: "unsupported", origin, message: reply.message };
  }
  return { kind: "error", message: reply.message };
}

function classifyError(cause: unknown): PopupState {
  if (cause instanceof BridgeError) {
    if (cause.code === "DESKTOP_OFFLINE") {
      return { kind: "offline", message: "请先启动StarAxis桌面端" };
    }
    if (cause.code === "UNPAIRED") return { kind: "unpaired" };
    if (cause.code === "VAULT_LOCKED") return { kind: "locked" };
  }
  return { kind: "error", message: messageOf(cause) };
}

async function activeTabContext(): Promise<{
  tabId?: number;
  origin?: string;
  display: string;
  message: string;
}> {
  const tabs = await queryTabs({ active: true, currentWindow: true });
  const tab = tabs[0];
  if (!tab?.url || tab.id === undefined) {
    return { display: "当前页面", message: "无法读取当前标签页地址" };
  }
  try {
    const url = new URL(tab.url);
    if (!["http:", "https:"].includes(url.protocol)) {
      return {
        tabId: tab.id,
        display: url.hostname || url.protocol,
        message: "StarAxis只在 HTTP 或 HTTPS 页面中填充密码",
      };
    }
    if (url.username || url.password) {
      return {
        tabId: tab.id,
        display: url.hostname,
        message: "包含 URL 凭据的页面不允许填充",
      };
    }
    return {
      tabId: tab.id,
      origin: url.origin,
      display: url.origin,
      message: "",
    };
  } catch {
    return { tabId: tab.id, display: "当前页面", message: "当前页面地址无效" };
  }
}

function queryTabs(query: chrome.tabs.QueryInfo): Promise<chrome.tabs.Tab[]> {
  return new Promise((resolve, reject) => {
    chrome.tabs.query(query, (tabs) => {
      const error = chrome.runtime.lastError;
      if (error) reject(new Error(error.message));
      else resolve(tabs);
    });
  });
}

function executeContentScript(tabId: number): Promise<void> {
  return new Promise((resolve, reject) => {
    chrome.scripting.executeScript(
      {
        target: { tabId, frameIds: [0] },
        files: ["assets/content.js"],
      },
      () => {
        const error = chrome.runtime.lastError;
        if (error) reject(new Error(error.message));
        else resolve();
      },
    );
  });
}

function sendToTab(
  tabId: number,
  message: object,
): Promise<{ ok: boolean; message: string }> {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tabId, message, { frameId: 0 }, (response) => {
      const error = chrome.runtime.lastError;
      if (error) reject(new Error(error.message));
      else resolve(response as { ok: boolean; message: string });
    });
  });
}

function messageOf(cause: unknown) {
  return cause instanceof Error ? cause.message : String(cause);
}

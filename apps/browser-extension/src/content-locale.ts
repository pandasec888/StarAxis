export type ContentLocale = "en" | "zh-CN";

export const CONTENT_LOCALE_KEY = "staraxis.extension.locale";
export const DEFAULT_CONTENT_LOCALE: ContentLocale = "en";

const english: Record<string, string> = {
  "StarAxis不在 iframe 中填充密码":
    "StarAxis does not fill passwords inside iframes",
  页面地址已变化或填充数据已过期:
    "The page address changed or the fill request expired",
  当前页面没有可见密码框: "No visible password field was found on this page",
  "页面包含多个密码框，请先聚焦登录表单后重试":
    "This page contains multiple password fields. Focus the login form and try again.",
  当前登录表单没有可确认的用户名输入框:
    "No verifiable username field was found in the current login form",
  账号密码已填入当前页面:
    "The username and password were filled into the current page",
  "更新StarAxis中的密码？": "Update Password in StarAxis?",
  "是否将该账号密码保存到StarAxis？":
    "Save this username and password to StarAxis?",
  现有登录项: "Existing login",
  未设置用户名: "No username",
  "不安全的 HTTP 网站 · ": "Unsecured HTTP website · ",
  暂不: "Not Now",
  更新: "Update",
  保存: "Save",
  "处理中…": "Working…",
  密码已是最新: "Password Is Up to Date",
  密码已更新: "Password Updated",
  账号已保存: "Account Saved",
  请先解锁StarAxis: "Unlock StarAxis First",
  暂时无法保存: "Unable to Save",
  "解锁桌面端后，点击扩展图标继续保存。":
    "Unlock the desktop app, then click the extension icon to continue saving.",
  关闭: "Close",
  桌面端已拒绝这次配对: "The desktop app rejected this pairing request",
  桌面端返回了意外状态: "The desktop app returned an unexpected status",
  候选账号响应格式不正确: "The account candidate response is invalid",
  登录页面来源无法确认: "The login page origin could not be verified",
  桌面端返回了意外的凭据状态:
    "The desktop app returned an unexpected credential status",
  待保存的登录信息已经过期: "The pending login information has expired",
  桌面端没有确认保存结果: "The desktop app did not confirm the save result",
  请先解锁StarAxis桌面端: "Unlock the StarAxis desktop app first",
  StarAxis暂时无法处理登录信息:
    "StarAxis is temporarily unable to process this login",
  "页面地址已经变化，请重新选择账号":
    "The page address changed. Choose the account again.",
  一次性填充数据已经过期: "The one-time fill request has expired",
  请先启动StarAxis桌面端: "Start the StarAxis desktop app first",
  当前页面: "Current page",
  无法读取当前标签页地址: "Unable to read the current tab address",
  "StarAxis只在 HTTP 或 HTTPS 页面中填充密码":
    "StarAxis fills passwords only on HTTP or HTTPS pages",
  "包含 URL 凭据的页面不允许填充":
    "Filling is not allowed on pages whose URL contains credentials",
  当前页面地址无效: "The current page address is invalid",
};

export function parseContentLocale(value: unknown): ContentLocale {
  return value === "zh-CN" ? "zh-CN" : DEFAULT_CONTENT_LOCALE;
}

export function readContentLocale(callback: (locale: ContentLocale) => void) {
  if (typeof chrome === "undefined" || !chrome.storage?.local) {
    callback(DEFAULT_CONTENT_LOCALE);
    return;
  }
  chrome.storage.local.get([CONTENT_LOCALE_KEY], (stored) => {
    const value: unknown = stored[CONTENT_LOCALE_KEY];
    callback(parseContentLocale(value));
  });
}

export function translateContentText(source: string, locale: ContentLocale) {
  if (locale === "zh-CN") return source;
  const exact = english[source];
  if (exact) return exact;

  const noUpdate = source.match(/^(.+) 无需更新。?$/);
  if (noUpdate) return `${noUpdate[1]} does not need an update.`;

  const saved = source.match(/^(.+) 已加密写入StarAxis保险库。?$/);
  if (saved)
    return `${saved[1]} was encrypted and saved to the StarAxis vault.`;

  return source;
}

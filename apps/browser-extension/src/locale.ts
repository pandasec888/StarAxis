export type ExtensionLocale = "en" | "zh-CN";

export const EXTENSION_LOCALE_KEY = "staraxis.extension.locale";
export const DEFAULT_EXTENSION_LOCALE: ExtensionLocale = "en";

const english: Record<string, string> = {
  安全填充: "Secure Fill",
  连接桌面端: "Connect to Desktop",
  "首次使用需要在StarAxis桌面端确认一次配对。":
    "First-time setup requires one pairing approval in the StarAxis desktop app.",
  "正在连接…": "Connecting…",
  开始配对: "Start Pairing",
  核对配对码: "Verify Pairing Code",
  "打开StarAxis → 浏览器扩展，确认两边显示相同数字。":
    "Open StarAxis → Browser Extension and confirm that both codes match.",
  配对请求将在一分钟内失效: "The pairing request expires in one minute",
  桌面端未连接: "Desktop Not Connected",
  重新连接: "Reconnect",
  保险库已锁定: "Vault Locked",
  "请在StarAxis桌面端输入主密码。扩展不会接收或保存主密码。":
    "Enter the master password in the StarAxis desktop app. The extension never receives or stores it.",
  "已解锁，刷新": "Unlocked, Refresh",
  已阻止填充: "Fill Blocked",
  没有匹配账号: "No Matching Accounts",
  "请检查条目网址及其“整个网站 / 精确主机 / 禁止填充”设置。":
    'Check the item URL and its "Entire website / Exact host / Never fill" setting.',
  "更新StarAxis中的密码？": "Update Password in StarAxis?",
  "保存到StarAxis？": "Save to StarAxis?",
  "是否将该账号密码保存到StarAxis？":
    "Save this username and password to StarAxis?",
  现有登录项: "Existing login",
  "这是未加密的 HTTP 网站；": "This is an unencrypted HTTP website; ",
  未设置用户名: "No username",
  暂不: "Not Now",
  "正在保存…": "Saving…",
  更新密码: "Update Password",
  保存账号: "Save Account",
  密码已是最新: "Password Is Up to Date",
  密码已更新: "Password Updated",
  账号已保存: "Account Saved",
  暂时无法填充: "Unable to Fill",
  重试: "Retry",
  已经填入: "Filled",
  仅连接本机StarAxis: "Connected only to local StarAxis",
  刷新: "Refresh",
  正在连接StarAxis: "Connecting to StarAxis",
  精确主机: "Exact host",
  同一网站: "Same website",
  "HTTPS 安全升级": "Secure HTTPS upgrade",
  扩展后台未响应: "The extension background service did not respond",
  "密码只在点击账号后解密，不会写入扩展存储；填充前会再次核对页面来源。":
    "Passwords are decrypted only after you choose an account and are never written to extension storage. The page origin is verified again before filling.",
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
  "不安全的 HTTP 网站 · ": "Unsecured HTTP website · ",
  更新: "Update",
  保存: "Save",
  "处理中…": "Working…",
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
  默认浏览器配置: "Default browser profile",
  桌面端没有返回配对请求: "The desktop app did not return a pairing request",
  "配对校验码不一致，已终止连接":
    "The pairing verification codes do not match. The connection was stopped.",
  无法读取配对状态: "Unable to read the pairing status",
  安全请求失败: "The secure request failed",
  浏览器尚未与StarAxis配对: "This browser has not been paired with StarAxis",
  "配对序列已耗尽，请重新配对":
    "The pairing sequence is exhausted. Pair the browser again.",
  桌面配对响应签名无效: "The desktop pairing response signature is invalid",
  配对状态签名无效: "The pairing status signature is invalid",
  桌面响应签名无效: "The desktop response signature is invalid",
  桌面响应与当前请求不匹配:
    "The desktop response does not match the current request",
  StarAxis桌面端未连接: "The StarAxis desktop app is not connected",
  StarAxis桌面端响应超时: "The StarAxis desktop app timed out",
  扩展存储读取失败: "Unable to read extension storage",
  扩展存储写入失败: "Unable to write extension storage",
  无法打开扩展密钥存储: "Unable to open the extension key store",
  无法读取扩展身份密钥: "Unable to read the extension identity key",
  无法保存扩展身份密钥: "Unable to save the extension identity key",
  语言: "Language",
};

function isExtensionLocale(value: unknown): value is ExtensionLocale {
  return value === "en" || value === "zh-CN";
}

export function translateExtensionText(
  source: string,
  locale: ExtensionLocale,
) {
  if (locale === "zh-CN") return source;
  const exact = english[source];
  if (exact) return exact;

  const pairingCode = source.match(/^配对码 (.+)$/);
  if (pairingCode) return `Pairing code ${pairingCode[1]}`;

  const accountCount = source.match(/^(\d+) 个可用账号$/);
  if (accountCount) {
    const count = Number(accountCount[1]);
    return `${count} available ${count === 1 ? "account" : "accounts"}`;
  }

  const httpAccountCount = source.match(/^HTTP 网站 · (\d+) 个可用账号$/);
  if (httpAccountCount) {
    const count = Number(httpAccountCount[1]);
    return `HTTP website · ${count} available ${count === 1 ? "account" : "accounts"}`;
  }

  const updating = source.match(/^(.+) 将使用刚提交的新密码。$/);
  if (updating) return `${updating[1]} will use the newly submitted password.`;

  const saving = source.match(/^为 (.+) 保存这个新账号。$/);
  if (saving) return `Save this new account for ${saving[1]}.`;

  const httpSaving = source.match(
    /^这是未加密的 HTTP 网站；为 (.+) 保存这个新账号。$/,
  );
  if (httpSaving) {
    return `This is an unencrypted HTTP website; save this new account for ${httpSaving[1]}.`;
  }

  const noUpdate = source.match(/^(.+) 无需更新。?$/);
  if (noUpdate) return `${noUpdate[1]} does not need an update.`;

  const saved = source.match(/^(.+) 已加密写入StarAxis保险库。?$/);
  if (saved)
    return `${saved[1]} was encrypted and saved to the StarAxis vault.`;

  const filled = source.match(/^(.+) 的账号密码已发送到当前登录表单。$/);
  if (filled) {
    return `The credentials for ${filled[1]} were sent to the current login form.`;
  }

  return source;
}

export function readExtensionLocale(
  callback: (locale: ExtensionLocale) => void,
) {
  if (typeof chrome === "undefined" || !chrome.storage?.local) {
    callback(DEFAULT_EXTENSION_LOCALE);
    return;
  }
  chrome.storage.local.get([EXTENSION_LOCALE_KEY], (stored) => {
    const value: unknown = stored[EXTENSION_LOCALE_KEY];
    callback(isExtensionLocale(value) ? value : DEFAULT_EXTENSION_LOCALE);
  });
}

export function writeExtensionLocale(locale: ExtensionLocale) {
  if (typeof chrome === "undefined" || !chrome.storage?.local) return;
  void chrome.storage.local.set({ [EXTENSION_LOCALE_KEY]: locale });
}

export function parseExtensionLocale(value: unknown): ExtensionLocale {
  return isExtensionLocale(value) ? value : DEFAULT_EXTENSION_LOCALE;
}

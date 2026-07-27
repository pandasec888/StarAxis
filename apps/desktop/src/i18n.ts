import { useLayoutEffect, useSyncExternalStore } from "react";

export type AppLocale = "en" | "zh-CN";

export const LOCALE_STORAGE_KEY = "staraxis.locale";
export const DEFAULT_LOCALE: AppLocale = "en";

const translations: Record<string, string> = {
  整个网站: "Entire website",
  精确主机: "Exact host",
  禁止填充: "Never fill",
  保险库已创建: "Vault created",
  保险库已解锁: "Vault unlocked",
  已安全保存到独立加密文件: "Safely saved to the encrypted vault file",
  "当前编辑尚未提交，确定切换条目吗？":
    "Your edits have not been saved. Switch items anyway?",
  "秘密将进入系统剪贴板；历史记录或其他应用仍可能保留它。继续吗？":
    "This secret will enter the system clipboard. Clipboard history or other apps may retain it. Continue?",
  条目已永久删除: "Item permanently deleted",
  条目已移动到回收站: "Item moved to Trash",
  "永久删除未完成，条目已安全保留在回收站":
    "Permanent deletion did not complete. The item remains safely in Trash.",
  条目已恢复: "Item restored",
  当前保险库没有可用的根分组: "This vault has no available root group",
  分组已重命名并保存: "Group renamed and saved",
  分组已创建并保存: "Group created and saved",
  空分组已删除并保存: "Empty group deleted and saved",
  "Root 已删除，内容已安全移交到新的根分组":
    "Root was deleted and its contents were safely moved to the new root group",
  回收站: "Trash",
  收藏条目: "Favorite Items",
  所有条目: "All Items",
  独立保险库: "Local Vault",
  有未保存修改: "Unsaved changes",
  正在加密保存: "Encrypting and saving",
  已加密保存: "Encrypted and saved",
  "保存状态需要确认，请保留候选文件并选择另存为。":
    "The save status needs confirmation. Keep the candidate file and use Save As.",
  关闭: "Close",
  保险库导航: "Vault navigation",
  返回所有条目: "Return to all items",
  作者: "Author",
  "作者：": "Author: ",
  分组: "Groups",
  新建分组: "New group",
  当前条目标签: "Current item tags",
  工具: "Tools",
  导入: "Import",
  备份与恢复: "Backup & Restore",
  浏览器扩展: "Browser Extension",
  设置: "Settings",
  条目列表: "Item list",
  "搜索密码、账号或网址": "Search passwords, accounts, or websites",
  条目排序: "Sort items",
  排序: "Sort",
  "标题 A–Z": "Title A–Z",
  最近修改: "Recently Modified",
  最近创建: "Recently Created",
  "标题 Z–A": "Title Z–A",
  添加: "Add",
  账号密码: "Login",
  "用户名、密码与网址": "Username, password, and website",
  安全笔记: "Secure Note",
  保存私密文本内容: "Store private text",
  条目详情: "Item details",
  条目已加密保存: "Item encrypted and saved",
  条目状态已保存: "Item status saved",
  未分组: "No group",
  导入记录已加密保存: "Imported records encrypted and saved",
  安全设置已保存: "Security settings saved",
  "主密码已修改；恢复密钥已失效，请重新生成":
    "Master password changed. The recovery key is now invalid; generate a new one.",
  选择保险库保存位置: "Choose where to save the vault",
  "打开 StarAxis 保险库": "Open StarAxis Vault",
  "panda8 的 GitHub 主页": "panda8's GitHub profile",
  最近使用的保险库: "Recent vaults",
  最近使用: "Recent",
  文件不可用: "File unavailable",
  新建保险库: "Create Vault",
  解锁保险库: "Unlock Vault",
  创建个人保险库: "Create your personal vault",
  欢迎回来: "Welcome back",
  创建保险库: "Create Vault",
  打开保险库: "Open Vault",
  "一个安静、安全的地方，保存你最重要的数字凭据。数据只留在你的设备上。":
    "A quiet, secure place for your most important digital credentials. Your data stays on your device.",
  保存位置: "Save location",
  保险库文件: "Vault file",
  绝对文件路径: "Absolute file path",
  请选择新保险库的保存位置: "Choose where to save the new vault",
  "请选择要打开的 .panda8 或旧版 .vaultx 文件":
    "Choose a .panda8 vault or a legacy .vaultx file",
  "选择位置…": "Choose Location…",
  "选择文件…": "Choose File…",
  继续创建: "Continue",
  解锁: "Unlock",
  主密码: "Master password",
  输入主密码: "Enter master password",
  "本地加密 · 不上传秘密 · 文件由你保管":
    "Encrypted locally · Secrets never uploaded · You own the file",
  刚刚: "Just now",
  账: "L",
  记: "N",
  登录项: "Login",
  当前版本: "Current version",
  账号: "Account",
  笔记: "Note",
  用户名: "Username",
  未填写: "Not provided",
  密码: "Password",
  网站: "Website",
  备注: "Notes",
  安全内容: "Secure content",
  已收藏: "Favorited",
  收藏: "Favorite",
  在编辑页面修改收藏状态: "Change favorite status while editing",
  编辑: "Edit",
  更多操作: "More actions",
  恢复: "Restore",
  返回原分组: "Return to the original group",
  移动到回收站: "Move to Trash",
  之后仍可恢复: "You can restore it later",
  永久删除: "Delete Permanently",
  此操作无法撤销: "This cannot be undone",
  未命名条目: "Untitled item",
  标签: "Tags",
  遮盖: "Hide",
  显示: "Show",
  自定义字段: "Custom field",
  不可恢复操作: "Irreversible action",
  可恢复操作: "Recoverable action",
  "永久删除这个条目？": "Permanently delete this item?",
  "移动到回收站？": "Move this item to Trash?",
  "将从保险库中永久移除，删除后无法恢复。":
    "This item will be permanently removed from the vault and cannot be recovered.",
  "会先安全移入回收站，再完成不可恢复删除。":
    "The item will first be moved safely to Trash, then permanently deleted.",
  "会进入回收站，之后仍可恢复。":
    "The item will be moved to Trash and can be restored later.",
  暂时无法打开条目: "Unable to open this item",
  正在打开条目: "Opening item",
  "请重试，或检查保险库是否仍处于解锁状态。":
    "Try again, or make sure the vault is still unlocked.",
  选择一条记录: "Select an item",
  "秘密只在需要时进入详情视图。":
    "Secrets enter the detail view only when needed.",
  编辑分组: "Edit Group",
  关闭分组窗口: "Close group window",
  "例如：工作、个人、家庭": "For example: Work, Personal, Family",
  "删除 Root 后，一个子分组会成为新根；Root 中的条目和其他子分组会一并安全迁移。":
    "After deleting Root, one child group becomes the new root. Items and other child groups are moved safely.",
  "保险库必须至少保留一个分组。创建子分组后即可删除 Root。":
    "A vault must keep at least one group. Create a child group before deleting Root.",
  "分组用于整理条目，不会改变文件的加密方式。":
    "Groups organize items and do not change how the file is encrypted.",
  再次点击确认删除: "Click again to confirm deletion",
  删除空分组: "Delete Empty Group",
  "删除 Root 分组": "Delete Root Group",
  "正在保存…": "Saving…",
  保存: "Save",
  创建分组: "Create Group",
  标题: "Title",
  "例如：Apple ID、公司邮箱": "For example: Apple ID, Work Email",
  "例如：服务器恢复说明": "For example: Server Recovery Notes",
  取消收藏: "Remove from Favorites",
  添加收藏: "Add to Favorites",
  保险库中的存放位置: "Location in vault",
  使用逗号分隔: "Separate with commas",
  "例如：工作, 邮箱": "For example: Work, Email",
  支持每行一个账号: "One account per line",
  当前可见: "Currently visible",
  默认安全遮盖: "Hidden by default",
  遮盖密码: "Hide password",
  显示密码: "Show password",
  复制密码: "Copy password",
  用于浏览器扩展匹配: "Used for browser extension matching",
  可为每个网址单独设置: "Configure each website separately",
  网址填充范围: "Website fill scope",
  不参与网站匹配: "Excluded from website matching",
  "添加与该账号相关的说明…": "Add notes related to this account…",
  随保险库加密保存在本地: "Encrypted locally with the vault",
  "输入需要安全保存的内容…": "Enter content to store securely…",
  "永久删除会移除当前记录并留下 tombstone，确定继续？":
    "Permanent deletion removes this record and leaves a tombstone. Continue?",
  "将条目移到回收站？": "Move this item to Trash?",
  保存修改: "Save Changes",
  按需保存额外信息: "Store additional information when needed",
  字段名: "Field name",
  值: "Value",
  密码生成器: "Password Generator",
  字符: "characters",
  "正在生成…": "Generating…",
  "选择要导入的 CSV 文件": "Choose a CSV file to import",
  "CSV 文件": "CSV files",
  "保存 CSV 导入模板": "Save CSV import template",
  "CSV 导入": "CSV Import",
  "选择 CSV 文件，核对字段映射并预览后再一次性导入。":
    "Choose a CSV file, review the field mapping and preview, then import everything at once.",
  明文警告: "Plaintext Warning",
  "文件只在本机读取，完整解析成功后才允许导入。最大 64 MB。":
    "The file is read only on this device and can be imported only after complete parsing. Maximum 64 MB.",
  "重新选择…": "Choose Again…",
  "正在导入并保存…": "Importing and saving…",
  全部导入: "Import All",
  选择备份保存位置: "Choose where to save the backup",
  选择要恢复的备份: "Choose a backup to restore",
  保存恢复后的保险库: "Save the restored vault",
  "创建一份完整加密副本，或从已有备份恢复保险库。":
    "Create a complete encrypted copy, or restore a vault from an existing backup.",
  备份恢复模式: "Backup and restore mode",
  创建加密备份: "Create Encrypted Backup",
  尚未选择保存位置: "No save location selected",
  备份保存位置: "Backup save location",
  "正在创建备份…": "Creating backup…",
  恢复为新的保险库: "Restore as a New Vault",
  "推荐方式。不会覆盖当前保险库，确认无误后再自行切换。":
    "Recommended. This does not overwrite the current vault; switch after verifying the restored file.",
  "选择一个 .panda8 或旧版 .vaultx 备份文件":
    "Choose a .panda8 or legacy .vaultx backup file",
  备份文件: "Backup file",
  用于验证备份完整性: "Used to verify backup integrity",
  新保险库不会覆盖现有文件: "The new vault will not overwrite an existing file",
  恢复文件保存位置: "Restored vault location",
  "正在验证并恢复…": "Verifying and restoring…",
  验证并恢复: "Verify & Restore",
  "高级选项：替换当前保险库": "Advanced: Replace Current Vault",
  "最后确认：用已验证备份替换当前保险库，并保留回滚副本？":
    "Final confirmation: replace the current vault with the verified backup and keep a rollback copy?",
  密钥与恢复: "Keys & Recovery",
  恢复密钥: "Recovery Key",
  "生成高熵恢复槽后，必须抄写并试恢复确认。密钥只显示一次。":
    "After generating a high-entropy recovery slot, copy the key and confirm it with a test restore. The key is shown only once.",
  "离线保存后，在下方重新输入以完成试恢复。":
    "Save it offline, then enter it below to complete a test restore.",
  恢复密钥试恢复成功: "Recovery key test succeeded",
  恢复密钥不匹配: "Recovery key does not match",
  修改主密码: "Change Master Password",
  待确认配对: "Pending Pairing",
  请核对扩展弹窗中的六位数字:
    "Verify the six-digit code shown in the extension",
  已拒绝浏览器配对: "Browser pairing rejected",
  浏览器扩展已安全配对: "Browser extension paired securely",
  已配对浏览器: "Paired Browsers",
  尚未连接浏览器: "No browsers connected",
  "安装扩展并点击“开始配对”，请求会在这里出现。":
    'Install the extension and click "Start Pairing"; the request will appear here.',
  浏览器配对已撤销: "Browser pairing revoked",
  桌面端唯一解密: "Desktop-only decryption",
  "精确 HTTPS 匹配": "Exact HTTPS matching",
  锁定立即拒绝: "Immediate rejection when locked",
  "撤销全部浏览器配对？所有扩展都需要重新确认。":
    "Revoke all browser pairings? Every extension will need to be approved again.",
  全部浏览器配对已撤销: "All browser pairings revoked",
  尚未使用: "Never used",
  安全设置: "Security Settings",
  保险库安全: "Vault Security",
  "管理当前已打开保险库的主密码。修改时会验证旧密码，并更新密钥派生参数。":
    "Manage the master password for the open vault. Changes verify the old password and update key derivation parameters.",
  当前能力: "Current Capabilities",
  "✓ 本地独立文件": "✓ Local standalone file",
  "✓ 条件剪贴板清理": "✓ Conditional clipboard clearing",
  "△ 截图防护依赖平台": "△ Screenshot protection depends on the platform",
  "△ 系统剪贴板历史无法清除": "△ System clipboard history cannot be cleared",
  "自动锁定（秒，0 为关闭）": "Auto-lock (seconds, 0 to disable)",
  "剪贴板条件清理（秒）": "Conditional clipboard clearing (seconds)",
  "同目录自动备份保留版本数（0 为关闭）":
    "Automatic backup versions in the same folder (0 to disable)",
  "每次提交前备份上一个已认证密文版本；降低数量后会尽力清理应用管理的旧自动备份。":
    "Before each commit, back up the previous authenticated ciphertext version. Reducing the count removes older app-managed backups when possible.",
  最小化时锁定保险库: "Lock vault when minimized",
  保存设置: "Save Settings",
  两次输入的新主密码不一致: "The new passwords do not match",
  新主密码需要与当前主密码不同:
    "The new password must be different from the current password",
  当前主密码不正确: "The current master password is incorrect",
  关闭修改主密码窗口: "Close change master password window",
  "此操作只影响当前保险库。StarAxis 不会保存或找回你的主密码。":
    "This affects only the current vault. StarAxis never stores or recovers your master password.",
  "请使用足够长且唯一的主密码。StarAxis 无法替你找回未配置恢复密钥的密码。":
    "Use a long, unique master password. StarAxis cannot recover it unless you configure a recovery key.",
  当前主密码: "Current master password",
  新主密码: "New master password",
  确认新主密码: "Confirm new master password",
  隐藏所有密码: "Hide all passwords",
  显示所有密码: "Show all passwords",
  "正在修改…": "Changing…",
  尚未选择保险库: "No vault selected",
  已连接: "Connected",
  "打开 StarAxis 选择保险库": "Open StarAxis to choose a vault",
  完成: "Done",
  "解锁中…": "Unlocking…",
  密码只在本机内存中用于本次解锁:
    "The password is used only in local memory for this unlock",
  语言: "Language",
  语言选择: "Language selection",
  选择应用显示语言: "Choose the application display language",
  个条目: "items",
  个保险库: "vaults",
  "· 最近更新于": "· Last updated",
  复制: "Copy",
  取消: "Cancel",
  重新加载: "Reload",
  分组名称: "Group name",
  生成: "Generate",
  网站地址: "Website address",
  填充范围: "Fill scope",
  填写网站地址后可设置填充范围:
    "Enter a website address to configure its fill scope",
  "历史版本 ·": "History ·",
  恢复条目: "Restore Item",
  移到回收站: "Move to Trash",
  "剪贴板清理策略：": "Clipboard clearing policy: ",
  "秒；系统剪贴板历史不受此策略控制。":
    " seconds; system clipboard history is not affected by this policy.",
  "＋ 添加": "＋ Add",
  重新生成: "Regenerate",
  使用此密码: "Use This Password",
  "下载 CSV 模板": "Download CSV Template",
  "CSV 通常包含整库明文。StarAxis 不创建明文临时文件，也不会把字段值写入错误报告；导入后请自行检查云盘、备份和回收站残留。":
    "CSV files usually contain an entire vault in plaintext. StarAxis creates no plaintext temporary files and never writes field values to error reports. After importing, check cloud drives, backups, and Trash for leftover copies.",
  "选择 CSV 文件": "Choose CSV File",
  目标分组: "Destination group",
  解析并预览: "Parse & Preview",
  已完整解析: "Fully parsed",
  "条，仅展示前": "records; showing the first",
  "条。": "records.",
  创建备份: "Create Backup",
  从备份恢复: "Restore from Backup",
  "选择保存位置后即可完成。未保存的修改会先安全提交，再复制当前加密版本。":
    "Choose a save location to finish. Unsaved changes are committed safely before the current encrypted version is copied.",
  "备份保持完整加密，可使用主密码或恢复密钥验证。":
    "The backup remains fully encrypted and can be verified with a master password or recovery key.",
  "1. 选择备份文件": "1. Choose a backup file",
  "2. 输入备份密码或恢复密钥": "2. Enter the backup password or recovery key",
  "3. 选择恢复后的保存位置": "3. Choose where to save the restored vault",
  "StarAxis 会先保留当前密文作为回滚副本，再用上方选择的备份替换并立即锁定。":
    "StarAxis keeps the current ciphertext as a rollback copy, replaces it with the selected backup, and immediately locks the vault.",
  当前保险库主密码: "Current vault master password",
  保留旧版并替换当前保险库: "Keep a Rollback Copy and Replace Current Vault",
  "为当前保险库增加独立的离线恢复凭据，或轮换主密码与密钥派生参数。StarAxis 不会上传、代管或在线找回这些凭据。":
    "Add an independent offline recovery credential, or rotate the master password and key derivation parameters. StarAxis never uploads, holds, or recovers these credentials online.",
  用于生成恢复密钥的当前主密码:
    "Current master password used to generate a recovery key",
  生成并写入恢复槽: "Generate and Add Recovery Slot",
  确认试恢复: "Confirm Test Recovery",
  "验证当前主密码后设置新密码，同时升级当前保险库的 Argon2id 参数。修改后需要重新生成恢复密钥。":
    "Verify the current master password, set a new one, and upgrade this vault's Argon2id parameters. Generate a new recovery key afterward.",
  "修改主密码…": "Change Master Password…",
  "在 Chrome、Edge 或 Firefox 中点击账号后，由当前已解锁保险库完成一次性安全填充。":
    "Choose an account in Chrome, Edge, or Firefox for a one-time secure fill from the currently unlocked vault.",
  拒绝: "Reject",
  "代码一致，允许": "Codes Match, Allow",
  个浏览器配置: "browser profiles",
  指纹: "Fingerprint",
  撤销: "Revoke",
  "扩展不读取保险库文件，也不保存主密码、Vault Key 或密码缓存。":
    "The extension cannot read vault files and never stores the master password, Vault Key, or a password cache.",
  "默认不在 HTTP、iframe、相似域名和没有精确 URL 匹配的页面填充。":
    "By default, filling is disabled on HTTP pages, iframes, look-alike domains, and pages without an exact URL match.",
  "保险库锁定后，候选查询和秘密释放都会被桌面端拒绝。":
    "When the vault is locked, the desktop app rejects credential queries and secret release requests.",
  撤销全部浏览器配对: "Revoke All Browser Pairings",
  "密钥与恢复…": "Keys & Recovery…",
  "当前保险库的旧主密码和恢复密钥将失效；历史备份及复制到其他位置的旧文件仍可能被旧凭据打开。":
    "The old master password and recovery key for this vault will stop working. Historical backups and old file copies elsewhere may still open with the old credentials.",
  "已复制，将在": "Copied. Conditional clearing will be attempted in",
  秒后尝试条件清除: "seconds",
  "修改已保留在当前会话，但自动保存未完成：":
    "The change remains in this session, but automatic saving did not complete: ",
  "。请使用顶部“保存”重试，不要重复操作。":
    '. Use "Save" at the top to retry; do not repeat the operation.',
  "。请不要重复提交，使用顶部“保存”重试。":
    '. Do not submit again; use "Save" at the top to retry.',
  分钟前: "minutes ago",
  小时前: "hours ago",
  天前: "days ago",
  "CSV 模板已保存到": "CSV template saved to",
  已解析: "Parsed",
  "条记录，请确认预览": "records. Review the preview.",
  "导入已保留在当前会话，但自动保存未完成：":
    "The import remains in this session, but automatic saving did not complete: ",
  "。请使用顶部“保存”重试，不要重复导入。":
    '. Use "Save" at the top to retry; do not import again.',
  加密备份已保存到: "Encrypted backup saved to",
  备份已验证并恢复到: "Backup verified and restored to",
  "已替换并锁定；旧版本保留在":
    "Replaced and locked; the previous version was kept at",
  最后使用: "Last used",
};

const listeners = new Set<() => void>();

function isLocale(value: string | null): value is AppLocale {
  return value === "en" || value === "zh-CN";
}

export function getAppLocale(): AppLocale {
  if (typeof window === "undefined") return DEFAULT_LOCALE;
  const stored = window.localStorage.getItem(LOCALE_STORAGE_KEY);
  return isLocale(stored) ? stored : DEFAULT_LOCALE;
}

export function setAppLocale(locale: AppLocale) {
  if (typeof window !== "undefined") {
    window.localStorage.setItem(LOCALE_STORAGE_KEY, locale);
  }
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function useAppLocale(): [AppLocale, (locale: AppLocale) => void] {
  const locale = useSyncExternalStore(
    subscribe,
    getAppLocale,
    () => DEFAULT_LOCALE,
  );
  return [locale, setAppLocale];
}

function preserveWhitespace(original: string, translated: string) {
  const leading = original.match(/^\s*/)?.[0] ?? "";
  const trailing = original.match(/\s*$/)?.[0] ?? "";
  return `${leading}${translated}${trailing}`;
}

export function translateText(
  source: string,
  locale: AppLocale = getAppLocale(),
) {
  if (locale === "zh-CN" || !source.trim()) return source;
  const trimmed = source.trim();
  const exact = translations[trimmed];
  if (exact) return preserveWhitespace(source, exact);

  const itemCount = trimmed.match(/^(\d+) 个条目$/);
  if (itemCount) {
    const count = Number(itemCount[1]);
    return preserveWhitespace(
      source,
      `${count} ${count === 1 ? "item" : "items"}`,
    );
  }
  const vaultCount = trimmed.match(/^(\d+) 个保险库$/);
  if (vaultCount) {
    const count = Number(vaultCount[1]);
    return preserveWhitespace(
      source,
      `${count} ${count === 1 ? "vault" : "vaults"}`,
    );
  }
  const browserCount = trimmed.match(/^(\d+) 个浏览器配置$/);
  if (browserCount) {
    const count = Number(browserCount[1]);
    return preserveWhitespace(
      source,
      `${count} browser ${count === 1 ? "profile" : "profiles"}`,
    );
  }
  const tagCount = trimmed.match(/^(\d+) 标签$/);
  if (tagCount) return preserveWhitespace(source, `${tagCount[1]} tags`);
  const characters = trimmed.match(/^(\d+) 字符$/);
  if (characters)
    return preserveWhitespace(source, `${characters[1]} characters`);
  const history = trimmed.match(/^历史版本 · (\d+)$/);
  if (history) return preserveWhitespace(source, `History · ${history[1]}`);
  const importConfirmation = trimmed.match(
    /^将 (\d+) 条记录作为一个事务导入？$/,
  );
  if (importConfirmation) {
    return preserveWhitespace(
      source,
      `Import ${importConfirmation[1]} records as one transaction?`,
    );
  }
  const copied = trimmed.match(/^已复制，将在 (\d+) 秒后尝试条件清除$/);
  if (copied) {
    return preserveWhitespace(
      source,
      `Copied. Conditional clearing will be attempted in ${copied[1]} seconds.`,
    );
  }

  return source;
}

const originalText = new WeakMap<Text, string>();
const lastLocalizedText = new WeakMap<Text, string>();
const originalAttributes = new WeakMap<Element, Map<string, string>>();
const lastLocalizedAttributes = new WeakMap<Element, Map<string, string>>();
const localizedAttributes = ["aria-label", "title", "placeholder"] as const;

function isSkipped(node: Node) {
  const element =
    node.nodeType === Node.ELEMENT_NODE
      ? (node as Element)
      : node.parentElement;
  return Boolean(element?.closest("[data-i18n-skip]"));
}

function localizeTextNode(node: Text, locale: AppLocale) {
  if (isSkipped(node)) return;
  const previousLocalized = lastLocalizedText.get(node);
  if (
    !originalText.has(node) ||
    (previousLocalized !== undefined && node.data !== previousLocalized)
  ) {
    originalText.set(node, node.data);
  }
  const source = originalText.get(node) ?? node.data;
  const next = translateText(source, locale);
  lastLocalizedText.set(node, next);
  if (node.data !== next) node.data = next;
}

function localizeElement(element: Element, locale: AppLocale) {
  if (isSkipped(element)) return;
  let originals = originalAttributes.get(element);
  let previousLocalized = lastLocalizedAttributes.get(element);
  if (!originals) {
    originals = new Map();
    originalAttributes.set(element, originals);
  }
  if (!previousLocalized) {
    previousLocalized = new Map();
    lastLocalizedAttributes.set(element, previousLocalized);
  }
  for (const attribute of localizedAttributes) {
    if (!element.hasAttribute(attribute)) continue;
    const current = element.getAttribute(attribute) ?? "";
    if (
      !originals.has(attribute) ||
      (previousLocalized.has(attribute) &&
        current !== previousLocalized.get(attribute))
    ) {
      originals.set(attribute, current);
    }
    const source = originals.get(attribute) ?? "";
    let next = translateText(source, locale);
    if (locale === "en") {
      next = next
        .replaceAll("，已加密保存", ", encrypted and saved")
        .replaceAll("，正在加密保存", ", encrypting and saving")
        .replaceAll("，有未保存修改", ", unsaved changes")
        .replace(/^作者 (.+)$/, "Author $1")
        .replace(/^作者：(.+)$/, "Author: $1")
        .replace(/^管理分组 (.+)$/, "Manage group $1")
        .replace(/^从最近列表移除 (.+)$/, "Remove $1 from recent vaults")
        .replace(/^(.+) 的填充范围$/, "Fill scope for $1");
    }
    previousLocalized.set(attribute, next);
    if (element.getAttribute(attribute) !== next) {
      element.setAttribute(attribute, next);
    }
  }
}

function localizeTree(root: Node, locale: AppLocale) {
  if (root.nodeType === Node.TEXT_NODE) localizeTextNode(root as Text, locale);
  if (root.nodeType === Node.ELEMENT_NODE) {
    localizeElement(root as Element, locale);
  }
  const walker = document.createTreeWalker(
    root,
    NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT,
  );
  let node = walker.nextNode();
  while (node) {
    if (node.nodeType === Node.TEXT_NODE)
      localizeTextNode(node as Text, locale);
    else localizeElement(node as Element, locale);
    node = walker.nextNode();
  }
}

export function useDocumentLocalization(rootId = "root") {
  const [locale] = useAppLocale();

  useLayoutEffect(() => {
    const root = document.getElementById(rootId) ?? document.body;
    if (!root) return;
    document.documentElement.lang = locale;
    document.title = "StarAxis";
    localizeTree(root, locale);

    const observer = new MutationObserver((records) => {
      for (const record of records) {
        if (record.type === "characterData") {
          localizeTextNode(record.target as Text, locale);
        } else if (record.type === "attributes") {
          localizeElement(record.target as Element, locale);
        } else {
          for (const node of record.addedNodes) localizeTree(node, locale);
        }
      }
    });
    observer.observe(root, {
      subtree: true,
      childList: true,
      characterData: true,
      attributes: true,
      attributeFilter: [...localizedAttributes],
    });
    return () => observer.disconnect();
  }, [locale, rootId]);
}

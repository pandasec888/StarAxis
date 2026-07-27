import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import {
  open as openDialog,
  save as saveDialog,
} from "@tauri-apps/plugin-dialog";

import { command, idKey, isTauriRuntime, sameId } from "./api";
import type {
  CsvMapping,
  CsvPreview,
  Group,
  Id,
  ItemDetail,
  ItemKind,
  ItemSort,
  ItemSummary,
  PairedExtension,
  PendingExtensionPair,
  RecentVault,
  SessionState,
  Settings,
  UrlMatchMode,
} from "./api";
import {
  clearClipboardIfUnchanged,
  copyWithConditionalClear,
} from "./clipboard";
import type { ClipboardLease } from "./clipboard";
import {
  VAULT_DIALOG_FILTERS,
  VAULT_EXTENSION,
  withVaultExtension,
} from "./vault-path";
import { translateText, useAppLocale, useDocumentLocalization } from "./i18n";
import appIconUrl from "../assets/icon.svg";

type WorkspaceView =
  | "items"
  | "trash"
  | "import"
  | "backup"
  | "security"
  | "extensions"
  | "settings";

type GroupEditorState = { mode: "create" } | { mode: "rename"; group: Group };

const PRODUCT_AUTHOR = "panda8";
const AUTHOR_GITHUB_URL = "https://github.com/pandasec888/";

const DEFAULT_SETTINGS: Settings = {
  auto_lock_seconds: 300,
  clipboard_clear_seconds: 30,
  lock_on_minimize: false,
  backup_versions: 3,
};

const DEFAULT_MAPPING: CsvMapping = {
  title: "name",
  username: "login",
  password: "password",
  url: "url",
  notes: "notes",
  tags: "tags",
};

const splitTags = (value: string) =>
  value
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);

const urlMatchModeLabel = (mode: UrlMatchMode) => {
  switch (mode) {
    case "anywhere_on_website":
      return "整个网站";
    case "exact_host":
      return "精确主机";
    case "never":
      return "禁止填充";
  }
};

const fileNameFromPath = (path: string) =>
  path.split(/[\\/]/).filter(Boolean).pop() || path;

function messageOf(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}

export function App() {
  useDocumentLocalization();
  const [locale, setLocale] = useAppLocale();
  const [session, setSession] = useState<SessionState>("locked");
  const [activePath, setActivePath] = useState("");
  const [groups, setGroups] = useState<Group[]>([]);
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [settings, setSettings] = useState(DEFAULT_SETTINGS);
  const [view, setView] = useState<WorkspaceView>("items");
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<ItemSort>("title_ascending");
  const [favoriteOnly, setFavoriteOnly] = useState(false);
  const [selectedGroup, setSelectedGroup] = useState<Id | undefined>();
  const [selected, setSelected] = useState<ItemSummary | undefined>();
  const [detail, setDetail] = useState<ItemDetail | undefined>();
  const [editingDetail, setEditingDetail] = useState(false);
  const [localDirty, setLocalDirty] = useState(false);
  const [addMenuOpen, setAddMenuOpen] = useState(false);
  const [groupEditor, setGroupEditor] = useState<GroupEditorState>();
  const [passwordDialogOpen, setPasswordDialogOpen] = useState(false);
  const [notice, setNotice] = useState<string>();
  const [error, setError] = useState<string>();
  const [clipboardLease, setClipboardLease] = useState<ClipboardLease | null>(
    null,
  );
  const [clipboardRemaining, setClipboardRemaining] = useState(0);
  const searchRef = useRef<HTMLInputElement>(null);

  const clearSensitiveUi = useCallback(async () => {
    setDetail(undefined);
    setSelected(undefined);
    setEditingDetail(false);
    setLocalDirty(false);
    setPasswordDialogOpen(false);
    await clearClipboardIfUnchanged(clipboardLease);
    setClipboardLease(null);
    setClipboardRemaining(0);
  }, [clipboardLease]);

  const refresh = useCallback(async () => {
    const includeDeleted = view === "trash";
    const [nextGroups, nextItems, nextSettings] = await Promise.all([
      command<Group[]>("list_groups"),
      command<ItemSummary[]>("list_items", {
        query,
        filter: {
          group_id: selectedGroup,
          kind: null,
          favorite_only: favoriteOnly,
          include_deleted: includeDeleted,
        },
        sort,
        offset: 0,
        limit: 200,
      }),
      command<Settings>("get_settings"),
    ]);
    setGroups(nextGroups);
    setItems(
      includeDeleted ? nextItems.filter((item) => item.deleted) : nextItems,
    );
    setSettings(nextSettings);
  }, [favoriteOnly, query, selectedGroup, sort, view]);

  useEffect(() => {
    if (!isTauriRuntime()) return;
    let cancelled = false;
    const poll = async () => {
      try {
        const next = await command<SessionState>("session_state");
        if (cancelled) return;
        setSession(next);
        if (next === "locked") await clearSensitiveUi();
      } catch {
        // Startup errors are shown when the user performs an explicit action.
      }
    };
    void poll();
    const timer = window.setInterval(() => void poll(), 1_000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [clearSensitiveUi]);

  useEffect(() => {
    if (!isTauriRuntime() || session === "locked") return;
    let lastRecordedAt = 0;
    const recordActivity = () => {
      const now = Date.now();
      if (now - lastRecordedAt < 1_000) return;
      lastRecordedAt = now;
      void command("record_user_activity").catch(() => {
        // The state poll owns lock/error presentation; activity reporting is best effort.
      });
    };
    window.addEventListener("pointerdown", recordActivity);
    window.addEventListener("keydown", recordActivity);
    window.addEventListener("input", recordActivity);
    return () => {
      window.removeEventListener("pointerdown", recordActivity);
      window.removeEventListener("keydown", recordActivity);
      window.removeEventListener("input", recordActivity);
    };
  }, [session]);

  useEffect(() => {
    if (session === "unlocked" || session === "dirty") {
      void refresh().catch((cause) => setError(messageOf(cause)));
    }
  }, [refresh, session]);

  useEffect(() => {
    if (!clipboardLease) return;
    const tick = async () => {
      const remaining = Math.max(
        0,
        Math.ceil((clipboardLease.expiresAt - Date.now()) / 1_000),
      );
      setClipboardRemaining(remaining);
      if (remaining === 0) {
        await clearClipboardIfUnchanged(clipboardLease);
        setClipboardLease(null);
      }
    };
    void tick();
    const timer = window.setInterval(() => void tick(), 1_000);
    return () => window.clearInterval(timer);
  }, [clipboardLease]);

  useEffect(() => {
    if (!notice) return;
    const timer = window.setTimeout(() => setNotice(undefined), 3_200);
    return () => window.clearTimeout(timer);
  }, [notice]);

  useEffect(() => {
    const beforeUnload = (event: BeforeUnloadEvent) => {
      if (localDirty || session === "dirty") {
        event.preventDefault();
        event.returnValue = "";
      }
    };
    window.addEventListener("beforeunload", beforeUnload);
    return () => window.removeEventListener("beforeunload", beforeUnload);
  }, [localDirty, session]);

  useEffect(() => {
    const shortcuts = (event: globalThis.KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        searchRef.current?.focus();
      }
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "s") {
        event.preventDefault();
        if (session === "dirty") void saveVault();
      }
    };
    window.addEventListener("keydown", shortcuts);
    return () => window.removeEventListener("keydown", shortcuts);
  });

  async function openSession(
    path: string,
    mode: "create" | "open",
    password: string,
  ) {
    setError(undefined);
    await command(mode === "create" ? "create_vault" : "unlock_vault", {
      path,
      password,
    });
    setActivePath(path);
    setSession("unlocked");
    setView("items");
    setNotice(mode === "create" ? "保险库已创建" : "保险库已解锁");
  }

  async function saveVault() {
    try {
      await command("save_vault");
      setSession("unlocked");
      setNotice("已安全保存到独立加密文件");
      setError(undefined);
    } catch (cause) {
      const text = messageOf(cause);
      setError(text);
      try {
        setSession(await command<SessionState>("session_state"));
      } catch {
        if (text.includes("candidate") || text.includes("changed externally"))
          setSession("conflict_pending");
      }
    }
  }

  function selectItem(item: ItemSummary) {
    if (
      localDirty &&
      !window.confirm(translateText("当前编辑尚未提交，确定切换条目吗？"))
    )
      return;
    setSelected(item);
    setDetail(undefined);
    setEditingDetail(false);
    setLocalDirty(false);
  }

  async function copySecret(value: string) {
    if (
      !window.confirm(
        translateText(
          "秘密将进入系统剪贴板；历史记录或其他应用仍可能保留它。继续吗？",
        ),
      )
    )
      return;
    const lease = await copyWithConditionalClear(
      value,
      settings.clipboard_clear_seconds,
    );
    setClipboardLease(lease);
    setNotice(
      `已复制，将在 ${settings.clipboard_clear_seconds} 秒后尝试条件清除`,
    );
  }

  async function handleSubmittedMutationFailure(
    cause: unknown,
    onApplied: () => Promise<void>,
  ): Promise<boolean> {
    const message = messageOf(cause);
    try {
      const nextSession = await command<SessionState>("session_state");
      if (
        nextSession === "dirty" ||
        nextSession === "conflict_pending" ||
        nextSession === "save_result_unknown"
      ) {
        setSession(nextSession);
        await onApplied();
        setError(
          `修改已保留在当前会话，但自动保存未完成：${message}。请使用顶部“保存”重试，不要重复操作。`,
        );
        return true;
      }
    } catch {
      // Preserve the original mutation error when state inspection fails.
    }
    setError(message);
    return false;
  }

  async function deleteDetailItem(permanent: boolean) {
    if (!detail?.id.length) return;

    const clearDeletedDetail = async () => {
      setDetail(undefined);
      setSelected(undefined);
      setEditingDetail(false);
      setLocalDirty(false);
      await refresh();
    };

    let movedToTrashFirst = false;
    try {
      if (permanent && view !== "trash") {
        await command("soft_delete_item", { id: detail.id });
        movedToTrashFirst = true;
      }
      await command(
        permanent ? "permanently_delete_item" : "soft_delete_item",
        {
          id: detail.id,
        },
      );
      setSession("unlocked");
      setError(undefined);
      setNotice(permanent ? "条目已永久删除" : "条目已移动到回收站");
      await clearDeletedDetail();
    } catch (cause) {
      const mutationWasApplied = await handleSubmittedMutationFailure(
        cause,
        clearDeletedDetail,
      );
      if (!mutationWasApplied && movedToTrashFirst) {
        setNotice("永久删除未完成，条目已安全保留在回收站");
        await clearDeletedDetail();
      }
    }
  }

  async function restoreDetailItem() {
    if (!detail?.id.length) return;

    const clearRestoredDetail = async () => {
      setDetail(undefined);
      setSelected(undefined);
      setEditingDetail(false);
      setLocalDirty(false);
      await refresh();
    };

    try {
      await command("restore_item", { id: detail.id });
      setSession("unlocked");
      setError(undefined);
      setNotice("条目已恢复");
      await clearRestoredDetail();
    } catch (cause) {
      await handleSubmittedMutationFailure(cause, clearRestoredDetail);
    }
  }

  async function saveGroup(name: string) {
    const root = groups.find((group) => !group.parent_id) || groups[0];
    if (!root) {
      setError("当前保险库没有可用的根分组");
      return;
    }
    const action =
      groupEditor?.mode === "rename"
        ? command("rename_group", {
            id: groupEditor.group.id,
            name,
          })
        : command("create_group", { parentId: root.id, name });
    try {
      await action;
      setSession("unlocked");
      setNotice(
        groupEditor?.mode === "rename"
          ? "分组已重命名并保存"
          : "分组已创建并保存",
      );
      setGroupEditor(undefined);
      await refresh();
    } catch (cause) {
      if (await handleSubmittedMutationFailure(cause, refresh))
        setGroupEditor(undefined);
    }
  }

  async function deleteGroup(group: Group) {
    try {
      await command("delete_group", { id: group.id });
      if (sameId(group.id, selectedGroup)) setSelectedGroup(undefined);
      setSession("unlocked");
      setNotice(
        group.parent_id
          ? "空分组已删除并保存"
          : "Root 已删除，内容已安全移交到新的根分组",
      );
      setGroupEditor(undefined);
      await refresh();
    } catch (cause) {
      if (await handleSubmittedMutationFailure(cause, refresh))
        setGroupEditor(undefined);
    }
  }

  const allTags = useMemo(
    () =>
      Array.from(new Set(items.flatMap((item) => item.tags))).sort((a, b) =>
        a.localeCompare(b),
      ),
    [items],
  );
  const selectedGroupName = groups.find((group) =>
    sameId(group.id, selectedGroup),
  )?.name;
  const listTitle =
    view === "trash"
      ? "回收站"
      : favoriteOnly
        ? "收藏条目"
        : selectedGroupName || "所有条目";
  const vaultFileName = activePath.split(/[\\/]/).pop() || "独立保险库";
  const vaultStatusText =
    session === "dirty"
      ? "有未保存修改"
      : session === "saving"
        ? "正在加密保存"
        : "已加密保存";

  if (session === "locked") {
    return (
      <Welcome
        lastPath={activePath}
        onSubmit={(path, mode, password) => {
          void openSession(path, mode, password).catch((cause) =>
            setError(messageOf(cause)),
          );
        }}
        error={error}
      />
    );
  }

  return (
    <main className="vault-app">
      {(notice ||
        error ||
        session === "conflict_pending" ||
        session === "save_result_unknown") && (
        <div className={error ? "banner banner-error" : "banner"} role="status">
          <span>
            {error ||
              notice ||
              "保存状态需要确认，请保留候选文件并选择另存为。"}
          </span>
          <button
            onClick={() => (error ? setError(undefined) : setNotice(undefined))}
          >
            关闭
          </button>
        </div>
      )}

      <div className="workspace">
        <aside className="rail" aria-label="保险库导航">
          <button
            className="wordmark rail-wordmark"
            onClick={() => {
              setView("items");
              setFavoriteOnly(false);
            }}
            aria-label="返回所有条目"
          >
            <img
              className="rail-app-icon"
              src={appIconUrl}
              alt=""
              aria-hidden="true"
            />
            <span className="rail-brand-copy">
              <strong className="rail-brand-title">StarAxis</strong>
              <small
                className="brand-author rail-brand-author"
                aria-label={`作者 ${PRODUCT_AUTHOR}`}
                title={`作者：${PRODUCT_AUTHOR}`}
              >
                作者：<b>{PRODUCT_AUTHOR}</b>
              </small>
            </span>
          </button>
          <nav>
            <NavButton
              active={view === "items" && !favoriteOnly}
              icon="◫"
              meta={items.length}
              onClick={() => {
                setView("items");
                setFavoriteOnly(false);
                setSelectedGroup(undefined);
              }}
            >
              所有条目
            </NavButton>
            <NavButton
              active={view === "trash"}
              icon="⌫"
              onClick={() => setView("trash")}
            >
              回收站
            </NavButton>
          </nav>
          <div className="rail-section">
            <div className="section-title">
              <span>分组</span>
              <button
                type="button"
                aria-label="新建分组"
                title="新建分组"
                onClick={() => setGroupEditor({ mode: "create" })}
              >
                ＋
              </button>
            </div>
            {groups.map((group) => (
              <div className="group-row" key={idKey(group.id)}>
                <button
                  className={
                    sameId(group.id, selectedGroup) ? "mini active" : "mini"
                  }
                  onClick={() => setSelectedGroup(group.id)}
                  data-i18n-skip
                >
                  {group.name}
                </button>
                <button
                  aria-label={`管理分组 ${group.name}`}
                  onClick={() => setGroupEditor({ mode: "rename", group })}
                >
                  •••
                </button>
              </div>
            ))}
          </div>
          {allTags.length > 0 && (
            <div className="tag-cloud" aria-label="当前条目标签">
              {allTags.slice(0, 12).map((tag) => (
                <span key={tag} data-i18n-skip>
                  #{tag}
                </span>
              ))}
            </div>
          )}
          <p className="rail-section-label">工具</p>
          <nav className="utility-nav">
            <NavButton
              active={view === "import"}
              icon="↳"
              onClick={() => setView("import")}
            >
              导入
            </NavButton>
            <NavButton
              active={view === "backup"}
              icon="◇"
              onClick={() => setView("backup")}
            >
              备份与恢复
            </NavButton>
            <NavButton
              active={view === "extensions"}
              icon="⌁"
              onClick={() => setView("extensions")}
            >
              浏览器扩展
            </NavButton>
            <NavButton
              active={view === "settings"}
              icon="⚙"
              onClick={() => setView("settings")}
            >
              设置
            </NavButton>
          </nav>
          <section className="rail-language" aria-label="语言选择">
            <div className="rail-language-heading">
              <span>语言</span>
              <small aria-hidden="true">A / 文</small>
            </div>
            <div
              className="rail-language-selector"
              role="group"
              aria-label="语言"
            >
              <button
                type="button"
                className={locale === "en" ? "active" : ""}
                aria-pressed={locale === "en"}
                onClick={() => setLocale("en")}
                data-i18n-skip
              >
                English
              </button>
              <button
                type="button"
                className={locale === "zh-CN" ? "active" : ""}
                aria-pressed={locale === "zh-CN"}
                onClick={() => setLocale("zh-CN")}
                data-i18n-skip
              >
                简体中文
              </button>
            </div>
          </section>
          <div
            className="vault-status-slot"
            role="status"
            title={`${vaultFileName} · ${vaultStatusText}`}
            aria-label={`${vaultFileName}，${vaultStatusText}`}
          >
            <div className="rail-vault-status">
              <span className={`state-dot state-${session}`} />
              <span className="rail-vault-copy">
                <strong data-i18n-skip>{vaultFileName}</strong>
                <small>{vaultStatusText}</small>
              </span>
              {clipboardRemaining > 0 && (
                <span className="rail-clipboard">{clipboardRemaining}s</span>
              )}
            </div>
          </div>
        </aside>

        {view === "items" || view === "trash" ? (
          <>
            <section className="item-column" aria-label="条目列表">
              <div className="list-tools">
                <label className="searchbox">
                  <span>⌕</span>
                  <input
                    ref={searchRef}
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                    placeholder="搜索密码、账号或网址"
                  />
                  <kbd>⌘K</kbd>
                </label>
              </div>
              <div className="list-heading">
                <div>
                  <strong>{listTitle}</strong>
                  <small>{items.length} 个条目</small>
                </div>
                {view !== "trash" && (
                  <div className="list-heading-actions">
                    <label className="sort-picker" title="条目排序">
                      <span aria-hidden="true">⇅</span>
                      <select
                        value={sort}
                        onChange={(event) =>
                          setSort(event.target.value as ItemSort)
                        }
                        aria-label="排序"
                      >
                        <option value="title_ascending">标题 A–Z</option>
                        <option value="updated_newest">最近修改</option>
                        <option value="created_newest">最近创建</option>
                        <option value="title_descending">标题 Z–A</option>
                      </select>
                    </label>
                    <div
                      className="add-menu"
                      onBlur={(event) => {
                        if (!event.currentTarget.contains(event.relatedTarget))
                          setAddMenuOpen(false);
                      }}
                      onKeyDown={(event) => {
                        if (event.key === "Escape") setAddMenuOpen(false);
                      }}
                    >
                      <button
                        type="button"
                        className="add-trigger"
                        aria-haspopup="menu"
                        aria-expanded={addMenuOpen}
                        onClick={() => setAddMenuOpen((open) => !open)}
                      >
                        <span aria-hidden="true">＋</span>
                        添加
                      </button>
                      {addMenuOpen && (
                        <div className="add-popover" role="menu">
                          <button
                            type="button"
                            role="menuitem"
                            aria-label="账号密码"
                            onClick={() => {
                              startNew("login", groups, setDetail, setSelected);
                              setEditingDetail(true);
                              setAddMenuOpen(false);
                            }}
                          >
                            <span className="add-kind-icon">↗</span>
                            <span>
                              <strong>账号密码</strong>
                              <small>用户名、密码与网址</small>
                            </span>
                          </button>
                          <button
                            type="button"
                            role="menuitem"
                            aria-label="安全笔记"
                            onClick={() => {
                              startNew(
                                "secure_note",
                                groups,
                                setDetail,
                                setSelected,
                              );
                              setEditingDetail(true);
                              setAddMenuOpen(false);
                            }}
                          >
                            <span className="add-kind-icon">◇</span>
                            <span>
                              <strong>安全笔记</strong>
                              <small>保存私密文本内容</small>
                            </span>
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
              <VirtualItemList
                items={items}
                selected={selected}
                onSelect={selectItem}
              />
            </section>
            <section className="detail-column" aria-label="条目详情">
              {detail ? (
                editingDetail || !detail.id.length ? (
                  <ItemEditor
                    detail={detail}
                    inTrash={view === "trash"}
                    groups={groups}
                    settings={settings}
                    onDirty={() => setLocalDirty(true)}
                    onCancel={() => {
                      setLocalDirty(false);
                      if (detail.id.length) setEditingDetail(false);
                      else setDetail(undefined);
                    }}
                    onCopy={(value) => void copySecret(value)}
                    onSaved={async (savedDetail) => {
                      setLocalDirty(false);
                      setSession("unlocked");
                      setNotice("条目已加密保存");
                      setDetail(savedDetail);
                      setEditingDetail(false);
                      await refresh();
                    }}
                    onDeleted={async () => {
                      setDetail(undefined);
                      setSelected(undefined);
                      setEditingDetail(false);
                      setSession("unlocked");
                      setNotice("条目状态已保存");
                      await refresh();
                    }}
                    onPending={async (nextSession, cause) => {
                      setLocalDirty(false);
                      setSession(nextSession);
                      setDetail(undefined);
                      setSelected(undefined);
                      setEditingDetail(false);
                      await refresh();
                      setError(
                        `修改已保留在当前会话，但自动保存未完成：${cause}。请不要重复提交，使用顶部“保存”重试。`,
                      );
                    }}
                    onError={setError}
                  />
                ) : (
                  <ItemDetailView
                    detail={detail}
                    inTrash={view === "trash"}
                    groupName={
                      groups.find((group) => sameId(group.id, detail.group_id))
                        ?.name || "未分组"
                    }
                    onEdit={() => setEditingDetail(true)}
                    onCopy={(value) => void copySecret(value)}
                    onRestore={() => void restoreDetailItem()}
                    onMoveToTrash={() => void deleteDetailItem(false)}
                    onPermanentlyDelete={() => void deleteDetailItem(true)}
                  />
                )
              ) : selected ? (
                <DetailLoader
                  item={selected}
                  onLoaded={setDetail}
                  onError={setError}
                />
              ) : (
                <EmptyDetail />
              )}
            </section>
          </>
        ) : (
          <section className="tool-page">
            {view === "import" && (
              <ImportPanel
                groups={groups}
                onImported={async () => {
                  setSession("unlocked");
                  setNotice("导入记录已加密保存");
                  await refresh();
                }}
                onNotice={setNotice}
                onError={setError}
              />
            )}
            {view === "backup" && (
              <BackupPanel onNotice={setNotice} onError={setError} />
            )}
            {view === "security" && (
              <SecurityPanel
                onChangePassword={() => setPasswordDialogOpen(true)}
                onNotice={setNotice}
                onError={setError}
              />
            )}
            {view === "settings" && (
              <SettingsPanel
                settings={settings}
                onChangePassword={() => setPasswordDialogOpen(true)}
                onOpenKeyRecovery={() => setView("security")}
                onSaved={(next) => {
                  setSettings(next);
                  setSession("unlocked");
                  setNotice("安全设置已保存");
                }}
                onError={setError}
              />
            )}
            {view === "extensions" && (
              <BrowserExtensionPanel onNotice={setNotice} onError={setError} />
            )}
          </section>
        )}
      </div>
      {groupEditor && (
        <GroupEditorDialog
          editor={groupEditor}
          onClose={() => setGroupEditor(undefined)}
          onSave={saveGroup}
          onDelete={deleteGroup}
          canDelete={
            groupEditor.mode !== "rename" ||
            Boolean(groupEditor.group.parent_id) ||
            groups.length > 1
          }
        />
      )}
      {passwordDialogOpen && (
        <ChangeMainPasswordDialog
          onClose={() => setPasswordDialogOpen(false)}
          onChanged={() => {
            setPasswordDialogOpen(false);
            setError(undefined);
            setNotice("主密码已修改；恢复密钥已失效，请重新生成");
          }}
        />
      )}
    </main>
  );
}

function Welcome({
  lastPath,
  onSubmit,
  error,
}: {
  lastPath: string;
  onSubmit: (path: string, mode: "create" | "open", password: string) => void;
  error?: string;
}) {
  const [mode, setMode] = useState<"create" | "open">(
    lastPath ? "open" : "create",
  );
  const [path, setPath] = useState(lastPath);
  const [password, setPassword] = useState("");
  const [recentVaults, setRecentVaults] = useState<RecentVault[]>([]);
  const passwordRef = useRef<HTMLInputElement>(null);

  const loadRecentVaults = useCallback(async () => {
    if (!isTauriRuntime()) return;
    try {
      setRecentVaults(await command<RecentVault[]>("list_recent_vaults"));
    } catch {
      setRecentVaults([]);
    }
  }, []);

  useEffect(() => {
    void loadRecentVaults();
  }, [loadRecentVaults]);

  async function chooseVaultPath() {
    if (!isTauriRuntime()) return;
    const selectedPath =
      mode === "create"
        ? await saveDialog({
            title: translateText("选择保险库保存位置"),
            defaultPath: path || `StarAxis Vault.${VAULT_EXTENSION}`,
            canCreateDirectories: true,
            filters: VAULT_DIALOG_FILTERS,
          })
        : await openDialog({
            title: translateText("打开 StarAxis 保险库"),
            defaultPath: path || undefined,
            directory: false,
            multiple: false,
            filters: VAULT_DIALOG_FILTERS,
          });
    if (typeof selectedPath !== "string") return;
    setPath(
      mode === "create" ? withVaultExtension(selectedPath) : selectedPath,
    );
    window.setTimeout(() => passwordRef.current?.focus(), 0);
  }

  async function forgetRecentVault(recentPath: string) {
    if (!isTauriRuntime()) return;
    await command("forget_recent_vault", { path: recentPath });
    await loadRecentVaults();
    if (path === recentPath) setPath("");
  }

  return (
    <main className="welcome-scene">
      <div className="grid-lines" />
      <section className="welcome-copy">
        <p className="eyebrow welcome-english-name">LOCAL PASSWORD VAULT</p>
        <h1>StarAxis</h1>
        <p className="lede">
          一个安静、安全的地方，保存你最重要的数字凭据。数据只留在你的设备上。
        </p>
        <p
          className="brand-author welcome-author"
          aria-label={`作者 ${PRODUCT_AUTHOR}`}
          title={`作者：${PRODUCT_AUTHOR}`}
        >
          作者：<b>{PRODUCT_AUTHOR}</b>
          <span className="author-separator" aria-hidden="true">
            ·
          </span>
          <a
            className="author-github"
            href={AUTHOR_GITHUB_URL}
            target="_blank"
            rel="noreferrer noopener"
            aria-label="panda8 的 GitHub 主页"
          >
            github.com/pandasec888
          </a>
        </p>
      </section>
      <section className="entry-panel" aria-labelledby="entry-title">
        <div className="mode-tabs">
          <button
            className={mode === "create" ? "active" : ""}
            onClick={() => {
              setMode("create");
              if (mode !== "create") setPath("");
            }}
          >
            创建保险库
          </button>
          <button
            className={mode === "open" ? "active" : ""}
            onClick={() => {
              setMode("open");
              if (mode !== "open") setPath("");
            }}
          >
            打开保险库
          </button>
        </div>
        {recentVaults.length > 0 && (
          <section className="recent-vaults" aria-label="最近使用的保险库">
            <div className="recent-heading">
              <span>最近使用</span>
              <small>{recentVaults.length} 个保险库</small>
            </div>
            <div className="recent-list">
              {recentVaults.slice(0, 4).map((vault) => (
                <div className="recent-row" key={vault.path}>
                  <button
                    type="button"
                    className={
                      path === vault.path
                        ? "recent-vault selected"
                        : "recent-vault"
                    }
                    disabled={!vault.exists}
                    onClick={() => {
                      setMode("open");
                      setPath(vault.path);
                      window.setTimeout(() => passwordRef.current?.focus(), 0);
                    }}
                  >
                    <span className="recent-icon">⌑</span>
                    <span className="recent-copy" data-i18n-skip>
                      <strong>{vault.name}</strong>
                      <small>{vault.parent}</small>
                    </span>
                    <span className="recent-time">
                      {vault.exists
                        ? formatRecentTime(vault.last_opened_unix_ms)
                        : "文件不可用"}
                    </span>
                  </button>
                  <button
                    type="button"
                    className="recent-remove"
                    aria-label={`从最近列表移除 ${vault.name}`}
                    onClick={() => void forgetRecentVault(vault.path)}
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>
          </section>
        )}
        <form
          onSubmit={(event) => {
            event.preventDefault();
            onSubmit(path, mode, password);
          }}
        >
          <p className="step-index">
            {mode === "create" ? "新建保险库" : "解锁保险库"}
          </p>
          <h2 id="entry-title">
            {mode === "create" ? "创建个人保险库" : "欢迎回来"}
          </h2>
          <label>
            {mode === "create" ? "保存位置" : "保险库文件"}
            <div className="path-picker">
              <input
                required
                readOnly
                aria-label="绝对文件路径"
                value={path}
                placeholder={
                  mode === "create"
                    ? "请选择新保险库的保存位置"
                    : "请选择要打开的 .panda8 或旧版 .vaultx 文件"
                }
              />
              <button type="button" onClick={() => void chooseVaultPath()}>
                {mode === "create" ? "选择位置…" : "选择文件…"}
              </button>
            </div>
          </label>
          <label>
            主密码
            <input
              ref={passwordRef}
              required
              type="password"
              autoComplete={
                mode === "create" ? "new-password" : "current-password"
              }
              spellCheck={false}
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </label>
          {mode === "create" && (
            <p className="field-help">
              请使用足够长且唯一的主密码。StarAxis
              无法替你找回未配置恢复密钥的密码。
            </p>
          )}
          {error && (
            <p className="form-error" role="alert">
              {error}
            </p>
          )}
          <button className="entry-submit" type="submit">
            {mode === "create" ? "继续创建" : "解锁"}
            <span>→</span>
          </button>
        </form>
        <footer>本地加密 · 不上传秘密 · 文件由你保管</footer>
      </section>
    </main>
  );
}

function formatRecentTime(timestamp: number) {
  const elapsed = Math.max(0, Date.now() - timestamp);
  if (elapsed < 60_000) return "刚刚";
  if (elapsed < 3_600_000) return `${Math.floor(elapsed / 60_000)} 分钟前`;
  if (elapsed < 86_400_000) return `${Math.floor(elapsed / 3_600_000)} 小时前`;
  if (elapsed < 604_800_000) return `${Math.floor(elapsed / 86_400_000)} 天前`;
  return new Intl.DateTimeFormat("zh-CN", {
    month: "numeric",
    day: "numeric",
  }).format(timestamp);
}

function NavButton({
  active,
  icon,
  meta,
  onClick,
  children,
}: {
  active: boolean;
  icon: string;
  meta?: number | string;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      className={active ? "nav-button active" : "nav-button"}
      onClick={onClick}
    >
      <span className="nav-icon">{icon}</span>
      <span className="nav-label">{children}</span>
      {meta !== undefined && <small className="nav-meta">{meta}</small>}
    </button>
  );
}

function VirtualItemList({
  items,
  selected,
  onSelect,
}: {
  items: ItemSummary[];
  selected?: ItemSummary;
  onSelect: (item: ItemSummary) => void;
}) {
  const rowHeight = 58;
  const [scrollTop, setScrollTop] = useState(0);
  const viewport = 600;
  const start = Math.max(0, Math.floor(scrollTop / rowHeight) - 4);
  const end = Math.min(
    items.length,
    start + Math.ceil(viewport / rowHeight) + 8,
  );
  return (
    <div
      className="virtual-list"
      onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}
    >
      <div style={{ height: items.length * rowHeight, position: "relative" }}>
        {items.slice(start, end).map((item, index) => (
          <button
            className={
              selected && sameId(item.id, selected.id)
                ? "item-row active"
                : "item-row"
            }
            key={idKey(item.id)}
            style={{
              transform: `translateY(${(start + index) * rowHeight}px)`,
            }}
            onClick={() => onSelect(item)}
          >
            <span className="item-glyph">
              {(item.title.trim() || (item.kind === "login" ? "账" : "记"))
                .slice(0, 1)
                .toUpperCase()}
            </span>
            <span className="item-copy">
              <strong data-i18n-skip>{item.title}</strong>
              <small>
                {item.primary_username ||
                  item.primary_url ||
                  (item.kind === "login" ? "登录项" : "安全笔记")}
              </small>
            </span>
            <span className="favorite" aria-hidden="true">
              {item.favorite ? "★" : item.kind === "login" ? "☆" : "◇"}
            </span>
          </button>
        ))}
      </div>
    </div>
  );
}

function ItemDetailView({
  detail,
  inTrash,
  groupName,
  onEdit,
  onCopy,
  onRestore,
  onMoveToTrash,
  onPermanentlyDelete,
}: {
  detail: ItemDetail;
  inTrash: boolean;
  groupName: string;
  onEdit: () => void;
  onCopy: (value: string) => void;
  onRestore: () => void;
  onMoveToTrash: () => void;
  onPermanentlyDelete: () => void;
}) {
  const [showPassword, setShowPassword] = useState(false);
  const [moreMenuOpen, setMoreMenuOpen] = useState(false);
  const [deleteConfirmation, setDeleteConfirmation] = useState<
    "trash" | "permanent" | null
  >(null);
  const moreMenuRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!moreMenuOpen) return;
    const closeOnOutsideClick = (event: globalThis.MouseEvent) => {
      const menu = moreMenuRef.current;
      if (menu && !event.composedPath().includes(menu)) setMoreMenuOpen(false);
    };
    document.addEventListener("click", closeOnOutsideClick);
    return () => document.removeEventListener("click", closeOnOutsideClick);
  }, [moreMenuOpen]);
  const latestHistory = detail.history[detail.history.length - 1];
  const updatedText = latestHistory
    ? new Intl.DateTimeFormat("zh-CN", {
        month: "long",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      }).format(latestHistory.updated_at_unix_ms)
    : "当前版本";
  const mark = (
    detail.title.trim() || (detail.kind === "login" ? "账号" : "笔记")
  )
    .slice(0, 1)
    .toUpperCase();
  const fields =
    detail.kind === "login"
      ? [
          {
            label: "用户名",
            value: detail.usernames.join("\n") || "未填写",
            copy: detail.usernames[0],
          },
          {
            label: "密码",
            value: showPassword
              ? detail.password || "未填写"
              : detail.password
                ? "••••••••••••••••"
                : "未填写",
            copy: detail.password,
            secret: true,
          },
          {
            label: "网站",
            value:
              detail.urls
                .map(
                  (url, index) =>
                    `${url} · ${urlMatchModeLabel(
                      detail.url_match_modes[index] ?? "exact_host",
                    )}`,
                )
                .join("\n") || "未填写",
            copy: detail.urls[0],
          },
          {
            label: "备注",
            value: detail.notes || "未填写",
          },
        ]
      : [
          {
            label: "安全内容",
            value: detail.content || "未填写",
          },
        ];

  return (
    <article className="detail-view">
      <div className="detail-toolbar">
        <button
          type="button"
          className={detail.favorite ? "detail-icon active" : "detail-icon"}
          aria-label={detail.favorite ? "已收藏" : "收藏"}
          title="在编辑页面修改收藏状态"
          onClick={onEdit}
        >
          {detail.favorite ? "★" : "☆"}
        </button>
        <button type="button" className="detail-edit" onClick={onEdit}>
          编辑
        </button>
        <div
          ref={moreMenuRef}
          className="detail-more-menu"
          onKeyDown={(event) => {
            if (event.key === "Escape") setMoreMenuOpen(false);
          }}
        >
          <button
            type="button"
            className="detail-icon"
            aria-label="更多操作"
            aria-haspopup="menu"
            aria-expanded={moreMenuOpen}
            onClick={() => setMoreMenuOpen((open) => !open)}
          >
            •••
          </button>
          {moreMenuOpen && (
            <div className="detail-more-popover" role="menu">
              {inTrash && (
                <button
                  autoFocus
                  type="button"
                  role="menuitem"
                  className="restore"
                  onClick={() => {
                    setMoreMenuOpen(false);
                    onRestore();
                  }}
                >
                  <span className="detail-menu-icon" aria-hidden="true">
                    ↶
                  </span>
                  <span>
                    <strong>恢复</strong>
                    <small>返回原分组</small>
                  </span>
                </button>
              )}
              {!inTrash && (
                <button
                  autoFocus
                  type="button"
                  role="menuitem"
                  onClick={() => {
                    setMoreMenuOpen(false);
                    setDeleteConfirmation("trash");
                  }}
                >
                  <span className="detail-menu-icon" aria-hidden="true">
                    ⌫
                  </span>
                  <span>
                    <strong>移动到回收站</strong>
                    <small>之后仍可恢复</small>
                  </span>
                </button>
              )}
              <button
                type="button"
                role="menuitem"
                className="permanent"
                onClick={() => {
                  setMoreMenuOpen(false);
                  setDeleteConfirmation("permanent");
                }}
              >
                <span className="detail-menu-icon" aria-hidden="true">
                  ×
                </span>
                <span>
                  <strong>永久删除</strong>
                  <small>此操作无法撤销</small>
                </span>
              </button>
            </div>
          )}
        </div>
      </div>

      <header className="detail-hero">
        <span className="detail-site-icon" aria-hidden="true">
          {mark}
        </span>
        <div>
          <h2 data-i18n-skip>{detail.title || translateText("未命名条目")}</h2>
          <p>
            <span data-i18n-skip>{groupName}</span> · 最近更新于 {updatedText}
          </p>
        </div>
      </header>

      {detail.tags.length > 0 && (
        <div className="detail-tags" aria-label="标签">
          {detail.tags.map((tag) => (
            <span key={tag} data-i18n-skip>
              #{tag}
            </span>
          ))}
        </div>
      )}

      <div className="detail-fields">
        {fields.map((field) => (
          <section className="detail-field" key={field.label}>
            <div>
              <small>{field.label}</small>
              <strong data-i18n-skip>{field.value}</strong>
            </div>
            <div className="detail-field-actions">
              {field.secret && detail.password && (
                <button
                  type="button"
                  onClick={() => setShowPassword((visible) => !visible)}
                >
                  {showPassword ? "遮盖" : "显示"}
                </button>
              )}
              {field.copy && (
                <button type="button" onClick={() => onCopy(field.copy || "")}>
                  复制
                </button>
              )}
            </div>
          </section>
        ))}
        {detail.custom_fields.map((field) => (
          <section className="detail-field" key={field.name}>
            <div>
              <small data-i18n-skip>
                {field.name || translateText("自定义字段")}
              </small>
              <strong>
                {field.sensitivity === "concealed"
                  ? "••••••••"
                  : field.value || "未填写"}
              </strong>
            </div>
            {field.value && (
              <div className="detail-field-actions">
                <button type="button" onClick={() => onCopy(field.value)}>
                  复制
                </button>
              </div>
            )}
          </section>
        ))}
      </div>

      {deleteConfirmation && (
        <div
          className="dialog-backdrop"
          role="presentation"
          onMouseDown={() => setDeleteConfirmation(null)}
        >
          <section
            className="delete-confirm-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="delete-confirm-title"
            onMouseDown={(event) => event.stopPropagation()}
            onKeyDown={(event) => {
              if (event.key === "Escape") setDeleteConfirmation(null);
            }}
          >
            <span
              className={
                deleteConfirmation === "permanent"
                  ? "delete-confirm-icon permanent"
                  : "delete-confirm-icon"
              }
              aria-hidden="true"
            >
              {deleteConfirmation === "permanent" ? "×" : "⌫"}
            </span>
            <div className="delete-confirm-copy">
              <p className="eyebrow">
                {deleteConfirmation === "permanent"
                  ? "不可恢复操作"
                  : "可恢复操作"}
              </p>
              <h2 id="delete-confirm-title">
                {deleteConfirmation === "permanent"
                  ? "永久删除这个条目？"
                  : "移动到回收站？"}
              </h2>
              <p>
                <strong data-i18n-skip>
                  {detail.title || translateText("未命名条目")}
                </strong>
                {deleteConfirmation === "permanent"
                  ? inTrash
                    ? " 将从保险库中永久移除，删除后无法恢复。"
                    : " 会先安全移入回收站，再完成不可恢复删除。"
                  : " 会进入回收站，之后仍可恢复。"}
              </p>
            </div>
            <div className="delete-confirm-actions">
              <button
                autoFocus
                type="button"
                className="quiet"
                onClick={() => setDeleteConfirmation(null)}
              >
                取消
              </button>
              <button
                type="button"
                className={
                  deleteConfirmation === "permanent"
                    ? "danger-confirm"
                    : "signal"
                }
                onClick={() => {
                  const action = deleteConfirmation;
                  setDeleteConfirmation(null);
                  if (action === "permanent") onPermanentlyDelete();
                  else onMoveToTrash();
                }}
              >
                {deleteConfirmation === "permanent"
                  ? "永久删除"
                  : "移动到回收站"}
              </button>
            </div>
          </section>
        </div>
      )}
    </article>
  );
}

function DetailLoader({
  item,
  onLoaded,
  onError,
}: {
  item: ItemSummary;
  onLoaded: (detail: ItemDetail) => void;
  onError: (error: string) => void;
}) {
  const [attempt, setAttempt] = useState(0);
  const [failed, setFailed] = useState(false);
  const itemKey = idKey(item.id);

  useEffect(() => {
    let cancelled = false;
    setFailed(false);
    void command<ItemDetail>("get_item_detail", { id: item.id })
      .then((value) => {
        if (!cancelled) onLoaded(value);
      })
      .catch((cause) => {
        if (cancelled) return;
        setFailed(true);
        onError(messageOf(cause));
      });
    return () => {
      cancelled = true;
    };
  }, [attempt, item.id, itemKey, onError, onLoaded]);

  return (
    <div className="detail-loading" role="status" aria-live="polite">
      <span className={failed ? "detail-load-mark failed" : "detail-load-mark"}>
        {failed ? "!" : ""}
      </span>
      <h2>{failed ? "暂时无法打开条目" : "正在打开条目"}</h2>
      <p>{failed ? "请重试，或检查保险库是否仍处于解锁状态。" : item.title}</p>
      {failed && (
        <button type="button" onClick={() => setAttempt((value) => value + 1)}>
          重新加载
        </button>
      )}
    </div>
  );
}

function EmptyDetail() {
  return (
    <div className="empty-detail">
      <span>⌁</span>
      <h2>选择一条记录</h2>
      <p>秘密只在需要时进入详情视图。</p>
    </div>
  );
}

function GroupEditorDialog({
  editor,
  onClose,
  onSave,
  onDelete,
  canDelete,
}: {
  editor: GroupEditorState;
  onClose: () => void;
  onSave: (name: string) => Promise<void>;
  onDelete: (group: Group) => Promise<void>;
  canDelete: boolean;
}) {
  const [name, setName] = useState(
    editor.mode === "rename" ? editor.group.name : "",
  );
  const [busy, setBusy] = useState(false);
  const [deleteArmed, setDeleteArmed] = useState(false);
  const title = editor.mode === "rename" ? "编辑分组" : "新建分组";

  async function submit(event: FormEvent) {
    event.preventDefault();
    const nextName = name.trim();
    if (!nextName || busy) return;
    setBusy(true);
    try {
      await onSave(nextName);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="dialog-backdrop" role="presentation" onMouseDown={onClose}>
      <form
        className="group-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="group-dialog-title"
        onSubmit={(event) => void submit(event)}
        onMouseDown={(event) => event.stopPropagation()}
        onKeyDown={(event) => {
          if (event.key === "Escape" && !busy) onClose();
        }}
      >
        <div className="dialog-head">
          <div>
            <span className="dialog-icon" aria-hidden="true">
              {editor.mode === "rename" ? "⌘" : "＋"}
            </span>
            <div>
              <p className="eyebrow">GROUP</p>
              <h2 id="group-dialog-title">{title}</h2>
            </div>
          </div>
          <button
            type="button"
            className="dialog-close"
            aria-label="关闭分组窗口"
            onClick={onClose}
            disabled={busy}
          >
            ×
          </button>
        </div>
        <label className="group-name-field">
          分组名称
          <input
            autoFocus
            required
            maxLength={4096}
            value={name}
            onChange={(event) => {
              setName(event.target.value);
              setDeleteArmed(false);
            }}
            placeholder="例如：工作、个人、家庭"
          />
        </label>
        <p className="dialog-help">
          {editor.mode === "rename" && !editor.group.parent_id
            ? canDelete
              ? "删除 Root 后，一个子分组会成为新根；Root 中的条目和其他子分组会一并安全迁移。"
              : "保险库必须至少保留一个分组。创建子分组后即可删除 Root。"
            : "分组用于整理条目，不会改变文件的加密方式。"}
        </p>
        <div className="dialog-actions">
          {editor.mode === "rename" && (
            <button
              type="button"
              className={deleteArmed ? "danger delete-armed" : "danger quiet"}
              disabled={busy || !canDelete}
              onClick={() => {
                if (!deleteArmed) {
                  setDeleteArmed(true);
                  return;
                }
                setBusy(true);
                void onDelete(editor.group).finally(() => setBusy(false));
              }}
            >
              {deleteArmed
                ? "再次点击确认删除"
                : editor.group.parent_id
                  ? "删除空分组"
                  : "删除 Root 分组"}
            </button>
          )}
          <span />
          <button
            type="button"
            className="quiet"
            onClick={onClose}
            disabled={busy}
          >
            取消
          </button>
          <button
            className="signal"
            type="submit"
            disabled={!name.trim() || busy}
          >
            {busy
              ? "正在保存…"
              : editor.mode === "rename"
                ? "保存"
                : "创建分组"}
          </button>
        </div>
      </form>
    </div>
  );
}

function ItemEditor({
  detail,
  inTrash,
  groups,
  settings,
  onDirty,
  onCancel,
  onCopy,
  onSaved,
  onDeleted,
  onPending,
  onError,
}: {
  detail: ItemDetail;
  inTrash: boolean;
  groups: Group[];
  settings: Settings;
  onDirty: () => void;
  onCancel: () => void;
  onCopy: (value: string) => void;
  onSaved: (savedDetail: ItemDetail) => Promise<void>;
  onDeleted: () => Promise<void>;
  onPending: (state: SessionState, error: string) => Promise<void>;
  onError: (error: string) => void;
}) {
  const [draft, setDraft] = useState(detail);
  const [showPassword, setShowPassword] = useState(false);
  const [generatorOpen, setGeneratorOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const update = <K extends keyof ItemDetail>(key: K, value: ItemDetail[K]) => {
    setDraft((current) => ({ ...current, [key]: value }));
    onDirty();
  };
  const handleMutationFailure = async (cause: unknown) => {
    const message = messageOf(cause);
    try {
      const nextSession = await command<SessionState>("session_state");
      if (
        nextSession === "dirty" ||
        nextSession === "conflict_pending" ||
        nextSession === "save_result_unknown"
      ) {
        await onPending(nextSession, message);
        return;
      }
    } catch {
      // Preserve the original mutation error when state inspection also fails.
    }
    onError(message);
  };
  const save = async (event: FormEvent) => {
    event.preventDefault();
    if (submitting) return;
    setSubmitting(true);
    const common = {
      group_id: draft.group_id,
      title: draft.title,
      favorite: draft.favorite,
      tags: draft.tags,
      custom_fields: draft.custom_fields,
    };
    try {
      let savedId = detail.id;
      if (draft.kind === "login") {
        const usernames = draft.usernames
          .map((value) => value.trim())
          .filter(Boolean);
        const urlEntries = draft.urls
          .map((value, index) => ({
            url: value.trim(),
            mode: draft.url_match_modes[index] ?? "anywhere_on_website",
          }))
          .filter((entry) => Boolean(entry.url));
        const urls = urlEntries.map((entry) => entry.url);
        const urlMatchModes = urlEntries.map((entry) => entry.mode);
        const input = {
          ...common,
          usernames,
          password: draft.password || "",
          urls,
          url_match_modes: urlMatchModes,
          notes: draft.notes || "",
        };
        if (detail.id.length) {
          await command("update_login", { id: detail.id, input });
        } else {
          savedId = await command<Id>("create_login", { input });
        }
      } else {
        const input = { ...common, content: draft.content || "" };
        if (detail.id.length) {
          await command("update_secure_note", { id: detail.id, input });
        } else {
          savedId = await command<Id>("create_secure_note", { input });
        }
      }
      await onSaved({
        ...draft,
        id: savedId,
        usernames: draft.usernames.map((value) => value.trim()).filter(Boolean),
        urls:
          draft.kind === "login"
            ? draft.urls.map((value) => value.trim()).filter(Boolean)
            : [],
        url_match_modes:
          draft.kind === "login"
            ? draft.urls
                .map((value, index) => ({
                  url: value.trim(),
                  mode: draft.url_match_modes[index] ?? "anywhere_on_website",
                }))
                .filter((entry) => Boolean(entry.url))
                .map((entry) => entry.mode)
            : [],
      });
    } catch (cause) {
      await handleMutationFailure(cause);
    } finally {
      setSubmitting(false);
    }
  };
  return (
    <form
      className="editor mist-settings-editor"
      onSubmit={(event) => void save(event)}
      onChange={onDirty}
    >
      <div className="mist-editor-hero">
        <div className="mist-editor-identity">
          <span className="mist-identity-mark" aria-hidden="true">
            {(draft.title.trim() || (draft.kind === "login" ? "账号" : "笔记"))
              .slice(0, 2)
              .toUpperCase()}
          </span>
          <div className="mist-title-block">
            <p className="mist-record-type">标题</p>
            <input
              className="mist-title-input"
              value={draft.title}
              onChange={(event) => update("title", event.target.value)}
              placeholder={
                draft.kind === "login"
                  ? "例如：Apple ID、公司邮箱"
                  : "例如：服务器恢复说明"
              }
              aria-label="标题"
            />
          </div>
        </div>
        <button
          type="button"
          className={draft.favorite ? "star active" : "star"}
          onClick={() => update("favorite", !draft.favorite)}
          aria-label={draft.favorite ? "取消收藏" : "添加收藏"}
          title={draft.favorite ? "取消收藏" : "添加收藏"}
        >
          ★
        </button>
      </div>

      <div className="mist-setting-stack">
        <section className="mist-setting-card">
          <label className="mist-setting-row">
            <span className="mist-setting-copy">
              分组
              <small>保险库中的存放位置</small>
            </span>
            <select
              value={idKey(draft.group_id)}
              onChange={(event) =>
                update(
                  "group_id",
                  groups.find((group) => idKey(group.id) === event.target.value)
                    ?.id || draft.group_id,
                )
              }
            >
              {groups.map((group) => (
                <option
                  key={idKey(group.id)}
                  value={idKey(group.id)}
                  data-i18n-skip
                >
                  {group.name}
                </option>
              ))}
            </select>
          </label>
          <label className="mist-setting-row">
            <span className="mist-setting-copy">
              标签
              <small>使用逗号分隔</small>
            </span>
            <input
              value={draft.tags.join(", ")}
              onChange={(event) =>
                update("tags", splitTags(event.target.value))
              }
              placeholder="例如：工作, 邮箱"
            />
          </label>
        </section>

        {draft.kind === "login" ? (
          <>
            <section className="mist-setting-card">
              <label className="mist-setting-row mist-setting-row-top">
                <span className="mist-setting-copy">
                  用户名
                  <small>支持每行一个账号</small>
                </span>
                <textarea
                  rows={2}
                  value={draft.usernames.join("\n")}
                  onChange={(event) =>
                    update("usernames", event.target.value.split(/\r?\n/))
                  }
                  placeholder="name@example.com"
                  spellCheck={false}
                />
              </label>
              <label className="mist-setting-row">
                <span className="mist-setting-copy">
                  密码
                  <small>{showPassword ? "当前可见" : "默认安全遮盖"}</small>
                </span>
                <div className="secret-field">
                  <input
                    type={showPassword ? "text" : "password"}
                    value={draft.password || ""}
                    onChange={(event) => update("password", event.target.value)}
                    spellCheck={false}
                    autoComplete="new-password"
                    aria-label="密码"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((value) => !value)}
                    aria-label={showPassword ? "遮盖密码" : "显示密码"}
                  >
                    {showPassword ? "遮盖" : "显示"}
                  </button>
                  <button
                    type="button"
                    onClick={() => onCopy(draft.password || "")}
                    aria-label="复制密码"
                  >
                    复制
                  </button>
                  <button
                    type="button"
                    className={generatorOpen ? "active" : ""}
                    onClick={() => setGeneratorOpen((value) => !value)}
                    aria-expanded={generatorOpen}
                  >
                    生成
                  </button>
                </div>
              </label>
              {generatorOpen && (
                <div className="mist-generator-row">
                  <PasswordGenerator
                    onUse={(password) => {
                      update("password", password);
                      setGeneratorOpen(false);
                    }}
                    onError={onError}
                  />
                </div>
              )}
            </section>

            <section className="mist-setting-card">
              <label className="mist-setting-row mist-setting-row-top">
                <span className="mist-setting-copy">
                  网站地址
                  <small>用于浏览器扩展匹配</small>
                </span>
                <textarea
                  rows={3}
                  value={draft.urls.join("\n")}
                  placeholder={"mozhe.cn\nhttps://accounts.example.com"}
                  spellCheck={false}
                  onChange={(event) => {
                    const urls = event.target.value.split(/\r?\n/);
                    setDraft((current) => ({
                      ...current,
                      urls,
                      url_match_modes: urls.map(
                        (_, index) =>
                          current.url_match_modes[index] ??
                          "anywhere_on_website",
                      ),
                    }));
                    onDirty();
                  }}
                />
              </label>
              <div className="mist-setting-row mist-setting-row-top">
                <span className="mist-setting-copy">
                  填充范围
                  <small>可为每个网址单独设置</small>
                </span>
                <div className="mist-policy-list" aria-label="网址填充范围">
                  {draft.urls.some((url) => url.trim()) ? (
                    draft.urls.map((url, index) =>
                      url.trim() ? (
                        <label
                          className="mist-policy-entry"
                          key={`${index}-${url}`}
                        >
                          <span title={url.trim()}>{url.trim()}</span>
                          <select
                            value={
                              draft.url_match_modes[index] ??
                              "anywhere_on_website"
                            }
                            onChange={(event) => {
                              const mode = event.target.value as UrlMatchMode;
                              setDraft((current) => {
                                const urlMatchModes = [
                                  ...current.url_match_modes,
                                ];
                                urlMatchModes[index] = mode;
                                return {
                                  ...current,
                                  url_match_modes: urlMatchModes,
                                };
                              });
                              onDirty();
                            }}
                            aria-label={`${url.trim()} 的填充范围`}
                          >
                            <option value="anywhere_on_website">
                              整个网站
                            </option>
                            <option value="exact_host">精确主机</option>
                            <option value="never">禁止填充</option>
                          </select>
                        </label>
                      ) : null,
                    )
                  ) : (
                    <small className="mist-policy-empty">
                      填写网站地址后可设置填充范围
                    </small>
                  )}
                </div>
              </div>
            </section>

            <section className="mist-setting-card">
              <label className="mist-setting-row mist-setting-row-top">
                <span className="mist-setting-copy">
                  备注
                  <small>不参与网站匹配</small>
                </span>
                <textarea
                  rows={5}
                  value={draft.notes || ""}
                  placeholder="添加与该账号相关的说明…"
                  onChange={(event) => update("notes", event.target.value)}
                />
              </label>
            </section>
          </>
        ) : (
          <section className="mist-setting-card">
            <label className="mist-setting-row mist-setting-row-top mist-note-row">
              <span className="mist-setting-copy">
                安全内容
                <small>随保险库加密保存在本地</small>
              </span>
              <textarea
                className="note-area"
                rows={14}
                value={draft.content || ""}
                placeholder="输入需要安全保存的内容…"
                onChange={(event) => update("content", event.target.value)}
              />
            </label>
          </section>
        )}

        <CustomFields
          fields={draft.custom_fields}
          onChange={(fields) => update("custom_fields", fields)}
        />
        {draft.history.length > 0 && (
          <details className="history mist-setting-card">
            <summary>历史版本 · {draft.history.length}</summary>
            {draft.history.map((entry) => (
              <div key={entry.index}>
                <span>
                  r{entry.revision} · {entry.title}
                </span>
                <button
                  type="button"
                  onClick={() =>
                    void command("restore_item_history", {
                      id: draft.id,
                      historyIndex: entry.index,
                    })
                      .then(() => onSaved(draft))
                      .catch(handleMutationFailure)
                  }
                >
                  恢复
                </button>
              </div>
            ))}
          </details>
        )}
      </div>

      <div className="editor-actions">
        {inTrash ? (
          <>
            <button
              type="button"
              onClick={() =>
                void command("restore_item", { id: draft.id })
                  .then(onDeleted)
                  .catch(handleMutationFailure)
              }
            >
              恢复条目
            </button>
            <button
              className="danger"
              type="button"
              onClick={() => {
                if (
                  window.confirm(
                    translateText(
                      "永久删除会移除当前记录并留下 tombstone，确定继续？",
                    ),
                  )
                )
                  void command("permanently_delete_item", { id: draft.id })
                    .then(onDeleted)
                    .catch(handleMutationFailure);
              }}
            >
              永久删除
            </button>
          </>
        ) : (
          <button
            className="danger"
            type="button"
            disabled={!draft.id.length}
            onClick={() => {
              if (window.confirm(translateText("将条目移到回收站？")))
                void command("soft_delete_item", { id: draft.id })
                  .then(onDeleted)
                  .catch(handleMutationFailure);
            }}
          >
            移到回收站
          </button>
        )}
        <span />
        <button
          type="button"
          className="quiet"
          onClick={() => {
            setDraft(detail);
            onCancel();
          }}
        >
          取消
        </button>
        <button className="signal" type="submit" disabled={submitting}>
          {submitting ? "正在保存…" : "保存修改"}
        </button>
      </div>
      <small className="security-footnote">
        剪贴板清理策略：{settings.clipboard_clear_seconds}{" "}
        秒；系统剪贴板历史不受此策略控制。
      </small>
    </form>
  );
}

function CustomFields({
  fields,
  onChange,
}: {
  fields: ItemDetail["custom_fields"];
  onChange: (fields: ItemDetail["custom_fields"]) => void;
}) {
  return (
    <section className="custom-fields mist-setting-card">
      <div className="mist-setting-row mist-custom-header">
        <span className="mist-setting-copy">
          自定义字段
          <small>按需保存额外信息</small>
        </span>
        <button
          className="mist-add-field"
          type="button"
          onClick={() =>
            onChange([
              ...fields,
              { name: "", value: "", sensitivity: "concealed" },
            ])
          }
        >
          ＋ 添加
        </button>
      </div>
      {fields.map((field, index) => (
        <div className="custom-row" key={index}>
          <input
            value={field.name}
            placeholder="字段名"
            onChange={(event) =>
              onChange(
                fields.map((value, i) =>
                  i === index ? { ...value, name: event.target.value } : value,
                ),
              )
            }
          />
          <input
            type={field.sensitivity === "concealed" ? "password" : "text"}
            value={field.value}
            placeholder="值"
            onChange={(event) =>
              onChange(
                fields.map((value, i) =>
                  i === index ? { ...value, value: event.target.value } : value,
                ),
              )
            }
          />
          <select
            value={field.sensitivity}
            onChange={(event) =>
              onChange(
                fields.map((value, i) =>
                  i === index
                    ? {
                        ...value,
                        sensitivity: event.target.value as
                          "concealed" | "visible",
                      }
                    : value,
                ),
              )
            }
          >
            <option value="concealed">遮盖</option>
            <option value="visible">显示</option>
          </select>
          <button
            type="button"
            onClick={() => onChange(fields.filter((_, i) => i !== index))}
          >
            ×
          </button>
        </div>
      ))}
    </section>
  );
}

function PasswordGenerator({
  onUse,
  onError,
}: {
  onUse: (password: string) => void;
  onError: (error: string) => void;
}) {
  const [length, setLength] = useState(24);
  const [generated, setGenerated] = useState("");
  const generate = () =>
    void command<string>("generate_password_value", {
      policy: {
        length,
        lowercase: true,
        uppercase: true,
        digits: true,
        symbols: true,
        exclude_ambiguous: true,
      },
    })
      .then(setGenerated)
      .catch((cause) => onError(messageOf(cause)));
  useEffect(generate, [length]);
  return (
    <div className="generator">
      <div>
        <strong>密码生成器</strong>
        <span>{length} 字符</span>
      </div>
      <input
        type="range"
        min="12"
        max="64"
        value={length}
        onChange={(event) => setLength(Number(event.target.value))}
      />
      <code>{generated || "正在生成…"}</code>
      <div>
        <button type="button" onClick={generate}>
          重新生成
        </button>
        <button
          type="button"
          className="signal"
          onClick={() => onUse(generated)}
          disabled={!generated}
        >
          使用此密码
        </button>
      </div>
    </div>
  );
}

function ImportPanel({
  groups,
  onImported,
  onNotice,
  onError,
}: {
  groups: Group[];
  onImported: () => Promise<void>;
  onNotice: (message: string) => void;
  onError: (error: string) => void;
}) {
  const [csvPath, setCsvPath] = useState("");
  const [mapping, setMapping] = useState(DEFAULT_MAPPING);
  const [preview, setPreview] = useState<CsvPreview>();
  const [groupId, setGroupId] = useState<Id | undefined>(groups[0]?.id);
  const [importing, setImporting] = useState(false);

  async function chooseCsvFile() {
    try {
      const selectedPath = await openDialog({
        title: translateText("选择要导入的 CSV 文件"),
        directory: false,
        multiple: false,
        filters: [{ name: "CSV 文件", extensions: ["csv"] }],
      });
      if (typeof selectedPath !== "string") return;
      setCsvPath(selectedPath);
      setPreview(undefined);
    } catch (cause) {
      onError(messageOf(cause));
    }
  }

  async function downloadTemplate() {
    try {
      const selectedPath = await saveDialog({
        title: translateText("保存 CSV 导入模板"),
        defaultPath: "StarAxis-Import-Template.csv",
        canCreateDirectories: true,
        filters: [{ name: "CSV 文件", extensions: ["csv"] }],
      });
      if (typeof selectedPath !== "string") return;
      const path = selectedPath.toLowerCase().endsWith(".csv")
        ? selectedPath
        : `${selectedPath}.csv`;
      await command("write_csv_import_template", { path });
      onNotice(`CSV 模板已保存到 ${path}`);
    } catch (cause) {
      onError(messageOf(cause));
    }
  }

  return (
    <div className="tool-card wide">
      <div className="tool-heading">
        <div>
          <p className="eyebrow">PLAINTEXT TRANSFER</p>
          <h2>CSV 导入</h2>
          <p>选择 CSV 文件，核对字段映射并预览后再一次性导入。</p>
        </div>
        <button
          type="button"
          className="template-download"
          onClick={() => void downloadTemplate()}
        >
          <span aria-hidden="true">↓</span>
          下载 CSV 模板
        </button>
      </div>
      <div className="warning-box">
        <strong>明文警告</strong>
        <p>
          CSV 通常包含整库明文。StarAxis
          不创建明文临时文件，也不会把字段值写入错误报告；导入后请自行检查云盘、备份和回收站残留。
        </p>
      </div>
      <section className={`csv-file-picker ${csvPath ? "selected" : ""}`}>
        <span className="csv-file-icon" aria-hidden="true">
          CSV
        </span>
        <div>
          <strong>
            {csvPath ? fileNameFromPath(csvPath) : "选择 CSV 文件"}
          </strong>
          <p>
            {csvPath
              ? csvPath
              : "文件只在本机读取，完整解析成功后才允许导入。最大 64 MB。"}
          </p>
        </div>
        <button type="button" onClick={() => void chooseCsvFile()}>
          {csvPath ? "重新选择…" : "选择文件…"}
        </button>
      </section>
      <div className="mapping-grid">
        {(
          ["title", "username", "password", "url", "notes", "tags"] as const
        ).map((key) => (
          <label key={key}>
            {key}
            <input
              value={mapping[key] || ""}
              onChange={(event) => {
                setMapping({
                  ...mapping,
                  [key]: event.target.value || undefined,
                });
                setPreview(undefined);
              }}
            />
          </label>
        ))}
      </div>
      <div className="panel-actions">
        <label>
          目标分组
          <select
            value={groupId ? idKey(groupId) : ""}
            onChange={(event) =>
              setGroupId(
                groups.find((group) => idKey(group.id) === event.target.value)
                  ?.id,
              )
            }
          >
            {groups.map((group) => (
              <option
                key={idKey(group.id)}
                value={idKey(group.id)}
                data-i18n-skip
              >
                {group.name}
              </option>
            ))}
          </select>
        </label>
        <button
          type="button"
          disabled={!csvPath || importing}
          onClick={() =>
            void command<CsvPreview>("preview_csv_import_file", {
              path: csvPath,
              mapping,
            })
              .then((nextPreview) => {
                setPreview(nextPreview);
                onNotice(
                  `已解析 ${nextPreview.total_records} 条记录，请确认预览`,
                );
              })
              .catch((cause) => onError(messageOf(cause)))
          }
        >
          解析并预览
        </button>
        <button
          className="signal"
          disabled={!preview || !groupId || importing}
          onClick={() => {
            if (
              groupId &&
              preview &&
              window.confirm(
                translateText(
                  `将 ${preview?.total_records || 0} 条记录作为一个事务导入？`,
                ),
              )
            ) {
              setImporting(true);
              void command<number>("commit_csv_import_file", {
                groupId,
                path: csvPath,
                expectedHash: preview.source_hash,
                mapping,
              })
                .then(async () => {
                  setCsvPath("");
                  setPreview(undefined);
                  await onImported();
                })
                .catch(async (cause) => {
                  const message = messageOf(cause);
                  try {
                    const nextSession =
                      await command<SessionState>("session_state");
                    if (
                      nextSession === "dirty" ||
                      nextSession === "conflict_pending" ||
                      nextSession === "save_result_unknown"
                    ) {
                      setCsvPath("");
                      setPreview(undefined);
                      onError(
                        `导入已保留在当前会话，但自动保存未完成：${message}。请使用顶部“保存”重试，不要重复导入。`,
                      );
                      return;
                    }
                  } catch {
                    // Preserve the original import error.
                  }
                  onError(message);
                })
                .finally(() => setImporting(false));
            }
          }}
        >
          {importing ? "正在导入并保存…" : "全部导入"}
        </button>
      </div>
      {preview && (
        <div className="preview-table">
          <p>
            已完整解析 {preview.total_records} 条，仅展示前{" "}
            {preview.records.length} 条。
          </p>
          {preview.records.map((record, index) => (
            <div key={index}>
              <strong data-i18n-skip>{record.title}</strong>
              <span data-i18n-skip>{record.username || "—"}</span>
              <span data-i18n-skip>{record.url || "—"}</span>
              <small>{record.tag_count} 标签</small>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function BackupPanel({
  onNotice,
  onError,
}: {
  onNotice: (message: string) => void;
  onError: (error: string) => void;
}) {
  const [mode, setMode] = useState<"backup" | "restore">("backup");
  const [backupPath, setBackupPath] = useState("");
  const [source, setSource] = useState("");
  const [destination, setDestination] = useState("");
  const [password, setPassword] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [busy, setBusy] = useState(false);

  async function chooseBackupPath() {
    try {
      const date = new Date().toISOString().slice(0, 10);
      const selectedPath = await saveDialog({
        title: translateText("选择备份保存位置"),
        defaultPath: `StarAxis-Backup-${date}.${VAULT_EXTENSION}`,
        canCreateDirectories: true,
        filters: VAULT_DIALOG_FILTERS,
      });
      if (typeof selectedPath === "string")
        setBackupPath(withVaultExtension(selectedPath));
    } catch (cause) {
      onError(messageOf(cause));
    }
  }

  async function chooseBackupSource() {
    try {
      const selectedPath = await openDialog({
        title: translateText("选择要恢复的备份"),
        directory: false,
        multiple: false,
        filters: VAULT_DIALOG_FILTERS,
      });
      if (typeof selectedPath === "string") setSource(selectedPath);
    } catch (cause) {
      onError(messageOf(cause));
    }
  }

  async function chooseRestoreDestination() {
    try {
      const selectedPath = await saveDialog({
        title: translateText("保存恢复后的保险库"),
        defaultPath: `Restored StarAxis Vault.${VAULT_EXTENSION}`,
        canCreateDirectories: true,
        filters: VAULT_DIALOG_FILTERS,
      });
      if (typeof selectedPath === "string")
        setDestination(withVaultExtension(selectedPath));
    } catch (cause) {
      onError(messageOf(cause));
    }
  }

  async function createBackup() {
    if (!backupPath || busy) return;
    setBusy(true);
    try {
      await command("save_vault_with_backup", { backupPath });
      onNotice(`加密备份已保存到 ${backupPath}`);
    } catch (cause) {
      onError(messageOf(cause));
    } finally {
      setBusy(false);
    }
  }

  async function restoreAsNew() {
    if (!source || !destination || !password || busy) return;
    setBusy(true);
    try {
      await command("restore_backup_as_new", {
        sourcePath: source,
        destinationPath: destination,
        password,
      });
      setPassword("");
      onNotice(`备份已验证并恢复到 ${destination}`);
    } catch (cause) {
      onError(messageOf(cause));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="tool-card backup-card wide">
      <div className="tool-heading">
        <div>
          <p className="eyebrow">ENCRYPTED SAFETY COPY</p>
          <h2>备份与恢复</h2>
          <p>创建一份完整加密副本，或从已有备份恢复保险库。</p>
        </div>
      </div>
      <div className="backup-tabs" role="tablist" aria-label="备份恢复模式">
        <button
          type="button"
          role="tab"
          aria-selected={mode === "backup"}
          className={mode === "backup" ? "active" : ""}
          onClick={() => setMode("backup")}
        >
          创建备份
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={mode === "restore"}
          className={mode === "restore" ? "active" : ""}
          onClick={() => setMode("restore")}
        >
          从备份恢复
        </button>
      </div>

      {mode === "backup" ? (
        <section className="workflow-card" role="tabpanel">
          <div className="workflow-heading">
            <span className="workflow-icon" aria-hidden="true">
              ◇
            </span>
            <div>
              <h3>创建加密备份</h3>
              <p>
                选择保存位置后即可完成。未保存的修改会先安全提交，再复制当前加密版本。
              </p>
            </div>
          </div>
          <label>
            备份保存位置
            <div className="path-picker">
              <input
                readOnly
                value={backupPath}
                placeholder="尚未选择保存位置"
                aria-label="备份保存位置"
              />
              <button type="button" onClick={() => void chooseBackupPath()}>
                选择位置…
              </button>
            </div>
          </label>
          <button
            type="button"
            className="signal primary-workflow-action"
            disabled={!backupPath || busy}
            onClick={() => void createBackup()}
          >
            {busy ? "正在创建备份…" : "创建加密备份"}
          </button>
          <p className="safety-note">
            <span aria-hidden="true">✓</span>
            备份保持完整加密，可使用主密码或恢复密钥验证。
          </p>
        </section>
      ) : (
        <>
          <section className="workflow-card" role="tabpanel">
            <div className="workflow-heading">
              <span className="workflow-icon" aria-hidden="true">
                ↶
              </span>
              <div>
                <h3>恢复为新的保险库</h3>
                <p>推荐方式。不会覆盖当前保险库，确认无误后再自行切换。</p>
              </div>
            </div>
            <label>
              1. 选择备份文件
              <div className="path-picker">
                <input
                  readOnly
                  value={source}
                  placeholder="选择一个 .panda8 或旧版 .vaultx 备份文件"
                  aria-label="备份文件"
                />
                <button type="button" onClick={() => void chooseBackupSource()}>
                  选择文件…
                </button>
              </div>
            </label>
            <label>
              2. 输入备份密码或恢复密钥
              <input
                type="password"
                value={password}
                autoComplete="current-password"
                onChange={(event) => setPassword(event.target.value)}
                placeholder="用于验证备份完整性"
              />
            </label>
            <label>
              3. 选择恢复后的保存位置
              <div className="path-picker">
                <input
                  readOnly
                  value={destination}
                  placeholder="新保险库不会覆盖现有文件"
                  aria-label="恢复文件保存位置"
                />
                <button
                  type="button"
                  onClick={() => void chooseRestoreDestination()}
                >
                  选择位置…
                </button>
              </div>
            </label>
            <button
              type="button"
              className="signal primary-workflow-action"
              disabled={!source || !destination || !password || busy}
              onClick={() => void restoreAsNew()}
            >
              {busy ? "正在验证并恢复…" : "验证并恢复"}
            </button>
          </section>
          <details className="advanced-restore">
            <summary>高级选项：替换当前保险库</summary>
            <div>
              <p>
                StarAxis
                会先保留当前密文作为回滚副本，再用上方选择的备份替换并立即锁定。
              </p>
              <label>
                当前保险库主密码
                <input
                  type="password"
                  value={currentPassword}
                  autoComplete="current-password"
                  onChange={(event) => setCurrentPassword(event.target.value)}
                />
              </label>
              <button
                type="button"
                className="danger"
                disabled={!source || !password || !currentPassword || busy}
                onClick={() => {
                  if (
                    !window.confirm(
                      translateText(
                        "最后确认：用已验证备份替换当前保险库，并保留回滚副本？",
                      ),
                    )
                  )
                    return;
                  setBusy(true);
                  void command<string>("replace_active_vault_from_backup", {
                    sourcePath: source,
                    sourcePassword: password,
                    currentPassword,
                    confirmed: true,
                  })
                    .then((rollback) => {
                      setPassword("");
                      setCurrentPassword("");
                      onNotice(`已替换并锁定；旧版本保留在 ${rollback}`);
                    })
                    .catch((cause) => onError(messageOf(cause)))
                    .finally(() => setBusy(false));
                }}
              >
                保留旧版并替换当前保险库
              </button>
            </div>
          </details>
        </>
      )}
    </div>
  );
}

function SecurityPanel({
  onChangePassword,
  onNotice,
  onError,
}: {
  onChangePassword: () => void;
  onNotice: (message: string) => void;
  onError: (error: string) => void;
}) {
  const [recoveryPassword, setRecoveryPassword] = useState("");
  const [recovery, setRecovery] = useState("");
  const [confirmation, setConfirmation] = useState("");
  return (
    <div className="tool-card">
      <p className="eyebrow">CREDENTIAL SLOTS</p>
      <h2>密钥与恢复</h2>
      <p className="field-help">
        为当前保险库增加独立的离线恢复凭据，或轮换主密码与密钥派生参数。StarAxis
        不会上传、代管或在线找回这些凭据。
      </p>
      <section>
        <h3>恢复密钥</h3>
        <p>生成高熵恢复槽后，必须抄写并试恢复确认。密钥只显示一次。</p>
        <label>
          用于生成恢复密钥的当前主密码
          <input
            type="password"
            autoComplete="current-password"
            value={recoveryPassword}
            onChange={(event) => setRecoveryPassword(event.target.value)}
          />
        </label>
        <button
          type="button"
          disabled={!recoveryPassword}
          onClick={() =>
            void command<string>("generate_recovery_key_value", {
              currentPassword: recoveryPassword,
            })
              .then((key) => {
                setRecovery(key);
                setRecoveryPassword("");
              })
              .catch((cause) => onError(messageOf(cause)))
          }
        >
          生成并写入恢复槽
        </button>
        {recovery && (
          <div className="recovery-key">
            <code>{recovery}</code>
            <p>离线保存后，在下方重新输入以完成试恢复。</p>
            <input
              value={confirmation}
              onChange={(event) => setConfirmation(event.target.value)}
            />
            <button
              type="button"
              className="signal"
              disabled={!confirmation}
              onClick={() =>
                void command<boolean>("confirm_recovery_key_value", {
                  recoveryKey: confirmation,
                })
                  .then((valid) =>
                    valid
                      ? (setRecovery(""),
                        setConfirmation(""),
                        onNotice("恢复密钥试恢复成功"))
                      : onError("恢复密钥不匹配"),
                  )
                  .catch((cause) => onError(messageOf(cause)))
              }
            >
              确认试恢复
            </button>
          </div>
        )}
      </section>
      <section>
        <h3>修改主密码</h3>
        <p className="field-help">
          验证当前主密码后设置新密码，同时升级当前保险库的 Argon2id
          参数。修改后需要重新生成恢复密钥。
        </p>
        <button type="button" className="signal" onClick={onChangePassword}>
          修改主密码…
        </button>
      </section>
    </div>
  );
}

function BrowserExtensionPanel({
  onNotice,
  onError,
}: {
  onNotice: (notice: string) => void;
  onError: (error: string) => void;
}) {
  const [pending, setPending] = useState<PendingExtensionPair[]>([]);
  const [paired, setPaired] = useState<PairedExtension[]>([]);
  const [busyId, setBusyId] = useState<string>();

  const refresh = useCallback(async () => {
    try {
      const [nextPending, nextPaired] = await Promise.all([
        command<PendingExtensionPair[]>("list_pending_extension_pairs"),
        command<PairedExtension[]>("list_paired_extensions"),
      ]);
      setPending(nextPending);
      setPaired(nextPaired);
    } catch (cause) {
      onError(messageOf(cause));
    }
  }, [onError]);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 1_000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const act = async (id: string, operation: () => Promise<unknown>) => {
    setBusyId(id);
    try {
      await operation();
      await refresh();
    } catch (cause) {
      onError(messageOf(cause));
    } finally {
      setBusyId(undefined);
    }
  };

  return (
    <div className="extension-settings">
      <header className="extension-hero">
        <div>
          <p className="eyebrow">LOCAL BROWSER BRIDGE</p>
          <h2>浏览器扩展</h2>
          <p>
            在 Chrome、Edge 或 Firefox
            中点击账号后，由当前已解锁保险库完成一次性安全填充。
          </p>
        </div>
        <span className="extension-orbit" aria-hidden="true">
          <i />
          <i />
          <i />
        </span>
      </header>

      {pending.length > 0 && (
        <section className="pairing-requests" aria-label="待确认配对">
          <div className="extension-section-title">
            <div>
              <span className="live-dot" />
              <strong>待确认配对</strong>
            </div>
            <small>请核对扩展弹窗中的六位数字</small>
          </div>
          {pending.map((pair) => (
            <article className="pair-request" key={pair.pending_id}>
              <div className="browser-badge">
                {browserName(pair.browser).slice(0, 1)}
              </div>
              <div className="pair-copy">
                <strong>
                  {browserName(pair.browser)} · {pair.profile_name}
                </strong>
                <small>{pair.extension_origin}</small>
              </div>
              <code>{pair.verification_code}</code>
              <div className="pair-actions">
                <button
                  type="button"
                  className="quiet"
                  disabled={busyId === pair.pending_id}
                  onClick={() =>
                    void act(pair.pending_id, async () => {
                      await command("reject_extension_pairing", {
                        pendingId: pair.pending_id,
                      });
                      onNotice("已拒绝浏览器配对");
                    })
                  }
                >
                  拒绝
                </button>
                <button
                  type="button"
                  className="signal"
                  disabled={busyId === pair.pending_id}
                  onClick={() =>
                    void act(pair.pending_id, async () => {
                      await command("approve_extension_pairing", {
                        pendingId: pair.pending_id,
                        verificationCode: pair.verification_code,
                      });
                      onNotice("浏览器扩展已安全配对");
                    })
                  }
                >
                  代码一致，允许
                </button>
              </div>
            </article>
          ))}
        </section>
      )}

      <section className="paired-browsers">
        <div className="extension-section-title">
          <div>
            <strong>已配对浏览器</strong>
          </div>
          <small>{paired.length} 个浏览器配置</small>
        </div>
        {paired.length === 0 ? (
          <div className="extension-empty">
            <span>⌁</span>
            <div>
              <strong>尚未连接浏览器</strong>
              <p>安装扩展并点击“开始配对”，请求会在这里出现。</p>
            </div>
          </div>
        ) : (
          <div className="paired-list">
            {paired.map((pair) => (
              <article key={pair.pair_id}>
                <div className="browser-badge paired">
                  {browserName(pair.browser).slice(0, 1)}
                </div>
                <div className="pair-copy">
                  <strong>
                    {browserName(pair.browser)} · {pair.profile_name}
                  </strong>
                  <small>
                    指纹 {pair.fingerprint} · {lastUsedText(pair.last_used_at)}
                  </small>
                </div>
                <button
                  type="button"
                  className="danger-link"
                  disabled={busyId === pair.pair_id}
                  onClick={() =>
                    void act(pair.pair_id, async () => {
                      await command("revoke_extension_pairing", {
                        pairId: pair.pair_id,
                      });
                      onNotice("浏览器配对已撤销");
                    })
                  }
                >
                  撤销
                </button>
              </article>
            ))}
          </div>
        )}
      </section>

      <section className="extension-policy">
        <div>
          <span>✓</span>
          <p>
            <strong>桌面端唯一解密</strong>
            扩展不读取保险库文件，也不保存主密码、Vault Key 或密码缓存。
          </p>
        </div>
        <div>
          <span>✓</span>
          <p>
            <strong>精确 HTTPS 匹配</strong>
            默认不在 HTTP、iframe、相似域名和没有精确 URL 匹配的页面填充。
          </p>
        </div>
        <div>
          <span>✓</span>
          <p>
            <strong>锁定立即拒绝</strong>
            保险库锁定后，候选查询和秘密释放都会被桌面端拒绝。
          </p>
        </div>
      </section>

      {paired.length > 1 && (
        <button
          type="button"
          className="revoke-all"
          onClick={() => {
            if (
              !window.confirm(
                translateText("撤销全部浏览器配对？所有扩展都需要重新确认。"),
              )
            )
              return;
            void act("all", async () => {
              await command("revoke_all_extension_pairings", {
                confirmed: true,
              });
              onNotice("全部浏览器配对已撤销");
            });
          }}
        >
          撤销全部浏览器配对
        </button>
      )}
    </div>
  );
}

function browserName(browser: PairedExtension["browser"]) {
  if (browser === "edge") return "Microsoft Edge";
  if (browser === "firefox") return "Firefox";
  return "Google Chrome";
}

function lastUsedText(value?: number) {
  if (!value) return "尚未使用";
  return `最后使用 ${new Date(value).toLocaleString("zh-CN", {
    month: "numeric",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  })}`;
}

function SettingsPanel({
  settings,
  onChangePassword,
  onOpenKeyRecovery,
  onSaved,
  onError,
}: {
  settings: Settings;
  onChangePassword: () => void;
  onOpenKeyRecovery: () => void;
  onSaved: (settings: Settings) => void;
  onError: (error: string) => void;
}) {
  const [draft, setDraft] = useState(settings);
  return (
    <form
      className="tool-card"
      onSubmit={(event) => {
        event.preventDefault();
        void command("update_settings", { settings: draft })
          .then(() => onSaved(draft))
          .catch((cause) => onError(messageOf(cause)));
      }}
    >
      <p className="eyebrow">LOCAL POLICY</p>
      <h2>安全设置</h2>
      <section className="vault-security-settings">
        <div className="vault-security-heading">
          <span className="vault-security-icon" aria-hidden="true">
            ⌁
          </span>
          <div>
            <h3>保险库安全</h3>
            <p>
              管理当前已打开保险库的主密码。修改时会验证旧密码，并更新密钥派生参数。
            </p>
          </div>
        </div>
        <div className="vault-security-actions">
          <button type="button" className="quiet" onClick={onOpenKeyRecovery}>
            密钥与恢复…
          </button>
          <button type="button" className="quiet" onClick={onChangePassword}>
            修改主密码…
          </button>
        </div>
      </section>
      <label>
        自动锁定（秒，0 为关闭）
        <input
          type="number"
          min="0"
          max="86400"
          value={draft.auto_lock_seconds}
          onChange={(event) =>
            setDraft({
              ...draft,
              auto_lock_seconds: Number(event.target.value),
            })
          }
        />
      </label>
      <label>
        剪贴板条件清理（秒）
        <input
          type="number"
          min="5"
          max="300"
          value={draft.clipboard_clear_seconds}
          onChange={(event) =>
            setDraft({
              ...draft,
              clipboard_clear_seconds: Number(event.target.value),
            })
          }
        />
      </label>
      <label>
        同目录自动备份保留版本数（0 为关闭）
        <input
          type="number"
          min="0"
          max="100"
          value={draft.backup_versions}
          onChange={(event) =>
            setDraft({ ...draft, backup_versions: Number(event.target.value) })
          }
        />
        <small className="field-help">
          每次提交前备份上一个已认证密文版本；降低数量后会尽力清理应用管理的旧自动备份。
        </small>
      </label>
      <label className="check-row">
        <input
          type="checkbox"
          checked={draft.lock_on_minimize}
          onChange={(event) =>
            setDraft({ ...draft, lock_on_minimize: event.target.checked })
          }
        />
        最小化时锁定保险库
      </label>
      <div className="capability-box">
        <strong>当前能力</strong>
        <span>✓ 本地独立文件</span>
        <span>✓ 条件剪贴板清理</span>
        <span>△ 截图防护依赖平台</span>
        <span>△ 系统剪贴板历史无法清除</span>
      </div>
      <button className="signal" type="submit">
        保存设置
      </button>
    </form>
  );
}

function ChangeMainPasswordDialog({
  onClose,
  onChanged,
}: {
  onClose: () => void;
  onChanged: () => void;
}) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [passwordsVisible, setPasswordsVisible] = useState(false);
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<string>();

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy) return;
    if (newPassword !== confirmation) {
      setFormError("两次输入的新主密码不一致");
      return;
    }
    if (currentPassword === newPassword) {
      setFormError("新主密码需要与当前主密码不同");
      return;
    }

    setBusy(true);
    setFormError(undefined);
    try {
      await command("change_main_password", {
        currentPassword,
        newPassword,
      });
      setCurrentPassword("");
      setNewPassword("");
      setConfirmation("");
      onChanged();
    } catch (cause) {
      const message = messageOf(cause);
      setFormError(
        /authentication|reauthentication/i.test(message)
          ? "当前主密码不正确"
          : message,
      );
    } finally {
      setBusy(false);
    }
  }

  const inputType = passwordsVisible ? "text" : "password";

  return (
    <div
      className="dialog-backdrop"
      role="presentation"
      onMouseDown={() => {
        if (!busy) onClose();
      }}
    >
      <form
        className="password-change-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="password-change-title"
        onSubmit={(event) => void submit(event)}
        onMouseDown={(event) => event.stopPropagation()}
        onKeyDown={(event) => {
          if (event.key === "Escape" && !busy) onClose();
        }}
      >
        <div className="dialog-head">
          <div>
            <span
              className="dialog-icon password-change-icon"
              aria-hidden="true"
            >
              ⌁
            </span>
            <div>
              <p className="eyebrow">VAULT SECURITY</p>
              <h2 id="password-change-title">修改主密码</h2>
            </div>
          </div>
          <button
            type="button"
            className="dialog-close"
            aria-label="关闭修改主密码窗口"
            onClick={onClose}
            disabled={busy}
          >
            ×
          </button>
        </div>

        <p className="password-change-intro">
          此操作只影响当前保险库。StarAxis 不会保存或找回你的主密码。
        </p>

        <div className="password-change-fields">
          <label>
            当前主密码
            <input
              autoFocus
              required
              type={inputType}
              autoComplete="current-password"
              value={currentPassword}
              onChange={(event) => {
                setCurrentPassword(event.target.value);
                setFormError(undefined);
              }}
            />
          </label>
          <label>
            新主密码
            <input
              required
              type={inputType}
              autoComplete="new-password"
              value={newPassword}
              onChange={(event) => {
                setNewPassword(event.target.value);
                setFormError(undefined);
              }}
            />
          </label>
          <label>
            确认新主密码
            <input
              required
              type={inputType}
              autoComplete="new-password"
              value={confirmation}
              onChange={(event) => {
                setConfirmation(event.target.value);
                setFormError(undefined);
              }}
            />
          </label>
        </div>

        <button
          type="button"
          className="password-visibility"
          aria-pressed={passwordsVisible}
          onClick={() => setPasswordsVisible((visible) => !visible)}
        >
          <span aria-hidden="true">{passwordsVisible ? "◉" : "◎"}</span>
          {passwordsVisible ? "隐藏所有密码" : "显示所有密码"}
        </button>

        <div className="password-change-warning">
          <span aria-hidden="true">!</span>
          <p>
            当前保险库的旧主密码和恢复密钥将失效；历史备份及复制到其他位置的旧文件仍可能被旧凭据打开。
          </p>
        </div>

        {formError && (
          <p className="form-error" role="alert">
            {formError}
          </p>
        )}

        <div className="dialog-actions password-change-actions">
          <span />
          <button
            type="button"
            className="quiet"
            onClick={onClose}
            disabled={busy}
          >
            取消
          </button>
          <button
            type="submit"
            className="signal"
            disabled={busy || !currentPassword || !newPassword || !confirmation}
          >
            {busy ? "正在修改…" : "修改主密码"}
          </button>
        </div>
      </form>
    </div>
  );
}

function startNew(
  kind: ItemKind,
  groups: Group[],
  setDetail: (detail: ItemDetail) => void,
  setSelected: (item: ItemSummary | undefined) => void,
) {
  if (!groups[0]) return;
  setSelected(undefined);
  setDetail({
    id: [],
    group_id: groups[0].id,
    kind,
    title: "",
    favorite: false,
    tags: [],
    usernames: [],
    password: "",
    urls: [],
    url_match_modes: [],
    notes: "",
    content: "",
    custom_fields: [],
    history: [],
  });
}

import "@testing-library/jest-dom/vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";
import { LOCALE_STORAGE_KEY } from "./i18n";

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));

vi.mock("@tauri-apps/api/core", () => ({ invoke: invokeMock }));

const root = Array(16).fill(1);
const work = Array(16).fill(2);
const login = Array(16).fill(3);
const note = Array(16).fill(4);

const settings = {
  auto_lock_seconds: 300,
  clipboard_clear_seconds: 30,
  lock_on_minimize: false,
  backup_versions: 3,
};

describe("E01 mist settings item editors", () => {
  beforeEach(() => {
    window.localStorage.setItem(LOCALE_STORAGE_KEY, "zh-CN");
    Object.defineProperty(window, "__TAURI_INTERNALS__", {
      configurable: true,
      value: {},
    });
    invokeMock.mockImplementation(
      (
        command: string,
        args?: {
          id?: number[];
          filter?: { include_deleted?: boolean };
        },
      ) => {
        if (command === "session_state") return Promise.resolve("unlocked");
        if (command === "record_user_activity") return Promise.resolve(null);
        if (command === "list_groups")
          return Promise.resolve([
            { id: root, parent_id: null, name: "Root" },
            { id: work, parent_id: root, name: "工作" },
          ]);
        if (command === "list_items") {
          const deleted = Boolean(args?.filter?.include_deleted);
          return Promise.resolve([
            {
              id: login,
              kind: "login",
              title: "墨者学院",
              favorite: true,
              tags: ["学习"],
              primary_username: "panda8@example.com",
              primary_url: "mozhe.cn",
              deleted,
            },
            {
              id: note,
              kind: "secure_note",
              title: "服务器恢复说明",
              favorite: false,
              tags: ["运维"],
              deleted,
            },
          ]);
        }
        if (command === "get_settings") return Promise.resolve(settings);
        if (command === "get_item_detail") {
          const isNote = JSON.stringify(args?.id) === JSON.stringify(note);
          return Promise.resolve(
            isNote
              ? {
                  id: note,
                  group_id: work,
                  kind: "secure_note",
                  title: "服务器恢复说明",
                  favorite: false,
                  tags: ["运维"],
                  usernames: [],
                  password: null,
                  urls: [],
                  url_match_modes: [],
                  notes: null,
                  content: "恢复前先确认备份完整性。",
                  custom_fields: [],
                  history: [],
                }
              : {
                  id: login,
                  group_id: work,
                  kind: "login",
                  title: "墨者学院",
                  favorite: true,
                  tags: ["学习"],
                  usernames: ["panda8@example.com"],
                  password: "correct-horse-battery-staple",
                  urls: ["mozhe.cn"],
                  url_match_modes: ["anywhere_on_website"],
                  notes: "网络安全学习平台账号",
                  content: null,
                  custom_fields: [],
                  history: [],
                },
          );
        }
        return Promise.resolve(null);
      },
    );
  });

  afterEach(() => {
    cleanup();
    invokeMock.mockReset();
    vi.restoreAllMocks();
    window.localStorage.removeItem(LOCALE_STORAGE_KEY);
    Reflect.deleteProperty(window, "__TAURI_INTERNALS__");
  });

  it("uses the selected settings-group layout for login and note editing only", async () => {
    render(<App />);

    const loginButton = (
      await screen.findByText("墨者学院", { selector: "strong" })
    ).closest("button");
    expect(loginButton).not.toBeNull();
    fireEvent.click(loginButton!);
    await screen.findByRole("heading", { name: "墨者学院" });
    fireEvent.click(screen.getByRole("button", { name: "编辑" }));

    const loginTitle = await screen.findByRole("textbox", { name: "标题" });
    const loginEditor = loginTitle.closest("form");
    expect(loginEditor).toHaveClass("mist-settings-editor");
    expect(loginEditor?.querySelectorAll(".mist-setting-card").length).toBe(5);
    expect(loginEditor?.querySelector(".editor-section")).toBeNull();
    expect(loginEditor?.querySelector(".mist-record-type")).toHaveTextContent(
      "标题",
    );
    expect(screen.getByText("用于浏览器扩展匹配")).toBeVisible();

    const noteButton = screen
      .getByText("服务器恢复说明", { selector: "strong" })
      .closest("button");
    expect(noteButton).not.toBeNull();
    fireEvent.click(noteButton!);
    await screen.findByRole("heading", { name: "服务器恢复说明" });
    fireEvent.click(screen.getByRole("button", { name: "编辑" }));

    await waitFor(() => {
      const noteTitle = screen.getByRole("textbox", { name: "标题" });
      expect(noteTitle.closest("form")).toHaveClass("mist-settings-editor");
    });
    expect(screen.getByText("随保险库加密保存在本地")).toBeVisible();
    expect(document.querySelector(".mist-note-row")).not.toBeNull();
    expect(document.querySelector(".mist-record-type")).toHaveTextContent(
      "标题",
    );
  });

  it("offers contextual deletion actions from the detail more menu", async () => {
    render(<App />);

    const loginButton = (
      await screen.findByText("墨者学院", { selector: "strong" })
    ).closest("button");
    expect(loginButton).not.toBeNull();
    fireEvent.click(loginButton!);
    await screen.findByRole("heading", { name: "墨者学院" });

    fireEvent.click(screen.getByRole("button", { name: "更多操作" }));
    const moveToTrash = screen.getByRole("menuitem", {
      name: /移动到回收站/,
    });
    expect(moveToTrash).toBeVisible();
    expect(
      screen.queryByRole("menuitem", { name: /^恢复/ }),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: /永久删除/ })).toBeVisible();
    fireEvent.click(moveToTrash);
    expect(
      screen.getByRole("dialog", { name: "移动到回收站？" }),
    ).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "移动到回收站" }));
    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith("soft_delete_item", {
        id: login,
      }),
    );

    fireEvent.click(screen.getByRole("button", { name: /回收站/ }));
    const trashedLoginButton = (
      await screen.findByText("墨者学院", { selector: "strong" })
    ).closest("button");
    expect(trashedLoginButton).not.toBeNull();
    fireEvent.click(trashedLoginButton!);
    await screen.findByRole("heading", { name: "墨者学院" });

    fireEvent.click(screen.getByRole("button", { name: "更多操作" }));
    expect(screen.getByRole("menuitem", { name: /^恢复/ })).toBeVisible();
    const permanentlyDelete = screen.getByRole("menuitem", {
      name: /永久删除/,
    });
    expect(permanentlyDelete).toBeVisible();
    fireEvent.click(permanentlyDelete);
    expect(
      screen.getByRole("dialog", { name: "永久删除这个条目？" }),
    ).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "永久删除" }));
    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith("permanently_delete_item", {
        id: login,
      }),
    );
  });

  it("restores a recycled item directly from the detail more menu", async () => {
    render(<App />);

    fireEvent.click(await screen.findByRole("button", { name: /回收站/ }));
    const trashedLoginButton = (
      await screen.findByText("墨者学院", { selector: "strong" })
    ).closest("button");
    expect(trashedLoginButton).not.toBeNull();
    fireEvent.click(trashedLoginButton!);
    await screen.findByRole("heading", { name: "墨者学院" });

    fireEvent.click(screen.getByRole("button", { name: "更多操作" }));
    fireEvent.click(screen.getByRole("menuitem", { name: /^恢复/ }));

    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith("restore_item", {
        id: login,
      }),
    );
    expect(await screen.findByText("条目已恢复")).toBeVisible();
    expect(
      screen.queryByRole("heading", { name: "墨者学院" }),
    ).not.toBeInTheDocument();
  });

  it("keeps a deletion action mounted through the macOS WebKit focus-to-click sequence", async () => {
    render(<App />);

    const loginButton = (
      await screen.findByText("墨者学院", { selector: "strong" })
    ).closest("button");
    expect(loginButton).not.toBeNull();
    fireEvent.click(loginButton!);
    await screen.findByRole("heading", { name: "墨者学院" });

    fireEvent.click(screen.getByRole("button", { name: "更多操作" }));
    const permanentlyDelete = screen.getByRole("menuitem", {
      name: /永久删除/,
    });

    fireEvent.pointerDown(permanentlyDelete);
    fireEvent.blur(permanentlyDelete, { relatedTarget: null });
    expect(permanentlyDelete).toBeInTheDocument();
    fireEvent.click(permanentlyDelete);

    expect(
      screen.getByRole("dialog", { name: "永久删除这个条目？" }),
    ).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "取消" }));
    expect(invokeMock).not.toHaveBeenCalledWith("permanently_delete_item", {
      id: login,
    });
  });

  it("permanently deletes an active detail through a safe recycle-bin transition", async () => {
    render(<App />);

    const loginButton = (
      await screen.findByText("墨者学院", { selector: "strong" })
    ).closest("button");
    expect(loginButton).not.toBeNull();
    fireEvent.click(loginButton!);
    await screen.findByRole("heading", { name: "墨者学院" });

    fireEvent.click(screen.getByRole("button", { name: "更多操作" }));
    fireEvent.click(screen.getByRole("menuitem", { name: /永久删除/ }));
    expect(
      screen.getByRole("dialog", { name: "永久删除这个条目？" }),
    ).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "永久删除" }));

    await waitFor(() => {
      const deletionCalls = invokeMock.mock.calls.filter(
        ([command]) =>
          typeof command === "string" &&
          ["soft_delete_item", "permanently_delete_item"].includes(command),
      );
      expect(deletionCalls).toEqual([
        ["soft_delete_item", { id: login }],
        ["permanently_delete_item", { id: login }],
      ]);
    });
  });

  it("changes the current vault password from the security settings dialog", async () => {
    render(<App />);

    const vaultStatus = await screen.findByRole("status", {
      name: "独立保险库，已加密保存",
    });
    expect(vaultStatus).toBeVisible();
    expect(vaultStatus.tagName).toBe("DIV");
    fireEvent.click(vaultStatus);
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();

    const settingsButton = (
      await screen.findByText("设置", { selector: ".nav-label" })
    ).closest("button");
    expect(settingsButton).not.toBeNull();
    fireEvent.click(settingsButton!);
    expect(
      await screen.findByRole("heading", { name: "保险库安全" }),
    ).toBeVisible();
    expect(screen.getByRole("button", { name: "密钥与恢复…" })).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "修改主密码…" }));

    const dialog = screen.getByRole("dialog", { name: "修改主密码" });
    expect(dialog).toBeVisible();
    const currentPassword = screen.getByLabelText("当前主密码");
    const newPassword = screen.getByLabelText("新主密码");
    const confirmation = screen.getByLabelText("确认新主密码");

    fireEvent.change(currentPassword, { target: { value: "old password" } });
    fireEvent.change(newPassword, { target: { value: "new password" } });
    fireEvent.change(confirmation, { target: { value: "not the same" } });
    fireEvent.click(screen.getByRole("button", { name: "修改主密码" }));
    expect(screen.getByRole("alert")).toHaveTextContent(
      "两次输入的新主密码不一致",
    );
    expect(invokeMock).not.toHaveBeenCalledWith("change_main_password", {
      currentPassword: "old password",
      newPassword: "new password",
    });

    fireEvent.change(confirmation, { target: { value: "new password" } });
    fireEvent.click(screen.getByRole("button", { name: "显示所有密码" }));
    expect(currentPassword).toHaveAttribute("type", "text");
    expect(newPassword).toHaveAttribute("type", "text");
    expect(confirmation).toHaveAttribute("type", "text");

    fireEvent.click(screen.getByRole("button", { name: "修改主密码" }));
    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith("change_main_password", {
        currentPassword: "old password",
        newPassword: "new password",
      }),
    );
    expect(
      await screen.findByText("主密码已修改；恢复密钥已失效，请重新生成"),
    ).toBeVisible();
    expect(
      screen.queryByRole("dialog", { name: "修改主密码" }),
    ).not.toBeInTheDocument();
  });

  it("switches the vault interface language immediately and persists it", async () => {
    render(<App />);

    const languageSelector = await screen.findByRole("group", {
      name: "语言",
    });
    expect(languageSelector.closest(".rail")).not.toBeNull();
    fireEvent.click(
      screen.getByRole("button", { name: "English", pressed: false }),
    );
    expect(window.localStorage.getItem(LOCALE_STORAGE_KEY)).toBe("en");

    fireEvent.click(
      (await screen.findByText("Settings", { selector: ".nav-label" })).closest(
        "button",
      )!,
    );
    expect(
      await screen.findByRole("heading", { name: "Security Settings" }),
    ).toBeVisible();
    expect(
      screen.getByRole("heading", { name: "Vault Security" }),
    ).toBeVisible();

    fireEvent.click(screen.getByRole("button", { name: "简体中文" }));
    expect(window.localStorage.getItem(LOCALE_STORAGE_KEY)).toBe("zh-CN");
    expect(
      await screen.findByRole("heading", { name: "安全设置" }),
    ).toBeVisible();
    expect(
      screen.queryByRole("heading", { name: "语言" }),
    ).not.toBeInTheDocument();
  });
});

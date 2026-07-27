import { afterEach, describe, expect, it, vi } from "vitest";

import {
  DEFAULT_EXTENSION_LOCALE,
  EXTENSION_LOCALE_KEY,
  readExtensionLocale,
  translateExtensionText,
  writeExtensionLocale,
} from "./locale";

describe("extension locale", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("uses English as the default and translates dynamic extension messages", () => {
    expect(DEFAULT_EXTENSION_LOCALE).toBe("en");
    expect(translateExtensionText("连接桌面端", "en")).toBe(
      "Connect to Desktop",
    );
    expect(translateExtensionText("2 个可用账号", "en")).toBe(
      "2 available accounts",
    );
    expect(
      translateExtensionText("Portal 已加密写入StarAxis保险库", "en"),
    ).toBe("Portal was encrypted and saved to the StarAxis vault.");
    expect(translateExtensionText("连接桌面端", "zh-CN")).toBe("连接桌面端");
  });

  it("reads and writes the independent browser-storage preference", async () => {
    const set = vi.fn();
    const get = vi.fn(
      (_keys: string[], callback: (items: Record<string, unknown>) => void) =>
        callback({ [EXTENSION_LOCALE_KEY]: "zh-CN" }),
    );
    vi.stubGlobal("chrome", {
      storage: {
        local: { get, set },
      },
    });

    const locale = await new Promise<string>((resolve) => {
      readExtensionLocale(resolve);
    });
    expect(locale).toBe("zh-CN");

    writeExtensionLocale("en");
    expect(set).toHaveBeenCalledWith({ [EXTENSION_LOCALE_KEY]: "en" });
  });
});

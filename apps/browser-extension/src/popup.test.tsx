import "@testing-library/jest-dom/vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { beforeAll, describe, expect, it, vi } from "vitest";

import { EXTENSION_LOCALE_KEY } from "./locale";

const storageSet = vi.fn();

beforeAll(async () => {
  document.body.innerHTML = '<div id="root"></div>';
  vi.stubGlobal("chrome", {
    runtime: {
      lastError: undefined,
      sendMessage: (_message: unknown, callback: (response: unknown) => void) =>
        callback({ kind: "unpaired" }),
    },
    storage: {
      local: {
        get: (
          _keys: string[],
          callback: (items: Record<string, unknown>) => void,
        ) => callback({}),
        set: storageSet,
      },
      onChanged: {
        addListener: vi.fn(),
        removeListener: vi.fn(),
      },
    },
  });
  await import("./popup");
});

describe("popup language selector", () => {
  it("defaults to English and persists Simplified Chinese independently", async () => {
    expect(
      await screen.findByRole("heading", { name: "Connect to Desktop" }),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "English", pressed: true }),
    ).toBeVisible();

    fireEvent.click(
      screen.getByRole("button", { name: "简体中文", pressed: false }),
    );
    expect(
      await screen.findByRole("heading", { name: "连接桌面端" }),
    ).toBeVisible();
    await waitFor(() =>
      expect(storageSet).toHaveBeenCalledWith({
        [EXTENSION_LOCALE_KEY]: "zh-CN",
      }),
    );
  });
});

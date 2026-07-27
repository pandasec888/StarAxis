import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  clearClipboardIfUnchanged,
  copyWithConditionalClear,
} from "./clipboard";

describe("conditional clipboard clearing", () => {
  let clipboardValue = "";
  const writeText = vi.fn((value: string) => {
    clipboardValue = value;
    return Promise.resolve();
  });
  const readText = vi.fn(() => Promise.resolve(clipboardValue));

  beforeEach(() => {
    clipboardValue = "";
    writeText.mockClear();
    readText.mockClear();
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { readText, writeText },
    });
  });

  it("clears only the exact secret previously written by StarAxis", async () => {
    const lease = await copyWithConditionalClear("vault-secret", 30);
    expect(clipboardValue).toBe("vault-secret");
    expect(await clearClipboardIfUnchanged(lease)).toBe(true);
    expect(clipboardValue).toBe("");
  });

  it("does not overwrite content copied by the user afterwards", async () => {
    const lease = await copyWithConditionalClear("vault-secret", 30);
    clipboardValue = "new user content";
    expect(await clearClipboardIfUnchanged(lease)).toBe(false);
    expect(clipboardValue).toBe("new user content");
    expect(writeText).toHaveBeenCalledTimes(1);
  });
});

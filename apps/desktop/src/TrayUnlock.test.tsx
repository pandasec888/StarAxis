import "@testing-library/jest-dom/vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { TrayUnlock } from "./TrayUnlock";
import { LOCALE_STORAGE_KEY } from "./i18n";

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));

vi.mock("@tauri-apps/api/core", () => ({ invoke: invokeMock }));

describe("TrayUnlock", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.localStorage.removeItem(LOCALE_STORAGE_KEY);
    Object.defineProperty(window, "__TAURI_INTERNALS__", {
      configurable: true,
      value: {},
    });
    invokeMock.mockImplementation((name: string) => {
      if (name === "tray_unlock_context") {
        return Promise.resolve({
          state: "locked",
          vault_name: "personal.panda8",
        });
      }
      return Promise.resolve();
    });
  });

  it("unlocks the selected vault without persisting the password in the UI", async () => {
    render(<TrayUnlock />);

    expect(await screen.findByText("personal.panda8")).toBeVisible();
    const password = screen.getByLabelText("Master password");
    fireEvent.change(password, { target: { value: "menu-bar-secret" } });
    fireEvent.click(screen.getByRole("button", { name: "Unlock" }));

    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith("unlock_vault_from_tray", {
        password: "menu-bar-secret",
      }),
    );
    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith("hide_tray_unlock", {}),
    );
    expect(password).toHaveValue("");
  });
});

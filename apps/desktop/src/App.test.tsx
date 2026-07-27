import "@testing-library/jest-dom/vitest";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import { App } from "./App";
import { LOCALE_STORAGE_KEY } from "./i18n";

describe("App", () => {
  beforeEach(() => {
    window.localStorage.removeItem(LOCALE_STORAGE_KEY);
  });

  it("renders the desktop shell", () => {
    render(<App />);

    expect(screen.getByRole("heading", { name: "StarAxis" })).toBeVisible();
    expect(screen.getByText(/Encrypted locally/)).toBeVisible();
    expect(screen.getByLabelText("Author panda8")).toHaveTextContent(
      "Author: panda8",
    );
    expect(
      screen.getByRole("link", { name: "panda8's GitHub profile" }),
    ).toHaveAttribute("href", "https://github.com/pandasec888/");
    expect(screen.getByLabelText("Master password")).not.toHaveAttribute(
      "minlength",
    );
  });
});

import { describe, expect, it } from "vitest";

import {
  LEGACY_VAULT_EXTENSION,
  VAULT_DIALOG_FILTERS,
  VAULT_EXTENSION,
  withVaultExtension,
} from "./vault-path";

describe("vault file paths", () => {
  it("uses panda8 for new vaults and exported backups", () => {
    expect(withVaultExtension("/Users/me/Personal")).toBe(
      "/Users/me/Personal.panda8",
    );
    expect(withVaultExtension("/Users/me/Personal.PANDA8")).toBe(
      "/Users/me/Personal.PANDA8",
    );
    expect(withVaultExtension("/Users/me/Personal.vaultx")).toBe(
      "/Users/me/Personal.panda8",
    );
  });

  it("keeps the legacy extension available in open dialogs", () => {
    expect(VAULT_EXTENSION).toBe("panda8");
    expect(LEGACY_VAULT_EXTENSION).toBe("vaultx");
    expect(VAULT_DIALOG_FILTERS[0]?.extensions).toEqual(["panda8", "vaultx"]);
  });
});

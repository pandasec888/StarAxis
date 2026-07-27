export const VAULT_EXTENSION = "panda8";
export const LEGACY_VAULT_EXTENSION = "vaultx";

export const VAULT_DIALOG_FILTERS = [
  {
    name: "StarAxis Vault",
    extensions: [VAULT_EXTENSION, LEGACY_VAULT_EXTENSION],
  },
];

export function withVaultExtension(path: string) {
  const lowerPath = path.toLowerCase();
  if (lowerPath.endsWith(`.${VAULT_EXTENSION}`)) return path;
  if (lowerPath.endsWith(`.${LEGACY_VAULT_EXTENSION}`)) {
    return `${path.slice(0, -LEGACY_VAULT_EXTENSION.length)}${VAULT_EXTENSION}`;
  }
  return `${path}.${VAULT_EXTENSION}`;
}

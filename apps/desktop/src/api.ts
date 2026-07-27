import { invoke } from "@tauri-apps/api/core";

export type Id = number[];
export type SessionState =
  | "locked"
  | "unlocked"
  | "dirty"
  | "saving"
  | "conflict_pending"
  | "save_result_unknown";

export type ItemKind = "login" | "secure_note";
export type UrlMatchMode = "anywhere_on_website" | "exact_host" | "never";
export type ItemSort =
  | "title_ascending"
  | "title_descending"
  | "updated_newest"
  | "updated_oldest"
  | "created_newest"
  | "created_oldest";

export interface ItemSummary {
  id: Id;
  kind: ItemKind;
  title: string;
  favorite: boolean;
  tags: string[];
  primary_username?: string;
  primary_url?: string;
  deleted: boolean;
}

export interface Group {
  id: Id;
  parent_id?: Id;
  name: string;
}

export interface CustomField {
  name: string;
  value: string;
  sensitivity: "concealed" | "visible";
}

export interface ItemDetail {
  id: Id;
  group_id: Id;
  kind: ItemKind;
  title: string;
  favorite: boolean;
  tags: string[];
  usernames: string[];
  password?: string;
  urls: string[];
  url_match_modes: UrlMatchMode[];
  notes?: string;
  content?: string;
  custom_fields: CustomField[];
  history: Array<{
    index: number;
    revision: number;
    title: string;
    updated_at_unix_ms: number;
  }>;
}

export interface Settings {
  auto_lock_seconds: number;
  clipboard_clear_seconds: number;
  lock_on_minimize: boolean;
  backup_versions: number;
}

export interface RecentVault {
  path: string;
  name: string;
  parent: string;
  last_opened_unix_ms: number;
  exists: boolean;
}

export type BrowserKind = "chrome" | "edge" | "firefox";

export interface PendingExtensionPair {
  pending_id: string;
  browser: BrowserKind;
  profile_name: string;
  extension_origin: string;
  verification_code: string;
  expires_at: number;
}

export interface PairedExtension {
  pair_id: string;
  browser: BrowserKind;
  profile_name: string;
  extension_origin: string;
  fingerprint: string;
  created_at: number;
  last_used_at?: number;
}

export interface CsvMapping {
  title: string;
  username?: string;
  password: string;
  url?: string;
  notes?: string;
  tags?: string;
}

export interface CsvPreview {
  total_records: number;
  source_hash: number[];
  records: Array<{
    title: string;
    username?: string;
    url?: string;
    tag_count: number;
  }>;
}

export const isTauriRuntime = () =>
  "__TAURI_INTERNALS__" in
  (window as Window & { __TAURI_INTERNALS__?: unknown });

export async function command<T>(
  name: string,
  args: Record<string, unknown> = {},
): Promise<T> {
  if (!isTauriRuntime()) {
    throw new Error("This action requires the StarAxis desktop application");
  }
  return invoke<T>(name, args);
}

export const idKey = (id: Id) =>
  id.map((byte) => byte.toString(16).padStart(2, "0")).join("");

export const sameId = (left?: Id, right?: Id) =>
  Boolean(
    left &&
    right &&
    left.length === right.length &&
    left.every((byte, i) => byte === right[i]),
  );

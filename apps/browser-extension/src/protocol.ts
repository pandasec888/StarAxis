export const PROTOCOL_VERSION = 1;
export const NATIVE_HOST = "com.staraxis.browser";

export type BrowserKind = "chrome" | "edge" | "firefox";

export type CredentialMatch = "exact_host" | "website" | "https_upgrade";
export type CredentialSaveAction = "create" | "update" | "unchanged";

export interface CredentialCandidate {
  item_id: string;
  title: string;
  usernames: string[];
  match_type: CredentialMatch;
}

export type ErrorCode =
  | "DESKTOP_OFFLINE"
  | "UNPAIRED"
  | "PAIRING_EXPIRED"
  | "PAIRING_REJECTED"
  | "VAULT_LOCKED"
  | "ORIGIN_NOT_ALLOWED"
  | "NO_MATCH"
  | "STALE_REQUEST"
  | "RATE_LIMITED"
  | "INVALID_REQUEST"
  | "PROTOCOL_ERROR"
  | "INTERNAL_ERROR";

export interface PairChallenge {
  type: "pair_challenge";
  version: number;
  pending_id: string;
  desktop_identity_public_key: string;
  desktop_exchange_public_key: string;
  ephemeral_public_key: string;
  server_nonce: string;
  verification_code: string;
  expires_at: number;
  signature: string;
}

export interface PairStatusResponse {
  type: "pair_status";
  version: number;
  pending_id: string;
  status: "pending" | "approved" | "rejected" | "expired";
  pair_id?: string;
  signature: string;
}

export interface SecureResponse {
  type: "secure";
  version: number;
  pair_id: string;
  request_id: string;
  sequence: number;
  created_at: number;
  nonce: string;
  ciphertext: string;
  signature: string;
}

export interface ErrorResponse {
  type: "error";
  code: ErrorCode;
  message: string;
}

export type HostResponse =
  PairChallenge | PairStatusResponse | SecureResponse | ErrorResponse;

export type SecureCommand =
  | { type: "status" }
  | { type: "candidates"; origin: string }
  | {
      type: "fill";
      origin: string;
      request_token: string;
      item_id: string;
      username_index: number;
    }
  | {
      type: "credential_status";
      origin: string;
      username: string;
      password: string;
    }
  | {
      type: "save_credential";
      origin: string;
      title: string;
      username: string;
      password: string;
    };

export type SecureReply =
  | { type: "status"; vault_state: "locked" | "unlocked" }
  | {
      type: "candidates";
      origin: string;
      request_token: string;
      expires_at: number;
      candidates: CredentialCandidate[];
    }
  | {
      type: "fill";
      origin: string;
      username: string;
      password: string;
      expires_at: number;
    }
  | {
      type: "credential_status";
      action: CredentialSaveAction;
      title?: string;
    }
  | {
      type: "credential_saved";
      action: CredentialSaveAction;
      title: string;
    }
  | { type: "error"; code: ErrorCode; message: string };

export interface PairState {
  pairId: string;
  desktopIdentityPublicKey: string;
  desktopExchangePublicKey: string;
  sequence: number;
}

export interface PendingPairState {
  pendingId: string;
  desktopIdentityPublicKey: string;
  desktopExchangePublicKey: string;
  verificationCode: string;
  expiresAt: number;
}

export type PopupState =
  | { kind: "loading" }
  | { kind: "offline"; message: string }
  | { kind: "unpaired" }
  | { kind: "pairing"; code: string; expiresAt: number }
  | { kind: "locked" }
  | { kind: "unsupported"; origin: string; message: string }
  | { kind: "empty"; origin: string }
  | {
      kind: "save_prompt";
      captureId: string;
      origin: string;
      username: string;
      action: Exclude<CredentialSaveAction, "unchanged">;
      title?: string;
    }
  | {
      kind: "saved";
      origin: string;
      title: string;
      action: CredentialSaveAction;
    }
  | {
      kind: "candidates";
      origin: string;
      requestToken: string;
      candidates: CredentialCandidate[];
    }
  | { kind: "success"; origin: string; title: string }
  | { kind: "error"; message: string };

export type PopupRequest =
  | { type: "popup_state" }
  | { type: "begin_pairing" }
  | { type: "poll_pairing" }
  | { type: "refresh_candidates" }
  | { type: "save_capture"; captureId: string }
  | { type: "dismiss_capture"; captureId: string }
  | {
      type: "fill";
      origin: string;
      requestToken: string;
      itemId: string;
      usernameIndex: number;
      title: string;
    };

export type ContentRequest =
  | {
      type: "staraxis_login_submitted";
      origin: string;
      title: string;
      username: string;
      password: string;
      documentId: string;
      formSignature: string;
    }
  | { type: "staraxis_prompt_state"; origin: string }
  | {
      type: "staraxis_login_outcome";
      origin: string;
      documentId: string;
      formSignature: string;
      outcome: "success" | "failure";
    }
  | {
      type: "staraxis_page_observed";
      origin: string;
      documentId: string;
      formSignatures: string[];
    }
  | {
      type: "staraxis_capture_decision";
      captureId: string;
      decision: "save" | "dismiss";
    };

export type ContentResponse =
  | { kind: "none" }
  | Extract<PopupState, { kind: "save_prompt" | "saved" | "locked" | "error" }>;

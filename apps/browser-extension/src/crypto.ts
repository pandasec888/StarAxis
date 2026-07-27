import {
  NATIVE_HOST,
  PROTOCOL_VERSION,
  type BrowserKind,
  type HostResponse,
  type PairChallenge,
  type PairState,
  type PairStatusResponse,
  type PendingPairState,
  type SecureCommand,
  type SecureReply,
  type SecureResponse,
} from "./protocol";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const DATABASE_NAME = "staraxis-extension-keys";
const STORE_NAME = "keys";
const IDENTITY_KEY = "identity-v1";
const NATIVE_REQUEST_TIMEOUT_MS = 5_000;
let nativePort: chrome.runtime.Port | undefined;

interface IdentityKeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

interface PairBeginWire {
  type: "pair_begin";
  version: number;
  client_id: string;
  browser: BrowserKind;
  profile_name: string;
  extension_origin: string;
  identity_public_key: string;
  ephemeral_public_key: string;
  client_nonce: string;
}

export class BridgeError extends Error {
  constructor(
    message: string,
    readonly code?: string,
  ) {
    super(message);
  }
}

export function browserKind(): BrowserKind {
  const agent = navigator.userAgent;
  if (agent.includes("Firefox/")) return "firefox";
  if (agent.includes("Edg/")) return "edge";
  return "chrome";
}

export async function beginPairing(): Promise<PendingPairState> {
  const identity = await getOrCreateIdentity();
  const clientId = await getOrCreateClientId();
  const ephemeral = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const identityPublic = await exportRaw(identity.publicKey);
  const ephemeralPublic = await exportRaw(ephemeral.publicKey);
  const request: PairBeginWire = {
    type: "pair_begin",
    version: PROTOCOL_VERSION,
    client_id: clientId,
    browser: browserKind(),
    profile_name: "默认浏览器配置",
    extension_origin: extensionIdentityOrigin(),
    identity_public_key: encode(identityPublic),
    ephemeral_public_key: encode(ephemeralPublic),
    client_nonce: encode(randomBytes(32)),
  };
  const response = await nativeMessage(request);
  if (response.type !== "pair_challenge") {
    throw responseError(response, "桌面端没有返回配对请求");
  }
  await verifyPairChallenge(response);
  const serverEphemeral = await importEcdhPublic(response.ephemeral_public_key);
  const shared = await crypto.subtle.deriveBits(
    { name: "ECDH", public: serverEphemeral },
    ephemeral.privateKey,
    256,
  );
  const transcript = pairingTranscript(request, response);
  const code = await pairingVerificationCode(
    new Uint8Array(shared),
    transcript,
  );
  if (code !== response.verification_code) {
    throw new BridgeError("配对校验码不一致，已终止连接", "PROTOCOL_ERROR");
  }
  const pending: PendingPairState = {
    pendingId: response.pending_id,
    desktopIdentityPublicKey: response.desktop_identity_public_key,
    desktopExchangePublicKey: response.desktop_exchange_public_key,
    verificationCode: code,
    expiresAt: response.expires_at,
  };
  await storageSet({ pendingPair: pending });
  return pending;
}

export async function pollPairing(): Promise<
  "pending" | "approved" | "rejected" | "expired"
> {
  const { pendingPair } = await storageGet<{
    pendingPair?: PendingPairState;
  }>(["pendingPair"]);
  if (!pendingPair) return "expired";
  const response = await nativeMessage({
    type: "pair_poll",
    version: PROTOCOL_VERSION,
    pending_id: pendingPair.pendingId,
  });
  if (response.type !== "pair_status") {
    throw responseError(response, "无法读取配对状态");
  }
  await verifyPairStatus(response, pendingPair.desktopIdentityPublicKey);
  if (response.status === "approved" && response.pair_id) {
    const pair: PairState = {
      pairId: response.pair_id,
      desktopIdentityPublicKey: pendingPair.desktopIdentityPublicKey,
      desktopExchangePublicKey: pendingPair.desktopExchangePublicKey,
      sequence: 0,
    };
    await storageSet({ pair, pendingPair: null });
  } else if (response.status === "rejected" || response.status === "expired") {
    await storageSet({ pendingPair: null });
  }
  return response.status;
}

export async function secureCommand(
  command: SecureCommand,
): Promise<SecureReply> {
  const identity = await getOrCreateIdentity();
  const pair = await nextPairSequence();
  const requestId = encode(randomBytes(16));
  const ephemeral = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const desktopExchange = await importEcdhPublic(pair.desktopExchangePublicKey);
  const shared = await crypto.subtle.deriveBits(
    { name: "ECDH", public: desktopExchange },
    ephemeral.privateKey,
    256,
  );
  const context = secureContext(pair.pairId, pair.sequence, requestId);
  const key = await deriveAesKey(shared, context, "staraxis/request");
  const nonce = randomBytes(12);
  const plaintext = encoder.encode(JSON.stringify(command));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: nonce,
        additionalData: secureAad(
          pair.pairId,
          pair.sequence,
          requestId,
          "request",
        ),
        tagLength: 128,
      },
      key,
      plaintext,
    ),
  );
  plaintext.fill(0);
  const ephemeralPublic = encode(await exportRaw(ephemeral.publicKey));
  const wire = {
    type: "secure" as const,
    version: PROTOCOL_VERSION,
    pair_id: pair.pairId,
    request_id: requestId,
    sequence: pair.sequence,
    created_at: Date.now(),
    ephemeral_public_key: ephemeralPublic,
    nonce: encode(nonce),
    ciphertext: encode(ciphertext),
    signature: "",
  };
  const signatureInput = secureRequestSignatureInput(wire);
  wire.signature = encode(
    new Uint8Array(
      await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        identity.privateKey,
        signatureInput,
      ),
    ),
  );
  const response = await nativeMessage(wire);
  if (response.type !== "secure") {
    throw responseError(response, "安全请求失败");
  }
  validateSecureResponse(response, pair, requestId);
  await verifySecureResponse(response, pair.desktopIdentityPublicKey);
  const responseKey = await deriveAesKey(shared, context, "staraxis/response");
  const decrypted = new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: decode(response.nonce),
        additionalData: secureAad(
          pair.pairId,
          pair.sequence,
          requestId,
          "response",
        ),
        tagLength: 128,
      },
      responseKey,
      decode(response.ciphertext),
    ),
  );
  try {
    return JSON.parse(decoder.decode(decrypted)) as SecureReply;
  } finally {
    decrypted.fill(0);
    ciphertext.fill(0);
  }
}

export async function storedPair(): Promise<PairState | undefined> {
  const value = await storageGet<{ pair?: PairState }>(["pair"]);
  return value.pair;
}

export async function storedPendingPair(): Promise<
  PendingPairState | undefined
> {
  const value = await storageGet<{ pendingPair?: PendingPairState }>([
    "pendingPair",
  ]);
  return value.pendingPair ?? undefined;
}

function extensionIdentityOrigin() {
  return browserKind() === "firefox"
    ? "firefox-extension://browser@staraxis.local"
    : chrome.runtime.getURL("");
}

async function nextPairSequence(): Promise<PairState> {
  const pair = await storedPair();
  if (!pair) throw new BridgeError("浏览器尚未与StarAxis配对", "UNPAIRED");
  const next = { ...pair, sequence: pair.sequence + 1 };
  if (!Number.isSafeInteger(next.sequence)) {
    throw new BridgeError("配对序列已耗尽，请重新配对", "STALE_REQUEST");
  }
  await storageSet({ pair: next });
  return next;
}

async function verifyPairChallenge(response: PairChallenge) {
  const key = await importEcdsaPublic(response.desktop_identity_public_key);
  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    decode(response.signature),
    pairChallengeSignatureInput(response),
  );
  if (!valid) throw new BridgeError("桌面配对响应签名无效", "PROTOCOL_ERROR");
}

async function verifyPairStatus(
  response: PairStatusResponse,
  identityPublicKey: string,
) {
  const key = await importEcdsaPublic(identityPublicKey);
  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    decode(response.signature),
    pairStatusSignatureInput(response),
  );
  if (!valid) throw new BridgeError("配对状态签名无效", "PROTOCOL_ERROR");
}

async function verifySecureResponse(
  response: SecureResponse,
  identityPublicKey: string,
) {
  const key = await importEcdsaPublic(identityPublicKey);
  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    decode(response.signature),
    secureResponseSignatureInput(response),
  );
  if (!valid) throw new BridgeError("桌面响应签名无效", "PROTOCOL_ERROR");
}

function validateSecureResponse(
  response: SecureResponse,
  pair: PairState,
  requestId: string,
) {
  if (
    response.version !== PROTOCOL_VERSION ||
    response.pair_id !== pair.pairId ||
    response.sequence !== pair.sequence ||
    response.request_id !== requestId ||
    Math.abs(Date.now() - response.created_at) > 120_000
  ) {
    throw new BridgeError("桌面响应与当前请求不匹配", "STALE_REQUEST");
  }
}

async function deriveAesKey(
  shared: ArrayBuffer,
  context: string,
  info: string,
) {
  const material = await crypto.subtle.importKey("raw", shared, "HKDF", false, [
    "deriveKey",
  ]);
  const salt = await crypto.subtle.digest("SHA-256", encoder.encode(context));
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info: encoder.encode(info),
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export function secureContext(
  pairId: string,
  sequence: number,
  requestId: string,
) {
  return `staraxis-v1|${pairId}|${sequence}|${requestId}`;
}

export function secureAad(
  pairId: string,
  sequence: number,
  requestId: string,
  direction: "request" | "response",
) {
  return encoder.encode(
    `${secureContext(pairId, sequence, requestId)}|${direction}`,
  );
}

export function secureRequestSignatureInput(request: {
  version: number;
  pair_id: string;
  request_id: string;
  sequence: number;
  created_at: number;
  ephemeral_public_key: string;
  nonce: string;
  ciphertext: string;
}) {
  return encoder.encode(
    `${request.version}|${request.pair_id}|${request.request_id}|${request.sequence}|${request.created_at}|${request.ephemeral_public_key}|${request.nonce}|${request.ciphertext}`,
  );
}

function secureResponseSignatureInput(response: SecureResponse) {
  return encoder.encode(
    `${response.version}|${response.pair_id}|${response.request_id}|${response.sequence}|${response.created_at}|${response.nonce}|${response.ciphertext}`,
  );
}

function pairChallengeSignatureInput(response: PairChallenge) {
  return encoder.encode(
    `${response.version}|${response.pending_id}|${response.desktop_identity_public_key}|${response.desktop_exchange_public_key}|${response.ephemeral_public_key}|${response.server_nonce}|${response.verification_code}|${response.expires_at}`,
  );
}

function pairStatusSignatureInput(response: PairStatusResponse) {
  return encoder.encode(
    `${response.version}|${response.pending_id}|${response.status}|${response.pair_id ?? ""}`,
  );
}

function pairingTranscript(request: PairBeginWire, response: PairChallenge) {
  return encoder.encode(
    `${request.version}|${request.client_id}|${request.browser}|${request.profile_name}|${request.extension_origin}|${request.identity_public_key}|${request.ephemeral_public_key}|${request.client_nonce}|${response.pending_id}|${response.desktop_identity_public_key}|${response.desktop_exchange_public_key}|${response.ephemeral_public_key}|${response.server_nonce}`,
  );
}

async function importEcdsaPublic(encoded: string) {
  return crypto.subtle.importKey(
    "raw",
    decode(encoded),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
}

async function importEcdhPublic(encoded: string) {
  return crypto.subtle.importKey(
    "raw",
    decode(encoded),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
}

async function exportRaw(key: CryptoKey) {
  return new Uint8Array(await crypto.subtle.exportKey("raw", key));
}

async function getOrCreateIdentity(): Promise<IdentityKeyPair> {
  const existing = await databaseGet<IdentityKeyPair>(IDENTITY_KEY);
  if (existing) return existing;
  const generated = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"],
  );
  const identity = {
    privateKey: generated.privateKey,
    publicKey: generated.publicKey,
  };
  await databasePut(IDENTITY_KEY, identity);
  return identity;
}

async function getOrCreateClientId() {
  const value = await storageGet<{ clientId?: string }>(["clientId"]);
  if (value.clientId) return value.clientId;
  const clientId = encode(randomBytes(16));
  await storageSet({ clientId });
  return clientId;
}

function nativeMessage(message: object): Promise<HostResponse> {
  return new Promise((resolve, reject) => {
    const port = nativePort ?? chrome.runtime.connectNative(NATIVE_HOST);
    nativePort = port;
    let settled = false;
    const cleanup = () => {
      clearTimeout(timeout);
      port.onMessage.removeListener(onMessage);
      port.onDisconnect.removeListener(onDisconnect);
    };
    const onMessage = (response: unknown) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(response as HostResponse);
    };
    const onDisconnect = () => {
      nativePort = undefined;
      if (settled) return;
      settled = true;
      const error = chrome.runtime.lastError;
      cleanup();
      reject(
        new BridgeError(
          error?.message || "StarAxis桌面端未连接",
          "DESKTOP_OFFLINE",
        ),
      );
    };
    const timeout = setTimeout(() => {
      if (settled) return;
      settled = true;
      cleanup();
      nativePort = undefined;
      port.disconnect();
      reject(new BridgeError("StarAxis桌面端响应超时", "DESKTOP_OFFLINE"));
    }, NATIVE_REQUEST_TIMEOUT_MS);
    port.onMessage.addListener(onMessage);
    port.onDisconnect.addListener(onDisconnect);
    try {
      port.postMessage(message);
    } catch (cause) {
      settled = true;
      cleanup();
      nativePort = undefined;
      reject(
        new BridgeError(
          cause instanceof Error ? cause.message : "StarAxis桌面端未连接",
          "DESKTOP_OFFLINE",
        ),
      );
    }
  });
}

function responseError(response: HostResponse, fallback: string) {
  return response.type === "error"
    ? new BridgeError(response.message, response.code)
    : new BridgeError(fallback, "PROTOCOL_ERROR");
}

function storageGet<T>(keys: string[]): Promise<T> {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get(keys, (value) => {
      const error = chrome.runtime.lastError;
      if (error) reject(new BridgeError(error.message || "扩展存储读取失败"));
      else resolve(value as T);
    });
  });
}

function storageSet(value: object): Promise<void> {
  return new Promise((resolve, reject) => {
    chrome.storage.local.set(value, () => {
      const error = chrome.runtime.lastError;
      if (error) reject(new BridgeError(error.message || "扩展存储写入失败"));
      else resolve();
    });
  });
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) {
        request.result.createObjectStore(STORE_NAME);
      }
    };
    request.onerror = () => reject(new BridgeError("无法打开扩展密钥存储"));
    request.onsuccess = () => resolve(request.result);
  });
}

async function databaseGet<T>(key: string): Promise<T | undefined> {
  const database = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(STORE_NAME, "readonly");
    const request = transaction.objectStore(STORE_NAME).get(key);
    request.onerror = () => reject(new BridgeError("无法读取扩展身份密钥"));
    request.onsuccess = () => resolve(request.result as T | undefined);
    transaction.oncomplete = () => database.close();
  });
}

async function databasePut(key: string, value: unknown): Promise<void> {
  const database = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(STORE_NAME, "readwrite");
    transaction.objectStore(STORE_NAME).put(value, key);
    transaction.onerror = () => reject(new BridgeError("无法保存扩展身份密钥"));
    transaction.oncomplete = () => {
      database.close();
      resolve();
    };
  });
}

export function encode(value: Uint8Array) {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

export function decode(value: string) {
  const padded = value
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function randomBytes(length: number) {
  return crypto.getRandomValues(new Uint8Array(length));
}

function concat(...values: Uint8Array[]) {
  const output = new Uint8Array(
    values.reduce((total, value) => total + value.length, 0),
  );
  let offset = 0;
  for (const value of values) {
    output.set(value, offset);
    offset += value.length;
  }
  return output;
}

export async function pairingVerificationCode(
  sharedSecret: Uint8Array,
  transcript: Uint8Array,
) {
  const digest = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      concat(encoder.encode("staraxis-pairing-v1"), sharedSecret, transcript),
    ),
  );
  return String(
    new DataView(digest.buffer).getUint32(0, false) % 1_000_000,
  ).padStart(6, "0");
}

#![doc = "Pairing, origin matching and one-time credential release for browser extensions."]
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
#[cfg(not(windows))]
use interprocess::local_socket::GenericFilePath;
#[cfg(windows)]
use interprocess::local_socket::GenericNamespaced;
use interprocess::local_socket::{ListenerOptions, prelude::*};
use p256::ecdh::{EphemeralSecret, diffie_hellman};
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::{OsRng, RngCore as _};
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use p256::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use url::Url;
use vault_domain::{Id, UrlMatchMode, VaultItem, VaultPayload};
use vault_extension_protocol::{
    ClientRequest, CredentialCandidate, CredentialMatch, CredentialSaveAction, ErrorCode,
    FILL_RESULT_TTL_MS, FILL_TOKEN_TTL_MS, HostRequest, HostResponse, MAX_CANDIDATES,
    MAX_CLOCK_SKEW_MS, NormalizedOrigin, PAIRING_TTL_MS, PROTOCOL_VERSION, PairBeginRequest,
    PairChallengeResponse, PairPollRequest, PairStatus, PairStatusResponse, SecureCommand,
    SecureReply, SecureRequest, SecureResponse, VaultState, local_endpoint_name,
    pair_challenge_signature_input, pair_status_signature_input, pairing_transcript,
    pairing_verification_code, secure_aad, secure_context, secure_response_signature_input,
    secure_signature_input,
};
use vault_platform::{atomic_replace_preserving_old, harden_private_file};
use vault_service::{ItemFilter, ItemSort, LoginInput, SessionState, VaultService};
use zeroize::Zeroize as _;

const STORE_VERSION: u16 = 1;
const MAX_LABEL_BYTES: usize = 128;
const MAX_ORIGIN_BYTES: usize = 512;
const MAX_CAPTURE_USERNAME_BYTES: usize = 16 * 1024;
const MAX_CAPTURE_PASSWORD_BYTES: usize = 64 * 1024;
const MAX_CAPTURE_TITLE_CHARS: usize = 128;
const MAX_SEQUENCE_JUMP: u64 = 1_000;

pub fn start_broker(
    extension: Arc<Mutex<ExtensionService>>,
    vault: Arc<Mutex<VaultService>>,
) -> Result<thread::JoinHandle<()>, ExtensionError> {
    let endpoint = local_endpoint_name().ok_or(ExtensionError::EndpointUnavailable)?;
    prepare_endpoint(&endpoint)?;
    #[cfg(windows)]
    let name = endpoint
        .to_ns_name::<GenericNamespaced>()
        .map_err(|_| ExtensionError::EndpointUnavailable)?;
    #[cfg(not(windows))]
    let name = Path::new(&endpoint)
        .to_fs_name::<GenericFilePath>()
        .map_err(|_| ExtensionError::EndpointUnavailable)?;
    let listener = ListenerOptions::new().name(name).create_sync()?;
    Ok(thread::spawn(move || {
        while let Ok(mut stream) = listener.accept() {
            let extension = Arc::clone(&extension);
            let vault = Arc::clone(&vault);
            thread::spawn(move || {
                let response = read_broker_request(&mut stream).map_or_else(
                    |_| HostResponse::error(ErrorCode::InvalidRequest, "invalid broker request"),
                    |request| {
                        let mut extension = match extension.lock() {
                            Ok(extension) => extension,
                            Err(_) => {
                                return HostResponse::error(
                                    ErrorCode::InternalError,
                                    "extension service unavailable",
                                );
                            }
                        };
                        let mut vault = match vault.lock() {
                            Ok(vault) => vault,
                            Err(_) => {
                                return HostResponse::error(
                                    ErrorCode::InternalError,
                                    "vault service unavailable",
                                );
                            }
                        };
                        extension.handle(request, &mut vault, now_unix_ms())
                    },
                );
                let _ = write_broker_response(&mut stream, &response);
            });
        }
    }))
}

#[derive(Clone, Debug, Serialize)]
pub struct PendingPairSummary {
    pub pending_id: String,
    pub browser: vault_extension_protocol::BrowserKind,
    pub profile_name: String,
    pub extension_origin: String,
    pub verification_code: String,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct PairedClientSummary {
    pub pair_id: String,
    pub browser: vault_extension_protocol::BrowserKind,
    pub profile_name: String,
    pub extension_origin: String,
    pub fingerprint: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PersistedStore {
    version: u16,
    identity_private_key: String,
    exchange_private_key: String,
    pairs: Vec<PairRecord>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PairRecord {
    pair_id: String,
    client_id: String,
    browser: vault_extension_protocol::BrowserKind,
    profile_name: String,
    extension_origin: String,
    identity_public_key: String,
    fingerprint: String,
    created_at: i64,
    last_used_at: Option<i64>,
    last_sequence: u64,
}

#[derive(Clone, Debug)]
struct PendingPair {
    pending_id: String,
    client_id: String,
    browser: vault_extension_protocol::BrowserKind,
    profile_name: String,
    extension_origin: String,
    identity_public_key: String,
    verification_code: String,
    expires_at: i64,
    status: PairStatus,
    approved_pair_id: Option<String>,
}

#[derive(Clone, Debug)]
struct FillGrant {
    pair_id: String,
    origin: String,
    allowed_items: HashMap<String, usize>,
    expires_at: i64,
}

pub struct ExtensionService {
    store_path: PathBuf,
    store: PersistedStore,
    identity: SigningKey,
    exchange: SecretKey,
    pending: HashMap<String, PendingPair>,
    fill_grants: HashMap<String, FillGrant>,
}

impl ExtensionService {
    pub fn load_or_create(path: impl Into<PathBuf>) -> Result<Self, ExtensionError> {
        let store_path = path.into();
        let store = if store_path.exists() {
            let metadata = fs::symlink_metadata(&store_path)?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(ExtensionError::UnsafeStorePath);
            }
            let bytes = fs::read(&store_path)?;
            if bytes.len() > 1024 * 1024 {
                return Err(ExtensionError::InvalidStore);
            }
            let parsed: PersistedStore = serde_json::from_slice(&bytes)?;
            if parsed.version != STORE_VERSION {
                return Err(ExtensionError::UnsupportedStoreVersion);
            }
            parsed
        } else {
            PersistedStore {
                version: STORE_VERSION,
                identity_private_key: encode(SigningKey::random(&mut OsRng).to_bytes().as_slice()),
                exchange_private_key: encode(SecretKey::random(&mut OsRng).to_bytes().as_slice()),
                pairs: Vec::new(),
            }
        };
        let identity_bytes = decode_exact::<32>(&store.identity_private_key)?;
        let exchange_bytes = decode_exact::<32>(&store.exchange_private_key)?;
        let identity = SigningKey::from_bytes((&identity_bytes).into())
            .map_err(|_| ExtensionError::InvalidStore)?;
        let exchange =
            SecretKey::from_slice(&exchange_bytes).map_err(|_| ExtensionError::InvalidStore)?;
        let service = Self {
            store_path,
            store,
            identity,
            exchange,
            pending: HashMap::new(),
            fill_grants: HashMap::new(),
        };
        service.persist()?;
        Ok(service)
    }

    #[must_use]
    pub fn desktop_identity_public_key(&self) -> String {
        encode(
            self.identity
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        )
    }

    #[must_use]
    pub fn desktop_exchange_public_key(&self) -> String {
        encode(
            self.exchange
                .public_key()
                .to_encoded_point(false)
                .as_bytes(),
        )
    }

    pub fn handle(
        &mut self,
        request: HostRequest,
        vault: &mut VaultService,
        now_unix_ms: i64,
    ) -> HostResponse {
        let was_unlocked = is_unlocked(vault.state());
        vault.lock_if_idle(now_unix_ms);
        if was_unlocked && !is_unlocked(vault.state()) {
            self.clear_runtime_authorizations();
        }
        self.expire_transient_state(now_unix_ms);
        if !valid_extension_origin(&request.caller_origin) {
            return HostResponse::error(ErrorCode::InvalidRequest, "invalid extension origin");
        }
        match request.request {
            ClientRequest::PairBegin(body) => {
                self.begin_pairing(&request.caller_origin, body, now_unix_ms)
            }
            ClientRequest::PairPoll(body) => {
                self.poll_pairing(&request.caller_origin, body, now_unix_ms)
            }
            ClientRequest::Secure(body) => {
                self.handle_secure(&request.caller_origin, body, vault, now_unix_ms)
            }
        }
    }

    #[must_use]
    pub fn pending_pairs(&mut self, now_unix_ms: i64) -> Vec<PendingPairSummary> {
        self.expire_transient_state(now_unix_ms);
        let mut values = self
            .pending
            .values()
            .filter(|pending| pending.status == PairStatus::Pending)
            .map(|pending| PendingPairSummary {
                pending_id: pending.pending_id.clone(),
                browser: pending.browser,
                profile_name: pending.profile_name.clone(),
                extension_origin: pending.extension_origin.clone(),
                verification_code: pending.verification_code.clone(),
                expires_at: pending.expires_at,
            })
            .collect::<Vec<_>>();
        values.sort_by_key(|pending| pending.expires_at);
        values
    }

    #[must_use]
    pub fn paired_clients(&self) -> Vec<PairedClientSummary> {
        let mut values = self
            .store
            .pairs
            .iter()
            .map(|pair| PairedClientSummary {
                pair_id: pair.pair_id.clone(),
                browser: pair.browser,
                profile_name: pair.profile_name.clone(),
                extension_origin: pair.extension_origin.clone(),
                fingerprint: pair.fingerprint.clone(),
                created_at: pair.created_at,
                last_used_at: pair.last_used_at,
            })
            .collect::<Vec<_>>();
        values.sort_by_key(|pair| std::cmp::Reverse(pair.created_at));
        values
    }

    pub fn approve_pairing(
        &mut self,
        pending_id: &str,
        now_unix_ms: i64,
    ) -> Result<String, ExtensionError> {
        self.expire_transient_state(now_unix_ms);
        let pending = self
            .pending
            .get_mut(pending_id)
            .ok_or(ExtensionError::PairingNotFound)?;
        if pending.status != PairStatus::Pending || pending.expires_at <= now_unix_ms {
            return Err(ExtensionError::PairingExpired);
        }
        let pair_id = random_id();
        let fingerprint = fingerprint(&pending.identity_public_key);
        self.store.pairs.retain(|pair| {
            pair.client_id != pending.client_id || pair.extension_origin != pending.extension_origin
        });
        self.store.pairs.push(PairRecord {
            pair_id: pair_id.clone(),
            client_id: pending.client_id.clone(),
            browser: pending.browser,
            profile_name: pending.profile_name.clone(),
            extension_origin: pending.extension_origin.clone(),
            identity_public_key: pending.identity_public_key.clone(),
            fingerprint,
            created_at: now_unix_ms,
            last_used_at: None,
            last_sequence: 0,
        });
        pending.status = PairStatus::Approved;
        pending.approved_pair_id = Some(pair_id.clone());
        self.persist()?;
        Ok(pair_id)
    }

    pub fn reject_pairing(&mut self, pending_id: &str) -> Result<(), ExtensionError> {
        let pending = self
            .pending
            .get_mut(pending_id)
            .ok_or(ExtensionError::PairingNotFound)?;
        pending.status = PairStatus::Rejected;
        Ok(())
    }

    pub fn revoke_pairing(&mut self, pair_id: &str) -> Result<(), ExtensionError> {
        let before = self.store.pairs.len();
        self.store.pairs.retain(|pair| pair.pair_id != pair_id);
        if before == self.store.pairs.len() {
            return Err(ExtensionError::PairingNotFound);
        }
        self.fill_grants.retain(|_, grant| grant.pair_id != pair_id);
        self.persist()
    }

    pub fn revoke_all(&mut self) -> Result<(), ExtensionError> {
        self.store.pairs.clear();
        self.pending.clear();
        self.fill_grants.clear();
        self.persist()
    }

    pub fn clear_runtime_authorizations(&mut self) {
        self.fill_grants.clear();
    }

    fn begin_pairing(
        &mut self,
        caller_origin: &str,
        request: PairBeginRequest,
        now_unix_ms: i64,
    ) -> HostResponse {
        if request.version != PROTOCOL_VERSION
            || request.extension_origin != caller_origin
            || !valid_label(&request.client_id)
            || !valid_label(&request.profile_name)
            || decode_public_key(&request.identity_public_key).is_err()
            || decode_public_key(&request.ephemeral_public_key).is_err()
            || decode_exact::<32>(&request.client_nonce).is_err()
        {
            return HostResponse::error(ErrorCode::InvalidRequest, "invalid pairing request");
        }

        let client_ephemeral = match decode_public_key(&request.ephemeral_public_key) {
            Ok(key) => key,
            Err(_) => {
                return HostResponse::error(ErrorCode::InvalidRequest, "invalid pairing key");
            }
        };
        let server_ephemeral = EphemeralSecret::random(&mut OsRng);
        let server_public = PublicKey::from(&server_ephemeral);
        let shared = server_ephemeral.diffie_hellman(&client_ephemeral);
        let pending_id = random_id();
        let server_nonce = random_bytes::<32>();
        let expires_at = now_unix_ms.saturating_add(PAIRING_TTL_MS);
        let mut response = PairChallengeResponse {
            version: PROTOCOL_VERSION,
            pending_id: pending_id.clone(),
            desktop_identity_public_key: self.desktop_identity_public_key(),
            desktop_exchange_public_key: self.desktop_exchange_public_key(),
            ephemeral_public_key: encode(server_public.to_encoded_point(false).as_bytes()),
            server_nonce: encode(&server_nonce),
            verification_code: String::new(),
            expires_at,
            signature: String::new(),
        };
        let transcript = pairing_transcript(&request, &response);
        response.verification_code =
            pairing_verification_code(shared.raw_secret_bytes().as_slice(), &transcript);
        response.signature = self.sign(&pair_challenge_signature_input(&response));
        self.pending.insert(
            pending_id.clone(),
            PendingPair {
                pending_id,
                client_id: request.client_id,
                browser: request.browser,
                profile_name: request.profile_name,
                extension_origin: request.extension_origin,
                identity_public_key: request.identity_public_key,
                verification_code: response.verification_code.clone(),
                expires_at,
                status: PairStatus::Pending,
                approved_pair_id: None,
            },
        );
        HostResponse::PairChallenge(response)
    }

    fn poll_pairing(
        &self,
        caller_origin: &str,
        request: PairPollRequest,
        now_unix_ms: i64,
    ) -> HostResponse {
        if request.version != PROTOCOL_VERSION {
            return HostResponse::error(ErrorCode::ProtocolError, "unsupported protocol version");
        }
        let Some(pending) = self.pending.get(&request.pending_id) else {
            return HostResponse::error(ErrorCode::PairingExpired, "pairing request expired");
        };
        if pending.extension_origin != caller_origin {
            return HostResponse::error(ErrorCode::Unpaired, "pairing origin does not match");
        }
        let status = if pending.expires_at <= now_unix_ms {
            PairStatus::Expired
        } else {
            pending.status
        };
        let mut response = PairStatusResponse {
            version: PROTOCOL_VERSION,
            pending_id: pending.pending_id.clone(),
            status,
            pair_id: pending.approved_pair_id.clone(),
            signature: String::new(),
        };
        response.signature = self.sign(&pair_status_signature_input(&response));
        HostResponse::PairStatus(response)
    }

    fn handle_secure(
        &mut self,
        caller_origin: &str,
        request: SecureRequest,
        vault: &mut VaultService,
        now_unix_ms: i64,
    ) -> HostResponse {
        if request.version != PROTOCOL_VERSION
            || now_unix_ms.saturating_sub(request.created_at).abs() > MAX_CLOCK_SKEW_MS
        {
            return HostResponse::error(ErrorCode::StaleRequest, "request is stale");
        }
        let Some(pair_index) = self
            .store
            .pairs
            .iter()
            .position(|pair| pair.pair_id == request.pair_id)
        else {
            return HostResponse::error(ErrorCode::Unpaired, "browser is not paired");
        };
        let pair = &self.store.pairs[pair_index];
        if pair.extension_origin != caller_origin
            || request.sequence <= pair.last_sequence
            || request.sequence > pair.last_sequence.saturating_add(MAX_SEQUENCE_JUMP)
        {
            return HostResponse::error(ErrorCode::StaleRequest, "request sequence is invalid");
        }
        let verifying = match decode_verifying_key(&pair.identity_public_key) {
            Ok(key) => key,
            Err(_) => {
                return HostResponse::error(ErrorCode::Unpaired, "paired identity is invalid");
            }
        };
        let signature = match decode_signature(&request.signature) {
            Ok(signature) => signature,
            Err(_) => return HostResponse::error(ErrorCode::ProtocolError, "invalid signature"),
        };
        if verifying
            .verify(&secure_signature_input(&request), &signature)
            .is_err()
        {
            return HostResponse::error(ErrorCode::ProtocolError, "signature verification failed");
        }
        let peer = match decode_public_key(&request.ephemeral_public_key) {
            Ok(peer) => peer,
            Err(_) => return HostResponse::error(ErrorCode::ProtocolError, "invalid session key"),
        };
        let nonce = match decode_exact::<12>(&request.nonce) {
            Ok(nonce) => nonce,
            Err(_) => return HostResponse::error(ErrorCode::ProtocolError, "invalid nonce"),
        };
        let ciphertext = match decode(&request.ciphertext) {
            Ok(value) => value,
            Err(_) => return HostResponse::error(ErrorCode::ProtocolError, "invalid ciphertext"),
        };
        let shared = diffie_hellman(self.exchange.to_nonzero_scalar(), peer.as_affine());
        let context = secure_context(&request.pair_id, request.sequence, &request.request_id);
        let request_key = match derive_key(
            shared.raw_secret_bytes().as_slice(),
            &context,
            b"staraxis/request",
        ) {
            Ok(key) => key,
            Err(_) => {
                return HostResponse::error(ErrorCode::InternalError, "key derivation failed");
            }
        };
        let cipher = match Aes256Gcm::new_from_slice(&request_key) {
            Ok(cipher) => cipher,
            Err(_) => return HostResponse::error(ErrorCode::InternalError, "cipher setup failed"),
        };
        let mut plaintext = match cipher.decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &secure_aad(
                    &request.pair_id,
                    request.sequence,
                    &request.request_id,
                    "request",
                ),
            },
        ) {
            Ok(value) => value,
            Err(_) => {
                return HostResponse::error(
                    ErrorCode::ProtocolError,
                    "message authentication failed",
                );
            }
        };
        let command: SecureCommand = match serde_json::from_slice(&plaintext) {
            Ok(command) => command,
            Err(_) => {
                plaintext.zeroize();
                return HostResponse::error(ErrorCode::InvalidRequest, "invalid secure command");
            }
        };
        plaintext.zeroize();

        let mut reply = self.execute_command(&request.pair_id, command, vault, now_unix_ms);
        let mut reply_bytes = match serde_json::to_vec(&reply) {
            Ok(value) => value,
            Err(_) => {
                return HostResponse::error(ErrorCode::InternalError, "response encoding failed");
            }
        };
        zeroize_reply(&mut reply);
        let response_key = match derive_key(
            shared.raw_secret_bytes().as_slice(),
            &context,
            b"staraxis/response",
        ) {
            Ok(key) => key,
            Err(_) => {
                reply_bytes.zeroize();
                return HostResponse::error(ErrorCode::InternalError, "key derivation failed");
            }
        };
        let response_nonce = random_bytes::<12>();
        let response_cipher = match Aes256Gcm::new_from_slice(&response_key) {
            Ok(cipher) => cipher,
            Err(_) => {
                reply_bytes.zeroize();
                return HostResponse::error(ErrorCode::InternalError, "cipher setup failed");
            }
        };
        let response_ciphertext = match response_cipher.encrypt(
            Nonce::from_slice(&response_nonce),
            Payload {
                msg: &reply_bytes,
                aad: &secure_aad(
                    &request.pair_id,
                    request.sequence,
                    &request.request_id,
                    "response",
                ),
            },
        ) {
            Ok(value) => value,
            Err(_) => {
                reply_bytes.zeroize();
                return HostResponse::error(ErrorCode::InternalError, "response encryption failed");
            }
        };
        reply_bytes.zeroize();

        self.store.pairs[pair_index].last_sequence = request.sequence;
        self.store.pairs[pair_index].last_used_at = Some(now_unix_ms);
        if self.persist().is_err() {
            return HostResponse::error(
                ErrorCode::InternalError,
                "pairing state could not be saved",
            );
        }
        let mut response = SecureResponse {
            version: PROTOCOL_VERSION,
            pair_id: request.pair_id,
            request_id: request.request_id,
            sequence: request.sequence,
            created_at: now_unix_ms,
            nonce: encode(&response_nonce),
            ciphertext: encode(&response_ciphertext),
            signature: String::new(),
        };
        response.signature = self.sign(&secure_response_signature_input(&response));
        HostResponse::Secure(response)
    }

    fn execute_command(
        &mut self,
        pair_id: &str,
        command: SecureCommand,
        vault: &mut VaultService,
        now_unix_ms: i64,
    ) -> SecureReply {
        match command {
            SecureCommand::Status => SecureReply::Status {
                vault_state: if is_unlocked(vault.state()) {
                    VaultState::Unlocked
                } else {
                    VaultState::Locked
                },
            },
            SecureCommand::Candidates { origin } => {
                if !is_unlocked(vault.state()) {
                    return secure_error(ErrorCode::VaultLocked, "保险库已锁定");
                }
                let origin = match NormalizedOrigin::parse_web(&origin) {
                    Ok(origin) => origin,
                    Err(_) => {
                        return secure_error(
                            ErrorCode::OriginNotAllowed,
                            "当前页面不是受支持的 HTTP 或 HTTPS origin",
                        );
                    }
                };
                let candidates = match collect_candidates(vault, &origin) {
                    Ok(candidates) => candidates,
                    Err(_) => return secure_error(ErrorCode::InternalError, "无法查询保险库条目"),
                };
                if candidates.is_empty() {
                    return secure_error(ErrorCode::NoMatch, "当前网站没有精确匹配的账号");
                }
                let token = random_id();
                let allowed_items = candidates
                    .iter()
                    .map(|candidate| (candidate.item_id.clone(), candidate.usernames.len().max(1)))
                    .collect();
                let expires_at = now_unix_ms.saturating_add(FILL_TOKEN_TTL_MS);
                self.fill_grants.insert(
                    token.clone(),
                    FillGrant {
                        pair_id: pair_id.to_owned(),
                        origin: origin.as_str().to_owned(),
                        allowed_items,
                        expires_at,
                    },
                );
                SecureReply::Candidates {
                    origin: origin.as_str().to_owned(),
                    request_token: token,
                    expires_at,
                    candidates,
                }
            }
            SecureCommand::Fill {
                origin,
                request_token,
                item_id,
                username_index,
            } => {
                if !is_unlocked(vault.state()) {
                    return secure_error(ErrorCode::VaultLocked, "保险库已锁定");
                }
                let Some(grant) = self.fill_grants.remove(&request_token) else {
                    return secure_error(ErrorCode::StaleRequest, "填充请求已失效");
                };
                let allowed = grant.pair_id == pair_id
                    && grant.origin == origin
                    && grant.expires_at > now_unix_ms
                    && grant
                        .allowed_items
                        .get(&item_id)
                        .is_some_and(|count| username_index < *count);
                if !allowed {
                    return secure_error(ErrorCode::OriginNotAllowed, "填充授权与当前页面不匹配");
                }
                match release_credential(vault, &item_id, username_index, &grant.origin) {
                    Ok((username, password)) => {
                        vault.record_activity(now_unix_ms);
                        SecureReply::Fill {
                            origin: grant.origin,
                            username,
                            password,
                            expires_at: now_unix_ms.saturating_add(FILL_RESULT_TTL_MS),
                        }
                    }
                    Err(ExtensionError::OriginMismatch) => {
                        secure_error(ErrorCode::OriginNotAllowed, "条目不再匹配当前页面")
                    }
                    Err(_) => secure_error(ErrorCode::InvalidRequest, "条目或用户名不存在"),
                }
            }
            SecureCommand::CredentialStatus {
                origin,
                username,
                mut password,
            } => {
                if !is_unlocked(vault.state()) {
                    password.zeroize();
                    return secure_error(ErrorCode::VaultLocked, "保险库已锁定");
                }
                let origin = match validate_submitted_credential(&origin, &username, &password) {
                    Ok(origin) => origin,
                    Err(_) => {
                        password.zeroize();
                        return secure_error(ErrorCode::InvalidRequest, "登录凭据格式无效");
                    }
                };
                let status = credential_status(vault, &origin, &username, &password);
                password.zeroize();
                match status {
                    Ok((action, title)) => SecureReply::CredentialStatus { action, title },
                    Err(_) => secure_error(ErrorCode::InternalError, "无法检查保险库登录项"),
                }
            }
            SecureCommand::SaveCredential {
                origin,
                title,
                username,
                mut password,
            } => {
                if !is_unlocked(vault.state()) {
                    password.zeroize();
                    return secure_error(ErrorCode::VaultLocked, "保险库已锁定");
                }
                let origin = match validate_submitted_credential(&origin, &username, &password) {
                    Ok(origin) => origin,
                    Err(_) => {
                        password.zeroize();
                        return secure_error(ErrorCode::InvalidRequest, "登录凭据格式无效");
                    }
                };
                match save_submitted_credential(
                    vault,
                    &origin,
                    &title,
                    &username,
                    password,
                    now_unix_ms,
                ) {
                    Ok((action, title)) => {
                        vault.record_activity(now_unix_ms);
                        SecureReply::CredentialSaved { action, title }
                    }
                    Err(_) => secure_error(ErrorCode::InternalError, "登录凭据未能保存到保险库"),
                }
            }
        }
    }

    fn expire_transient_state(&mut self, now_unix_ms: i64) {
        for pending in self.pending.values_mut() {
            if pending.expires_at <= now_unix_ms && pending.status == PairStatus::Pending {
                pending.status = PairStatus::Expired;
            }
        }
        self.fill_grants
            .retain(|_, grant| grant.expires_at > now_unix_ms);
    }

    fn persist(&self) -> Result<(), ExtensionError> {
        let parent = self
            .store_path
            .parent()
            .ok_or(ExtensionError::UnsafeStorePath)?;
        fs::create_dir_all(parent)?;
        harden_directory(parent)?;
        if fs::symlink_metadata(parent)?.file_type().is_symlink() {
            return Err(ExtensionError::UnsafeStorePath);
        }
        let suffix = format!("{}-{}", std::process::id(), monotonic_suffix());
        let file_name = self
            .store_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(ExtensionError::UnsafeStorePath)?;
        let temp = parent.join(format!(".{file_name}.{suffix}.tmp"));
        let rollback = parent.join(format!(".{file_name}.{suffix}.old"));
        let bytes = serde_json::to_vec(&self.store)?;

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        if let Err(error) = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            harden_private_file(&temp)
        })() {
            let _ = fs::remove_file(&temp);
            return Err(error.into());
        }
        drop(file);

        if self.store_path.exists() {
            if let Err(error) = atomic_replace_preserving_old(&self.store_path, &temp, &rollback) {
                let _ = fs::remove_file(&temp);
                return Err(error.into());
            }
            let _ = fs::remove_file(&rollback);
        } else if let Err(error) = fs::rename(&temp, &self.store_path) {
            let _ = fs::remove_file(&temp);
            return Err(error.into());
        }
        harden_private_file(&self.store_path)?;
        Ok(())
    }

    fn sign(&self, value: &[u8]) -> String {
        let signature: Signature = self.identity.sign(value);
        encode(signature.to_bytes().as_slice())
    }
}

fn collect_candidates(
    vault: &VaultService,
    origin: &NormalizedOrigin,
) -> Result<Vec<CredentialCandidate>, ExtensionError> {
    let mut candidates = Vec::new();
    let mut offset = 0;
    while candidates.len() < MAX_CANDIDATES {
        let page = vault
            .query_items(
                "",
                ItemFilter::default(),
                ItemSort::TitleAscending,
                offset,
                200,
            )
            .map_err(|_| ExtensionError::Vault)?;
        if page.is_empty() {
            break;
        }
        offset += page.len();
        for summary in page {
            if candidates.len() >= MAX_CANDIDATES {
                break;
            }
            let item = vault.item(summary.id).map_err(|_| ExtensionError::Vault)?;
            let VaultPayload::Login(login) = &item.payload else {
                continue;
            };
            let match_type = login
                .urls
                .iter()
                .enumerate()
                .filter_map(|(index, url)| {
                    match_login_url(url, login.url_match_mode(index), origin)
                })
                .max_by_key(|match_type| match_strength(*match_type));
            if let Some(match_type) = match_type {
                candidates.push(CredentialCandidate {
                    item_id: encode_item_id(item.id),
                    title: item.title.clone(),
                    usernames: login.usernames.clone(),
                    match_type,
                });
            }
        }
        if offset % 200 != 0 {
            break;
        }
    }
    Ok(candidates)
}

fn release_credential(
    vault: &VaultService,
    item_id: &str,
    username_index: usize,
    origin: &str,
) -> Result<(String, String), ExtensionError> {
    let id = decode_item_id(item_id)?;
    let item = vault.item(id).map_err(|_| ExtensionError::ItemNotFound)?;
    let VaultPayload::Login(login) = &item.payload else {
        return Err(ExtensionError::ItemNotFound);
    };
    let normalized =
        NormalizedOrigin::parse_web(origin).map_err(|_| ExtensionError::OriginMismatch)?;
    if !login.urls.iter().enumerate().any(|(index, url)| {
        match_login_url(url, login.url_match_mode(index), &normalized).is_some()
    }) {
        return Err(ExtensionError::OriginMismatch);
    }
    let username = if login.usernames.is_empty() && username_index == 0 {
        String::new()
    } else {
        login
            .usernames
            .get(username_index)
            .cloned()
            .ok_or(ExtensionError::ItemNotFound)?
    };
    Ok((username, login.password.clone()))
}

fn match_login_url(
    item_url: &str,
    mode: UrlMatchMode,
    page_origin: &NormalizedOrigin,
) -> Option<CredentialMatch> {
    if mode == UrlMatchMode::Never {
        return None;
    }

    let item = parse_fill_url(item_url)?;
    let page = Url::parse(page_origin.as_str()).ok()?;
    let item_host = item.host_str()?;
    let page_host = page.host_str()?;

    if item.scheme() == "http" && page.scheme() == "https" {
        return (item_host.eq_ignore_ascii_case(page_host)
            && http_upgrade_ports_match(&item, &page))
        .then_some(CredentialMatch::HttpsUpgrade);
    }

    let same_scheme = item.scheme() == page.scheme();
    let exact_host = same_scheme
        && item_host.eq_ignore_ascii_case(page_host)
        && item.port_or_known_default() == page.port_or_known_default();
    if exact_host {
        return Some(CredentialMatch::ExactHost);
    }
    if same_scheme
        && mode == UrlMatchMode::AnywhereOnWebsite
        && same_registrable_website(item_host, page_host)
    {
        return Some(CredentialMatch::Website);
    }
    None
}

fn parse_fill_url(value: &str) -> Option<Url> {
    let value = value.trim();
    if value.is_empty() || value.len() > 2_048 {
        return None;
    }
    let normalized = if value.starts_with("//") {
        format!("https:{value}")
    } else if value.contains("://") {
        value.to_owned()
    } else {
        format!("https://{value}")
    };
    let url = Url::parse(&normalized).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
    {
        return None;
    }
    Some(url)
}

fn same_registrable_website(left: &str, right: &str) -> bool {
    let Some(left_domain) = psl::domain_str(left) else {
        return false;
    };
    let Some(right_domain) = psl::domain_str(right) else {
        return false;
    };
    left_domain.eq_ignore_ascii_case(right_domain)
}

fn http_upgrade_ports_match(http_url: &Url, https_url: &Url) -> bool {
    match (http_url.port(), https_url.port()) {
        (None, None) => true,
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

const fn match_strength(match_type: CredentialMatch) -> u8 {
    match match_type {
        CredentialMatch::ExactHost => 3,
        CredentialMatch::HttpsUpgrade => 2,
        CredentialMatch::Website => 1,
    }
}

fn validate_submitted_credential(
    origin: &str,
    username: &str,
    password: &str,
) -> Result<NormalizedOrigin, ExtensionError> {
    let origin = validate_submitted_identity(origin, username)?;
    if password.is_empty()
        || password.len() > MAX_CAPTURE_PASSWORD_BYTES
        || password.chars().any(|character| character == '\0')
    {
        return Err(ExtensionError::InvalidCredential);
    }
    Ok(origin)
}

fn validate_submitted_identity(
    origin: &str,
    username: &str,
) -> Result<NormalizedOrigin, ExtensionError> {
    if username.len() > MAX_CAPTURE_USERNAME_BYTES || username.chars().any(char::is_control) {
        return Err(ExtensionError::InvalidCredential);
    }
    NormalizedOrigin::parse_web(origin).map_err(|_| ExtensionError::InvalidCredential)
}

fn credential_status(
    vault: &VaultService,
    origin: &NormalizedOrigin,
    username: &str,
    password: &str,
) -> Result<(CredentialSaveAction, Option<String>), ExtensionError> {
    let Some(item) = find_existing_credential(vault, origin, username)? else {
        return Ok((CredentialSaveAction::Create, None));
    };
    if let VaultPayload::Login(login) = &item.payload
        && login.password == password
    {
        return Ok((CredentialSaveAction::Unchanged, Some(item.title)));
    }
    Ok((CredentialSaveAction::Update, Some(item.title)))
}

fn find_existing_credential(
    vault: &VaultService,
    origin: &NormalizedOrigin,
    username: &str,
) -> Result<Option<VaultItem>, ExtensionError> {
    let mut best: Option<(u8, VaultItem)> = None;
    let mut offset = 0;
    loop {
        let page = vault
            .query_items(
                "",
                ItemFilter::default(),
                ItemSort::TitleAscending,
                offset,
                200,
            )
            .map_err(|_| ExtensionError::Vault)?;
        if page.is_empty() {
            break;
        }
        offset += page.len();
        for summary in page {
            let item = vault.item(summary.id).map_err(|_| ExtensionError::Vault)?;
            let VaultPayload::Login(login) = &item.payload else {
                continue;
            };
            let username_matches = if username.is_empty() {
                login.usernames.is_empty()
                    || login.usernames.iter().any(|candidate| candidate.is_empty())
            } else {
                login
                    .usernames
                    .iter()
                    .any(|candidate| candidate == username)
            };
            if !username_matches {
                continue;
            }
            let strength = login
                .urls
                .iter()
                .enumerate()
                .filter_map(|(index, url)| {
                    match_login_url(url, login.url_match_mode(index), origin)
                })
                .map(match_strength)
                .max();
            let Some(strength) = strength else {
                continue;
            };
            if best.as_ref().is_none_or(|(current, _)| strength > *current) {
                best = Some((strength, item.clone()));
            }
        }
        if offset % 200 != 0 {
            break;
        }
    }
    Ok(best.map(|(_, item)| item))
}

fn save_submitted_credential(
    vault: &mut VaultService,
    origin: &NormalizedOrigin,
    requested_title: &str,
    username: &str,
    mut password: String,
    now_unix_ms: i64,
) -> Result<(CredentialSaveAction, String), ExtensionError> {
    let existing = match find_existing_credential(vault, origin, username) {
        Ok(existing) => existing,
        Err(error) => {
            password.zeroize();
            return Err(error);
        }
    };
    if let Some(item) = existing {
        let VaultPayload::Login(login) = &item.payload else {
            password.zeroize();
            return Err(ExtensionError::Vault);
        };
        if login.password == password {
            password.zeroize();
            return Ok((CredentialSaveAction::Unchanged, item.title));
        }
        let input = LoginInput {
            group_id: item.group_id,
            title: item.title.clone(),
            favorite: item.favorite,
            tags: item.tags.clone(),
            usernames: login.usernames.clone(),
            password,
            urls: login.urls.clone(),
            url_match_modes: (0..login.urls.len())
                .map(|index| login.url_match_mode(index))
                .collect(),
            notes: login.notes.clone(),
            custom_fields: login.custom_fields.clone(),
        };
        vault
            .apply_and_save(|service| service.update_login(item.id, input, now_unix_ms))
            .map_err(|_| ExtensionError::Vault)?;
        return Ok((CredentialSaveAction::Update, item.title));
    }

    let root_group = match vault
        .groups()
        .ok()
        .and_then(|groups| groups.into_iter().find(|group| group.parent_id.is_none()))
        .map(|group| group.id)
    {
        Some(root_group) => root_group,
        None => {
            password.zeroize();
            return Err(ExtensionError::Vault);
        }
    };
    let title = capture_title(requested_title, origin);
    let usernames = if username.is_empty() {
        Vec::new()
    } else {
        vec![username.to_owned()]
    };
    let input = LoginInput {
        group_id: root_group,
        title: title.clone(),
        favorite: false,
        tags: Vec::new(),
        usernames,
        password,
        urls: vec![origin.as_str().to_owned()],
        url_match_modes: vec![UrlMatchMode::ExactHost],
        notes: String::new(),
        custom_fields: Vec::new(),
    };
    vault
        .apply_and_save(|service| service.create_login(input, now_unix_ms))
        .map_err(|_| ExtensionError::Vault)?;
    Ok((CredentialSaveAction::Create, title))
}

fn capture_title(requested: &str, origin: &NormalizedOrigin) -> String {
    let cleaned = requested
        .trim()
        .chars()
        .filter(|character| !character.is_control())
        .take(MAX_CAPTURE_TITLE_CHARS)
        .collect::<String>();
    if !cleaned.is_empty() {
        return cleaned;
    }
    Url::parse(origin.as_str())
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| "网站登录".to_owned())
}

fn secure_error(code: ErrorCode, message: impl Into<String>) -> SecureReply {
    SecureReply::Error {
        code,
        message: message.into(),
    }
}

fn zeroize_reply(reply: &mut SecureReply) {
    if let SecureReply::Fill {
        username, password, ..
    } = reply
    {
        username.zeroize();
        password.zeroize();
    }
}

fn is_unlocked(state: SessionState) -> bool {
    matches!(state, SessionState::Unlocked | SessionState::Dirty)
}

fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LABEL_BYTES
        && !value.contains('|')
        && !value.chars().any(char::is_control)
}

fn valid_extension_origin(value: &str) -> bool {
    value.len() <= MAX_ORIGIN_BYTES
        && !value.contains('|')
        && (value.starts_with("chrome-extension://")
            || value.starts_with("moz-extension://")
            || value.starts_with("firefox-extension://"))
}

fn derive_key(
    shared_secret: &[u8],
    context: &str,
    info: &[u8],
) -> Result<[u8; 32], ExtensionError> {
    let salt = Sha256::digest(context.as_bytes());
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut output = [0_u8; 32];
    hkdf.expand(info, &mut output)
        .map_err(|_| ExtensionError::Crypto)?;
    Ok(output)
}

fn encode(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(value)
}

fn decode(value: &str) -> Result<Vec<u8>, ExtensionError> {
    if value.len() > 16 * 1024 {
        return Err(ExtensionError::InvalidEncoding);
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ExtensionError::InvalidEncoding)
}

fn decode_exact<const N: usize>(value: &str) -> Result<[u8; N], ExtensionError> {
    decode(value)?
        .try_into()
        .map_err(|_| ExtensionError::InvalidEncoding)
}

fn decode_public_key(value: &str) -> Result<PublicKey, ExtensionError> {
    PublicKey::from_sec1_bytes(&decode(value)?).map_err(|_| ExtensionError::InvalidEncoding)
}

fn decode_verifying_key(value: &str) -> Result<VerifyingKey, ExtensionError> {
    VerifyingKey::from_sec1_bytes(&decode(value)?).map_err(|_| ExtensionError::InvalidEncoding)
}

fn decode_signature(value: &str) -> Result<Signature, ExtensionError> {
    Signature::from_slice(&decode(value)?).map_err(|_| ExtensionError::InvalidEncoding)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut value = [0_u8; N];
    OsRng.fill_bytes(&mut value);
    value
}

fn random_id() -> String {
    encode(&random_bytes::<16>())
}

fn monotonic_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

fn fingerprint(public_key: &str) -> String {
    let digest = Sha256::digest(public_key.as_bytes());
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn encode_item_id(id: Id) -> String {
    id.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn decode_item_id(value: &str) -> Result<Id, ExtensionError> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ExtensionError::ItemNotFound);
    }
    let mut bytes = [0_u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| ExtensionError::ItemNotFound)?;
    }
    Ok(Id::from_bytes(bytes))
}

fn harden_directory(_path: &Path) -> Result<(), ExtensionError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(_path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn prepare_endpoint(_endpoint: &str) -> Result<(), ExtensionError> {
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::FileTypeExt as _;

        let path = Path::new(_endpoint);
        let parent = path.parent().ok_or(ExtensionError::EndpointUnavailable)?;
        fs::create_dir_all(parent)?;
        harden_directory(parent)?;
        if fs::symlink_metadata(parent)?.file_type().is_symlink() {
            return Err(ExtensionError::UnsafeStorePath);
        }
        if path.exists() {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
                return Err(ExtensionError::UnsafeStorePath);
            }
            let name = path
                .to_fs_name::<GenericFilePath>()
                .map_err(|_| ExtensionError::EndpointUnavailable)?;
            if LocalSocketStream::connect(name).is_ok() {
                return Err(ExtensionError::BrokerAlreadyRunning);
            }
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn read_broker_request(reader: &mut impl std::io::Read) -> Result<HostRequest, ExtensionError> {
    let bytes = read_frame(reader)?;
    serde_json::from_slice(&bytes).map_err(ExtensionError::Json)
}

fn write_broker_response(
    writer: &mut impl std::io::Write,
    response: &HostResponse,
) -> Result<(), ExtensionError> {
    let bytes = serde_json::to_vec(response)?;
    write_frame(writer, &bytes)
}

fn read_frame(reader: &mut impl std::io::Read) -> Result<Vec<u8>, ExtensionError> {
    let mut length = [0_u8; 4];
    reader.read_exact(&mut length)?;
    let length =
        usize::try_from(u32::from_le_bytes(length)).map_err(|_| ExtensionError::FrameTooLarge)?;
    if length == 0 || length > vault_extension_protocol::MAX_FRAME_BYTES {
        return Err(ExtensionError::FrameTooLarge);
    }
    let mut bytes = vec![0_u8; length];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn write_frame(writer: &mut impl std::io::Write, bytes: &[u8]) -> Result<(), ExtensionError> {
    if bytes.is_empty() || bytes.len() > vault_extension_protocol::MAX_FRAME_BYTES {
        return Err(ExtensionError::FrameTooLarge);
    }
    let length = u32::try_from(bytes.len()).map_err(|_| ExtensionError::FrameTooLarge)?;
    writer.write_all(&length.to_le_bytes())?;
    writer.write_all(bytes)?;
    writer.flush()?;
    Ok(())
}

#[must_use]
pub fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

#[derive(Debug, Error)]
pub enum ExtensionError {
    #[error("extension store I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("extension store JSON is invalid")]
    Json(#[from] serde_json::Error),
    #[error("extension store path is unsafe")]
    UnsafeStorePath,
    #[error("extension store is invalid")]
    InvalidStore,
    #[error("extension store version is unsupported")]
    UnsupportedStoreVersion,
    #[error("extension value encoding is invalid")]
    InvalidEncoding,
    #[error("pairing was not found")]
    PairingNotFound,
    #[error("pairing expired")]
    PairingExpired,
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("vault query failed")]
    Vault,
    #[error("item was not found")]
    ItemNotFound,
    #[error("item origin does not match")]
    OriginMismatch,
    #[error("submitted credential is invalid")]
    InvalidCredential,
    #[error("local broker endpoint is unavailable")]
    EndpointUnavailable,
    #[error("another StarAxis browser broker is already running")]
    BrokerAlreadyRunning,
    #[error("local broker frame exceeds its limit")]
    FrameTooLarge,
}

#[cfg(test)]
mod tests {
    use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    use p256::PublicKey;
    use p256::ecdh::EphemeralSecret;
    use p256::ecdsa::signature::{Signer as _, Verifier as _};
    use p256::ecdsa::{Signature, SigningKey};
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::elliptic_curve::sec1::ToEncodedPoint as _;
    use tempfile::tempdir;
    use vault_crypto::KdfParams;
    use vault_domain::{UrlMatchMode, VaultPayload};
    use vault_extension_protocol::{
        BrowserKind, ClientRequest, CredentialMatch, CredentialSaveAction, ErrorCode, HostRequest,
        HostResponse, PROTOCOL_VERSION, PairBeginRequest, PairChallengeResponse, PairPollRequest,
        PairStatus, SecureCommand, SecureReply, SecureRequest, secure_aad, secure_context,
        secure_response_signature_input, secure_signature_input,
    };
    use vault_service::{LoginInput, NewGroup, VaultService};

    use super::{ExtensionService, now_unix_ms};

    #[test]
    fn existing_store_reopens_and_preserves_desktop_identity() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("pairs.json");
        let first = ExtensionService::load_or_create(&path).expect("initial extension store");
        let identity = first.desktop_identity_public_key();
        let exchange = first.desktop_exchange_public_key();
        drop(first);

        let reopened = ExtensionService::load_or_create(&path).expect("existing extension store");
        assert_eq!(reopened.desktop_identity_public_key(), identity);
        assert_eq!(reopened.desktop_exchange_public_key(), exchange);
    }

    #[test]
    fn pairing_requires_matching_origin_and_explicit_approval() {
        let directory = tempdir().expect("temporary directory");
        let mut extension = ExtensionService::load_or_create(directory.path().join("pairs.json"))
            .expect("extension store");
        let mut vault = VaultService::new();
        let client_identity = p256::ecdsa::SigningKey::random(&mut OsRng);
        let client_ephemeral = EphemeralSecret::random(&mut OsRng);
        let request = PairBeginRequest {
            version: PROTOCOL_VERSION,
            client_id: "test-client".to_owned(),
            browser: BrowserKind::Chrome,
            profile_name: "Default".to_owned(),
            extension_origin: "chrome-extension://test/".to_owned(),
            identity_public_key: super::encode(
                client_identity
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes(),
            ),
            ephemeral_public_key: super::encode(
                PublicKey::from(&client_ephemeral)
                    .to_encoded_point(false)
                    .as_bytes(),
            ),
            client_nonce: super::encode(&[7_u8; 32]),
        };
        let now = now_unix_ms();
        let response = extension.handle(
            HostRequest {
                caller_origin: request.extension_origin.clone(),
                request: ClientRequest::PairBegin(request),
            },
            &mut vault,
            now,
        );
        let HostResponse::PairChallenge(challenge) = response else {
            panic!("expected pairing challenge")
        };
        assert_eq!(extension.pending_pairs(now).len(), 1);
        let pair_id = extension
            .approve_pairing(&challenge.pending_id, now)
            .expect("pair approval");
        let polled = extension.handle(
            HostRequest {
                caller_origin: "chrome-extension://test/".to_owned(),
                request: ClientRequest::PairPoll(PairPollRequest {
                    version: PROTOCOL_VERSION,
                    pending_id: challenge.pending_id,
                }),
            },
            &mut vault,
            now,
        );
        let HostResponse::PairStatus(status) = polled else {
            panic!("expected pairing status")
        };
        assert_eq!(status.status, PairStatus::Approved);
        assert_eq!(status.pair_id.as_deref(), Some(pair_id.as_str()));
    }

    #[test]
    fn candidates_are_origin_bound_login_items_only() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("test.vaultx");
        let mut vault = VaultService::new();
        vault
            .create(&path, b"strong password", 1, KdfParams::testing())
            .expect("create vault");
        let root = vault
            .groups()
            .expect("groups")
            .into_iter()
            .find(|group| group.parent_id.is_none())
            .expect("root group")
            .id;
        let group = vault
            .create_group(
                NewGroup {
                    parent_id: root,
                    name: "Web".to_owned(),
                },
                2,
            )
            .expect("create group");
        vault
            .create_login(
                LoginInput {
                    group_id: group,
                    title: "Example".to_owned(),
                    favorite: false,
                    tags: vec![],
                    usernames: vec!["alice".to_owned()],
                    password: "secret".to_owned(),
                    urls: vec!["https://example.com/login".to_owned()],
                    url_match_modes: vec![UrlMatchMode::ExactHost],
                    notes: String::new(),
                    custom_fields: vec![],
                },
                3,
            )
            .expect("create login");
        let origin =
            vault_extension_protocol::NormalizedOrigin::parse_web("https://example.com/account")
                .expect("origin");
        let candidates = super::collect_candidates(&vault, &origin).expect("candidates");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].title, "Example");
        assert_eq!(candidates[0].match_type, CredentialMatch::ExactHost);
        assert!(
            super::release_credential(&vault, &candidates[0].item_id, 0, "https://example.com")
                .is_ok()
        );
        assert!(
            super::release_credential(
                &vault,
                &candidates[0].item_id,
                0,
                "https://example.com.evil.test"
            )
            .is_err()
        );

        for (title, url, mode, now) in [
            ("Mozhe Apex", "mozhe.cn", UrlMatchMode::AnywhereOnWebsite, 4),
            ("Mozhe WWW", "www.mozhe.cn", UrlMatchMode::ExactHost, 5),
        ] {
            vault
                .create_login(
                    LoginInput {
                        group_id: group,
                        title: title.to_owned(),
                        favorite: false,
                        tags: vec![],
                        usernames: vec![title.to_owned()],
                        password: "secret".to_owned(),
                        urls: vec![url.to_owned()],
                        url_match_modes: vec![mode],
                        notes: String::new(),
                        custom_fields: vec![],
                    },
                    now,
                )
                .expect("create schemeless login");
        }
        let mozhe =
            vault_extension_protocol::NormalizedOrigin::parse_web("https://www.mozhe.cn/login")
                .expect("mozhe origin");
        let candidates = super::collect_candidates(&vault, &mozhe).expect("mozhe candidates");
        assert_eq!(candidates.len(), 2);
        assert_eq!(
            candidates
                .iter()
                .map(|candidate| (candidate.title.as_str(), candidate.match_type))
                .collect::<Vec<_>>(),
            vec![
                ("Mozhe Apex", CredentialMatch::Website),
                ("Mozhe WWW", CredentialMatch::ExactHost),
            ]
        );
    }

    #[test]
    fn match_policy_supports_public_suffix_sites_and_safe_https_upgrade() {
        let subdomain =
            vault_extension_protocol::NormalizedOrigin::parse_web("https://login.example.co.uk")
                .expect("subdomain origin");
        assert_eq!(
            super::match_login_url(
                "https://accounts.example.co.uk/login",
                UrlMatchMode::AnywhereOnWebsite,
                &subdomain,
            ),
            Some(CredentialMatch::Website)
        );
        assert_eq!(
            super::match_login_url(
                "https://accounts.example.co.uk/login",
                UrlMatchMode::ExactHost,
                &subdomain,
            ),
            None
        );

        let mozhe =
            vault_extension_protocol::NormalizedOrigin::parse_web("https://www.mozhe.cn/login")
                .expect("mozhe origin");
        assert_eq!(
            super::match_login_url("www.mozhe.cn", UrlMatchMode::ExactHost, &mozhe,),
            Some(CredentialMatch::ExactHost)
        );
        assert_eq!(
            super::match_login_url("mozhe.cn", UrlMatchMode::AnywhereOnWebsite, &mozhe,),
            Some(CredentialMatch::Website)
        );
        assert_eq!(
            super::match_login_url("mozhe.cn", UrlMatchMode::ExactHost, &mozhe,),
            None
        );
        assert_eq!(
            super::match_login_url("http://www.mozhe.cn/", UrlMatchMode::ExactHost, &mozhe,),
            Some(CredentialMatch::HttpsUpgrade)
        );
        assert_eq!(
            super::match_login_url("http://mozhe.cn/", UrlMatchMode::AnywhereOnWebsite, &mozhe,),
            None
        );
        assert_eq!(
            super::match_login_url("https://www.mozhe.cn/", UrlMatchMode::Never, &mozhe,),
            None
        );
        assert_eq!(
            super::match_login_url(
                "javascript:alert(1)",
                UrlMatchMode::AnywhereOnWebsite,
                &mozhe,
            ),
            None
        );
        assert_eq!(
            super::match_login_url("user@www.mozhe.cn", UrlMatchMode::AnywhereOnWebsite, &mozhe,),
            None
        );

        let insecure =
            vault_extension_protocol::NormalizedOrigin::parse_web("http://www.mozhe.cn/login")
                .expect("HTTP origin");
        assert_eq!(
            super::match_login_url("http://www.mozhe.cn/", UrlMatchMode::ExactHost, &insecure,),
            Some(CredentialMatch::ExactHost)
        );
        assert_eq!(
            super::match_login_url("https://www.mozhe.cn/", UrlMatchMode::ExactHost, &insecure,),
            None,
            "HTTPS credentials must never be downgraded into an HTTP page"
        );
    }

    #[test]
    fn submitted_credentials_create_update_and_skip_unchanged_logins() {
        let directory = tempdir().expect("temporary directory");
        let mut vault = populated_vault(directory.path());
        let origin =
            vault_extension_protocol::NormalizedOrigin::parse_web("https://example.com/login")
                .expect("origin");

        assert_eq!(
            super::credential_status(&vault, &origin, "alice", "secret")
                .expect("existing account status")
                .0,
            CredentialSaveAction::Unchanged
        );
        assert_eq!(
            super::save_submitted_credential(
                &mut vault,
                &origin,
                "Untrusted page title",
                "alice",
                "secret".to_owned(),
                3,
            )
            .expect("unchanged credential is accepted")
            .0,
            CredentialSaveAction::Unchanged
        );
        assert_eq!(
            super::credential_status(&vault, &origin, "bob", "new secret")
                .expect("new account status")
                .0,
            CredentialSaveAction::Create
        );
        let (action, title) = super::save_submitted_credential(
            &mut vault,
            &origin,
            "Example sign in",
            "bob",
            "new secret".to_owned(),
            4,
        )
        .expect("new account saves");
        assert_eq!(action, CredentialSaveAction::Create);
        assert_eq!(title, "Example sign in");

        assert_eq!(
            super::credential_status(&vault, &origin, "alice", "updated secret")
                .expect("updated account status")
                .0,
            CredentialSaveAction::Update
        );
        let (action, title) = super::save_submitted_credential(
            &mut vault,
            &origin,
            "Untrusted page title",
            "alice",
            "rotated secret".to_owned(),
            5,
        )
        .expect("password update saves");
        assert_eq!(action, CredentialSaveAction::Update);
        assert_eq!(title, "Example");

        let candidates = super::collect_candidates(&vault, &origin).expect("candidates");
        assert_eq!(candidates.len(), 2);
        let example = candidates
            .iter()
            .find(|candidate| candidate.title == "Example")
            .expect("updated login remains");
        let item = vault
            .item(super::decode_item_id(&example.item_id).expect("item id"))
            .expect("updated item");
        let VaultPayload::Login(login) = &item.payload else {
            panic!("login expected")
        };
        assert_eq!(login.password, "rotated secret");
    }

    #[test]
    fn encrypted_fill_is_origin_bound_one_time_and_replay_safe() {
        let directory = tempdir().expect("temporary directory");
        let mut extension = ExtensionService::load_or_create(directory.path().join("pairs.json"))
            .expect("extension store");
        let mut vault = populated_vault(directory.path());
        let client_identity = SigningKey::random(&mut OsRng);
        let now = now_unix_ms();
        let (pair_id, challenge) = pair_client(&mut extension, &mut vault, &client_identity, now);

        let candidates = secure_round_trip(
            &mut extension,
            &mut vault,
            &client_identity,
            &pair_id,
            &challenge,
            1,
            now,
            SecureCommand::Candidates {
                origin: "https://example.com".to_owned(),
            },
        );
        let SecureReply::Candidates {
            request_token,
            candidates,
            ..
        } = candidates
        else {
            panic!("expected candidates")
        };
        assert_eq!(candidates.len(), 1);

        let fill = secure_round_trip(
            &mut extension,
            &mut vault,
            &client_identity,
            &pair_id,
            &challenge,
            2,
            now + 1,
            SecureCommand::Fill {
                origin: "https://example.com".to_owned(),
                request_token: request_token.clone(),
                item_id: candidates[0].item_id.clone(),
                username_index: 0,
            },
        );
        let SecureReply::Fill {
            username, password, ..
        } = fill
        else {
            panic!("expected fill")
        };
        assert_eq!(username, "alice");
        assert_eq!(password, "secret");

        let consumed = secure_round_trip(
            &mut extension,
            &mut vault,
            &client_identity,
            &pair_id,
            &challenge,
            3,
            now + 2,
            SecureCommand::Fill {
                origin: "https://example.com".to_owned(),
                request_token,
                item_id: candidates[0].item_id.clone(),
                username_index: 0,
            },
        );
        assert!(matches!(
            consumed,
            SecureReply::Error {
                code: ErrorCode::StaleRequest,
                ..
            }
        ));

        let replay = make_secure_request(
            &client_identity,
            &pair_id,
            &challenge.desktop_exchange_public_key,
            3,
            now + 2,
            &SecureCommand::Status,
        );
        let replay_response = extension.handle(
            HostRequest {
                caller_origin: "chrome-extension://test/".to_owned(),
                request: ClientRequest::Secure(replay.request),
            },
            &mut vault,
            now + 2,
        );
        assert!(matches!(
            replay_response,
            HostResponse::Error(error) if error.code == ErrorCode::StaleRequest
        ));
    }

    fn populated_vault(directory: &std::path::Path) -> VaultService {
        let path = directory.join("secure-test.vaultx");
        let mut vault = VaultService::new();
        vault
            .create(&path, b"strong password", 1, KdfParams::testing())
            .expect("create vault");
        let root = vault
            .groups()
            .expect("groups")
            .into_iter()
            .find(|group| group.parent_id.is_none())
            .expect("root group")
            .id;
        let group = vault
            .create_group(
                NewGroup {
                    parent_id: root,
                    name: "Web".to_owned(),
                },
                2,
            )
            .expect("create group");
        vault
            .create_login(
                LoginInput {
                    group_id: group,
                    title: "Example".to_owned(),
                    favorite: false,
                    tags: vec![],
                    usernames: vec!["alice".to_owned()],
                    password: "secret".to_owned(),
                    urls: vec!["https://example.com/login".to_owned()],
                    url_match_modes: vec![UrlMatchMode::ExactHost],
                    notes: "must never leave the desktop".to_owned(),
                    custom_fields: vec![],
                },
                3,
            )
            .expect("create login");
        vault
    }

    fn pair_client(
        extension: &mut ExtensionService,
        vault: &mut VaultService,
        identity: &SigningKey,
        now: i64,
    ) -> (String, PairChallengeResponse) {
        let ephemeral = EphemeralSecret::random(&mut OsRng);
        let request = PairBeginRequest {
            version: PROTOCOL_VERSION,
            client_id: "secure-test-client".to_owned(),
            browser: BrowserKind::Chrome,
            profile_name: "Default".to_owned(),
            extension_origin: "chrome-extension://test/".to_owned(),
            identity_public_key: super::encode(
                identity.verifying_key().to_encoded_point(false).as_bytes(),
            ),
            ephemeral_public_key: super::encode(
                PublicKey::from(&ephemeral)
                    .to_encoded_point(false)
                    .as_bytes(),
            ),
            client_nonce: super::encode(&[9_u8; 32]),
        };
        let HostResponse::PairChallenge(challenge) = extension.handle(
            HostRequest {
                caller_origin: request.extension_origin.clone(),
                request: ClientRequest::PairBegin(request),
            },
            vault,
            now,
        ) else {
            panic!("expected pairing challenge")
        };
        let pair_id = extension
            .approve_pairing(&challenge.pending_id, now)
            .expect("approve pairing");
        (pair_id, challenge)
    }

    struct PreparedSecureRequest {
        request: SecureRequest,
        shared_secret: Vec<u8>,
    }

    fn make_secure_request(
        identity: &SigningKey,
        pair_id: &str,
        desktop_exchange_public_key: &str,
        sequence: u64,
        now: i64,
        command: &SecureCommand,
    ) -> PreparedSecureRequest {
        let request_id = super::encode(&sequence.to_le_bytes());
        let ephemeral = EphemeralSecret::random(&mut OsRng);
        let desktop_exchange = super::decode_public_key(desktop_exchange_public_key)
            .expect("desktop exchange public key");
        let shared = ephemeral.diffie_hellman(&desktop_exchange);
        let shared_secret = shared.raw_secret_bytes().to_vec();
        let context = secure_context(pair_id, sequence, &request_id);
        let key =
            super::derive_key(&shared_secret, &context, b"staraxis/request").expect("request key");
        let cipher = Aes256Gcm::new_from_slice(&key).expect("request cipher");
        let nonce = [sequence as u8; 12];
        let plaintext = serde_json::to_vec(command).expect("command JSON");
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &secure_aad(pair_id, sequence, &request_id, "request"),
                },
            )
            .expect("encrypt request");
        let mut request = SecureRequest {
            version: PROTOCOL_VERSION,
            pair_id: pair_id.to_owned(),
            request_id,
            sequence,
            created_at: now,
            ephemeral_public_key: super::encode(
                PublicKey::from(&ephemeral)
                    .to_encoded_point(false)
                    .as_bytes(),
            ),
            nonce: super::encode(&nonce),
            ciphertext: super::encode(&ciphertext),
            signature: String::new(),
        };
        let signature: Signature = identity.sign(&secure_signature_input(&request));
        request.signature = super::encode(signature.to_bytes().as_slice());
        PreparedSecureRequest {
            request,
            shared_secret,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn secure_round_trip(
        extension: &mut ExtensionService,
        vault: &mut VaultService,
        identity: &SigningKey,
        pair_id: &str,
        challenge: &PairChallengeResponse,
        sequence: u64,
        now: i64,
        command: SecureCommand,
    ) -> SecureReply {
        let prepared = make_secure_request(
            identity,
            pair_id,
            &challenge.desktop_exchange_public_key,
            sequence,
            now,
            &command,
        );
        let HostResponse::Secure(response) = extension.handle(
            HostRequest {
                caller_origin: "chrome-extension://test/".to_owned(),
                request: ClientRequest::Secure(prepared.request),
            },
            vault,
            now,
        ) else {
            panic!("expected secure response")
        };
        let desktop_identity = super::decode_verifying_key(&challenge.desktop_identity_public_key)
            .expect("desktop identity public key");
        let signature = super::decode_signature(&response.signature).expect("response signature");
        desktop_identity
            .verify(&secure_response_signature_input(&response), &signature)
            .expect("valid desktop response signature");
        let context = secure_context(pair_id, sequence, &response.request_id);
        let key = super::derive_key(&prepared.shared_secret, &context, b"staraxis/response")
            .expect("response key");
        let cipher = Aes256Gcm::new_from_slice(&key).expect("response cipher");
        let nonce = super::decode_exact::<12>(&response.nonce).expect("response nonce");
        let ciphertext = super::decode(&response.ciphertext).expect("response ciphertext");
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &secure_aad(pair_id, sequence, &response.request_id, "response"),
                },
            )
            .expect("decrypt response");
        serde_json::from_slice(&plaintext).expect("secure reply")
    }
}

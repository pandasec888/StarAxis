#![doc = "Versioned wire contract shared by the StarAxis browser bridge components."]
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use url::Url;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 256 * 1024;
pub const MAX_PENDING_REQUESTS: usize = 8;
pub const MAX_CANDIDATES: usize = 50;
pub const MAX_CLOCK_SKEW_MS: i64 = 120_000;
pub const PAIRING_TTL_MS: i64 = 60_000;
pub const FILL_TOKEN_TTL_MS: i64 = 30_000;
pub const FILL_RESULT_TTL_MS: i64 = 10_000;

#[must_use]
pub fn local_endpoint_name() -> Option<String> {
    #[cfg(windows)]
    {
        let identity = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("USERNAME"))
            .ok()?;
        let digest = Sha256::digest(identity.as_bytes());
        let suffix = digest[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Some(format!("staraxis.browser.v1.{suffix}"))
    }
    #[cfg(not(windows))]
    {
        let base = std::env::var_os("XDG_RUNTIME_DIR")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(std::path::PathBuf::from)
                    .map(|home| home.join(".staraxis").join("run"))
            })?;
        if !base.is_absolute() {
            return None;
        }
        Some(
            base.join("staraxis-browser-v1.sock")
                .to_string_lossy()
                .into_owned(),
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserKind {
    Chrome,
    Edge,
    Firefox,
}

impl BrowserKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Edge => "edge",
            Self::Firefox => "firefox",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostRequest {
    pub caller_origin: String,
    pub request: ClientRequest,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientRequest {
    PairBegin(PairBeginRequest),
    PairPoll(PairPollRequest),
    Secure(SecureRequest),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PairBeginRequest {
    pub version: u16,
    pub client_id: String,
    pub browser: BrowserKind,
    pub profile_name: String,
    pub extension_origin: String,
    pub identity_public_key: String,
    pub ephemeral_public_key: String,
    pub client_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PairPollRequest {
    pub version: u16,
    pub pending_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecureRequest {
    pub version: u16,
    pub pair_id: String,
    pub request_id: String,
    pub sequence: u64,
    pub created_at: i64,
    pub ephemeral_public_key: String,
    pub nonce: String,
    pub ciphertext: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostResponse {
    PairChallenge(PairChallengeResponse),
    PairStatus(PairStatusResponse),
    Secure(SecureResponse),
    Error(ErrorResponse),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PairChallengeResponse {
    pub version: u16,
    pub pending_id: String,
    pub desktop_identity_public_key: String,
    pub desktop_exchange_public_key: String,
    pub ephemeral_public_key: String,
    pub server_nonce: String,
    pub verification_code: String,
    pub expires_at: i64,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PairStatusResponse {
    pub version: u16,
    pub pending_id: String,
    pub status: PairStatus,
    pub pair_id: Option<String>,
    pub signature: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PairStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecureResponse {
    pub version: u16,
    pub pair_id: String,
    pub request_id: String,
    pub sequence: u64,
    pub created_at: i64,
    pub nonce: String,
    pub ciphertext: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorResponse {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    DesktopOffline,
    Unpaired,
    PairingExpired,
    PairingRejected,
    VaultLocked,
    OriginNotAllowed,
    NoMatch,
    StaleRequest,
    RateLimited,
    InvalidRequest,
    ProtocolError,
    InternalError,
}

impl HostResponse {
    #[must_use]
    pub fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Error(ErrorResponse {
            code,
            message: message.into(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecureCommand {
    Status,
    Candidates {
        origin: String,
    },
    Fill {
        origin: String,
        request_token: String,
        item_id: String,
        username_index: usize,
    },
    CredentialStatus {
        origin: String,
        username: String,
        password: String,
    },
    SaveCredential {
        origin: String,
        title: String,
        username: String,
        password: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecureReply {
    Status {
        vault_state: VaultState,
    },
    Candidates {
        origin: String,
        request_token: String,
        expires_at: i64,
        candidates: Vec<CredentialCandidate>,
    },
    Fill {
        origin: String,
        username: String,
        password: String,
        expires_at: i64,
    },
    CredentialStatus {
        action: CredentialSaveAction,
        title: Option<String>,
    },
    CredentialSaved {
        action: CredentialSaveAction,
        title: String,
    },
    Error {
        code: ErrorCode,
        message: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultState {
    Locked,
    Unlocked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CredentialCandidate {
    pub item_id: String,
    pub title: String,
    pub usernames: Vec<String>,
    pub match_type: CredentialMatch,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialMatch {
    ExactHost,
    Website,
    HttpsUpgrade,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialSaveAction {
    Create,
    Update,
    Unchanged,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedOrigin(String);

impl NormalizedOrigin {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn parse_web(value: &str) -> Result<Self, OriginError> {
        if value.len() > 2_048 {
            return Err(OriginError::TooLong);
        }
        let url = Url::parse(value).map_err(|_| OriginError::Invalid)?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(OriginError::InsecureScheme);
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(OriginError::CredentialsNotAllowed);
        }
        let host = url.host_str().ok_or(OriginError::MissingHost)?;
        let port = url.port_or_known_default().ok_or(OriginError::Invalid)?;
        let scheme = url.scheme();
        let default_port = if scheme == "https" { 443 } else { 80 };
        let normalized = if port == default_port {
            format!("{scheme}://{host}")
        } else {
            format!("{scheme}://{host}:{port}")
        };
        Ok(Self(normalized))
    }

    pub fn from_item_url(value: &str) -> Result<Self, OriginError> {
        Self::parse_web(value)
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum OriginError {
    #[error("origin exceeds the accepted size")]
    TooLong,
    #[error("origin is not a valid absolute URL")]
    Invalid,
    #[error("only HTTP and HTTPS origins are accepted")]
    InsecureScheme,
    #[error("origin does not contain a host")]
    MissingHost,
    #[error("URL credentials are not accepted")]
    CredentialsNotAllowed,
}

#[must_use]
pub fn secure_context(pair_id: &str, sequence: u64, request_id: &str) -> String {
    format!("staraxis-v1|{pair_id}|{sequence}|{request_id}")
}

#[must_use]
pub fn secure_aad(pair_id: &str, sequence: u64, request_id: &str, direction: &str) -> Vec<u8> {
    format!(
        "{}|{direction}",
        secure_context(pair_id, sequence, request_id)
    )
    .into_bytes()
}

#[must_use]
pub fn secure_signature_input(request: &SecureRequest) -> Vec<u8> {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        request.version,
        request.pair_id,
        request.request_id,
        request.sequence,
        request.created_at,
        request.ephemeral_public_key,
        request.nonce,
        request.ciphertext
    )
    .into_bytes()
}

#[must_use]
pub fn secure_response_signature_input(response: &SecureResponse) -> Vec<u8> {
    format!(
        "{}|{}|{}|{}|{}|{}|{}",
        response.version,
        response.pair_id,
        response.request_id,
        response.sequence,
        response.created_at,
        response.nonce,
        response.ciphertext
    )
    .into_bytes()
}

#[must_use]
pub fn pair_challenge_signature_input(response: &PairChallengeResponse) -> Vec<u8> {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        response.version,
        response.pending_id,
        response.desktop_identity_public_key,
        response.desktop_exchange_public_key,
        response.ephemeral_public_key,
        response.server_nonce,
        response.verification_code,
        response.expires_at
    )
    .into_bytes()
}

#[must_use]
pub fn pair_status_signature_input(response: &PairStatusResponse) -> Vec<u8> {
    format!(
        "{}|{}|{}|{}",
        response.version,
        response.pending_id,
        match response.status {
            PairStatus::Pending => "pending",
            PairStatus::Approved => "approved",
            PairStatus::Rejected => "rejected",
            PairStatus::Expired => "expired",
        },
        response.pair_id.as_deref().unwrap_or("")
    )
    .into_bytes()
}

#[must_use]
pub fn pairing_transcript(request: &PairBeginRequest, response: &PairChallengeResponse) -> Vec<u8> {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        request.version,
        request.client_id,
        request.browser.as_str(),
        request.profile_name,
        request.extension_origin,
        request.identity_public_key,
        request.ephemeral_public_key,
        request.client_nonce,
        response.pending_id,
        response.desktop_identity_public_key,
        response.desktop_exchange_public_key,
        response.ephemeral_public_key,
        response.server_nonce
    )
    .into_bytes()
}

#[must_use]
pub fn pairing_verification_code(shared_secret: &[u8], transcript: &[u8]) -> String {
    let digest = Sha256::new()
        .chain_update(b"staraxis-pairing-v1")
        .chain_update(shared_secret)
        .chain_update(transcript)
        .finalize();
    let number = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    format!("{number:06}")
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::{
        NormalizedOrigin, SecureRequest, pairing_verification_code, secure_aad, secure_context,
        secure_signature_input,
    };

    #[derive(Deserialize)]
    struct ProtocolVectors {
        secure_request: SecureRequest,
        secure_context: String,
        secure_aad_request_base64url: String,
        secure_signature_input: String,
        pairing_shared_utf8: String,
        pairing_transcript_utf8: String,
        pairing_verification_code: String,
    }

    #[test]
    fn normalizes_exact_web_origins() {
        assert_eq!(
            NormalizedOrigin::parse_web("https://Example.COM/login?next=1")
                .expect("valid origin")
                .as_str(),
            "https://example.com"
        );
        assert_eq!(
            NormalizedOrigin::parse_web("https://example.com:8443/path")
                .expect("valid origin")
                .as_str(),
            "https://example.com:8443"
        );
        assert_eq!(
            NormalizedOrigin::parse_web("http://Example.COM:80/login")
                .expect("valid HTTP origin")
                .as_str(),
            "http://example.com"
        );
        assert_eq!(
            NormalizedOrigin::parse_web("http://example.com:8080/login")
                .expect("valid HTTP origin")
                .as_str(),
            "http://example.com:8080"
        );
        assert!(NormalizedOrigin::parse_web("ftp://example.com").is_err());
        assert!(NormalizedOrigin::parse_web("https://example.com.evil.test").is_ok());
        assert_ne!(
            NormalizedOrigin::parse_web("https://example.com")
                .expect("valid origin")
                .as_str(),
            NormalizedOrigin::parse_web("https://example.com.evil.test")
                .expect("valid origin")
                .as_str()
        );
        assert_eq!(
            NormalizedOrigin::parse_web("https://bücher.example:443/path")
                .expect("IDNA origin")
                .as_str(),
            "https://xn--bcher-kva.example"
        );
        assert_eq!(
            NormalizedOrigin::parse_web("https://example.com:444/path")
                .expect("non-default port")
                .as_str(),
            "https://example.com:444"
        );
        assert!(NormalizedOrigin::parse_web("https://user@example.com").is_err());
        assert!(NormalizedOrigin::parse_web("https://example.com:443.evil.test").is_err());
    }

    #[test]
    fn pairing_code_is_fixed_width_and_deterministic() {
        let first = pairing_verification_code(b"shared", b"transcript");
        assert_eq!(first.len(), 6);
        assert_eq!(first, pairing_verification_code(b"shared", b"transcript"));
        assert!(first.bytes().all(|byte| byte.is_ascii_digit()));
    }

    #[test]
    fn protocol_v1_vectors_are_stable() {
        let vectors: ProtocolVectors = serde_json::from_str(include_str!(
            "../../../tests/browser-extension/protocol-v1-vectors.json"
        ))
        .expect("protocol vectors");
        let request = &vectors.secure_request;
        assert_eq!(
            secure_context(&request.pair_id, request.sequence, &request.request_id),
            vectors.secure_context
        );
        assert_eq!(
            base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                secure_aad(
                    &request.pair_id,
                    request.sequence,
                    &request.request_id,
                    "request"
                )
            ),
            vectors.secure_aad_request_base64url
        );
        assert_eq!(
            secure_signature_input(request),
            vectors.secure_signature_input.as_bytes()
        );
        assert_eq!(
            pairing_verification_code(
                vectors.pairing_shared_utf8.as_bytes(),
                vectors.pairing_transcript_utf8.as_bytes()
            ),
            vectors.pairing_verification_code
        );
    }

    #[test]
    fn unknown_fields_and_versions_fail_closed() {
        let unknown = r#"{"type":"pair_poll","version":1,"pending_id":"id","extra":true}"#;
        assert!(serde_json::from_str::<super::ClientRequest>(unknown).is_err());
        let unknown_type = r#"{"type":"future_operation","version":1}"#;
        assert!(serde_json::from_str::<super::ClientRequest>(unknown_type).is_err());
    }
}

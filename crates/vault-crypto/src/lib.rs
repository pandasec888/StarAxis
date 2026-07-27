#![doc = "StarAxis cryptographic primitives, domain-separated keys, and secret types."]
#![forbid(unsafe_code)]

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Number of bytes in a Vault Key and every derived symmetric key.
pub const KEY_LEN: usize = 32;
/// Number of bytes in an XChaCha20-Poly1305 nonce.
pub const NONCE_LEN: usize = 24;
/// Number of bytes in an Argon2 salt stored by V1.
pub const SALT_LEN: usize = 16;
/// Size of a wrapped Vault Key including the Poly1305 tag.
pub const WRAPPED_KEY_LEN: usize = KEY_LEN + 16;

const HEADER_INFO: &[u8] = b"vaultx/v1/header-auth";
const PAYLOAD_INFO: &[u8] = b"vaultx/v1/payload";

/// Validated Argon2id parameters stored in the public file header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    pub const MIN_MEMORY_KIB: u32 = 8 * 1024;
    pub const MAX_MEMORY_KIB: u32 = 1024 * 1024;
    pub const MAX_ITERATIONS: u32 = 10;
    pub const MAX_PARALLELISM: u32 = 16;

    /// Recommended baseline for newly created desktop vaults.
    #[must_use]
    pub const fn recommended() -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }

    /// Low-cost parameters reserved for deterministic tests and benchmarks.
    #[must_use]
    pub const fn testing() -> Self {
        Self {
            memory_kib: Self::MIN_MEMORY_KIB,
            iterations: 1,
            parallelism: 1,
        }
    }

    /// Rejects attacker-controlled parameters before any expensive allocation.
    pub fn validate(self) -> Result<(), CryptoError> {
        if !(Self::MIN_MEMORY_KIB..=Self::MAX_MEMORY_KIB).contains(&self.memory_kib)
            || !(1..=Self::MAX_ITERATIONS).contains(&self.iterations)
            || !(1..=Self::MAX_PARALLELISM).contains(&self.parallelism)
        {
            return Err(CryptoError::InvalidKdfParameters);
        }
        Ok(())
    }
}

/// Random 256-bit data-encryption key. Debug output never exposes its value.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultKey([u8; KEY_LEN]);

impl VaultKey {
    /// Generates a key from the operating system CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self(random_array()?))
    }

    /// Imports exact key bytes after a successful authenticated unwrap.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrows key bytes for narrowly scoped cryptographic operations.
    #[must_use]
    pub const fn expose_secret(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Compares two Vault Keys without data-dependent early exit.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl fmt::Debug for VaultKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VaultKey([REDACTED])")
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretKey([u8; KEY_LEN]);

/// Generates an exact-size random byte array using only the OS CSPRNG.
pub fn random_array<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut bytes = [0_u8; N];
    fill_random(&mut bytes)?;
    Ok(bytes)
}

/// Fills a caller-owned buffer from the operating system CSPRNG.
pub fn fill_random(bytes: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(bytes).map_err(|error| CryptoError::Randomness(error.to_string()))
}

/// Derives a KEK and wraps a Vault Key with XChaCha20-Poly1305.
pub fn wrap_vault_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    params: KdfParams,
    vault_key: &VaultKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
) -> Result<[u8; WRAPPED_KEY_LEN], CryptoError> {
    let kek = derive_kek(password, salt, params)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(&kek.0).map_err(|_| CryptoError::InvalidKeyLength)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: vault_key.expose_secret(),
                aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    ciphertext
        .try_into()
        .map_err(|_| CryptoError::InvalidWrappedKeyLength)
}

/// Unwraps and authenticates a Vault Key. Wrong passwords and modified slots are indistinguishable.
pub fn unwrap_vault_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    params: KdfParams,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<VaultKey, CryptoError> {
    if ciphertext.len() != WRAPPED_KEY_LEN {
        return Err(CryptoError::AuthenticationFailed);
    }
    let kek = derive_kek(password, salt, params)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(&kek.0).map_err(|_| CryptoError::InvalidKeyLength)?;
    let mut plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    let key_bytes: [u8; KEY_LEN] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    plaintext.zeroize();
    Ok(VaultKey::from_bytes(key_bytes))
}

/// Returns SHA-256 for pre-KDF accidental-corruption detection.
#[must_use]
pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part);
    }
    digest.finalize().into()
}

/// Computes a domain-separated header authentication tag.
pub fn header_auth_tag(
    vault_key: &VaultKey,
    vault_id: &[u8; 16],
    authenticated_bytes: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let key = derive_subkey(vault_key, vault_id, HEADER_INFO)?;
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&key.0).map_err(|_| CryptoError::InvalidKeyLength)?;
    mac.update(authenticated_bytes);
    Ok(mac.finalize().into_bytes().into())
}

/// Verifies a header authentication tag in constant time.
pub fn verify_header_auth_tag(
    vault_key: &VaultKey,
    vault_id: &[u8; 16],
    authenticated_bytes: &[u8],
    expected_tag: &[u8; 32],
) -> Result<(), CryptoError> {
    let key = derive_subkey(vault_key, vault_id, HEADER_INFO)?;
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&key.0).map_err(|_| CryptoError::InvalidKeyLength)?;
    mac.update(authenticated_bytes);
    mac.verify_slice(expected_tag)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

/// Encrypts the complete canonical snapshot with a domain-separated payload key.
pub fn encrypt_payload(
    vault_key: &VaultKey,
    vault_id: &[u8; 16],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = derive_subkey(vault_key, vault_id, PAYLOAD_INFO)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| CryptoError::InvalidKeyLength)?;
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)
}

/// Authenticates and decrypts a complete snapshot before any business parsing.
pub fn decrypt_payload(
    vault_key: &VaultKey,
    vault_id: &[u8; 16],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = derive_subkey(vault_key, vault_id, PAYLOAD_INFO)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| CryptoError::InvalidKeyLength)?;
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)
}

fn derive_kek(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<SecretKey, CryptoError> {
    params.validate()?;
    if password.is_empty() || password.len() > 1024 * 1024 {
        return Err(CryptoError::InvalidPasswordLength);
    }
    let params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| CryptoError::InvalidKdfParameters)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0_u8; KEY_LEN];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|_| CryptoError::KdfFailed)?;
    Ok(SecretKey(output))
}

fn derive_subkey(
    vault_key: &VaultKey,
    vault_id: &[u8; 16],
    info: &[u8],
) -> Result<SecretKey, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(vault_id), vault_key.expose_secret());
    let mut output = [0_u8; KEY_LEN];
    hkdf.expand(info, &mut output)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(SecretKey(output))
}

/// Errors are deliberately coarse around credentials and authenticated ciphertext.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum CryptoError {
    #[error("invalid KDF parameters")]
    InvalidKdfParameters,
    #[error("password length is outside accepted bounds")]
    InvalidPasswordLength,
    #[error("operating system randomness failed: {0}")]
    Randomness(String),
    #[error("key derivation failed")]
    KeyDerivationFailed,
    #[error("Argon2id failed")]
    KdfFailed,
    #[error("invalid cryptographic key length")]
    InvalidKeyLength,
    #[error("invalid wrapped Vault Key length")]
    InvalidWrappedKeyLength,
    #[error("authentication failed")]
    AuthenticationFailed,
}

#[cfg(test)]
mod tests {
    use super::{
        CryptoError, KdfParams, NONCE_LEN, SALT_LEN, VaultKey, decrypt_payload, encrypt_payload,
        header_auth_tag, random_array, unwrap_vault_key, verify_header_auth_tag, wrap_vault_key,
    };

    #[test]
    fn wraps_and_unwraps_with_bound_aad() {
        let vault_key = VaultKey::from_bytes([7_u8; 32]);
        let salt = [3_u8; SALT_LEN];
        let nonce = [4_u8; NONCE_LEN];
        let params = KdfParams::testing();
        let wrapped = wrap_vault_key(
            b"correct horse battery staple",
            &salt,
            params,
            &vault_key,
            &nonce,
            b"slot-aad",
        )
        .expect("valid key must wrap");
        let unwrapped = unwrap_vault_key(
            b"correct horse battery staple",
            &salt,
            params,
            &nonce,
            &wrapped,
            b"slot-aad",
        )
        .expect("valid credentials must unwrap");
        assert_eq!(unwrapped.expose_secret(), vault_key.expose_secret());
    }

    #[test]
    fn wrong_password_and_modified_aad_fail_identically() {
        let vault_key = VaultKey::from_bytes([7_u8; 32]);
        let salt = [3_u8; SALT_LEN];
        let nonce = [4_u8; NONCE_LEN];
        let params = KdfParams::testing();
        let wrapped = wrap_vault_key(b"correct", &salt, params, &vault_key, &nonce, b"slot-aad")
            .expect("valid key must wrap");

        assert!(matches!(
            unwrap_vault_key(b"incorrect", &salt, params, &nonce, &wrapped, b"slot-aad"),
            Err(CryptoError::AuthenticationFailed)
        ));
        assert!(matches!(
            unwrap_vault_key(b"correct", &salt, params, &nonce, &wrapped, b"other-aad"),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn header_tag_rejects_changes() {
        let vault_key = VaultKey::from_bytes([9_u8; 32]);
        let vault_id = [1_u8; 16];
        let tag = header_auth_tag(&vault_key, &vault_id, b"header").expect("tag must compute");
        assert!(verify_header_auth_tag(&vault_key, &vault_id, b"header", &tag).is_ok());
        assert_eq!(
            verify_header_auth_tag(&vault_key, &vault_id, b"changed", &tag),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn payload_is_bound_to_vault_and_aad() {
        let vault_key = VaultKey::from_bytes([5_u8; 32]);
        let nonce = [6_u8; NONCE_LEN];
        let ciphertext =
            encrypt_payload(&vault_key, &[1_u8; 16], &nonce, b"snapshot", b"payload-aad")
                .expect("payload must encrypt");
        assert_eq!(
            decrypt_payload(&vault_key, &[1_u8; 16], &nonce, &ciphertext, b"payload-aad"),
            Ok(b"snapshot".to_vec())
        );
        assert_eq!(
            decrypt_payload(&vault_key, &[2_u8; 16], &nonce, &ciphertext, b"payload-aad"),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn random_nonces_are_not_reused_in_sample() {
        let first = random_array::<NONCE_LEN>().expect("OS RNG must be available");
        let second = random_array::<NONCE_LEN>().expect("OS RNG must be available");
        assert_ne!(first, second);
    }

    #[test]
    fn rejects_excessive_kdf_before_work() {
        let params = KdfParams {
            memory_kib: KdfParams::MAX_MEMORY_KIB + 1,
            iterations: 1,
            parallelism: 1,
        };
        assert_eq!(params.validate(), Err(CryptoError::InvalidKdfParameters));
    }
}

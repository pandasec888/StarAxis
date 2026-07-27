#![doc = "StarAxis file creation, authenticated opening, safe save, and recovery candidates."]
#![forbid(unsafe_code)]

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use thiserror::Error;
use vault_codec::{
    CIPHER_SUITE_XCHACHA20_POLY1305, COMPRESSION_NONE, FORMAT_MAJOR, FORMAT_MINOR,
    KDF_ARGON2ID_V13, KdfHeader, PASSWORD_SLOT_TYPE, PREAMBLE_LEN, Preamble, PublicHeader,
    WrappingSlot, encode_envelope, header_auth_input, parse_envelope, payload_aad, slot_aad,
};
use vault_crypto::{
    CryptoError, KdfParams, VaultKey, decrypt_payload, encrypt_payload, header_auth_tag,
    random_array, sha256, unwrap_vault_key, verify_header_auth_tag, wrap_vault_key,
};
use vault_domain::{DomainError, Id, VaultSnapshot, decode_snapshot, encode_snapshot};
use vault_platform::{atomic_replace_preserving_old, harden_private_file};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Extension used for a standalone encrypted vault file.
pub const VAULT_EXTENSION: &str = "panda8";
/// Legacy extension accepted for vaults created before the StarAxis rename.
pub const LEGACY_VAULT_EXTENSION: &str = "vaultx";
const MAX_FILE_LEN: u64 = PREAMBLE_LEN as u64
    + vault_codec::MAX_HEADER_LEN as u64
    + vault_codec::HASH_LEN as u64
    + vault_codec::HEADER_TAG_LEN as u64
    + vault_codec::MAX_PAYLOAD_LEN;

/// A fully authenticated in-memory vault plus the exact disk state it was opened from.
pub struct UnlockedVault {
    snapshot: VaultSnapshot,
    vault_key: VaultKey,
    header: PublicHeader,
    fingerprint: [u8; 32],
}

impl Drop for UnlockedVault {
    fn drop(&mut self) {
        self.snapshot.zeroize_secrets();
    }
}

impl UnlockedVault {
    #[must_use]
    pub const fn snapshot(&self) -> &VaultSnapshot {
        &self.snapshot
    }

    #[must_use]
    pub const fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    #[must_use]
    pub const fn header(&self) -> &PublicHeader {
        &self.header
    }

    /// Verifies the current main password by performing a real slot unwrap.
    pub fn verify_password(&self, password: &[u8]) -> Result<bool, VaultFileError> {
        let slot = self
            .header
            .password_slot()
            .ok_or(VaultFileError::AuthenticationFailed)?;
        let aad = slot_aad(&self.header, slot);
        let kdf = KdfParams {
            memory_kib: self.header.kdf.memory_kib,
            iterations: self.header.kdf.iterations,
            parallelism: self.header.kdf.parallelism,
        };
        match unwrap_vault_key(
            password,
            &self.header.kdf.salt,
            kdf,
            &slot.nonce,
            &slot.ciphertext,
            &aad,
        ) {
            Ok(candidate) => Ok(self.vault_key.ct_eq(&candidate)),
            Err(CryptoError::AuthenticationFailed) => Ok(false),
            Err(error) => Err(VaultFileError::Crypto(error)),
        }
    }

    /// Verifies a main password or recovery-key slot without exposing which slot matched.
    pub fn verify_any_secret(&self, secret: &[u8]) -> Result<bool, VaultFileError> {
        for slot in self
            .header
            .slots
            .iter()
            .filter(|slot| slot.slot_type == PASSWORD_SLOT_TYPE)
        {
            let aad = slot_aad(&self.header, slot);
            let kdf = KdfParams {
                memory_kib: self.header.kdf.memory_kib,
                iterations: self.header.kdf.iterations,
                parallelism: self.header.kdf.parallelism,
            };
            match unwrap_vault_key(
                secret,
                &self.header.kdf.salt,
                kdf,
                &slot.nonce,
                &slot.ciphertext,
                &aad,
            ) {
                Ok(candidate) if self.vault_key.ct_eq(&candidate) => return Ok(true),
                Ok(_) | Err(CryptoError::AuthenticationFailed) => {}
                Err(error) => return Err(VaultFileError::Crypto(error)),
            }
        }
        Ok(false)
    }

    /// Produces a new complete authenticated snapshot without mutating session state.
    pub fn prepare_save(&self, snapshot: &VaultSnapshot) -> Result<PreparedSave, VaultFileError> {
        self.prepare_save_with_header(snapshot, self.header.clone())
    }

    fn prepare_save_with_header(
        &self,
        snapshot: &VaultSnapshot,
        mut header: PublicHeader,
    ) -> Result<PreparedSave, VaultFileError> {
        if snapshot.vault_id.as_bytes() != &self.header.vault_id {
            return Err(VaultFileError::VaultIdMismatch);
        }
        let next_generation = self
            .header
            .payload_generation
            .checked_add(1)
            .ok_or(VaultFileError::GenerationOverflow)?;
        header.payload_generation = next_generation;
        header.payload_nonce = random_array()?;
        let snapshot_bytes = encode_snapshot(snapshot)?;
        let aad = payload_aad(&header);
        let ciphertext = encrypt_payload(
            &self.vault_key,
            &header.vault_id,
            &header.payload_nonce,
            &snapshot_bytes,
            &aad,
        )?;
        header.payload_len = ciphertext.len() as u64;
        let bytes = seal_envelope(&header, &self.vault_key, &ciphertext)?;
        let verified = verify_with_key(&bytes, &self.vault_key)?;
        if &verified != snapshot {
            return Err(VaultFileError::RoundTripMismatch);
        }
        Ok(PreparedSave {
            fingerprint: sha256(&[&bytes]),
            header,
            bytes,
            snapshot: snapshot.clone(),
        })
    }

    fn commit(&mut self, prepared: PreparedSave) {
        self.snapshot.zeroize_secrets();
        self.snapshot = prepared.snapshot;
        self.header = prepared.header;
        self.fingerprint = prepared.fingerprint;
    }
}

/// A validated but not yet committed save image.
pub struct PreparedSave {
    bytes: Vec<u8>,
    snapshot: VaultSnapshot,
    header: PublicHeader,
    fingerprint: [u8; 32],
}

/// Newly generated recovery credential with redacted formatting and drop-time zeroization.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveryKey(String);

impl RecoveryKey {
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RecoveryKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryKey([REDACTED])")
    }
}

impl PreparedSave {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Opened vault associated with a local file path.
pub struct VaultFile {
    path: PathBuf,
    unlocked: UnlockedVault,
    lock: VaultLock,
}

struct VaultLock {
    file: File,
}

impl Drop for VaultLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

impl VaultFile {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub const fn unlocked(&self) -> &UnlockedVault {
        &self.unlocked
    }

    /// Copies the currently saved authenticated ciphertext to a new backup path.
    pub fn backup_current_as(&self, destination: impl AsRef<Path>) -> Result<(), VaultFileError> {
        let destination = destination.as_ref();
        if destination.exists() {
            return Err(VaultFileError::AlreadyExists);
        }
        let bytes = read_bounded(&self.path)?;
        if sha256(&[&bytes]) != self.unlocked.fingerprint {
            return Err(VaultFileError::SourceChanged);
        }
        verify_with_key(&bytes, &self.unlocked.vault_key)?;
        let candidate = write_verified_candidate(destination, &bytes, |candidate_bytes| {
            verify_with_key(candidate_bytes, &self.unlocked.vault_key).map(|_| ())
        })?;
        commit_new_candidate(&candidate, destination)
    }

    /// Saves through a verified same-directory temporary file and atomic rename commit point.
    pub fn save(&mut self, snapshot: &VaultSnapshot) -> Result<(), SaveError> {
        let prepared = self.unlocked.prepare_save(snapshot)?;
        self.commit_prepared(prepared)
    }

    /// Adds a high-entropy recovery slot and commits it together with the current snapshot.
    pub fn add_recovery_key(&mut self, snapshot: &VaultSnapshot) -> Result<RecoveryKey, SaveError> {
        if self.unlocked.header.slots.len() >= vault_codec::MAX_SLOTS {
            return Err(VaultFileError::TooManyCredentialSlots.into());
        }
        let recovery_bytes = random_array::<32>()?;
        let recovery_text = recovery_bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let mut header = self.unlocked.header.clone();
        let key_generation = header
            .slots
            .iter()
            .map(|slot| slot.key_generation)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(VaultFileError::GenerationOverflow)?;
        header.slots.push(WrappingSlot {
            id: random_nonzero_id()?,
            slot_type: PASSWORD_SLOT_TYPE,
            key_generation,
            nonce: random_array()?,
            ciphertext: vec![0_u8; vault_crypto::WRAPPED_KEY_LEN],
        });
        let index = header.slots.len() - 1;
        let aad = slot_aad(&header, &header.slots[index]);
        let kdf = KdfParams {
            memory_kib: header.kdf.memory_kib,
            iterations: header.kdf.iterations,
            parallelism: header.kdf.parallelism,
        };
        header.slots[index].ciphertext = wrap_vault_key(
            recovery_text.as_bytes(),
            &header.kdf.salt,
            kdf,
            &self.unlocked.vault_key,
            &header.slots[index].nonce,
            &aad,
        )?
        .to_vec();
        let prepared = self.unlocked.prepare_save_with_header(snapshot, header)?;
        self.commit_prepared(prepared)?;
        Ok(RecoveryKey(recovery_text))
    }

    /// Replaces all credential slots with a new main password and optional stronger KDF.
    pub fn change_main_password(
        &mut self,
        snapshot: &VaultSnapshot,
        current_password: &[u8],
        new_password: &[u8],
        new_kdf: KdfParams,
    ) -> Result<(), SaveError> {
        if !self.unlocked.verify_password(current_password)? {
            return Err(VaultFileError::AuthenticationFailed.into());
        }
        new_kdf.validate()?;
        let mut header = self.unlocked.header.clone();
        header.kdf = KdfHeader {
            algorithm: KDF_ARGON2ID_V13,
            memory_kib: new_kdf.memory_kib,
            iterations: new_kdf.iterations,
            parallelism: new_kdf.parallelism,
            salt: random_array()?,
        };
        let key_generation = header
            .slots
            .first()
            .map(|slot| slot.key_generation)
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(VaultFileError::GenerationOverflow)?;
        header.slots = vec![WrappingSlot {
            id: random_nonzero_id()?,
            slot_type: PASSWORD_SLOT_TYPE,
            key_generation,
            nonce: random_array()?,
            ciphertext: vec![0_u8; vault_crypto::WRAPPED_KEY_LEN],
        }];
        let aad = slot_aad(&header, &header.slots[0]);
        header.slots[0].ciphertext = wrap_vault_key(
            new_password,
            &header.kdf.salt,
            new_kdf,
            &self.unlocked.vault_key,
            &header.slots[0].nonce,
            &aad,
        )?
        .to_vec();
        let prepared = self.unlocked.prepare_save_with_header(snapshot, header)?;
        self.commit_prepared(prepared)
    }

    fn commit_prepared(&mut self, prepared: PreparedSave) -> Result<(), SaveError> {
        let candidate_path = write_verified_candidate(&self.path, &prepared.bytes, |bytes| {
            verify_with_key(bytes, &self.unlocked.vault_key).map(|_| ())
        })?;

        let current = read_bounded(&self.path)?;
        if sha256(&[&current]) != self.unlocked.fingerprint {
            return Err(SaveError::Conflict {
                candidate: candidate_path,
            });
        }

        let rollback = retained_backup_path(&self.path)?;
        if let Err(error) = injected_failure("replace")
            .and_then(|()| atomic_replace_preserving_old(&self.path, &candidate_path, &rollback))
        {
            return Err(SaveError::Commit {
                candidate: candidate_path,
                source: error,
            });
        }

        if sha256(&[&read_bounded(&rollback)?]) != self.unlocked.fingerprint {
            return Err(SaveError::PostCommitConflict { rollback });
        }
        if sha256(&[&read_bounded(&self.path)?]) != prepared.fingerprint {
            return Err(SaveError::PostCommitConflict { rollback });
        }

        if let Err(error) = injected_failure("parent_sync").and_then(|()| sync_parent(&self.path)) {
            return Err(SaveError::ResultUnknown {
                expected_fingerprint: prepared.fingerprint,
                source: error,
            });
        }
        if fs::remove_file(&rollback).is_ok() {
            let _ = sync_parent(&self.path);
        }
        self.unlocked.commit(prepared);
        Ok(())
    }

    /// Saves the current snapshot to a new path and makes that path the active vault.
    pub fn save_as(
        &mut self,
        destination: impl AsRef<Path>,
        snapshot: &VaultSnapshot,
    ) -> Result<(), SaveError> {
        let destination = destination.as_ref();
        if destination.exists() {
            return Err(VaultFileError::AlreadyExists.into());
        }
        let destination_lock = acquire_vault_lock(destination)?;
        let prepared = self.unlocked.prepare_save(snapshot)?;
        let candidate = write_verified_candidate(destination, &prepared.bytes, |bytes| {
            verify_with_key(bytes, &self.unlocked.vault_key).map(|_| ())
        })?;
        commit_new_candidate(&candidate, destination)?;
        self.path = destination.to_path_buf();
        self.lock = destination_lock;
        self.unlocked.commit(prepared);
        Ok(())
    }
}

/// Creates an empty vault with random IDs and returns its authenticated bytes.
pub fn create_empty_vault_bytes(
    password: &[u8],
    now_unix_ms: i64,
    kdf: KdfParams,
) -> Result<Vec<u8>, VaultFileError> {
    let vault_id = Id::from_bytes(random_nonzero_id()?);
    let root_id = Id::from_bytes(random_nonzero_id()?);
    let snapshot = VaultSnapshot::empty(vault_id, root_id, now_unix_ms);
    create_vault_bytes(password, &snapshot, kdf)
}

/// Creates a new authenticated envelope for a supplied valid snapshot.
pub fn create_vault_bytes(
    password: &[u8],
    snapshot: &VaultSnapshot,
    kdf: KdfParams,
) -> Result<Vec<u8>, VaultFileError> {
    snapshot.validate()?;
    kdf.validate()?;
    create_vault_bytes_with_material(
        password,
        snapshot,
        kdf,
        CreationMaterial {
            vault_key: VaultKey::generate()?,
            salt: random_array()?,
            slot_id: random_nonzero_id()?,
            slot_nonce: random_array()?,
            payload_nonce: random_array()?,
        },
    )
}

fn create_vault_bytes_with_material(
    password: &[u8],
    snapshot: &VaultSnapshot,
    kdf: KdfParams,
    material: CreationMaterial,
) -> Result<Vec<u8>, VaultFileError> {
    let mut header = PublicHeader {
        vault_id: *snapshot.vault_id.as_bytes(),
        cipher_suite: CIPHER_SUITE_XCHACHA20_POLY1305,
        kdf: KdfHeader {
            algorithm: KDF_ARGON2ID_V13,
            memory_kib: kdf.memory_kib,
            iterations: kdf.iterations,
            parallelism: kdf.parallelism,
            salt: material.salt,
        },
        slots: vec![WrappingSlot {
            id: material.slot_id,
            slot_type: PASSWORD_SLOT_TYPE,
            key_generation: 1,
            nonce: material.slot_nonce,
            ciphertext: vec![0_u8; vault_crypto::WRAPPED_KEY_LEN],
        }],
        payload_generation: 1,
        payload_nonce: material.payload_nonce,
        payload_len: 16,
        compression: COMPRESSION_NONE,
        feature_flags: 0,
    };

    let slot_aad = slot_aad(&header, &header.slots[0]);
    let wrapped = wrap_vault_key(
        password,
        &header.kdf.salt,
        kdf,
        &material.vault_key,
        &header.slots[0].nonce,
        &slot_aad,
    )?;
    header.slots[0].ciphertext = wrapped.to_vec();

    let snapshot_bytes = encode_snapshot(snapshot)?;
    let aad = payload_aad(&header);
    let ciphertext = encrypt_payload(
        &material.vault_key,
        &header.vault_id,
        &header.payload_nonce,
        &snapshot_bytes,
        &aad,
    )?;
    header.payload_len = ciphertext.len() as u64;
    seal_envelope(&header, &material.vault_key, &ciphertext)
}

struct CreationMaterial {
    vault_key: VaultKey,
    salt: [u8; 16],
    slot_id: [u8; 16],
    slot_nonce: [u8; 24],
    payload_nonce: [u8; 24],
}

/// Opens a vault only after corruption hash, wrapping slot, header tag, and payload AEAD pass.
pub fn open_vault_bytes(password: &[u8], bytes: &[u8]) -> Result<UnlockedVault, VaultFileError> {
    let envelope = parse_and_check_corruption(bytes)?;
    let kdf = KdfParams {
        memory_kib: envelope.header.kdf.memory_kib,
        iterations: envelope.header.kdf.iterations,
        parallelism: envelope.header.kdf.parallelism,
    };
    let vault_key = envelope
        .header
        .slots
        .iter()
        .filter(|slot| slot.slot_type == PASSWORD_SLOT_TYPE)
        .find_map(|slot| {
            let aad = slot_aad(&envelope.header, slot);
            match unwrap_vault_key(
                password,
                &envelope.header.kdf.salt,
                kdf,
                &slot.nonce,
                &slot.ciphertext,
                &aad,
            ) {
                Ok(key) => Some(Ok(key)),
                Err(CryptoError::AuthenticationFailed) => None,
                Err(error) => Some(Err(VaultFileError::Crypto(error))),
            }
        })
        .transpose()?
        .ok_or(VaultFileError::AuthenticationFailed)?;
    let snapshot = verify_envelope_with_key(&envelope, &vault_key)?;
    Ok(UnlockedVault {
        snapshot,
        vault_key,
        header: envelope.header,
        fingerprint: sha256(&[bytes]),
    })
}

/// Creates a new local vault without ever directly writing the destination path.
pub fn create_vault_file(
    path: impl AsRef<Path>,
    password: &[u8],
    now_unix_ms: i64,
    kdf: KdfParams,
) -> Result<VaultFile, VaultFileError> {
    let path = path.as_ref();
    if path.exists() {
        return Err(VaultFileError::AlreadyExists);
    }
    let lock = acquire_vault_lock(path)?;
    let bytes = create_empty_vault_bytes(password, now_unix_ms, kdf)?;
    let candidate = write_verified_candidate(path, &bytes, |candidate_bytes| {
        open_vault_bytes(password, candidate_bytes).map(|_| ())
    })?;
    commit_new_candidate(&candidate, path)?;
    let unlocked = open_vault_bytes(password, &read_bounded(path)?)?;
    Ok(VaultFile {
        path: path.to_path_buf(),
        unlocked,
        lock,
    })
}

/// Reads and unlocks an existing local vault.
pub fn open_vault_file(
    path: impl AsRef<Path>,
    password: &[u8],
) -> Result<VaultFile, VaultFileError> {
    let path = path.as_ref();
    let lock = acquire_vault_lock(path)?;
    let bytes = read_bounded(path)?;
    let unlocked = open_vault_bytes(password, &bytes)?;
    Ok(VaultFile {
        path: path.to_path_buf(),
        unlocked,
        lock,
    })
}

/// Lists same-directory temporary candidates without trusting or opening their contents.
pub fn discover_temporary_candidates(path: impl AsRef<Path>) -> io::Result<Vec<PathBuf>> {
    let path = path.as_ref();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let prefix = format!("{file_name}.");
    let mut candidates = Vec::new();
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with(&prefix) && name.ends_with(".tmp") && entry.file_type()?.is_file() {
            candidates.push(entry.path());
        }
    }
    candidates.sort();
    Ok(candidates)
}

/// Authenticates a candidate independently; callers must still require user confirmation before recovery.
pub fn validate_temporary_candidate(
    path: impl AsRef<Path>,
    password: &[u8],
) -> Result<[u8; 32], VaultFileError> {
    let bytes = read_bounded(path.as_ref())?;
    open_vault_bytes(password, &bytes)?;
    Ok(sha256(&[&bytes]))
}

/// Copies an authenticated candidate into a new destination without replacing any existing file.
pub fn recover_candidate_as(
    candidate: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    password: &[u8],
) -> Result<VaultFile, VaultFileError> {
    let destination = destination.as_ref();
    if destination.exists() {
        return Err(VaultFileError::AlreadyExists);
    }
    let source_bytes = read_bounded(candidate.as_ref())?;
    open_vault_bytes(password, &source_bytes)?;
    let destination_candidate =
        write_verified_candidate(destination, &source_bytes, |candidate_bytes| {
            open_vault_bytes(password, candidate_bytes).map(|_| ())
        })?;
    commit_new_candidate(&destination_candidate, destination)?;
    open_vault_file(destination, password)
}

/// Replaces a vault from an authenticated backup while retaining the previous ciphertext.
pub fn replace_vault_from_backup(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    source_password: &[u8],
    current_password: &[u8],
) -> Result<PathBuf, VaultFileError> {
    let source = source.as_ref();
    let destination = destination.as_ref();
    if source == destination {
        return Err(VaultFileError::InvalidPath);
    }
    let source_bytes = read_bounded(source)?;
    let source_vault = open_vault_bytes(source_password, &source_bytes)?;
    let current_bytes = read_bounded(destination)?;
    let current_vault = open_vault_bytes(current_password, &current_bytes)?;
    if source_vault.snapshot.vault_id != current_vault.snapshot.vault_id {
        return Err(VaultFileError::VaultIdMismatch);
    }

    let rollback = retained_backup_path(destination)?;
    let replacement = write_verified_candidate(destination, &source_bytes, |bytes| {
        open_vault_bytes(source_password, bytes).map(|_| ())
    })?;
    if sha256(&[&read_bounded(destination)?]) != sha256(&[&current_bytes]) {
        let _ = fs::remove_file(&replacement);
        return Err(VaultFileError::SourceChanged);
    }
    if let Err(error) = atomic_replace_preserving_old(destination, &replacement, &rollback) {
        return Err(VaultFileError::ReplaceCommit {
            candidate: replacement,
            rollback,
            source: error,
        });
    }
    sync_parent(destination)?;
    Ok(rollback)
}

/// Resolves a post-commit unknown result by authenticating the target and comparing ciphertext.
pub fn resolve_save_result(
    path: impl AsRef<Path>,
    password: &[u8],
    expected_fingerprint: &[u8; 32],
) -> Result<SaveResolution, VaultFileError> {
    let bytes = read_bounded(path.as_ref())?;
    open_vault_bytes(password, &bytes)?;
    let actual = sha256(&[&bytes]);
    if &actual == expected_fingerprint {
        Ok(SaveResolution::Committed)
    } else {
        Ok(SaveResolution::TargetIsDifferentValidVersion {
            actual_fingerprint: actual,
        })
    }
}

/// Authenticated interpretation of a previous `SaveError::ResultUnknown`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SaveResolution {
    Committed,
    TargetIsDifferentValidVersion { actual_fingerprint: [u8; 32] },
}

fn seal_envelope(
    header: &PublicHeader,
    vault_key: &VaultKey,
    payload: &[u8],
) -> Result<Vec<u8>, VaultFileError> {
    let header_bytes = header.encode()?;
    let preamble = Preamble {
        major: FORMAT_MAJOR,
        minor: FORMAT_MINOR,
        header_len: u32::try_from(header_bytes.len())
            .map_err(|_| VaultFileError::GenerationOverflow)?,
    }
    .encode();
    let corruption_hash = sha256(&[&preamble, &header_bytes]);
    let auth_input = header_auth_input(&preamble, &header_bytes, &corruption_hash);
    let tag = header_auth_tag(vault_key, &header.vault_id, &auth_input)?;
    Ok(encode_envelope(header, &corruption_hash, &tag, payload)?)
}

fn parse_and_check_corruption(
    bytes: &[u8],
) -> Result<vault_codec::ParsedEnvelope<'_>, VaultFileError> {
    let envelope = parse_envelope(bytes)?;
    let actual = sha256(&[envelope.preamble_bytes, envelope.header_bytes]);
    if actual != envelope.corruption_hash {
        return Err(VaultFileError::HeaderCorrupted);
    }
    Ok(envelope)
}

fn verify_with_key(bytes: &[u8], vault_key: &VaultKey) -> Result<VaultSnapshot, VaultFileError> {
    let envelope = parse_and_check_corruption(bytes)?;
    verify_envelope_with_key(&envelope, vault_key)
}

fn verify_envelope_with_key(
    envelope: &vault_codec::ParsedEnvelope<'_>,
    vault_key: &VaultKey,
) -> Result<VaultSnapshot, VaultFileError> {
    let auth_input = header_auth_input(
        envelope.preamble_bytes,
        envelope.header_bytes,
        &envelope.corruption_hash,
    );
    verify_header_auth_tag(
        vault_key,
        &envelope.header.vault_id,
        &auth_input,
        &envelope.header_tag,
    )
    .map_err(map_authentication_error)?;
    let aad = payload_aad(&envelope.header);
    let mut plaintext = decrypt_payload(
        vault_key,
        &envelope.header.vault_id,
        &envelope.header.payload_nonce,
        envelope.payload,
        &aad,
    )
    .map_err(map_authentication_error)?;
    let decoded = decode_snapshot(&plaintext);
    use zeroize::Zeroize;
    plaintext.zeroize();
    let snapshot = decoded?;
    if snapshot.vault_id.as_bytes() != &envelope.header.vault_id {
        return Err(VaultFileError::VaultIdMismatch);
    }
    Ok(snapshot)
}

fn write_verified_candidate<F>(
    target: &Path,
    bytes: &[u8],
    verify: F,
) -> Result<PathBuf, VaultFileError>
where
    F: FnOnce(&[u8]) -> Result<(), VaultFileError>,
{
    validate_parent_directory(target)?;
    let candidate_path = temporary_path(target)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&candidate_path)?;
    if let Err(error) = harden_private_file(&candidate_path) {
        drop(file);
        let _ = fs::remove_file(&candidate_path);
        return Err(error.into());
    }
    if let Err(error) = write_sync_verify(&mut file, bytes, &candidate_path, verify) {
        drop(file);
        let _ = fs::remove_file(&candidate_path);
        return Err(error);
    }
    drop(file);
    Ok(candidate_path)
}

fn commit_new_candidate(candidate: &Path, destination: &Path) -> Result<(), VaultFileError> {
    match fs::hard_link(candidate, destination) {
        Ok(()) => {
            fs::remove_file(candidate)?;
            sync_parent(destination)?;
            Ok(())
        }
        Err(error) => Err(VaultFileError::CreateCommit {
            candidate: candidate.to_path_buf(),
            source: error,
        }),
    }
}

fn write_sync_verify<F>(
    file: &mut File,
    bytes: &[u8],
    candidate_path: &Path,
    verify: F,
) -> Result<(), VaultFileError>
where
    F: FnOnce(&[u8]) -> Result<(), VaultFileError>,
{
    injected_failure("write")?;
    file.write_all(bytes)?;
    file.flush()?;
    injected_failure("fsync")?;
    file.sync_all()?;
    let reread = read_bounded(candidate_path)?;
    verify(&reread)
}

#[cfg(test)]
thread_local! {
    static INJECTED_FAILURE: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn injected_failure(point: &'static str) -> io::Result<()> {
    INJECTED_FAILURE.with(|active| {
        let requested = active.get();
        if requested == Some("disk_full") && point == "write" {
            active.set(None);
            Err(io::Error::from(io::ErrorKind::StorageFull))
        } else if requested == Some(point) {
            active.set(None);
            Err(io::Error::other(format!("injected {point} failure")))
        } else {
            Ok(())
        }
    })
}

#[cfg(not(test))]
fn injected_failure(_point: &'static str) -> io::Result<()> {
    Ok(())
}

fn temporary_path(target: &Path) -> Result<PathBuf, VaultFileError> {
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(VaultFileError::InvalidPath)?;
    for _ in 0..32 {
        let random = random_array::<16>()?;
        let suffix = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let candidate = parent.join(format!("{name}.{suffix}.tmp"));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(VaultFileError::TemporaryNameExhausted)
}

fn retained_backup_path(target: &Path) -> Result<PathBuf, VaultFileError> {
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(VaultFileError::InvalidPath)?;
    for _ in 0..32 {
        let random = random_array::<8>()?;
        let suffix = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let retained = parent.join(format!("{name}.pre-restore-{suffix}.{VAULT_EXTENSION}"));
        if !retained.exists() {
            return Ok(retained);
        }
    }
    Err(VaultFileError::TemporaryNameExhausted)
}

fn acquire_vault_lock(target: &Path) -> Result<VaultLock, VaultFileError> {
    validate_parent_directory(target)?;
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(VaultFileError::InvalidPath)?;
    let path = parent.join(format!(".{name}.lock"));
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(&path)?;
    match file.try_lock() {
        Ok(()) => {
            if let Err(error) = harden_private_file(&path) {
                let _ = file.unlock();
                return Err(error.into());
            }
            Ok(VaultLock { file })
        }
        Err(fs::TryLockError::WouldBlock) => Err(VaultFileError::VaultInUse),
        Err(fs::TryLockError::Error(error)) => Err(VaultFileError::Io(error)),
    }
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, VaultFileError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || is_windows_reparse_point(&metadata)
        || metadata.len() > MAX_FILE_LEN
    {
        return Err(VaultFileError::InvalidFileTypeOrSize);
    }
    Ok(fs::read(path)?)
}

fn validate_parent_directory(path: &Path) -> Result<(), VaultFileError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || is_windows_reparse_point(&metadata)
    {
        return Err(VaultFileError::UnsafeParentDirectory);
    }
    Ok(())
}

#[cfg(windows)]
fn is_windows_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_windows_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn sync_parent(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        File::open(parent)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

fn random_nonzero_id() -> Result<[u8; 16], CryptoError> {
    loop {
        let id = random_array()?;
        if id.iter().any(|byte| *byte != 0) {
            return Ok(id);
        }
    }
}

fn map_authentication_error(error: CryptoError) -> VaultFileError {
    match error {
        CryptoError::AuthenticationFailed => VaultFileError::AuthenticationFailed,
        other => VaultFileError::Crypto(other),
    }
}

#[derive(Debug, Error)]
pub enum VaultFileError {
    #[error("vault codec error: {0}")]
    Codec(#[from] vault_codec::CodecError),
    #[error("vault cryptography error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("vault domain error: {0}")]
    Domain(#[from] DomainError),
    #[error("file operation failed: {0}")]
    Io(#[from] io::Error),
    #[error("header corruption hash does not match")]
    HeaderCorrupted,
    #[error("password or authenticated vault data is invalid")]
    AuthenticationFailed,
    #[error("encrypted payload vault ID does not match the public header")]
    VaultIdMismatch,
    #[error("authenticated save reread does not match the source snapshot")]
    RoundTripMismatch,
    #[error("payload generation overflow")]
    GenerationOverflow,
    #[error("credential slot limit reached")]
    TooManyCredentialSlots,
    #[error("destination already exists")]
    AlreadyExists,
    #[error("path has no valid file name")]
    InvalidPath,
    #[error("could not allocate a unique temporary file name")]
    TemporaryNameExhausted,
    #[error("path is not a regular bounded vault file")]
    InvalidFileTypeOrSize,
    #[error("target parent is not a regular non-link directory")]
    UnsafeParentDirectory,
    #[error("vault is already locked by another process")]
    VaultInUse,
    #[error("source vault changed before the authenticated copy completed")]
    SourceChanged,
    #[error("new-vault commit failed; verified candidate retained at {candidate:?}: {source}")]
    CreateCommit {
        candidate: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "restore commit failed; verified candidate retained at {candidate:?} and rollback at {rollback:?}: {source}"
    )]
    ReplaceCommit {
        candidate: PathBuf,
        rollback: PathBuf,
        #[source]
        source: io::Error,
    },
}

#[derive(Debug, Error)]
pub enum SaveError {
    #[error(transparent)]
    Vault(#[from] VaultFileError),
    #[error("target changed externally; verified local candidate retained at {candidate:?}")]
    Conflict { candidate: PathBuf },
    #[error("commit captured an unexpected external version; retained at {rollback:?}")]
    PostCommitConflict { rollback: PathBuf },
    #[error("atomic commit failed; verified candidate retained at {candidate:?}: {source}")]
    Commit {
        candidate: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("commit may have succeeded but parent-directory synchronization failed: {source}")]
    ResultUnknown {
        expected_fingerprint: [u8; 32],
        #[source]
        source: io::Error,
    },
}

impl From<CryptoError> for SaveError {
    fn from(error: CryptoError) -> Self {
        Self::Vault(VaultFileError::Crypto(error))
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::fs;

    use tempfile::tempdir;
    use vault_crypto::{KdfParams, VaultKey};
    use vault_domain::{Id, LoginPayload, VaultItem, VaultPayload, VaultSnapshot};

    use super::{
        CreationMaterial, INJECTED_FAILURE, LEGACY_VAULT_EXTENSION, SaveError, SaveResolution,
        VAULT_EXTENSION, VaultFileError, create_empty_vault_bytes,
        create_vault_bytes_with_material, create_vault_file, discover_temporary_candidates,
        open_vault_bytes, open_vault_file, recover_candidate_as, replace_vault_from_backup,
        resolve_save_result, validate_temporary_candidate, write_verified_candidate,
    };

    #[test]
    fn empty_v1_matches_golden_vector() {
        let snapshot = VaultSnapshot::empty(
            Id::from_bytes([1_u8; 16]),
            Id::from_bytes([2_u8; 16]),
            1_700_000_000_000,
        );
        let bytes = create_vault_bytes_with_material(
            b"vaultx golden password",
            &snapshot,
            KdfParams::testing(),
            CreationMaterial {
                vault_key: VaultKey::from_bytes([3_u8; 32]),
                salt: [4_u8; 16],
                slot_id: [5_u8; 16],
                slot_nonce: [6_u8; 24],
                payload_nonce: [7_u8; 24],
            },
        )
        .expect("golden vector must encode");
        let expected = include_str!("../../../tests/golden/vaultx-v1-empty.hex").trim();
        assert_eq!(to_hex(&bytes), expected);
        let opened = open_vault_bytes(b"vaultx golden password", &bytes)
            .expect("golden vector must remain readable");
        assert_eq!(opened.snapshot(), &snapshot);
    }

    fn to_hex(bytes: &[u8]) -> String {
        let mut hex = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut hex, "{byte:02x}").expect("writing to String cannot fail");
        }
        hex
    }

    #[test]
    fn create_close_unlock_round_trip() {
        let bytes =
            create_empty_vault_bytes(b"test password", 1_700_000_000_000, KdfParams::testing())
                .expect("vault creation must succeed");
        let opened = open_vault_bytes(b"test password", &bytes).expect("vault must unlock");
        assert_eq!(opened.snapshot().items.len(), 0);
        assert!(open_vault_bytes(b"wrong password", &bytes).is_err());
    }

    #[test]
    fn panda8_is_primary_while_legacy_vaultx_remains_readable() {
        assert_eq!(VAULT_EXTENSION, "panda8");
        assert_eq!(LEGACY_VAULT_EXTENSION, "vaultx");

        let directory = tempdir().expect("temporary directory must exist");
        let primary = directory.path().join("primary.panda8");
        let legacy = directory.path().join("legacy.vaultx");
        let file = create_vault_file(&primary, b"test password", 0, KdfParams::testing())
            .expect("panda8 vault must be created");
        drop(file);
        fs::copy(&primary, &legacy).expect("legacy compatibility copy must succeed");

        let reopened = open_vault_file(&legacy, b"test password")
            .expect("unchanged encrypted bytes must open through the legacy suffix");
        assert!(reopened.unlocked().snapshot().items.is_empty());
    }

    #[test]
    fn authenticated_backup_restores_as_new_file() {
        let directory = tempdir().expect("temporary directory must exist");
        let primary = directory.path().join("primary.vaultx");
        let backup = directory.path().join("manual-backup.vaultx");
        let restored = directory.path().join("restored.vaultx");
        let file = create_vault_file(&primary, b"test password", 0, KdfParams::testing())
            .expect("vault must be created");
        file.backup_current_as(&backup)
            .expect("authenticated backup must be created");
        recover_candidate_as(&backup, &restored, b"test password")
            .expect("backup must restore as a new file");
        let reopened =
            open_vault_file(&restored, b"test password").expect("restored vault must authenticate");
        assert_eq!(reopened.unlocked().snapshot(), file.unlocked().snapshot());
    }

    #[test]
    fn recovery_slot_and_main_password_rotation_are_authenticated() {
        let directory = tempdir().expect("temporary directory must exist");
        let path = directory.path().join("credentials.vaultx");
        let mut file = create_vault_file(&path, b"old password", 0, KdfParams::testing())
            .expect("vault must be created");
        let snapshot = file.unlocked().snapshot().clone();
        let recovery = file
            .add_recovery_key(&snapshot)
            .expect("recovery slot must save");
        let recovery_text = recovery.expose_secret().to_owned();
        drop(recovery);
        drop(file);
        let recovered = open_vault_file(&path, recovery_text.as_bytes())
            .expect("recovery key must unlock the vault");
        drop(recovered);
        let mut file = open_vault_file(&path, b"old password")
            .expect("old password must still unlock before rotation");
        file.change_main_password(
            &snapshot,
            b"old password",
            b"new password",
            KdfParams::testing(),
        )
        .expect("main password must rotate");
        drop(file);
        assert!(open_vault_file(&path, b"old password").is_err());
        assert!(open_vault_file(&path, recovery_text.as_bytes()).is_err());
        open_vault_file(&path, b"new password").expect("new password must unlock");
    }

    #[test]
    fn confirmed_backup_replacement_retains_authenticated_rollback() {
        let directory = tempdir().expect("temporary directory must exist");
        let primary = directory.path().join("replace.panda8");
        let backup = directory.path().join("older.panda8");
        let mut file = create_vault_file(&primary, b"test password", 0, KdfParams::testing())
            .expect("vault must be created");
        file.backup_current_as(&backup)
            .expect("old version must backup");
        let mut changed = file.unlocked().snapshot().clone();
        changed.settings.auto_lock_seconds = 999;
        file.save(&changed).expect("changed version must save");
        drop(file);

        let rollback =
            replace_vault_from_backup(&backup, &primary, b"test password", b"test password")
                .expect("confirmed replacement must succeed");
        assert_eq!(
            rollback
                .extension()
                .and_then(|extension| extension.to_str()),
            Some(VAULT_EXTENSION)
        );
        assert_eq!(
            open_vault_file(&primary, b"test password")
                .expect("restored target must authenticate")
                .unlocked()
                .snapshot()
                .settings
                .auto_lock_seconds,
            300
        );
        assert_eq!(
            open_vault_file(&rollback, b"test password")
                .expect("rollback must authenticate")
                .unlocked()
                .snapshot()
                .settings
                .auto_lock_seconds,
            999
        );
    }

    #[test]
    fn second_process_style_open_is_rejected_until_lock_releases() {
        let directory = tempdir().expect("temporary directory must exist");
        let path = directory.path().join("locked.vaultx");
        let first = create_vault_file(&path, b"test password", 0, KdfParams::testing())
            .expect("first session must create the vault");
        assert!(matches!(
            open_vault_file(&path, b"test password"),
            Err(VaultFileError::VaultInUse)
        ));
        drop(first);
        open_vault_file(&path, b"test password")
            .expect("a new session must open after advisory lock release");
    }

    #[cfg(unix)]
    #[test]
    fn vault_and_advisory_lock_are_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempdir().expect("temporary directory must exist");
        let path = directory.path().join("permissions.vaultx");
        let file = create_vault_file(&path, b"test password", 0, KdfParams::testing())
            .expect("vault must be created");
        assert_eq!(
            fs::metadata(&path)
                .expect("vault metadata exists")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let lock_path = directory.path().join(".permissions.vaultx.lock");
        assert_eq!(
            fs::metadata(lock_path)
                .expect("lock metadata exists")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        drop(file);
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_link_vault_and_parent_are_rejected() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().expect("temporary directory must exist");
        let real = directory.path().join("real.vaultx");
        let file = create_vault_file(&real, b"test password", 0, KdfParams::testing())
            .expect("real vault must be created");
        drop(file);
        let link = directory.path().join("link.vaultx");
        symlink(&real, &link).expect("file symlink must be created");
        assert!(matches!(
            open_vault_file(&link, b"test password"),
            Err(VaultFileError::InvalidFileTypeOrSize)
        ));

        let real_parent = directory.path().join("real-parent");
        fs::create_dir(&real_parent).expect("real parent must exist");
        let linked_parent = directory.path().join("linked-parent");
        symlink(&real_parent, &linked_parent).expect("directory symlink must be created");
        assert!(matches!(
            create_vault_file(
                linked_parent.join("new.vaultx"),
                b"test password",
                0,
                KdfParams::testing()
            ),
            Err(VaultFileError::UnsafeParentDirectory)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_reparse_point_vault_and_parent_are_rejected() {
        use std::os::windows::fs::{symlink_dir, symlink_file};

        let directory = tempdir().expect("temporary directory must exist");
        let real = directory.path().join("real.vaultx");
        let file = create_vault_file(&real, b"test password", 0, KdfParams::testing())
            .expect("real vault must be created");
        drop(file);
        let link = directory.path().join("link.vaultx");
        symlink_file(&real, &link).expect("test runner must permit file symlinks");
        assert!(matches!(
            open_vault_file(&link, b"test password"),
            Err(VaultFileError::InvalidFileTypeOrSize)
        ));

        let real_parent = directory.path().join("real-parent");
        fs::create_dir(&real_parent).expect("real parent must exist");
        let linked_parent = directory.path().join("linked-parent");
        symlink_dir(&real_parent, &linked_parent).expect("test runner must permit directory links");
        assert!(matches!(
            create_vault_file(
                linked_parent.join("new.vaultx"),
                b"test password",
                0,
                KdfParams::testing()
            ),
            Err(VaultFileError::UnsafeParentDirectory)
        ));
    }

    #[test]
    fn injected_write_fsync_replace_and_post_commit_failures_preserve_old_or_new() {
        for point in ["disk_full", "write", "fsync"] {
            let directory = tempdir().expect("temporary directory must exist");
            let path = directory.path().join(format!("{point}.vaultx"));
            let mut file = create_vault_file(&path, b"test password", 0, KdfParams::testing())
                .expect("vault must be created");
            let mut changed = file.unlocked().snapshot().clone();
            changed.settings.auto_lock_seconds = 111;
            inject(point);
            assert!(file.save(&changed).is_err());
            let old = open_vault_bytes(
                b"test password",
                &fs::read(&path).expect("old target must remain"),
            )
            .expect("old target must authenticate");
            assert_eq!(old.snapshot().settings.auto_lock_seconds, 300);
            assert!(
                discover_temporary_candidates(&path)
                    .expect("candidate scan must work")
                    .is_empty()
            );
        }

        let directory = tempdir().expect("temporary directory must exist");
        let path = directory.path().join("replace-failure.vaultx");
        let mut file = create_vault_file(&path, b"test password", 0, KdfParams::testing())
            .expect("vault must be created");
        let mut changed = file.unlocked().snapshot().clone();
        changed.settings.auto_lock_seconds = 222;
        inject("replace");
        let candidate = match file.save(&changed) {
            Err(SaveError::Commit { candidate, .. }) => candidate,
            other => panic!("expected retained commit candidate, got {other:?}"),
        };
        validate_temporary_candidate(&candidate, b"test password")
            .expect("failed replacement candidate must authenticate");
        assert_eq!(
            open_vault_bytes(
                b"test password",
                &fs::read(&path).expect("old target remains")
            )
            .expect("old target authenticates")
            .snapshot()
            .settings
            .auto_lock_seconds,
            300
        );
        fs::remove_file(candidate).expect("test candidate must clean");
        drop(file);

        let path = directory.path().join("post-commit.vaultx");
        let mut file = create_vault_file(&path, b"test password", 0, KdfParams::testing())
            .expect("vault must be created");
        let mut changed = file.unlocked().snapshot().clone();
        changed.settings.auto_lock_seconds = 333;
        inject("parent_sync");
        assert!(matches!(
            file.save(&changed),
            Err(SaveError::ResultUnknown { .. })
        ));
        drop(file);
        assert_eq!(
            open_vault_file(&path, b"test password")
                .expect("new committed target must authenticate")
                .unlocked()
                .snapshot()
                .settings
                .auto_lock_seconds,
            333
        );
        assert!(
            fs::read_dir(directory.path())
                .expect("directory must list")
                .filter_map(Result::ok)
                .any(|entry| entry.file_name().to_string_lossy().contains("pre-restore"))
        );
    }

    #[test]
    fn abnormal_exit_before_commit_leaves_old_target_and_recoverable_candidate() {
        let directory = tempdir().expect("temporary directory must exist");
        let path = directory.path().join("interrupted.vaultx");
        let file = create_vault_file(&path, b"test password", 0, KdfParams::testing())
            .expect("vault must be created");
        let old_bytes = fs::read(&path).expect("old target must exist");
        let mut changed = file.unlocked().snapshot().clone();
        changed.settings.auto_lock_seconds = 444;
        let prepared = file
            .unlocked()
            .prepare_save(&changed)
            .expect("new snapshot must prepare");

        // This is the durable state an abrupt process exit leaves after candidate fsync and
        // before the atomic replace commit point.
        let candidate = write_verified_candidate(&path, prepared.bytes(), |bytes| {
            open_vault_bytes(b"test password", bytes).map(|_| ())
        })
        .expect("verified candidate must be durable");
        drop(file);

        assert_eq!(fs::read(&path).expect("target remains readable"), old_bytes);
        assert_eq!(
            discover_temporary_candidates(&path).expect("candidate discovery must work"),
            vec![candidate.clone()]
        );
        validate_temporary_candidate(&candidate, b"test password")
            .expect("candidate authenticates");
        assert_eq!(
            open_vault_bytes(
                b"test password",
                &fs::read(candidate).expect("candidate remains readable")
            )
            .expect("candidate opens")
            .snapshot()
            .settings
            .auto_lock_seconds,
            444
        );
    }

    fn inject(point: &'static str) {
        INJECTED_FAILURE.with(|active| active.set(Some(point)));
    }

    #[test]
    fn save_reopen_and_read_item() {
        let directory = tempdir().expect("temporary directory must exist");
        let path = directory.path().join("primary.vaultx");
        let mut file = create_vault_file(
            &path,
            b"test password",
            1_700_000_000_000,
            KdfParams::testing(),
        )
        .expect("vault file must be created");
        let mut snapshot = file.unlocked().snapshot().clone();
        snapshot.items.push(VaultItem {
            id: vault_domain::Id::from_bytes([8_u8; 16]),
            group_id: snapshot.root_group,
            title: "Example".to_owned(),
            favorite: false,
            tags: vec!["test".to_owned()],
            created_at_unix_ms: 1_700_000_000_001,
            updated_at_unix_ms: 1_700_000_000_001,
            revision: 1,
            history: Vec::new(),
            payload: VaultPayload::Login(LoginPayload {
                usernames: vec!["alice".to_owned()],
                password: "secret".to_owned(),
                urls: vec!["https://example.test".to_owned()],
                notes: String::new(),
                custom_fields: Vec::new(),
                url_match_modes: None,
            }),
            deleted_at_unix_ms: None,
        });
        snapshot.revision += 1;
        file.save(&snapshot).expect("safe save must succeed");
        drop(file);

        let reopened = open_vault_file(&path, b"test password").expect("saved vault must reopen");
        assert_eq!(reopened.unlocked().snapshot().items[0].title, "Example");
    }

    #[test]
    fn external_change_retains_valid_candidate() {
        let directory = tempdir().expect("temporary directory must exist");
        let path = directory.path().join("primary.vaultx");
        let mut file = create_vault_file(
            &path,
            b"test password",
            1_700_000_000_000,
            KdfParams::testing(),
        )
        .expect("vault file must be created");
        let snapshot = file.unlocked().snapshot().clone();
        let external =
            create_empty_vault_bytes(b"other password", 1_700_000_000_001, KdfParams::testing())
                .expect("external vault must encode");
        fs::write(&path, external).expect("external replacement must succeed");

        let candidate = match file.save(&snapshot) {
            Err(SaveError::Conflict { candidate }) => candidate,
            other => panic!("expected conflict, got {other:?}"),
        };
        assert!(candidate.exists());
        assert!(validate_temporary_candidate(&candidate, b"test password").is_ok());
        assert_eq!(
            discover_temporary_candidates(&path).expect("candidate discovery must work"),
            vec![candidate.clone()]
        );
        let recovered_path = directory.path().join("recovered.vaultx");
        let recovered = recover_candidate_as(&candidate, &recovered_path, b"test password")
            .expect("authenticated candidate must recover as a new file");
        assert_eq!(recovered.unlocked().snapshot(), &snapshot);
        assert!(candidate.exists());
    }

    #[test]
    fn tampering_and_trailing_data_fail() {
        let mut bytes = create_empty_vault_bytes(b"test password", 0, KdfParams::testing())
            .expect("vault creation must succeed");
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(open_vault_bytes(b"test password", &bytes).is_err());
        bytes.push(0);
        assert!(open_vault_bytes(b"test password", &bytes).is_err());
    }

    #[test]
    fn header_hmac_rejects_rehashed_public_header_tampering() {
        let bytes = create_empty_vault_bytes(b"test password", 0, KdfParams::testing())
            .expect("vault creation must succeed");
        let envelope = vault_codec::parse_envelope(&bytes).expect("created vault must parse");
        let mut header = envelope.header.clone();
        header.payload_generation += 1;
        let header_bytes = header
            .encode()
            .expect("mutated header remains structurally valid");
        let preamble = vault_codec::Preamble {
            major: vault_codec::FORMAT_MAJOR,
            minor: vault_codec::FORMAT_MINOR,
            header_len: u32::try_from(header_bytes.len()).expect("header length fits u32"),
        }
        .encode();
        let corruption_hash = vault_crypto::sha256(&[&preamble, &header_bytes]);
        let tampered = vault_codec::encode_envelope(
            &header,
            &corruption_hash,
            &envelope.header_tag,
            envelope.payload,
        )
        .expect("tampered envelope remains structurally valid");
        assert!(matches!(
            open_vault_bytes(b"test password", &tampered),
            Err(super::VaultFileError::AuthenticationFailed)
        ));
    }

    #[test]
    fn payload_cannot_be_replaced_across_vaults() {
        let first = create_empty_vault_bytes(b"same password", 0, KdfParams::testing())
            .expect("first vault creation must succeed");
        let second = create_empty_vault_bytes(b"same password", 0, KdfParams::testing())
            .expect("second vault creation must succeed");
        let first_envelope = vault_codec::parse_envelope(&first).expect("first vault must parse");
        let second_envelope =
            vault_codec::parse_envelope(&second).expect("second vault must parse");
        assert_eq!(first_envelope.payload.len(), second_envelope.payload.len());
        let replaced = vault_codec::encode_envelope(
            &first_envelope.header,
            &first_envelope.corruption_hash,
            &first_envelope.header_tag,
            second_envelope.payload,
        )
        .expect("replacement envelope must encode");
        assert!(matches!(
            open_vault_bytes(b"same password", &replaced),
            Err(super::VaultFileError::AuthenticationFailed)
        ));
    }

    #[test]
    fn each_prepared_save_uses_new_generation_and_nonce() {
        let bytes = create_empty_vault_bytes(b"test password", 0, KdfParams::testing())
            .expect("vault creation must succeed");
        let opened = open_vault_bytes(b"test password", &bytes).expect("vault must open");
        let first = opened
            .prepare_save(opened.snapshot())
            .expect("first save must prepare");
        let second = opened
            .prepare_save(opened.snapshot())
            .expect("second save must prepare");
        assert_eq!(
            first.header.payload_generation,
            opened.header().payload_generation + 1
        );
        assert_eq!(
            first.header.payload_generation,
            second.header.payload_generation
        );
        assert_ne!(first.header.payload_nonce, second.header.payload_nonce);
        assert_ne!(first.bytes, second.bytes);
        let directory = tempdir().expect("temporary directory must exist");
        let path = directory.path().join("result.vaultx");
        fs::write(&path, &first.bytes).expect("prepared file must be written");
        assert_eq!(
            resolve_save_result(&path, b"test password", &first.fingerprint)
                .expect("valid target must resolve"),
            SaveResolution::Committed
        );
        assert!(matches!(
            resolve_save_result(&path, b"test password", &second.fingerprint),
            Ok(SaveResolution::TargetIsDifferentValidVersion { .. })
        ));
    }
}

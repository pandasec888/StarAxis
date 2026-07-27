#![doc = "StarAxis domain objects, canonical snapshot encoding, and invariants."]
#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::fmt;

use minicbor::{Decode, Decoder, Encode, Encoder};
use thiserror::Error;
use zeroize::Zeroize;

/// On-disk business schema version implemented by this workspace.
pub const VAULT_SCHEMA_VERSION: u16 = 1;
/// Maximum accepted encoded snapshot size before decoding.
pub const MAX_SNAPSHOT_BYTES: usize = 128 * 1024 * 1024;
/// Maximum number of groups in a vault.
pub const MAX_GROUPS: usize = 10_000;
/// Maximum number of live items in a vault.
pub const MAX_ITEMS: usize = 100_000;
/// Maximum number of tombstones in a vault.
pub const MAX_TOMBSTONES: usize = 1_000_000;
/// Maximum UTF-8 byte length of any individual string.
pub const MAX_STRING_BYTES: usize = 1024 * 1024;
/// Maximum total history records across the vault.
pub const MAX_HISTORY_RECORDS: usize = 1_000_000;

/// Stable 128-bit identifier encoded as a CBOR byte string.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Id([u8; 16]);

impl Id {
    /// Creates an identifier from its exact bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the exact identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Returns true when every identifier byte is zero.
    #[must_use]
    pub fn is_nil(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl<C> Encode<C> for Id {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.bytes(&self.0)?;
        Ok(())
    }
}

impl<'bytes, C> Decode<'bytes, C> for Id {
    fn decode(
        decoder: &mut Decoder<'bytes>,
        _context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let bytes = decoder.bytes()?;
        let exact: [u8; 16] = bytes
            .try_into()
            .map_err(|_| minicbor::decode::Error::message("identifier must be 16 bytes"))?;
        Ok(Self(exact))
    }
}

/// Complete decrypted vault snapshot.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[cbor(map)]
pub struct VaultSnapshot {
    #[n(0)]
    pub vault_id: Id,
    #[n(1)]
    pub schema_version: u16,
    #[n(2)]
    pub root_group: Id,
    #[n(3)]
    pub groups: Vec<VaultGroup>,
    #[n(4)]
    pub items: Vec<VaultItem>,
    #[n(5)]
    pub tombstones: Vec<Tombstone>,
    #[n(6)]
    pub settings: VaultSettings,
    #[n(7)]
    pub revision: u64,
}

impl VaultSnapshot {
    /// Constructs an empty vault with one root group.
    #[must_use]
    pub fn empty(vault_id: Id, root_group: Id, now_unix_ms: i64) -> Self {
        Self {
            vault_id,
            schema_version: VAULT_SCHEMA_VERSION,
            root_group,
            groups: vec![VaultGroup {
                id: root_group,
                parent_id: None,
                name: "Root".to_owned(),
                created_at_unix_ms: now_unix_ms,
                updated_at_unix_ms: now_unix_ms,
            }],
            items: Vec::new(),
            tombstones: Vec::new(),
            settings: VaultSettings::default(),
            revision: 1,
        }
    }

    /// Checks resource bounds, identity uniqueness, references, and group cycles.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.schema_version != VAULT_SCHEMA_VERSION {
            return Err(DomainError::UnsupportedSchema(self.schema_version));
        }
        if self.vault_id.is_nil() || self.root_group.is_nil() {
            return Err(DomainError::NilIdentifier);
        }
        if self.revision == 0 {
            return Err(DomainError::InvalidRevision);
        }
        check_count("groups", self.groups.len(), MAX_GROUPS)?;
        check_count("items", self.items.len(), MAX_ITEMS)?;
        check_count("tombstones", self.tombstones.len(), MAX_TOMBSTONES)?;

        let mut group_ids = HashSet::with_capacity(self.groups.len());
        for group in &self.groups {
            check_string(&group.name)?;
            if group.id.is_nil() || !group_ids.insert(group.id) {
                return Err(DomainError::DuplicateOrNilId("group"));
            }
        }

        let root = self
            .groups
            .iter()
            .find(|group| group.id == self.root_group)
            .ok_or(DomainError::MissingRootGroup)?;
        if root.parent_id.is_some() {
            return Err(DomainError::RootHasParent);
        }

        for group in &self.groups {
            if let Some(parent) = group.parent_id {
                if !group_ids.contains(&parent) {
                    return Err(DomainError::MissingGroupReference);
                }
                ensure_no_group_cycle(group.id, &self.groups)?;
            }
        }

        let mut item_ids = HashSet::with_capacity(self.items.len());
        let mut history_count = 0usize;
        for item in &self.items {
            if item.id.is_nil() || !item_ids.insert(item.id) {
                return Err(DomainError::DuplicateOrNilId("item"));
            }
            if !group_ids.contains(&item.group_id) {
                return Err(DomainError::MissingGroupReference);
            }
            check_string(&item.title)?;
            for tag in &item.tags {
                check_string(tag)?;
            }
            check_payload(&item.payload)?;
            history_count = history_count
                .checked_add(item.history.len())
                .ok_or(DomainError::ResourceLimit("history"))?;
            for history in &item.history {
                check_string(&history.title)?;
                check_payload(&history.payload)?;
            }
        }
        check_count("history", history_count, MAX_HISTORY_RECORDS)?;

        let mut tombstone_ids = HashSet::with_capacity(self.tombstones.len());
        for tombstone in &self.tombstones {
            if tombstone.id.is_nil()
                || item_ids.contains(&tombstone.id)
                || !tombstone_ids.insert(tombstone.id)
            {
                return Err(DomainError::DuplicateOrNilId("tombstone"));
            }
        }
        Ok(())
    }

    /// Best-effort zeroization of all secret and business strings before the snapshot is dropped.
    pub fn zeroize_secrets(&mut self) {
        for group in &mut self.groups {
            group.name.zeroize();
        }
        for item in &mut self.items {
            item.title.zeroize();
            for tag in &mut item.tags {
                tag.zeroize();
            }
            zeroize_payload(&mut item.payload);
            for history in &mut item.history {
                history.title.zeroize();
                zeroize_payload(&mut history.payload);
            }
        }
    }
}

/// A group in the encrypted group tree.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[cbor(map)]
pub struct VaultGroup {
    #[n(0)]
    pub id: Id,
    #[n(1)]
    pub parent_id: Option<Id>,
    #[n(2)]
    pub name: String,
    #[n(3)]
    pub created_at_unix_ms: i64,
    #[n(4)]
    pub updated_at_unix_ms: i64,
}

/// A live vault item.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[cbor(map)]
pub struct VaultItem {
    #[n(0)]
    pub id: Id,
    #[n(1)]
    pub group_id: Id,
    #[n(2)]
    pub title: String,
    #[n(3)]
    pub favorite: bool,
    #[n(4)]
    pub tags: Vec<String>,
    #[n(5)]
    pub created_at_unix_ms: i64,
    #[n(6)]
    pub updated_at_unix_ms: i64,
    #[n(7)]
    pub revision: u64,
    #[n(8)]
    pub history: Vec<ItemHistory>,
    #[n(9)]
    pub payload: VaultPayload,
    #[n(10)]
    pub deleted_at_unix_ms: Option<i64>,
}

/// Historical item state retained before an edit.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[cbor(map)]
pub struct ItemHistory {
    #[n(0)]
    pub revision: u64,
    #[n(1)]
    pub title: String,
    #[n(2)]
    pub updated_at_unix_ms: i64,
    #[n(3)]
    pub payload: VaultPayload,
}

/// Supported encrypted item payloads.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub enum VaultPayload {
    #[n(0)]
    Login(#[n(0)] LoginPayload),
    #[n(1)]
    SecureNote(#[n(0)] SecureNotePayload),
}

/// Login-specific secret fields.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[cbor(map)]
pub struct LoginPayload {
    #[n(0)]
    pub usernames: Vec<String>,
    #[n(1)]
    pub password: String,
    #[n(2)]
    pub urls: Vec<String>,
    #[n(3)]
    pub notes: String,
    #[n(4)]
    pub custom_fields: Vec<CustomField>,
    /// Optional per-URL browser fill policy. Missing on legacy V1 snapshots.
    #[n(5)]
    pub url_match_modes: Option<Vec<UrlMatchMode>>,
}

/// Determines where a login URL may be suggested by browser integrations.
#[derive(Clone, Copy, Debug, Decode, Encode, Eq, PartialEq)]
#[cbor(index_only)]
pub enum UrlMatchMode {
    /// Match the registrable website and its subdomains.
    #[n(0)]
    AnywhereOnWebsite,
    /// Match only the exact host and effective port.
    #[n(1)]
    ExactHost,
    /// Never make this URL available to browser integrations.
    #[n(2)]
    Never,
}

impl LoginPayload {
    /// Returns the explicit policy, or the legacy-safe exact-host default.
    #[must_use]
    pub fn url_match_mode(&self, index: usize) -> UrlMatchMode {
        self.url_match_modes
            .as_ref()
            .and_then(|modes| modes.get(index))
            .copied()
            .unwrap_or(UrlMatchMode::ExactHost)
    }
}

/// Secure-note fields.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[cbor(map)]
pub struct SecureNotePayload {
    #[n(0)]
    pub content: String,
    #[n(1)]
    pub custom_fields: Vec<CustomField>,
}

/// User-defined field.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[cbor(map)]
pub struct CustomField {
    #[n(0)]
    pub name: String,
    #[n(1)]
    pub value: String,
    #[n(2)]
    pub sensitivity: FieldSensitivity,
}

/// Display policy for a custom field.
#[derive(Clone, Copy, Debug, Decode, Encode, Eq, PartialEq)]
#[cbor(index_only)]
pub enum FieldSensitivity {
    #[n(0)]
    Concealed,
    #[n(1)]
    Visible,
}

/// Deletion marker retained for future conflict handling.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[cbor(map)]
pub struct Tombstone {
    #[n(0)]
    pub id: Id,
    #[n(1)]
    pub deleted_at_unix_ms: i64,
    #[n(2)]
    pub revision: u64,
}

/// Settings stored inside the encrypted snapshot.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[cbor(map)]
pub struct VaultSettings {
    #[n(0)]
    pub auto_lock_seconds: u32,
    #[n(1)]
    pub clipboard_clear_seconds: u32,
    #[n(2)]
    pub lock_on_minimize: bool,
    #[n(3)]
    pub backup_versions: u16,
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self {
            auto_lock_seconds: 300,
            clipboard_clear_seconds: 30,
            lock_on_minimize: false,
            backup_versions: 3,
        }
    }
}

/// Encodes and validates a snapshot using the deterministic CBOR schema.
pub fn encode_snapshot(snapshot: &VaultSnapshot) -> Result<Vec<u8>, DomainError> {
    snapshot.validate()?;
    let bytes =
        minicbor::to_vec(snapshot).map_err(|error| DomainError::Encode(error.to_string()))?;
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(DomainError::ResourceLimit("snapshot bytes"));
    }
    Ok(bytes)
}

/// Decodes a bounded CBOR snapshot and validates all invariants.
pub fn decode_snapshot(bytes: &[u8]) -> Result<VaultSnapshot, DomainError> {
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(DomainError::ResourceLimit("snapshot bytes"));
    }
    let mut decoder = Decoder::new(bytes);
    let snapshot: VaultSnapshot = decoder
        .decode()
        .map_err(|error| DomainError::Decode(error.to_string()))?;
    if decoder.position() != bytes.len() {
        return Err(DomainError::Decode("trailing CBOR data".to_owned()));
    }
    snapshot.validate()?;
    Ok(snapshot)
}

/// Domain validation and codec errors.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum DomainError {
    #[error("unsupported vault schema version {0}")]
    UnsupportedSchema(u16),
    #[error("identifier must not be nil")]
    NilIdentifier,
    #[error("duplicate or nil {0} identifier")]
    DuplicateOrNilId(&'static str),
    #[error("root group is missing")]
    MissingRootGroup,
    #[error("root group cannot have a parent")]
    RootHasParent,
    #[error("referenced group does not exist")]
    MissingGroupReference,
    #[error("group hierarchy contains a cycle")]
    GroupCycle,
    #[error("revision must be greater than zero")]
    InvalidRevision,
    #[error("login URL match policies must align with login URLs")]
    InvalidUrlMatchModes,
    #[error("resource limit exceeded for {0}")]
    ResourceLimit(&'static str),
    #[error("snapshot encoding failed: {0}")]
    Encode(String),
    #[error("snapshot decoding failed: {0}")]
    Decode(String),
}

fn check_count(name: &'static str, actual: usize, maximum: usize) -> Result<(), DomainError> {
    if actual > maximum {
        return Err(DomainError::ResourceLimit(name));
    }
    Ok(())
}

fn check_string(value: &str) -> Result<(), DomainError> {
    check_count("string bytes", value.len(), MAX_STRING_BYTES)
}

fn check_custom_fields(fields: &[CustomField]) -> Result<(), DomainError> {
    for field in fields {
        check_string(&field.name)?;
        check_string(&field.value)?;
    }
    Ok(())
}

fn check_payload(payload: &VaultPayload) -> Result<(), DomainError> {
    match payload {
        VaultPayload::Login(login) => {
            for username in &login.usernames {
                check_string(username)?;
            }
            check_string(&login.password)?;
            for url in &login.urls {
                check_string(url)?;
            }
            if login
                .url_match_modes
                .as_ref()
                .is_some_and(|modes| modes.len() != login.urls.len())
            {
                return Err(DomainError::InvalidUrlMatchModes);
            }
            check_string(&login.notes)?;
            check_custom_fields(&login.custom_fields)
        }
        VaultPayload::SecureNote(note) => {
            check_string(&note.content)?;
            check_custom_fields(&note.custom_fields)
        }
    }
}

fn zeroize_payload(payload: &mut VaultPayload) {
    match payload {
        VaultPayload::Login(login) => {
            for username in &mut login.usernames {
                username.zeroize();
            }
            login.password.zeroize();
            for url in &mut login.urls {
                url.zeroize();
            }
            login.notes.zeroize();
            for field in &mut login.custom_fields {
                field.name.zeroize();
                field.value.zeroize();
            }
        }
        VaultPayload::SecureNote(note) => {
            note.content.zeroize();
            for field in &mut note.custom_fields {
                field.name.zeroize();
                field.value.zeroize();
            }
        }
    }
}

fn ensure_no_group_cycle(start: Id, groups: &[VaultGroup]) -> Result<(), DomainError> {
    let mut current = Some(start);
    let mut visited = HashSet::new();
    while let Some(id) = current {
        if !visited.insert(id) {
            return Err(DomainError::GroupCycle);
        }
        current = groups
            .iter()
            .find(|group| group.id == id)
            .and_then(|group| group.parent_id);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        DomainError, Id, LoginPayload, UrlMatchMode, VaultItem, VaultPayload, VaultSnapshot,
        decode_snapshot, encode_snapshot,
    };

    fn id(last: u8) -> Id {
        let mut bytes = [0_u8; 16];
        bytes[15] = last;
        Id::from_bytes(bytes)
    }

    #[test]
    fn snapshot_round_trip_is_deterministic() {
        let mut snapshot = VaultSnapshot::empty(id(1), id(2), 1_700_000_000_000);
        assert_eq!(snapshot.settings.backup_versions, 3);
        snapshot.items.push(VaultItem {
            id: id(3),
            group_id: id(2),
            title: "Example".to_owned(),
            favorite: true,
            tags: vec!["work".to_owned()],
            created_at_unix_ms: 1_700_000_000_001,
            updated_at_unix_ms: 1_700_000_000_001,
            revision: 1,
            history: Vec::new(),
            payload: VaultPayload::Login(LoginPayload {
                usernames: vec!["alice".to_owned()],
                password: "correct horse battery staple".to_owned(),
                urls: vec!["https://example.test".to_owned()],
                notes: String::new(),
                custom_fields: Vec::new(),
                url_match_modes: Some(vec![UrlMatchMode::AnywhereOnWebsite]),
            }),
            deleted_at_unix_ms: None,
        });

        let first = encode_snapshot(&snapshot).expect("valid snapshot must encode");
        let second = encode_snapshot(&snapshot).expect("same snapshot must encode");
        assert_eq!(first, second);
        assert_eq!(decode_snapshot(&first), Ok(snapshot));
    }

    #[test]
    fn legacy_login_without_url_modes_decodes_as_exact_host() {
        let mut bytes = Vec::new();
        let mut encoder = minicbor::Encoder::new(&mut bytes);
        encoder.map(5).expect("legacy login map");
        encoder.u8(0).expect("usernames key");
        encoder.array(0).expect("empty usernames");
        encoder.u8(1).expect("password key");
        encoder.str("").expect("empty password");
        encoder.u8(2).expect("urls key");
        encoder.array(1).expect("one URL");
        encoder
            .str("https://login.example.test")
            .expect("legacy URL");
        encoder.u8(3).expect("notes key");
        encoder.str("").expect("empty notes");
        encoder.u8(4).expect("custom fields key");
        encoder.array(0).expect("empty custom fields");

        let legacy: LoginPayload = minicbor::decode(&bytes).expect("legacy login must decode");
        assert_eq!(legacy.url_match_modes, None);
        assert_eq!(legacy.url_match_mode(0), UrlMatchMode::ExactHost);
    }

    #[test]
    fn rejects_group_cycles() {
        let mut snapshot = VaultSnapshot::empty(id(1), id(2), 0);
        snapshot.groups[0].parent_id = Some(id(2));
        assert_eq!(snapshot.validate(), Err(DomainError::RootHasParent));
    }

    #[test]
    fn rejects_trailing_cbor_data() {
        let snapshot = VaultSnapshot::empty(id(1), id(2), 0);
        let mut bytes = encode_snapshot(&snapshot).expect("valid snapshot must encode");
        bytes.push(0);
        assert!(decode_snapshot(&bytes).is_err());
    }
}

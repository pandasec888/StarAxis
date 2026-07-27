use std::collections::{HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;
use vault_crypto::{CryptoError, KdfParams, random_array};
use vault_domain::{
    CustomField, DomainError, Id, ItemHistory, LoginPayload, SecureNotePayload, Tombstone,
    UrlMatchMode, VaultGroup, VaultItem, VaultPayload, VaultSettings, VaultSnapshot,
};
use vault_file::{
    RecoveryKey, SaveError, VaultFile, VaultFileError, create_vault_file, open_vault_file,
    replace_vault_from_backup,
};
use vault_import::ImportedLogin;
use zeroize::Zeroize;

const MAX_PAGE_SIZE: usize = 200;
const REAUTH_WINDOW_MS: i64 = 60_000;
const REAUTH_MAX_FAILURES: usize = 5;
const REAUTH_COOLDOWN_MS: i64 = 30_000;
const REAUTH_TOKEN_MS: i64 = 60_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionState {
    Locked,
    Unlocked,
    Dirty,
    Saving,
    ConflictPending,
    SaveResultUnknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItemKind {
    Login,
    SecureNote,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItemSort {
    TitleAscending,
    TitleDescending,
    UpdatedNewest,
    UpdatedOldest,
    CreatedNewest,
    CreatedOldest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct ItemFilter {
    pub group_id: Option<Id>,
    pub kind: Option<ItemKind>,
    pub favorite_only: bool,
    pub include_deleted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemSummary {
    pub id: Id,
    pub kind: ItemKind,
    pub title: String,
    pub favorite: bool,
    pub tags: Vec<String>,
    pub primary_username: Option<String>,
    pub primary_url: Option<String>,
    pub deleted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoginInput {
    pub group_id: Id,
    pub title: String,
    pub favorite: bool,
    pub tags: Vec<String>,
    pub usernames: Vec<String>,
    pub password: String,
    pub urls: Vec<String>,
    pub url_match_modes: Vec<UrlMatchMode>,
    pub notes: String,
    pub custom_fields: Vec<CustomField>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecureNoteInput {
    pub group_id: Id,
    pub title: String,
    pub favorite: bool,
    pub tags: Vec<String>,
    pub content: String,
    pub custom_fields: Vec<CustomField>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewGroup {
    pub parent_id: Id,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupSummary {
    pub id: Id,
    pub parent_id: Option<Id>,
    pub name: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppSettings {
    pub auto_lock_seconds: u32,
    pub clipboard_clear_seconds: u32,
    pub lock_on_minimize: bool,
    pub backup_versions: u16,
}

impl From<&VaultSettings> for AppSettings {
    fn from(value: &VaultSettings) -> Self {
        Self {
            auto_lock_seconds: value.auto_lock_seconds,
            clipboard_clear_seconds: value.clipboard_clear_seconds,
            lock_on_minimize: value.lock_on_minimize,
            backup_versions: value.backup_versions,
        }
    }
}

/// Single-vault application service. Dropping the active file drops and zeroizes its Vault Key.
pub struct VaultService {
    state: SessionState,
    active_path: Option<PathBuf>,
    file: Option<VaultFile>,
    working: Option<VaultSnapshot>,
    search: SearchIndex,
    reauth: ReauthPolicy,
    last_activity_unix_ms: Option<i64>,
}

impl Default for VaultService {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultService {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: SessionState::Locked,
            active_path: None,
            file: None,
            working: None,
            search: SearchIndex::default(),
            reauth: ReauthPolicy::default(),
            last_activity_unix_ms: None,
        }
    }

    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    #[must_use]
    pub fn active_path(&self) -> Option<&Path> {
        self.active_path.as_deref()
    }

    pub fn create(
        &mut self,
        path: impl AsRef<Path>,
        password: &[u8],
        now_unix_ms: i64,
        kdf: KdfParams,
    ) -> Result<(), ServiceError> {
        self.lock();
        let file = create_vault_file(path.as_ref(), password, now_unix_ms, kdf)?;
        self.activate(file);
        Ok(())
    }

    pub fn unlock(&mut self, path: impl AsRef<Path>, password: &[u8]) -> Result<(), ServiceError> {
        self.lock();
        let file = open_vault_file(path.as_ref(), password)?;
        self.activate(file);
        Ok(())
    }

    pub fn lock(&mut self) {
        if let Some(snapshot) = self.working.as_mut() {
            snapshot.zeroize_secrets();
        }
        self.working = None;
        self.file = None;
        self.search.clear();
        self.reauth.clear();
        self.last_activity_unix_ms = None;
        self.state = SessionState::Locked;
    }

    pub fn record_activity(&mut self, now_unix_ms: i64) {
        if self.state != SessionState::Locked {
            self.last_activity_unix_ms = Some(now_unix_ms);
        }
    }

    pub fn lock_if_idle(&mut self, now_unix_ms: i64) -> bool {
        let Some(snapshot) = self.working.as_ref() else {
            return false;
        };
        let timeout_ms = i64::from(snapshot.settings.auto_lock_seconds).saturating_mul(1_000);
        let expired = timeout_ms > 0
            && self
                .last_activity_unix_ms
                .is_some_and(|last| now_unix_ms.saturating_sub(last) >= timeout_ms);
        if !expired {
            return false;
        }

        // Never discard a submitted mutation merely because the idle timer fired.
        // A dirty snapshot gets one final persistence attempt; conflict/unknown
        // states remain available for explicit recovery instead of being dropped.
        if self.state == SessionState::Dirty && self.save().is_err() {
            return false;
        }
        if !matches!(self.state, SessionState::Unlocked) {
            return false;
        }
        self.lock();
        true
    }

    /// Applies one logical user mutation and persists the resulting encrypted
    /// snapshot before reporting success to the caller.
    pub fn apply_and_save<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, ServiceError>,
    ) -> Result<T, ServiceError> {
        let output = operation(self)?;
        let backup_limit = self
            .working
            .as_ref()
            .ok_or(ServiceError::Locked)?
            .settings
            .backup_versions;
        if backup_limit > 0 {
            let backup = self.automatic_backup_path()?;
            self.backup_current_as(&backup)?;
        }
        self.save()?;
        // Failure to prune does not invalidate an already committed vault.
        // Extra authenticated backups are safer than reporting the mutation as
        // failed and inviting a duplicate retry.
        let _ = self.prune_automatic_backups(usize::from(backup_limit));
        Ok(output)
    }

    fn automatic_backup_path(&self) -> Result<PathBuf, ServiceError> {
        let active = self.active_path.as_ref().ok_or(ServiceError::Locked)?;
        let revision = self
            .file
            .as_ref()
            .ok_or(ServiceError::Locked)?
            .unlocked()
            .snapshot()
            .revision;
        let file_name = active.file_name().ok_or(VaultFileError::InvalidPath)?;
        for sequence in 0_u16..=u16::MAX {
            let mut backup_name = file_name.to_os_string();
            backup_name.push(format!(".backup-{revision:020}-{sequence:05}"));
            let candidate = active.with_file_name(backup_name);
            if !candidate.exists() {
                return Ok(candidate);
            }
        }
        Err(VaultFileError::AlreadyExists.into())
    }

    fn prune_automatic_backups(&self, limit: usize) -> Result<(), std::io::Error> {
        let Some(active) = self.active_path.as_ref() else {
            return Ok(());
        };
        let Some(parent) = active.parent() else {
            return Ok(());
        };
        let Some(file_name) = active.file_name() else {
            return Ok(());
        };
        let prefix = format!("{}.backup-", file_name.to_string_lossy());
        let mut backups = fs::read_dir(parent)?
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
            .filter_map(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                let suffix = name.strip_prefix(&prefix)?;
                let (revision, sequence) = suffix.split_once('-')?;
                if revision.len() == 20
                    && sequence.len() == 5
                    && revision.bytes().all(|byte| byte.is_ascii_digit())
                    && sequence.bytes().all(|byte| byte.is_ascii_digit())
                {
                    Some(entry.path())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        backups.sort();
        let remove_count = backups.len().saturating_sub(limit);
        for backup in backups.into_iter().take(remove_count) {
            fs::remove_file(backup)?;
        }
        Ok(())
    }

    pub fn create_group(&mut self, input: NewGroup, now_unix_ms: i64) -> Result<Id, ServiceError> {
        let id = random_id()?;
        self.mutate(|snapshot| {
            if !snapshot
                .groups
                .iter()
                .any(|group| group.id == input.parent_id)
            {
                return Err(ServiceError::GroupNotFound);
            }
            snapshot.groups.push(VaultGroup {
                id,
                parent_id: Some(input.parent_id),
                name: input.name,
                created_at_unix_ms: now_unix_ms,
                updated_at_unix_ms: now_unix_ms,
            });
            Ok(id)
        })
    }

    pub fn groups(&self) -> Result<Vec<GroupSummary>, ServiceError> {
        Ok(self
            .snapshot()?
            .groups
            .iter()
            .map(|group| GroupSummary {
                id: group.id,
                parent_id: group.parent_id,
                name: group.name.clone(),
            })
            .collect())
    }

    pub fn settings(&self) -> Result<AppSettings, ServiceError> {
        Ok(AppSettings::from(&self.snapshot()?.settings))
    }

    pub fn update_settings(&mut self, settings: AppSettings) -> Result<(), ServiceError> {
        if settings.auto_lock_seconds > 86_400
            || (settings.clipboard_clear_seconds != 0
                && !(5..=300).contains(&settings.clipboard_clear_seconds))
            || settings.backup_versions > 100
        {
            return Err(ServiceError::InvalidSettings);
        }
        self.mutate(|snapshot| {
            snapshot.settings = VaultSettings {
                auto_lock_seconds: settings.auto_lock_seconds,
                clipboard_clear_seconds: settings.clipboard_clear_seconds,
                lock_on_minimize: settings.lock_on_minimize,
                backup_versions: settings.backup_versions,
            };
            Ok(())
        })
    }

    pub fn rename_group(
        &mut self,
        id: Id,
        name: String,
        now_unix_ms: i64,
    ) -> Result<(), ServiceError> {
        self.mutate(|snapshot| {
            let group = snapshot
                .groups
                .iter_mut()
                .find(|group| group.id == id)
                .ok_or(ServiceError::GroupNotFound)?;
            group.name = name;
            group.updated_at_unix_ms = now_unix_ms;
            Ok(())
        })
    }

    pub fn delete_group(&mut self, id: Id) -> Result<(), ServiceError> {
        self.mutate(|snapshot| {
            if id == snapshot.root_group {
                let replacement = snapshot
                    .groups
                    .iter()
                    .find(|group| group.parent_id == Some(id))
                    .map(|group| group.id)
                    .ok_or(ServiceError::CannotDeleteLastGroup)?;
                for group in &mut snapshot.groups {
                    if group.id == replacement {
                        group.parent_id = None;
                    } else if group.parent_id == Some(id) {
                        group.parent_id = Some(replacement);
                    }
                }
                for item in &mut snapshot.items {
                    if item.group_id == id {
                        item.group_id = replacement;
                    }
                }
                snapshot.root_group = replacement;
                snapshot.groups.retain(|group| group.id != id);
                return Ok(());
            }
            if snapshot
                .groups
                .iter()
                .any(|group| group.parent_id == Some(id))
                || snapshot.items.iter().any(|item| item.group_id == id)
            {
                return Err(ServiceError::GroupNotEmpty);
            }
            let position = snapshot
                .groups
                .iter()
                .position(|group| group.id == id)
                .ok_or(ServiceError::GroupNotFound)?;
            snapshot.groups.remove(position);
            Ok(())
        })
    }

    pub fn create_login(
        &mut self,
        input: LoginInput,
        now_unix_ms: i64,
    ) -> Result<Id, ServiceError> {
        self.create_item(
            input.group_id,
            input.title,
            input.favorite,
            input.tags,
            VaultPayload::Login(LoginPayload {
                usernames: input.usernames,
                password: input.password,
                urls: input.urls,
                notes: input.notes,
                custom_fields: input.custom_fields,
                url_match_modes: Some(input.url_match_modes),
            }),
            now_unix_ms,
        )
    }

    pub fn create_secure_note(
        &mut self,
        input: SecureNoteInput,
        now_unix_ms: i64,
    ) -> Result<Id, ServiceError> {
        self.create_item(
            input.group_id,
            input.title,
            input.favorite,
            input.tags,
            VaultPayload::SecureNote(SecureNotePayload {
                content: input.content,
                custom_fields: input.custom_fields,
            }),
            now_unix_ms,
        )
    }

    pub fn import_logins(
        &mut self,
        group_id: Id,
        records: Vec<ImportedLogin>,
        now_unix_ms: i64,
    ) -> Result<Vec<Id>, ServiceError> {
        let ids = (0..records.len())
            .map(|_| random_id())
            .collect::<Result<Vec<_>, _>>()?;
        let result_ids = ids.clone();
        self.mutate(|snapshot| {
            if !snapshot.groups.iter().any(|group| group.id == group_id) {
                return Err(ServiceError::GroupNotFound);
            }
            snapshot.items.extend(
                records
                    .into_iter()
                    .zip(ids)
                    .map(|(mut record, id)| VaultItem {
                        id,
                        group_id,
                        title: std::mem::take(&mut record.title),
                        favorite: false,
                        tags: std::mem::take(&mut record.tags),
                        created_at_unix_ms: now_unix_ms,
                        updated_at_unix_ms: now_unix_ms,
                        revision: 1,
                        history: Vec::new(),
                        payload: VaultPayload::Login(LoginPayload {
                            usernames: std::mem::take(&mut record.usernames),
                            password: std::mem::take(&mut record.password),
                            urls: std::mem::take(&mut record.urls),
                            notes: std::mem::take(&mut record.notes),
                            custom_fields: Vec::new(),
                            url_match_modes: None,
                        }),
                        deleted_at_unix_ms: None,
                    }),
            );
            Ok(())
        })?;
        Ok(result_ids)
    }

    pub fn update_login(
        &mut self,
        id: Id,
        input: LoginInput,
        now_unix_ms: i64,
    ) -> Result<(), ServiceError> {
        self.update_item(
            id,
            input.group_id,
            input.title,
            input.favorite,
            input.tags,
            VaultPayload::Login(LoginPayload {
                usernames: input.usernames,
                password: input.password,
                urls: input.urls,
                notes: input.notes,
                custom_fields: input.custom_fields,
                url_match_modes: Some(input.url_match_modes),
            }),
            now_unix_ms,
        )
    }

    pub fn update_secure_note(
        &mut self,
        id: Id,
        input: SecureNoteInput,
        now_unix_ms: i64,
    ) -> Result<(), ServiceError> {
        self.update_item(
            id,
            input.group_id,
            input.title,
            input.favorite,
            input.tags,
            VaultPayload::SecureNote(SecureNotePayload {
                content: input.content,
                custom_fields: input.custom_fields,
            }),
            now_unix_ms,
        )
    }

    pub fn soft_delete(&mut self, id: Id, now_unix_ms: i64) -> Result<(), ServiceError> {
        self.mutate(|snapshot| {
            let item = snapshot
                .items
                .iter_mut()
                .find(|item| item.id == id)
                .ok_or(ServiceError::ItemNotFound)?;
            item.deleted_at_unix_ms = Some(now_unix_ms);
            item.updated_at_unix_ms = now_unix_ms;
            item.revision = item
                .revision
                .checked_add(1)
                .ok_or(ServiceError::RevisionOverflow)?;
            Ok(())
        })
    }

    pub fn restore(&mut self, id: Id, now_unix_ms: i64) -> Result<(), ServiceError> {
        self.mutate(|snapshot| {
            let item = snapshot
                .items
                .iter_mut()
                .find(|item| item.id == id)
                .ok_or(ServiceError::ItemNotFound)?;
            item.deleted_at_unix_ms = None;
            item.updated_at_unix_ms = now_unix_ms;
            item.revision = item
                .revision
                .checked_add(1)
                .ok_or(ServiceError::RevisionOverflow)?;
            Ok(())
        })
    }

    pub fn permanently_delete(&mut self, id: Id, now_unix_ms: i64) -> Result<(), ServiceError> {
        self.mutate(|snapshot| {
            let position = snapshot
                .items
                .iter()
                .position(|item| item.id == id && item.deleted_at_unix_ms.is_some())
                .ok_or(ServiceError::ItemNotFound)?;
            let removed = snapshot.items.remove(position);
            snapshot.tombstones.push(Tombstone {
                id: removed.id,
                deleted_at_unix_ms: now_unix_ms,
                revision: removed
                    .revision
                    .checked_add(1)
                    .ok_or(ServiceError::RevisionOverflow)?,
            });
            Ok(())
        })
    }

    pub fn restore_history(
        &mut self,
        id: Id,
        history_index: usize,
        now_unix_ms: i64,
    ) -> Result<(), ServiceError> {
        self.mutate(|snapshot| {
            let item = snapshot
                .items
                .iter_mut()
                .find(|item| item.id == id)
                .ok_or(ServiceError::ItemNotFound)?;
            let historical = item
                .history
                .get(history_index)
                .cloned()
                .ok_or(ServiceError::HistoryNotFound)?;
            push_history(item);
            item.title = historical.title;
            item.payload = historical.payload;
            item.updated_at_unix_ms = now_unix_ms;
            item.revision = item
                .revision
                .checked_add(1)
                .ok_or(ServiceError::RevisionOverflow)?;
            Ok(())
        })
    }

    pub fn list_items(
        &self,
        query: &str,
        include_deleted: bool,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<ItemSummary>, ServiceError> {
        self.query_items(
            query,
            ItemFilter {
                include_deleted,
                ..ItemFilter::default()
            },
            ItemSort::TitleAscending,
            offset,
            limit,
        )
    }

    pub fn query_items(
        &self,
        query: &str,
        filter: ItemFilter,
        sort: ItemSort,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<ItemSummary>, ServiceError> {
        if limit == 0 || limit > MAX_PAGE_SIZE || query.len() > 1024 {
            return Err(ServiceError::InvalidPage);
        }
        let snapshot = self.snapshot()?;
        let match_set = self.search.find(query).into_iter().collect::<HashSet<_>>();
        let mut items = snapshot
            .items
            .iter()
            .filter(|item| filter.include_deleted || item.deleted_at_unix_ms.is_none())
            .filter(|item| filter.group_id.is_none_or(|group| item.group_id == group))
            .filter(|item| !filter.favorite_only || item.favorite)
            .filter(|item| {
                filter.kind.is_none_or(|kind| {
                    matches!(
                        (&item.payload, kind),
                        (VaultPayload::Login(_), ItemKind::Login)
                            | (VaultPayload::SecureNote(_), ItemKind::SecureNote)
                    )
                })
            })
            .filter(|item| query.is_empty() || match_set.contains(&item.id))
            .collect::<Vec<_>>();
        items.sort_by(|left, right| match sort {
            ItemSort::TitleAscending => title_key(left).cmp(&title_key(right)),
            ItemSort::TitleDescending => title_key(right).cmp(&title_key(left)),
            ItemSort::UpdatedNewest => right
                .updated_at_unix_ms
                .cmp(&left.updated_at_unix_ms)
                .then_with(|| left.id.cmp(&right.id)),
            ItemSort::UpdatedOldest => left
                .updated_at_unix_ms
                .cmp(&right.updated_at_unix_ms)
                .then_with(|| left.id.cmp(&right.id)),
            ItemSort::CreatedNewest => right
                .created_at_unix_ms
                .cmp(&left.created_at_unix_ms)
                .then_with(|| left.id.cmp(&right.id)),
            ItemSort::CreatedOldest => left
                .created_at_unix_ms
                .cmp(&right.created_at_unix_ms)
                .then_with(|| left.id.cmp(&right.id)),
        });
        Ok(items
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(ItemSummary::from)
            .collect())
    }

    pub fn item(&self, id: Id) -> Result<&VaultItem, ServiceError> {
        self.snapshot()?
            .items
            .iter()
            .find(|item| item.id == id)
            .ok_or(ServiceError::ItemNotFound)
    }

    pub fn save(&mut self) -> Result<(), ServiceError> {
        if self.state != SessionState::Dirty {
            return Err(ServiceError::InvalidState);
        }
        self.state = SessionState::Saving;
        let snapshot = self.working.as_ref().ok_or(ServiceError::InvalidState)?;
        let file = self.file.as_mut().ok_or(ServiceError::InvalidState)?;
        match file.save(snapshot) {
            Ok(()) => {
                self.state = SessionState::Unlocked;
                Ok(())
            }
            Err(SaveError::Conflict { candidate }) => {
                self.state = SessionState::ConflictPending;
                Err(ServiceError::Conflict { candidate })
            }
            Err(SaveError::PostCommitConflict { rollback }) => {
                self.state = SessionState::ConflictPending;
                Err(ServiceError::Conflict {
                    candidate: rollback,
                })
            }
            Err(SaveError::ResultUnknown {
                expected_fingerprint,
                source,
            }) => {
                self.state = SessionState::SaveResultUnknown;
                Err(ServiceError::SaveResultUnknown {
                    expected_fingerprint,
                    source,
                })
            }
            Err(error) => {
                self.state = SessionState::Dirty;
                Err(ServiceError::Save(error))
            }
        }
    }

    pub fn save_as(&mut self, destination: impl AsRef<Path>) -> Result<(), ServiceError> {
        if !matches!(self.state, SessionState::Dirty | SessionState::Unlocked) {
            return Err(ServiceError::InvalidState);
        }
        let previous_state = self.state;
        self.state = SessionState::Saving;
        let snapshot = self.working.as_ref().ok_or(ServiceError::InvalidState)?;
        let file = self.file.as_mut().ok_or(ServiceError::InvalidState)?;
        match file.save_as(destination.as_ref(), snapshot) {
            Ok(()) => {
                self.active_path = Some(destination.as_ref().to_path_buf());
                self.state = SessionState::Unlocked;
                Ok(())
            }
            Err(error) => {
                self.state = previous_state;
                Err(ServiceError::Save(error))
            }
        }
    }

    pub fn backup_current_as(&self, destination: impl AsRef<Path>) -> Result<(), ServiceError> {
        if !matches!(self.state, SessionState::Unlocked | SessionState::Dirty) {
            return Err(ServiceError::InvalidState);
        }
        self.file
            .as_ref()
            .ok_or(ServiceError::Locked)?
            .backup_current_as(destination)
            .map_err(ServiceError::File)
    }

    pub fn replace_from_backup(
        &mut self,
        source: impl AsRef<Path>,
        source_password: &[u8],
        current_password: &[u8],
    ) -> Result<PathBuf, ServiceError> {
        if self.state != SessionState::Unlocked {
            return Err(ServiceError::InvalidState);
        }
        let destination = self.active_path.clone().ok_or(ServiceError::Locked)?;
        let rollback =
            replace_vault_from_backup(source, &destination, source_password, current_password)?;
        self.lock();
        Ok(rollback)
    }

    pub fn save_with_backup(
        &mut self,
        backup_destination: impl AsRef<Path>,
    ) -> Result<(), ServiceError> {
        if self.state != SessionState::Dirty {
            return Err(ServiceError::InvalidState);
        }
        let backup_destination = backup_destination.as_ref();
        if backup_destination.exists() {
            return Err(VaultFileError::AlreadyExists.into());
        }
        self.save()?;
        self.backup_current_as(backup_destination)
    }

    pub fn generate_recovery_key(
        &mut self,
        current_password: &[u8],
        now_unix_ms: i64,
    ) -> Result<RecoveryKey, ServiceError> {
        self.reauthenticate(current_password, now_unix_ms)?;
        if !matches!(self.state, SessionState::Unlocked | SessionState::Dirty) {
            return Err(ServiceError::InvalidState);
        }
        let previous_state = self.state;
        self.state = SessionState::Saving;
        let snapshot = self.working.as_ref().ok_or(ServiceError::Locked)?;
        let file = self.file.as_mut().ok_or(ServiceError::Locked)?;
        match file.add_recovery_key(snapshot) {
            Ok(key) => {
                self.state = SessionState::Unlocked;
                Ok(key)
            }
            Err(error) => {
                self.state = previous_state;
                Err(ServiceError::Save(error))
            }
        }
    }

    pub fn confirm_recovery_key(&self, recovery_key: &[u8]) -> Result<bool, ServiceError> {
        self.file
            .as_ref()
            .ok_or(ServiceError::Locked)?
            .unlocked()
            .verify_any_secret(recovery_key)
            .map_err(ServiceError::File)
    }

    pub fn change_main_password(
        &mut self,
        current_password: &[u8],
        new_password: &[u8],
        new_kdf: KdfParams,
    ) -> Result<(), ServiceError> {
        if !matches!(self.state, SessionState::Unlocked | SessionState::Dirty) {
            return Err(ServiceError::InvalidState);
        }
        let previous_state = self.state;
        self.state = SessionState::Saving;
        let snapshot = self.working.as_ref().ok_or(ServiceError::Locked)?;
        let file = self.file.as_mut().ok_or(ServiceError::Locked)?;
        match file.change_main_password(snapshot, current_password, new_password, new_kdf) {
            Ok(()) => {
                self.reauth.clear();
                self.state = SessionState::Unlocked;
                Ok(())
            }
            Err(error) => {
                self.state = previous_state;
                Err(ServiceError::Save(error))
            }
        }
    }

    pub fn reauthenticate(
        &mut self,
        password: &[u8],
        now_unix_ms: i64,
    ) -> Result<(), ServiceError> {
        self.reauth.check_allowed(now_unix_ms)?;
        let file = self.file.as_ref().ok_or(ServiceError::Locked)?;
        if file.unlocked().verify_password(password)? {
            self.reauth.success(now_unix_ms);
            Ok(())
        } else {
            self.reauth.failure(now_unix_ms);
            Err(ServiceError::ReauthenticationFailed)
        }
    }

    pub fn require_recent_reauthentication(&self, now_unix_ms: i64) -> Result<(), ServiceError> {
        if self.reauth.is_recent(now_unix_ms) {
            Ok(())
        } else {
            Err(ServiceError::ReauthenticationRequired)
        }
    }

    fn activate(&mut self, file: VaultFile) {
        self.active_path = Some(file.path().to_path_buf());
        self.working = Some(file.unlocked().snapshot().clone());
        self.search = SearchIndex::build(file.unlocked().snapshot());
        self.file = Some(file);
        self.reauth.clear();
        self.state = SessionState::Unlocked;
    }

    fn snapshot(&self) -> Result<&VaultSnapshot, ServiceError> {
        self.working.as_ref().ok_or(ServiceError::Locked)
    }

    fn create_item(
        &mut self,
        group_id: Id,
        title: String,
        favorite: bool,
        tags: Vec<String>,
        payload: VaultPayload,
        now_unix_ms: i64,
    ) -> Result<Id, ServiceError> {
        let id = random_id()?;
        self.mutate(|snapshot| {
            if !snapshot.groups.iter().any(|group| group.id == group_id) {
                return Err(ServiceError::GroupNotFound);
            }
            snapshot.items.push(VaultItem {
                id,
                group_id,
                title,
                favorite,
                tags,
                created_at_unix_ms: now_unix_ms,
                updated_at_unix_ms: now_unix_ms,
                revision: 1,
                history: Vec::new(),
                payload,
                deleted_at_unix_ms: None,
            });
            Ok(id)
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn update_item(
        &mut self,
        id: Id,
        group_id: Id,
        title: String,
        favorite: bool,
        tags: Vec<String>,
        payload: VaultPayload,
        now_unix_ms: i64,
    ) -> Result<(), ServiceError> {
        self.mutate(|snapshot| {
            if !snapshot.groups.iter().any(|group| group.id == group_id) {
                return Err(ServiceError::GroupNotFound);
            }
            let item = snapshot
                .items
                .iter_mut()
                .find(|item| item.id == id)
                .ok_or(ServiceError::ItemNotFound)?;
            push_history(item);
            item.group_id = group_id;
            item.title = title;
            item.favorite = favorite;
            item.tags = tags;
            item.payload = payload;
            item.updated_at_unix_ms = now_unix_ms;
            item.revision = item
                .revision
                .checked_add(1)
                .ok_or(ServiceError::RevisionOverflow)?;
            Ok(())
        })
    }

    fn mutate<T>(
        &mut self,
        operation: impl FnOnce(&mut VaultSnapshot) -> Result<T, ServiceError>,
    ) -> Result<T, ServiceError> {
        if !matches!(self.state, SessionState::Unlocked | SessionState::Dirty) {
            return Err(ServiceError::InvalidState);
        }
        let current = self.working.as_ref().ok_or(ServiceError::Locked)?;
        let mut candidate = current.clone();
        let output = match operation(&mut candidate) {
            Ok(output) => output,
            Err(error) => {
                candidate.zeroize_secrets();
                return Err(error);
            }
        };
        candidate.revision = match candidate.revision.checked_add(1) {
            Some(revision) => revision,
            None => {
                candidate.zeroize_secrets();
                return Err(ServiceError::RevisionOverflow);
            }
        };
        if let Err(error) = candidate.validate() {
            candidate.zeroize_secrets();
            return Err(error.into());
        }
        self.search = SearchIndex::build(&candidate);
        if let Some(mut old) = self.working.replace(candidate) {
            old.zeroize_secrets();
        }
        self.state = SessionState::Dirty;
        Ok(output)
    }
}

fn title_key(item: &VaultItem) -> (String, Id) {
    (item.title.to_lowercase(), item.id)
}

impl From<&VaultItem> for ItemSummary {
    fn from(item: &VaultItem) -> Self {
        let (kind, primary_username, primary_url) = match &item.payload {
            VaultPayload::Login(login) => (
                ItemKind::Login,
                login.usernames.first().cloned(),
                login.urls.first().cloned(),
            ),
            VaultPayload::SecureNote(_) => (ItemKind::SecureNote, None, None),
        };
        Self {
            id: item.id,
            kind,
            title: item.title.clone(),
            favorite: item.favorite,
            tags: item.tags.clone(),
            primary_username,
            primary_url,
            deleted: item.deleted_at_unix_ms.is_some(),
        }
    }
}

fn push_history(item: &mut VaultItem) {
    item.history.push(ItemHistory {
        revision: item.revision,
        title: item.title.clone(),
        updated_at_unix_ms: item.updated_at_unix_ms,
        payload: item.payload.clone(),
    });
}

fn random_id() -> Result<Id, CryptoError> {
    loop {
        let bytes = random_array::<16>()?;
        if bytes.iter().any(|byte| *byte != 0) {
            return Ok(Id::from_bytes(bytes));
        }
    }
}

#[derive(Default)]
struct SearchIndex {
    documents: Vec<SearchDocument>,
}

impl SearchIndex {
    fn build(snapshot: &VaultSnapshot) -> Self {
        Self {
            documents: snapshot
                .items
                .iter()
                .map(|item| {
                    let mut text = String::new();
                    append_search(&mut text, &item.title);
                    for tag in &item.tags {
                        append_search(&mut text, tag);
                    }
                    match &item.payload {
                        VaultPayload::Login(login) => {
                            for username in &login.usernames {
                                append_search(&mut text, username);
                            }
                            for url in &login.urls {
                                append_search(&mut text, url);
                            }
                        }
                        VaultPayload::SecureNote(_) => {}
                    }
                    SearchDocument { id: item.id, text }
                })
                .collect(),
        }
    }

    fn find(&self, query: &str) -> Vec<Id> {
        let query = query.to_lowercase();
        self.documents
            .iter()
            .filter(|document| document.text.contains(&query))
            .map(|document| document.id)
            .collect()
    }

    fn clear(&mut self) {
        for document in &mut self.documents {
            document.text.zeroize();
        }
        self.documents.clear();
    }
}

struct SearchDocument {
    id: Id,
    text: String,
}

fn append_search(target: &mut String, value: &str) {
    target.push(' ');
    target.push_str(&value.to_lowercase());
}

#[derive(Default)]
struct ReauthPolicy {
    failures: VecDeque<i64>,
    blocked_until: Option<i64>,
    authenticated_until: Option<i64>,
}

impl ReauthPolicy {
    fn check_allowed(&mut self, now: i64) -> Result<(), ServiceError> {
        self.expire(now);
        if self.blocked_until.is_some_and(|until| now < until) {
            return Err(ServiceError::ReauthenticationRateLimited);
        }
        Ok(())
    }

    fn failure(&mut self, now: i64) {
        self.expire(now);
        self.authenticated_until = None;
        self.failures.push_back(now);
        if self.failures.len() >= REAUTH_MAX_FAILURES {
            self.blocked_until = Some(now.saturating_add(REAUTH_COOLDOWN_MS));
        }
    }

    fn success(&mut self, now: i64) {
        self.failures.clear();
        self.blocked_until = None;
        self.authenticated_until = Some(now.saturating_add(REAUTH_TOKEN_MS));
    }

    fn is_recent(&self, now: i64) -> bool {
        self.authenticated_until.is_some_and(|until| now <= until)
    }

    fn expire(&mut self, now: i64) {
        while self
            .failures
            .front()
            .is_some_and(|failure| now.saturating_sub(*failure) > REAUTH_WINDOW_MS)
        {
            self.failures.pop_front();
        }
        if self.blocked_until.is_some_and(|until| now >= until) {
            self.blocked_until = None;
            self.failures.clear();
        }
        if self.authenticated_until.is_some_and(|until| now > until) {
            self.authenticated_until = None;
        }
    }

    fn clear(&mut self) {
        self.failures.clear();
        self.blocked_until = None;
        self.authenticated_until = None;
    }
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("vault is locked")]
    Locked,
    #[error("operation is not permitted in the current session state")]
    InvalidState,
    #[error("item was not found")]
    ItemNotFound,
    #[error("group was not found")]
    GroupNotFound,
    #[error("a vault must retain at least one group")]
    CannotDeleteLastGroup,
    #[error("the group must be empty before it can be deleted")]
    GroupNotEmpty,
    #[error("history record was not found")]
    HistoryNotFound,
    #[error("page parameters are outside accepted bounds")]
    InvalidPage,
    #[error("settings are outside accepted bounds")]
    InvalidSettings,
    #[error("revision overflow")]
    RevisionOverflow,
    #[error("target changed externally; candidate retained at {candidate:?}")]
    Conflict { candidate: PathBuf },
    #[error("save result is unknown: {source}")]
    SaveResultUnknown {
        expected_fingerprint: [u8; 32],
        #[source]
        source: std::io::Error,
    },
    #[error("recent main-password verification is required")]
    ReauthenticationRequired,
    #[error("main-password verification failed")]
    ReauthenticationFailed,
    #[error("main-password verification is temporarily rate limited")]
    ReauthenticationRateLimited,
    #[error(transparent)]
    File(#[from] VaultFileError),
    #[error(transparent)]
    Save(#[from] SaveError),
    #[error(transparent)]
    Domain(#[from] DomainError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    use vault_crypto::KdfParams;
    use vault_domain::{CustomField, FieldSensitivity, Id, UrlMatchMode, VaultPayload};
    use vault_import::{CsvMapping, parse_csv_logins};

    use super::{
        AppSettings, ItemFilter, ItemKind, ItemSort, LoginInput, NewGroup, SecureNoteInput,
        ServiceError, SessionState, VaultService, open_vault_file,
    };

    fn login(group_id: Id, title: &str, password: &str) -> LoginInput {
        LoginInput {
            group_id,
            title: title.to_owned(),
            favorite: false,
            tags: vec!["work".to_owned()],
            usernames: vec!["alice".to_owned()],
            password: password.to_owned(),
            urls: vec!["https://example.test".to_owned()],
            url_match_modes: vec![UrlMatchMode::ExactHost],
            notes: String::new(),
            custom_fields: Vec::new(),
        }
    }

    #[test]
    fn crud_dirty_save_reopen_and_lock() {
        let directory = tempdir().expect("temporary directory must exist");
        let path = directory.path().join("service.vaultx");
        let mut service = VaultService::new();
        service
            .create(&path, b"test password", 0, KdfParams::testing())
            .expect("vault must be created");
        let root = service.snapshot().expect("vault is unlocked").root_group;
        let group = service
            .create_group(
                NewGroup {
                    parent_id: root,
                    name: "Work".to_owned(),
                },
                1,
            )
            .expect("group must be created");
        let item = service
            .create_login(login(group, "Example", "secret"), 2)
            .expect("item must be created");
        assert_eq!(service.state(), SessionState::Dirty);
        assert_eq!(
            service
                .list_items("alice", false, 0, 20)
                .expect("search must work")
                .len(),
            1
        );
        service.save().expect("dirty vault must save");
        assert_eq!(service.state(), SessionState::Unlocked);
        service.lock();
        assert_eq!(service.state(), SessionState::Locked);
        assert!(matches!(service.item(item), Err(ServiceError::Locked)));
        service
            .unlock(&path, b"test password")
            .expect("vault must reopen");
        let reopened = service.item(item).expect("saved item must exist");
        assert!(matches!(reopened.payload, VaultPayload::Login(_)));
    }

    #[test]
    fn submitted_mutation_is_persisted_before_success_is_reported() {
        let directory = tempdir().expect("temporary directory must exist");
        let path = directory.path().join("submitted-mutation.vaultx");
        let mut service = VaultService::new();
        service
            .create(&path, b"test password", 0, KdfParams::testing())
            .expect("vault must be created");
        let root = service.snapshot().expect("vault is unlocked").root_group;

        let item = service
            .apply_and_save(|service| {
                service.create_login(login(root, "Persistent account", "secret"), 1)
            })
            .expect("submitted item must be encrypted and persisted");
        assert_eq!(service.state(), SessionState::Unlocked);

        service.lock();
        service
            .unlock(&path, b"test password")
            .expect("vault must reopen after a restart-equivalent lock");
        let reopened = service
            .item(item)
            .expect("submitted item must survive reopen");
        assert_eq!(reopened.title, "Persistent account");
    }

    #[test]
    fn submitted_mutations_keep_the_configured_number_of_authenticated_backups() {
        let directory = tempdir().expect("temporary directory must exist");
        let path = directory.path().join("backup-ring.vaultx");
        let mut service = VaultService::new();
        service
            .create(&path, b"test password", 0, KdfParams::testing())
            .expect("vault must be created");
        service
            .update_settings(AppSettings {
                auto_lock_seconds: 300,
                clipboard_clear_seconds: 30,
                lock_on_minimize: false,
                backup_versions: 2,
            })
            .expect("backup policy must update");
        service.save().expect("backup policy must save");
        let root = service.snapshot().expect("vault is unlocked").root_group;

        for index in 0..3 {
            service
                .apply_and_save(|service| {
                    service.create_login(
                        login(root, &format!("Account {index}"), "secret"),
                        i64::from(index) + 1,
                    )
                })
                .expect("mutation and automatic backup must succeed");
        }

        let backups = std::fs::read_dir(directory.path())
            .expect("backup directory must be readable")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().contains(".vaultx.backup-"))
            })
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 2);
        for backup in backups {
            open_vault_file(&backup, b"test password")
                .expect("every retained automatic backup must authenticate");
        }
    }

    #[test]
    fn updates_history_and_recycle_bin() {
        let directory = tempdir().expect("temporary directory must exist");
        let path = directory.path().join("history.vaultx");
        let mut service = VaultService::new();
        service
            .create(&path, b"test password", 0, KdfParams::testing())
            .expect("vault must be created");
        let root = service.snapshot().expect("vault is unlocked").root_group;
        let item = service
            .create_login(login(root, "Before", "one"), 1)
            .expect("item must be created");
        service
            .update_login(item, login(root, "After", "two"), 2)
            .expect("item must update");
        assert_eq!(service.item(item).expect("item exists").history.len(), 1);
        service.soft_delete(item, 3).expect("item must soft delete");
        assert!(
            service
                .list_items("", false, 0, 20)
                .expect("list works")
                .is_empty()
        );
        service.restore(item, 4).expect("item must restore");
        service
            .soft_delete(item, 5)
            .expect("item must soft delete again");
        service
            .permanently_delete(item, 6)
            .expect("item must permanently delete");
        assert!(matches!(
            service.item(item),
            Err(ServiceError::ItemNotFound)
        ));
    }

    #[test]
    fn reauthentication_is_recent_and_rate_limited() {
        let directory = tempdir().expect("temporary directory must exist");
        let path = directory.path().join("reauth.vaultx");
        let mut service = VaultService::new();
        service
            .create(&path, b"test password", 0, KdfParams::testing())
            .expect("vault must be created");
        assert!(matches!(
            service.require_recent_reauthentication(0),
            Err(ServiceError::ReauthenticationRequired)
        ));
        service
            .reauthenticate(b"test password", 1)
            .expect("correct password must verify");
        assert!(service.require_recent_reauthentication(2).is_ok());
        for now in 100..105 {
            assert!(matches!(
                service.reauthenticate(b"wrong", now),
                Err(ServiceError::ReauthenticationFailed)
            ));
        }
        assert!(matches!(
            service.reauthenticate(b"test password", 106),
            Err(ServiceError::ReauthenticationRateLimited)
        ));
    }

    #[test]
    fn groups_filters_sorting_and_failed_mutation_are_transactional() {
        let directory = tempdir().expect("temporary directory must exist");
        let path = directory.path().join("query.vaultx");
        let mut service = VaultService::new();
        service
            .create(&path, b"test password", 0, KdfParams::testing())
            .expect("vault must be created");
        let root = service.snapshot().expect("vault is unlocked").root_group;
        assert!(matches!(
            service.delete_group(root),
            Err(ServiceError::CannotDeleteLastGroup)
        ));
        assert_eq!(service.state(), SessionState::Unlocked);

        let group = service
            .create_group(
                NewGroup {
                    parent_id: root,
                    name: "Original".to_owned(),
                },
                1,
            )
            .expect("group must be created");
        service
            .rename_group(root, "Personal vault".to_owned(), 2)
            .expect("root group must rename");
        service
            .rename_group(group, "Renamed".to_owned(), 3)
            .expect("group must rename");
        let mut first = login(group, "Zulu", "one");
        first.favorite = true;
        service
            .create_login(first, 3)
            .expect("login must be created");
        service
            .create_secure_note(
                SecureNoteInput {
                    group_id: group,
                    title: "Alpha".to_owned(),
                    favorite: false,
                    tags: vec!["notes".to_owned()],
                    content: "private".to_owned(),
                    custom_fields: Vec::new(),
                },
                4,
            )
            .expect("note must be created");

        let filtered = service
            .query_items(
                "",
                ItemFilter {
                    group_id: Some(group),
                    kind: Some(ItemKind::Login),
                    favorite_only: true,
                    include_deleted: false,
                },
                ItemSort::UpdatedNewest,
                0,
                20,
            )
            .expect("filtered query must succeed");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].title, "Zulu");
        assert!(matches!(
            service.delete_group(group),
            Err(ServiceError::GroupNotEmpty)
        ));

        let sorted = service
            .query_items("", ItemFilter::default(), ItemSort::TitleAscending, 0, 20)
            .expect("sorted query must succeed");
        assert_eq!(
            sorted
                .iter()
                .map(|item| item.title.as_str())
                .collect::<Vec<_>>(),
            vec!["Alpha", "Zulu"]
        );
    }

    #[test]
    fn root_group_can_be_renamed_and_deleted_with_safe_handoff() {
        let directory = tempdir().expect("temporary directory must exist");
        let path = directory.path().join("root-handoff.vaultx");
        let mut service = VaultService::new();
        service
            .create(&path, b"test password", 0, KdfParams::testing())
            .expect("vault must be created");
        let root = service.snapshot().expect("vault is unlocked").root_group;
        service
            .rename_group(root, "My vault".to_owned(), 1)
            .expect("root group must rename");
        let replacement = service
            .create_group(
                NewGroup {
                    parent_id: root,
                    name: "Personal".to_owned(),
                },
                2,
            )
            .expect("replacement group must be created");
        let sibling = service
            .create_group(
                NewGroup {
                    parent_id: root,
                    name: "Work".to_owned(),
                },
                3,
            )
            .expect("sibling group must be created");
        let item = service
            .create_login(login(root, "Root account", "secret"), 4)
            .expect("root item must be created");

        service
            .delete_group(root)
            .expect("root group must hand off before deletion");

        let snapshot = service.snapshot().expect("vault is unlocked");
        assert_eq!(snapshot.root_group, replacement);
        assert!(!snapshot.groups.iter().any(|group| group.id == root));
        assert_eq!(
            snapshot
                .groups
                .iter()
                .find(|group| group.id == replacement)
                .expect("replacement root must remain")
                .parent_id,
            None
        );
        assert_eq!(
            snapshot
                .groups
                .iter()
                .find(|group| group.id == sibling)
                .expect("sibling group must remain")
                .parent_id,
            Some(replacement)
        );
        assert_eq!(
            service.item(item).expect("item must remain").group_id,
            replacement
        );
    }

    #[test]
    fn idle_timeout_zeroizes_session_and_rejects_sensitive_access() {
        let directory = tempdir().expect("temporary directory must exist");
        let path = directory.path().join("idle.vaultx");
        let mut service = VaultService::new();
        service
            .create(&path, b"test password", 0, KdfParams::testing())
            .expect("vault must be created");
        let root = service.snapshot().expect("vault is unlocked").root_group;
        let item = service
            .create_login(login(root, "Secret", "value"), 1)
            .expect("item must be created");
        service.record_activity(1);
        assert!(!service.lock_if_idle(299_999));
        assert!(service.lock_if_idle(300_001));
        assert_eq!(service.state(), SessionState::Locked);
        assert!(matches!(service.item(item), Err(ServiceError::Locked)));
        service
            .unlock(&path, b"test password")
            .expect("idle locking must persist a submitted dirty snapshot first");
        assert_eq!(
            service
                .item(item)
                .expect("item must survive idle lock")
                .title,
            "Secret"
        );
    }

    #[test]
    fn d3_application_service_end_to_end() {
        let directory = tempdir().expect("temporary directory must exist");
        let original = directory.path().join("original.vaultx");
        let copied = directory.path().join("copied.vaultx");
        let mut service = VaultService::new();
        service
            .create(&original, b"test password", 0, KdfParams::testing())
            .expect("vault must be created");
        let root = service.snapshot().expect("vault is unlocked").root_group;
        let mut input = login(root, "Portal", "secret-one");
        input.custom_fields.push(CustomField {
            name: "account id".to_owned(),
            value: "A-123".to_owned(),
            sensitivity: FieldSensitivity::Concealed,
        });
        let item = service
            .create_login(input, 1)
            .expect("login must be created");
        assert_eq!(
            service
                .list_items("alice", false, 0, 20)
                .expect("memory search must work")
                .len(),
            1
        );
        service
            .update_login(item, login(root, "Portal updated", "secret-two"), 2)
            .expect("login must update");
        assert_eq!(service.item(item).expect("item exists").history.len(), 1);
        service
            .reauthenticate(b"test password", 3)
            .expect("high-risk reauthentication must pass");
        service
            .require_recent_reauthentication(4)
            .expect("reauthentication token must be recent");
        service
            .save_as(&copied)
            .expect("save-as must close the dirty-state loop");
        assert_eq!(service.state(), SessionState::Unlocked);
        assert_eq!(service.active_path(), Some(copied.as_path()));
        service.lock();
        service
            .unlock(&copied, b"test password")
            .expect("saved copy must unlock after restart-equivalent lock");
        let reopened = service.item(item).expect("saved item must reopen");
        assert_eq!(reopened.title, "Portal updated");
        assert!(matches!(reopened.payload, VaultPayload::Login(_)));
    }

    #[test]
    fn d4_import_backup_recovery_credentials_and_settings_end_to_end() {
        let directory = tempdir().expect("temporary directory must exist");
        let primary = directory.path().join("d4.vaultx");
        let backup = directory.path().join("before-import.vaultx");
        let mut service = VaultService::new();
        service
            .create(&primary, b"old password", 0, KdfParams::testing())
            .expect("vault must be created");
        let root = service.snapshot().expect("vault is unlocked").root_group;
        let mapping = CsvMapping {
            title: "title".to_owned(),
            username: Some("username".to_owned()),
            password: "password".to_owned(),
            url: Some("url".to_owned()),
            notes: Some("notes".to_owned()),
            tags: Some("tags".to_owned()),
        };
        let records = parse_csv_logins(
            b"title,username,password,url,notes,tags\nOne,alice,secret,https://one.test,note,work\nTwo,bob,other,https://two.test,,home\n",
            &mapping,
            100,
        )
        .expect("complete CSV must parse");
        service
            .import_logins(root, records, 1)
            .expect("CSV records must commit as one mutation");
        service
            .update_settings(AppSettings {
                auto_lock_seconds: 120,
                clipboard_clear_seconds: 15,
                lock_on_minimize: true,
                backup_versions: 5,
            })
            .expect("settings must update");
        service
            .save_with_backup(&backup)
            .expect("current encrypted version must save before backup");
        assert_eq!(service.state(), SessionState::Unlocked);
        assert_eq!(
            open_vault_file(&backup, b"old password")
                .expect("backup must authenticate")
                .unlocked()
                .snapshot()
                .items
                .len(),
            2
        );
        assert_eq!(
            service
                .list_items("", false, 0, 20)
                .expect("list works")
                .len(),
            2
        );

        let recovery = service
            .generate_recovery_key(b"old password", 2)
            .expect("recovery key must be generated and saved");
        assert!(
            service
                .confirm_recovery_key(recovery.expose_secret().as_bytes())
                .expect("recovery key trial must run")
        );
        service
            .change_main_password(b"old password", b"new password", KdfParams::testing())
            .expect("main password and KDF must rotate");
        service.lock();
        assert!(service.unlock(&primary, b"old password").is_err());
        assert!(
            service
                .unlock(&primary, recovery.expose_secret().as_bytes())
                .is_err()
        );
        service
            .unlock(&primary, b"new password")
            .expect("new password must unlock after restart-equivalent lock");
        assert_eq!(
            service
                .settings()
                .expect("settings persist")
                .auto_lock_seconds,
            120
        );
        assert_eq!(
            service
                .list_items("", false, 0, 20)
                .expect("items persist")
                .len(),
            2
        );
    }
}

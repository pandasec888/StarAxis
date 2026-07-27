#![doc = "StarAxis desktop shell and its deliberately small IPC boundary."]
#![forbid(unsafe_code)]

mod recent;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
#[cfg(target_os = "macos")]
use tauri::{
    ActivationPolicy, PhysicalPosition, Position, WebviewUrl, WebviewWindowBuilder,
    menu::{MenuBuilder, SubmenuBuilder},
    tray::{TrayIconBuilder, TrayIconEvent},
};
use tauri::{AppHandle, Manager, State, WebviewWindow};
use vault_crypto::{KdfParams, sha256};
use vault_domain::{CustomField, FieldSensitivity, Id, UrlMatchMode, VaultPayload};
use vault_extension_service::{
    ExtensionService, PairedClientSummary, PendingPairSummary, start_broker,
};
use vault_file::recover_candidate_as;
use vault_import::{
    CSV_IMPORT_TEMPLATE, CsvMapping, ImportedLogin, parse_csv_logins, read_csv_file_bounded,
};
use vault_service::{
    AppSettings, GroupSummary, ItemFilter, ItemKind, ItemSort, ItemSummary, LoginInput, NewGroup,
    PasswordPolicy, SecureNoteInput, SessionState, VaultService, generate_password,
};
use zeroize::Zeroize;

const MAIN_WINDOW: &str = "main";
const TRAY_UNLOCK_WINDOW: &str = "tray-unlock";
#[cfg(target_os = "macos")]
const TRAY_OPEN: &str = "tray_open";
#[cfg(target_os = "macos")]
const TRAY_UNLOCK: &str = "tray_unlock";
#[cfg(target_os = "macos")]
const TRAY_LOCK: &str = "tray_lock";
#[cfg(target_os = "macos")]
const TRAY_QUIT: &str = "tray_quit";
const MAX_PATH_BYTES: usize = 4_096;
const MAX_PASSWORD_BYTES: usize = 1_024;
const MAX_TITLE_BYTES: usize = 4_096;
const MAX_TEXT_BYTES: usize = 1_048_576;
const MAX_COLLECTION_ITEMS: usize = 1_000;

#[derive(Clone)]
struct AppState {
    service: Arc<Mutex<VaultService>>,
    extension: Arc<Mutex<ExtensionService>>,
    #[cfg(target_os = "macos")]
    tray_anchor: Arc<Mutex<Option<(f64, f64)>>>,
}

impl AppState {
    fn new() -> Result<Self, String> {
        let service = Arc::new(Mutex::new(VaultService::new()));
        let extension = Arc::new(Mutex::new(
            ExtensionService::load_or_create(extension_store_path()?).map_err(error_string)?,
        ));
        let _broker =
            start_broker(Arc::clone(&extension), Arc::clone(&service)).map_err(error_string)?;
        Ok(Self {
            service,
            extension,
            #[cfg(target_os = "macos")]
            tray_anchor: Arc::new(Mutex::new(None)),
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ItemKindDto {
    Login,
    SecureNote,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ItemSortDto {
    TitleAscending,
    TitleDescending,
    UpdatedNewest,
    UpdatedOldest,
    CreatedNewest,
    CreatedOldest,
}

impl From<ItemSortDto> for ItemSort {
    fn from(value: ItemSortDto) -> Self {
        match value {
            ItemSortDto::TitleAscending => Self::TitleAscending,
            ItemSortDto::TitleDescending => Self::TitleDescending,
            ItemSortDto::UpdatedNewest => Self::UpdatedNewest,
            ItemSortDto::UpdatedOldest => Self::UpdatedOldest,
            ItemSortDto::CreatedNewest => Self::CreatedNewest,
            ItemSortDto::CreatedOldest => Self::CreatedOldest,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
struct ItemFilterDto {
    group_id: Option<[u8; 16]>,
    kind: Option<ItemKindDto>,
    favorite_only: bool,
    include_deleted: bool,
}

impl From<ItemFilterDto> for ItemFilter {
    fn from(value: ItemFilterDto) -> Self {
        Self {
            group_id: value.group_id.map(Id::from_bytes),
            kind: value.kind.map(|kind| match kind {
                ItemKindDto::Login => ItemKind::Login,
                ItemKindDto::SecureNote => ItemKind::SecureNote,
            }),
            favorite_only: value.favorite_only,
            include_deleted: value.include_deleted,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct ItemSummaryDto {
    id: [u8; 16],
    kind: ItemKindDto,
    title: String,
    favorite: bool,
    tags: Vec<String>,
    primary_username: Option<String>,
    primary_url: Option<String>,
    deleted: bool,
}

impl From<ItemSummary> for ItemSummaryDto {
    fn from(value: ItemSummary) -> Self {
        Self {
            id: *value.id.as_bytes(),
            kind: match value.kind {
                ItemKind::Login => ItemKindDto::Login,
                ItemKind::SecureNote => ItemKindDto::SecureNote,
            },
            title: value.title,
            favorite: value.favorite,
            tags: value.tags,
            primary_username: value.primary_username,
            primary_url: value.primary_url,
            deleted: value.deleted,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct GroupDto {
    id: [u8; 16],
    parent_id: Option<[u8; 16]>,
    name: String,
}

impl From<GroupSummary> for GroupDto {
    fn from(value: GroupSummary) -> Self {
        Self {
            id: *value.id.as_bytes(),
            parent_id: value.parent_id.map(|id| *id.as_bytes()),
            name: value.name,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum FieldSensitivityDto {
    Concealed,
    Visible,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum UrlMatchModeDto {
    AnywhereOnWebsite,
    ExactHost,
    Never,
}

impl From<UrlMatchMode> for UrlMatchModeDto {
    fn from(value: UrlMatchMode) -> Self {
        match value {
            UrlMatchMode::AnywhereOnWebsite => Self::AnywhereOnWebsite,
            UrlMatchMode::ExactHost => Self::ExactHost,
            UrlMatchMode::Never => Self::Never,
        }
    }
}

impl From<UrlMatchModeDto> for UrlMatchMode {
    fn from(value: UrlMatchModeDto) -> Self {
        match value {
            UrlMatchModeDto::AnywhereOnWebsite => Self::AnywhereOnWebsite,
            UrlMatchModeDto::ExactHost => Self::ExactHost,
            UrlMatchModeDto::Never => Self::Never,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CustomFieldDto {
    name: String,
    value: String,
    sensitivity: FieldSensitivityDto,
}

impl From<&CustomField> for CustomFieldDto {
    fn from(value: &CustomField) -> Self {
        Self {
            name: value.name.clone(),
            value: value.value.clone(),
            sensitivity: match value.sensitivity {
                FieldSensitivity::Concealed => FieldSensitivityDto::Concealed,
                FieldSensitivity::Visible => FieldSensitivityDto::Visible,
            },
        }
    }
}

impl From<CustomFieldDto> for CustomField {
    fn from(value: CustomFieldDto) -> Self {
        Self {
            name: value.name,
            value: value.value,
            sensitivity: match value.sensitivity {
                FieldSensitivityDto::Concealed => FieldSensitivity::Concealed,
                FieldSensitivityDto::Visible => FieldSensitivity::Visible,
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct LoginInputDto {
    group_id: [u8; 16],
    title: String,
    favorite: bool,
    tags: Vec<String>,
    usernames: Vec<String>,
    password: String,
    urls: Vec<String>,
    url_match_modes: Vec<UrlMatchModeDto>,
    notes: String,
    custom_fields: Vec<CustomFieldDto>,
}

impl TryFrom<LoginInputDto> for LoginInput {
    type Error = String;

    fn try_from(value: LoginInputDto) -> Result<Self, Self::Error> {
        validate_item_fields(
            &value.title,
            &value.tags,
            &value.usernames,
            &value.urls,
            &value.notes,
            &value.custom_fields,
        )?;
        validate_text(&value.password, MAX_TEXT_BYTES, "password")?;
        Ok(Self {
            group_id: Id::from_bytes(value.group_id),
            title: value.title,
            favorite: value.favorite,
            tags: value.tags,
            usernames: value.usernames,
            password: value.password,
            urls: value.urls,
            url_match_modes: value.url_match_modes.into_iter().map(Into::into).collect(),
            notes: value.notes,
            custom_fields: value.custom_fields.into_iter().map(Into::into).collect(),
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
struct SecureNoteInputDto {
    group_id: [u8; 16],
    title: String,
    favorite: bool,
    tags: Vec<String>,
    content: String,
    custom_fields: Vec<CustomFieldDto>,
}

impl TryFrom<SecureNoteInputDto> for SecureNoteInput {
    type Error = String;

    fn try_from(value: SecureNoteInputDto) -> Result<Self, Self::Error> {
        validate_item_fields(
            &value.title,
            &value.tags,
            &[],
            &[],
            &value.content,
            &value.custom_fields,
        )?;
        Ok(Self {
            group_id: Id::from_bytes(value.group_id),
            title: value.title,
            favorite: value.favorite,
            tags: value.tags,
            content: value.content,
            custom_fields: value.custom_fields.into_iter().map(Into::into).collect(),
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
struct PasswordPolicyDto {
    length: usize,
    lowercase: bool,
    uppercase: bool,
    digits: bool,
    symbols: bool,
    exclude_ambiguous: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum RevealedSecretDto {
    Login { password: String, notes: String },
    SecureNote { content: String },
}

#[derive(Clone, Debug, Serialize)]
struct HistoryDto {
    index: usize,
    revision: u64,
    title: String,
    updated_at_unix_ms: i64,
}

#[derive(Clone, Debug, Serialize)]
struct ItemDetailDto {
    id: [u8; 16],
    group_id: [u8; 16],
    kind: ItemKindDto,
    title: String,
    favorite: bool,
    tags: Vec<String>,
    usernames: Vec<String>,
    password: Option<String>,
    urls: Vec<String>,
    url_match_modes: Vec<UrlMatchModeDto>,
    notes: Option<String>,
    content: Option<String>,
    custom_fields: Vec<CustomFieldDto>,
    history: Vec<HistoryDto>,
}

#[derive(Clone, Debug, Deserialize)]
struct CsvMappingDto {
    title: String,
    username: Option<String>,
    password: String,
    url: Option<String>,
    notes: Option<String>,
    tags: Option<String>,
}

impl From<CsvMappingDto> for CsvMapping {
    fn from(value: CsvMappingDto) -> Self {
        Self {
            title: value.title,
            username: value.username,
            password: value.password,
            url: value.url,
            notes: value.notes,
            tags: value.tags,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct CsvPreviewDto {
    total_records: usize,
    source_hash: [u8; 32],
    records: Vec<CsvPreviewRecordDto>,
}

#[derive(Clone, Debug, Serialize)]
struct CsvPreviewRecordDto {
    title: String,
    username: Option<String>,
    url: Option<String>,
    tag_count: usize,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
struct SettingsDto {
    auto_lock_seconds: u32,
    clipboard_clear_seconds: u32,
    lock_on_minimize: bool,
    backup_versions: u16,
}

impl From<AppSettings> for SettingsDto {
    fn from(value: AppSettings) -> Self {
        Self {
            auto_lock_seconds: value.auto_lock_seconds,
            clipboard_clear_seconds: value.clipboard_clear_seconds,
            lock_on_minimize: value.lock_on_minimize,
            backup_versions: value.backup_versions,
        }
    }
}

impl From<SettingsDto> for AppSettings {
    fn from(value: SettingsDto) -> Self {
        Self {
            auto_lock_seconds: value.auto_lock_seconds,
            clipboard_clear_seconds: value.clipboard_clear_seconds,
            lock_on_minimize: value.lock_on_minimize,
            backup_versions: value.backup_versions,
        }
    }
}

#[tauri::command]
fn app_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[tauri::command]
fn session_state(window: WebviewWindow, state: State<'_, AppState>) -> Result<String, String> {
    authorize(&window)?;
    let service = state
        .service
        .lock()
        .map_err(|_| "application state lock was poisoned".to_owned())?;
    Ok(session_state_name(service.state()).to_owned())
}

#[tauri::command]
fn record_user_activity(window: WebviewWindow, state: State<'_, AppState>) -> Result<(), String> {
    authorize(&window)?;
    let now = now_unix_ms()?;
    let locked_by_idle = {
        let mut service = state
            .service
            .lock()
            .map_err(|_| "application state lock was poisoned".to_owned())?;
        let was_unlocked = is_unlocked_session(service.state());
        service.lock_if_idle(now);
        let locked_by_idle = was_unlocked && service.state() == SessionState::Locked;
        if service.state() != SessionState::Locked {
            service.record_activity(now);
        }
        locked_by_idle
    };
    if locked_by_idle {
        clear_extension_authorizations(&state)?;
    }
    Ok(())
}

#[tauri::command]
fn create_vault(
    window: WebviewWindow,
    app: AppHandle,
    state: State<'_, AppState>,
    path: String,
    mut password: String,
) -> Result<(), String> {
    authorize(&window)?;
    validate_path(&path)?;
    validate_main_password(&password)?;
    let now = now_unix_ms()?;
    let result = with_service(&state, |service| {
        service
            .create(
                path.clone(),
                password.as_bytes(),
                now,
                KdfParams::recommended(),
            )
            .map_err(error_string)
    });
    password.zeroize();
    if result.is_ok() {
        let _ = recent::record(&app, &path, now);
    }
    result
}

#[tauri::command]
fn unlock_vault(
    window: WebviewWindow,
    app: AppHandle,
    state: State<'_, AppState>,
    path: String,
    mut password: String,
) -> Result<(), String> {
    authorize(&window)?;
    validate_path(&path)?;
    validate_secret_length(&password)?;
    let result = with_service(&state, |service| {
        service
            .unlock(path.clone(), password.as_bytes())
            .map_err(error_string)
    });
    password.zeroize();
    if result.is_ok()
        && let Ok(now) = now_unix_ms()
    {
        let _ = recent::record(&app, &path, now);
    }
    result
}

#[derive(Serialize)]
struct TrayUnlockContextDto {
    state: &'static str,
    vault_name: Option<String>,
}

fn tray_unlock_target(app: &AppHandle, state: &AppState) -> Result<Option<PathBuf>, String> {
    let active = state
        .service
        .lock()
        .map_err(|_| "application state lock was poisoned".to_owned())?
        .active_path()
        .map(Path::to_path_buf);
    if active.is_some() {
        return Ok(active);
    }
    recent::latest_existing_path(app)
        .map(|path| path.map(PathBuf::from))
        .map_err(error_string)
}

#[tauri::command]
fn tray_unlock_context(
    window: WebviewWindow,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<TrayUnlockContextDto, String> {
    authorize_tray_unlock(&window)?;
    let session = state
        .service
        .lock()
        .map_err(|_| "application state lock was poisoned".to_owned())?
        .state();
    let target = tray_unlock_target(&app, &state)?;
    Ok(TrayUnlockContextDto {
        state: session_state_name(session),
        vault_name: target.as_deref().map(vault_display_name),
    })
}

#[tauri::command]
fn unlock_vault_from_tray(
    window: WebviewWindow,
    app: AppHandle,
    state: State<'_, AppState>,
    mut password: String,
) -> Result<(), String> {
    if let Err(error) = authorize_tray_unlock(&window) {
        password.zeroize();
        return Err(error);
    }
    if let Err(error) = validate_secret_length(&password) {
        password.zeroize();
        return Err(error);
    }
    let result = (|| {
        let path = tray_unlock_target(&app, &state)?
            .ok_or_else(|| "Open a vault in the StarAxis main window first".to_owned())?;
        let result = with_service(&state, |service| {
            if is_unlocked_session(service.state()) {
                return Ok(());
            }
            service
                .unlock(path.clone(), password.as_bytes())
                .map_err(error_string)
        });
        if result.is_ok()
            && let (Some(path), Ok(now)) = (path.to_str(), now_unix_ms())
        {
            let _ = recent::record(&app, path, now);
        }
        result
    })();
    password.zeroize();
    result
}

#[tauri::command]
fn hide_tray_unlock(window: WebviewWindow) -> Result<(), String> {
    authorize_tray_unlock(&window)?;
    window.destroy().map_err(error_string)
}

#[tauri::command]
fn open_main_from_tray(window: WebviewWindow, app: AppHandle) -> Result<(), String> {
    authorize_tray_unlock(&window)?;
    show_main_window(&app);
    window.destroy().map_err(error_string)
}

fn vault_display_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("未命名保险库")
        .to_owned()
}

#[tauri::command]
fn list_recent_vaults(
    window: WebviewWindow,
    app: AppHandle,
) -> Result<Vec<recent::RecentVaultDto>, String> {
    authorize(&window)?;
    recent::list(&app).map_err(error_string)
}

#[tauri::command]
fn forget_recent_vault(window: WebviewWindow, app: AppHandle, path: String) -> Result<(), String> {
    authorize(&window)?;
    recent::forget(&app, &path).map_err(error_string)
}

#[tauri::command]
fn lock_vault(window: WebviewWindow, state: State<'_, AppState>) -> Result<(), String> {
    authorize(&window)?;
    with_service(&state, |service| {
        if !persist_before_lock(service) {
            return Err(
                "pending changes could not be saved; the vault remains unlocked".to_owned(),
            );
        }
        service.lock();
        Ok(())
    })?;
    state
        .extension
        .lock()
        .map_err(|_| "extension service lock was poisoned".to_owned())?
        .clear_runtime_authorizations();
    Ok(())
}

#[tauri::command]
fn list_pending_extension_pairs(
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> Result<Vec<PendingPairSummary>, String> {
    authorize(&window)?;
    let mut extension = state
        .extension
        .lock()
        .map_err(|_| "extension service lock was poisoned".to_owned())?;
    Ok(extension.pending_pairs(now_unix_ms()?))
}

#[tauri::command]
fn list_paired_extensions(
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> Result<Vec<PairedClientSummary>, String> {
    authorize(&window)?;
    let extension = state
        .extension
        .lock()
        .map_err(|_| "extension service lock was poisoned".to_owned())?;
    Ok(extension.paired_clients())
}

#[tauri::command]
fn approve_extension_pairing(
    window: WebviewWindow,
    state: State<'_, AppState>,
    pending_id: String,
    verification_code: String,
) -> Result<String, String> {
    authorize(&window)?;
    if !window.is_focused().map_err(error_string)? {
        return Err("bring StarAxis to the foreground before approving pairing".to_owned());
    }
    {
        let service = state
            .service
            .lock()
            .map_err(|_| "application state lock was poisoned".to_owned())?;
        if !matches!(
            service.state(),
            SessionState::Unlocked | SessionState::Dirty
        ) {
            return Err("unlock the vault before approving a browser extension".to_owned());
        }
    }
    let mut extension = state
        .extension
        .lock()
        .map_err(|_| "extension service lock was poisoned".to_owned())?;
    let pending = extension.pending_pairs(now_unix_ms()?);
    if !pending
        .iter()
        .any(|pair| pair.pending_id == pending_id && pair.verification_code == verification_code)
    {
        return Err("pairing code does not match or has expired".to_owned());
    }
    extension
        .approve_pairing(&pending_id, now_unix_ms()?)
        .map_err(error_string)
}

#[tauri::command]
fn reject_extension_pairing(
    window: WebviewWindow,
    state: State<'_, AppState>,
    pending_id: String,
) -> Result<(), String> {
    authorize(&window)?;
    state
        .extension
        .lock()
        .map_err(|_| "extension service lock was poisoned".to_owned())?
        .reject_pairing(&pending_id)
        .map_err(error_string)
}

#[tauri::command]
fn revoke_extension_pairing(
    window: WebviewWindow,
    state: State<'_, AppState>,
    pair_id: String,
) -> Result<(), String> {
    authorize(&window)?;
    state
        .extension
        .lock()
        .map_err(|_| "extension service lock was poisoned".to_owned())?
        .revoke_pairing(&pair_id)
        .map_err(error_string)
}

#[tauri::command]
fn revoke_all_extension_pairings(
    window: WebviewWindow,
    state: State<'_, AppState>,
    confirmed: bool,
) -> Result<(), String> {
    authorize(&window)?;
    if !confirmed {
        return Err("explicit confirmation is required".to_owned());
    }
    state
        .extension
        .lock()
        .map_err(|_| "extension service lock was poisoned".to_owned())?
        .revoke_all()
        .map_err(error_string)
}

#[tauri::command]
fn list_groups(window: WebviewWindow, state: State<'_, AppState>) -> Result<Vec<GroupDto>, String> {
    authorize(&window)?;
    with_service(&state, |service| {
        service
            .groups()
            .map(|groups| groups.into_iter().map(Into::into).collect())
            .map_err(error_string)
    })
}

#[tauri::command]
fn get_settings(window: WebviewWindow, state: State<'_, AppState>) -> Result<SettingsDto, String> {
    authorize(&window)?;
    with_service(&state, |service| {
        service.settings().map(Into::into).map_err(error_string)
    })
}

#[tauri::command]
fn update_settings(
    window: WebviewWindow,
    state: State<'_, AppState>,
    settings: SettingsDto,
) -> Result<(), String> {
    authorize(&window)?;
    with_service(&state, |service| {
        service
            .apply_and_save(|service| service.update_settings(settings.into()))
            .map_err(error_string)
    })
}

#[tauri::command]
fn create_group(
    window: WebviewWindow,
    state: State<'_, AppState>,
    parent_id: [u8; 16],
    name: String,
) -> Result<[u8; 16], String> {
    authorize(&window)?;
    validate_title(&name)?;
    with_service(&state, |service| {
        let now = now_unix_ms()?;
        service
            .apply_and_save(|service| {
                service.create_group(
                    NewGroup {
                        parent_id: Id::from_bytes(parent_id),
                        name,
                    },
                    now,
                )
            })
            .map(|id| *id.as_bytes())
            .map_err(error_string)
    })
}

#[tauri::command]
fn rename_group(
    window: WebviewWindow,
    state: State<'_, AppState>,
    id: [u8; 16],
    name: String,
) -> Result<(), String> {
    authorize(&window)?;
    validate_title(&name)?;
    with_service(&state, |service| {
        let now = now_unix_ms()?;
        service
            .apply_and_save(|service| service.rename_group(Id::from_bytes(id), name, now))
            .map_err(error_string)
    })
}

#[tauri::command]
fn delete_group(
    window: WebviewWindow,
    state: State<'_, AppState>,
    id: [u8; 16],
) -> Result<(), String> {
    authorize(&window)?;
    with_service(&state, |service| {
        service
            .apply_and_save(|service| service.delete_group(Id::from_bytes(id)))
            .map_err(error_string)
    })
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn list_items(
    window: WebviewWindow,
    state: State<'_, AppState>,
    query: String,
    filter: ItemFilterDto,
    sort: ItemSortDto,
    offset: usize,
    limit: usize,
) -> Result<Vec<ItemSummaryDto>, String> {
    authorize(&window)?;
    with_service(&state, |service| {
        service
            .query_items(&query, filter.into(), sort.into(), offset, limit)
            .map(|items| items.into_iter().map(Into::into).collect())
            .map_err(error_string)
    })
}

#[tauri::command]
fn create_login(
    window: WebviewWindow,
    state: State<'_, AppState>,
    input: LoginInputDto,
) -> Result<[u8; 16], String> {
    authorize(&window)?;
    let input = LoginInput::try_from(input)?;
    with_service(&state, |service| {
        let now = now_unix_ms()?;
        service
            .apply_and_save(|service| service.create_login(input, now))
            .map(|id| *id.as_bytes())
            .map_err(error_string)
    })
}

#[tauri::command]
fn create_secure_note(
    window: WebviewWindow,
    state: State<'_, AppState>,
    input: SecureNoteInputDto,
) -> Result<[u8; 16], String> {
    authorize(&window)?;
    let input = SecureNoteInput::try_from(input)?;
    with_service(&state, |service| {
        let now = now_unix_ms()?;
        service
            .apply_and_save(|service| service.create_secure_note(input, now))
            .map(|id| *id.as_bytes())
            .map_err(error_string)
    })
}

#[tauri::command]
fn update_login(
    window: WebviewWindow,
    state: State<'_, AppState>,
    id: [u8; 16],
    input: LoginInputDto,
) -> Result<(), String> {
    authorize(&window)?;
    let input = LoginInput::try_from(input)?;
    with_service(&state, |service| {
        let now = now_unix_ms()?;
        service
            .apply_and_save(|service| service.update_login(Id::from_bytes(id), input, now))
            .map_err(error_string)
    })
}

#[tauri::command]
fn update_secure_note(
    window: WebviewWindow,
    state: State<'_, AppState>,
    id: [u8; 16],
    input: SecureNoteInputDto,
) -> Result<(), String> {
    authorize(&window)?;
    let input = SecureNoteInput::try_from(input)?;
    with_service(&state, |service| {
        let now = now_unix_ms()?;
        service
            .apply_and_save(|service| service.update_secure_note(Id::from_bytes(id), input, now))
            .map_err(error_string)
    })
}

#[tauri::command]
fn soft_delete_item(
    window: WebviewWindow,
    state: State<'_, AppState>,
    id: [u8; 16],
) -> Result<(), String> {
    authorize(&window)?;
    with_service(&state, |service| {
        let now = now_unix_ms()?;
        service
            .apply_and_save(|service| service.soft_delete(Id::from_bytes(id), now))
            .map_err(error_string)
    })
}

#[tauri::command]
fn restore_item(
    window: WebviewWindow,
    state: State<'_, AppState>,
    id: [u8; 16],
) -> Result<(), String> {
    authorize(&window)?;
    with_service(&state, |service| {
        let now = now_unix_ms()?;
        service
            .apply_and_save(|service| service.restore(Id::from_bytes(id), now))
            .map_err(error_string)
    })
}

#[tauri::command]
fn permanently_delete_item(
    window: WebviewWindow,
    state: State<'_, AppState>,
    id: [u8; 16],
) -> Result<(), String> {
    authorize(&window)?;
    with_service(&state, |service| {
        let now = now_unix_ms()?;
        service
            .apply_and_save(|service| service.permanently_delete(Id::from_bytes(id), now))
            .map_err(error_string)
    })
}

#[tauri::command]
fn restore_item_history(
    window: WebviewWindow,
    state: State<'_, AppState>,
    id: [u8; 16],
    history_index: usize,
) -> Result<(), String> {
    authorize(&window)?;
    with_service(&state, |service| {
        let now = now_unix_ms()?;
        service
            .apply_and_save(|service| {
                service.restore_history(Id::from_bytes(id), history_index, now)
            })
            .map_err(error_string)
    })
}

#[tauri::command]
fn save_vault(window: WebviewWindow, state: State<'_, AppState>) -> Result<(), String> {
    authorize(&window)?;
    with_service(&state, |service| match service.state() {
        SessionState::Unlocked => Ok(()),
        SessionState::Dirty => service.save().map_err(error_string),
        _ => Err("vault cannot be saved in the current session state".to_owned()),
    })
}

#[tauri::command]
fn save_vault_as(
    window: WebviewWindow,
    app: AppHandle,
    state: State<'_, AppState>,
    path: String,
) -> Result<(), String> {
    authorize(&window)?;
    validate_path(&path)?;
    let result = with_service(&state, |service| {
        service.save_as(&path).map_err(error_string)
    });
    if result.is_ok()
        && let Ok(now) = now_unix_ms()
    {
        let _ = recent::record(&app, &path, now);
    }
    result
}

#[tauri::command]
fn backup_current_vault(
    window: WebviewWindow,
    state: State<'_, AppState>,
    path: String,
) -> Result<(), String> {
    authorize(&window)?;
    validate_path(&path)?;
    with_service(&state, |service| {
        service.backup_current_as(path).map_err(error_string)
    })
}

#[tauri::command]
fn save_vault_with_backup(
    window: WebviewWindow,
    state: State<'_, AppState>,
    backup_path: String,
) -> Result<(), String> {
    authorize(&window)?;
    validate_path(&backup_path)?;
    if Path::new(&backup_path).exists() {
        return Err("backup destination already exists".to_owned());
    }
    with_service(&state, |service| match service.state() {
        SessionState::Dirty => service.save_with_backup(backup_path).map_err(error_string),
        SessionState::Unlocked => service.backup_current_as(backup_path).map_err(error_string),
        _ => Err("vault cannot be backed up in the current session state".to_owned()),
    })
}

#[tauri::command]
fn restore_backup_as_new(
    window: WebviewWindow,
    source_path: String,
    destination_path: String,
    mut password: String,
) -> Result<(), String> {
    authorize(&window)?;
    validate_path(&source_path)?;
    validate_path(&destination_path)?;
    validate_secret_length(&password)?;
    let result = recover_candidate_as(source_path, destination_path, password.as_bytes())
        .map(|_| ())
        .map_err(error_string);
    password.zeroize();
    result
}

#[tauri::command]
fn replace_active_vault_from_backup(
    window: WebviewWindow,
    state: State<'_, AppState>,
    source_path: String,
    mut source_password: String,
    mut current_password: String,
    confirmed: bool,
) -> Result<String, String> {
    authorize(&window)?;
    if !confirmed {
        return Err("explicit replacement confirmation is required".to_owned());
    }
    validate_path(&source_path)?;
    validate_secret_length(&source_password)?;
    validate_secret_length(&current_password)?;
    let result = with_service(&state, |service| {
        service
            .replace_from_backup(
                source_path,
                source_password.as_bytes(),
                current_password.as_bytes(),
            )
            .map(|path| path.to_string_lossy().into_owned())
            .map_err(error_string)
    });
    source_password.zeroize();
    current_password.zeroize();
    result
}

#[tauri::command]
fn reveal_item_secret(
    window: WebviewWindow,
    state: State<'_, AppState>,
    id: [u8; 16],
    mut main_password: String,
) -> Result<RevealedSecretDto, String> {
    authorize(&window)?;
    validate_secret_length(&main_password)?;
    let result = with_service(&state, |service| {
        service
            .reauthenticate(main_password.as_bytes(), now_unix_ms()?)
            .map_err(error_string)?;
        match &service
            .item(Id::from_bytes(id))
            .map_err(error_string)?
            .payload
        {
            VaultPayload::Login(login) => Ok(RevealedSecretDto::Login {
                password: login.password.clone(),
                notes: login.notes.clone(),
            }),
            VaultPayload::SecureNote(note) => Ok(RevealedSecretDto::SecureNote {
                content: note.content.clone(),
            }),
        }
    });
    main_password.zeroize();
    result
}

#[tauri::command]
fn get_item_detail(
    window: WebviewWindow,
    state: State<'_, AppState>,
    id: [u8; 16],
) -> Result<ItemDetailDto, String> {
    authorize(&window)?;
    with_service(&state, |service| {
        let item = service.item(Id::from_bytes(id)).map_err(error_string)?;
        let history = item
            .history
            .iter()
            .enumerate()
            .map(|(index, history)| HistoryDto {
                index,
                revision: history.revision,
                title: history.title.clone(),
                updated_at_unix_ms: history.updated_at_unix_ms,
            })
            .collect();
        let (kind, usernames, password, urls, url_match_modes, notes, content, custom_fields) =
            match &item.payload {
                VaultPayload::Login(login) => (
                    ItemKindDto::Login,
                    login.usernames.clone(),
                    Some(login.password.clone()),
                    login.urls.clone(),
                    (0..login.urls.len())
                        .map(|index| login.url_match_mode(index).into())
                        .collect(),
                    Some(login.notes.clone()),
                    None,
                    login.custom_fields.iter().map(Into::into).collect(),
                ),
                VaultPayload::SecureNote(note) => (
                    ItemKindDto::SecureNote,
                    Vec::new(),
                    None,
                    Vec::new(),
                    Vec::new(),
                    None,
                    Some(note.content.clone()),
                    note.custom_fields.iter().map(Into::into).collect(),
                ),
            };
        Ok(ItemDetailDto {
            id: *item.id.as_bytes(),
            group_id: *item.group_id.as_bytes(),
            kind,
            title: item.title.clone(),
            favorite: item.favorite,
            tags: item.tags.clone(),
            usernames,
            password,
            urls,
            url_match_modes,
            notes,
            content,
            custom_fields,
            history,
        })
    })
}

#[tauri::command]
fn preview_csv_import_file(
    window: WebviewWindow,
    path: String,
    mapping: CsvMappingDto,
) -> Result<CsvPreviewDto, String> {
    authorize(&window)?;
    validate_csv_path(&path)?;
    let csv = read_csv_file_bounded(&path).map_err(error_string)?;
    let source_hash = sha256(&[csv.as_slice()]);
    let parsed = parse_csv_logins(csv.as_slice(), &mapping.into(), 100_000);
    let records = parsed.map_err(error_string)?;
    Ok(CsvPreviewDto {
        total_records: records.len(),
        source_hash,
        records: records
            .into_iter()
            .take(20)
            .map(|mut record| CsvPreviewRecordDto {
                title: std::mem::take(&mut record.title),
                username: std::mem::take(&mut record.usernames).into_iter().next(),
                url: std::mem::take(&mut record.urls).into_iter().next(),
                tag_count: record.tags.len(),
            })
            .collect(),
    })
}

#[tauri::command]
fn write_csv_import_template(window: WebviewWindow, path: String) -> Result<(), String> {
    authorize(&window)?;
    validate_path(&path)?;
    fs::write(path, CSV_IMPORT_TEMPLATE.as_bytes()).map_err(error_string)
}

#[tauri::command]
fn commit_csv_import_file(
    window: WebviewWindow,
    state: State<'_, AppState>,
    group_id: [u8; 16],
    path: String,
    expected_hash: [u8; 32],
    mapping: CsvMappingDto,
) -> Result<usize, String> {
    authorize(&window)?;
    validate_csv_path(&path)?;
    let csv = read_csv_file_bounded(&path).map_err(error_string)?;
    if sha256(&[csv.as_slice()]) != expected_hash {
        return Err("CSV file changed after preview; parse it again".to_owned());
    }
    let parsed = parse_csv_logins(csv.as_slice(), &mapping.into(), 100_000);
    let records: Vec<ImportedLogin> = parsed.map_err(error_string)?;
    let count = records.len();
    with_service(&state, |service| {
        let now = now_unix_ms()?;
        service
            .apply_and_save(|service| service.import_logins(Id::from_bytes(group_id), records, now))
            .map(|_| count)
            .map_err(error_string)
    })
}

#[tauri::command]
fn generate_password_value(
    window: WebviewWindow,
    policy: PasswordPolicyDto,
) -> Result<String, String> {
    authorize(&window)?;
    generate_password(PasswordPolicy {
        length: policy.length,
        lowercase: policy.lowercase,
        uppercase: policy.uppercase,
        digits: policy.digits,
        symbols: policy.symbols,
        exclude_ambiguous: policy.exclude_ambiguous,
    })
    .map(|secret| secret.expose_secret().to_owned())
    .map_err(error_string)
}

#[tauri::command]
fn generate_recovery_key_value(
    window: WebviewWindow,
    state: State<'_, AppState>,
    mut current_password: String,
) -> Result<String, String> {
    authorize(&window)?;
    validate_secret_length(&current_password)?;
    let result = with_service(&state, |service| {
        service
            .generate_recovery_key(current_password.as_bytes(), now_unix_ms()?)
            .map(|key| key.expose_secret().to_owned())
            .map_err(error_string)
    });
    current_password.zeroize();
    result
}

#[tauri::command]
fn confirm_recovery_key_value(
    window: WebviewWindow,
    state: State<'_, AppState>,
    mut recovery_key: String,
) -> Result<bool, String> {
    authorize(&window)?;
    validate_secret_length(&recovery_key)?;
    let result = with_service(&state, |service| {
        service
            .confirm_recovery_key(recovery_key.as_bytes())
            .map_err(error_string)
    });
    recovery_key.zeroize();
    result
}

#[tauri::command]
fn change_main_password(
    window: WebviewWindow,
    state: State<'_, AppState>,
    mut current_password: String,
    mut new_password: String,
) -> Result<(), String> {
    authorize(&window)?;
    validate_secret_length(&current_password)?;
    validate_main_password(&new_password)?;
    let result = with_service(&state, |service| {
        service
            .change_main_password(
                current_password.as_bytes(),
                new_password.as_bytes(),
                KdfParams::recommended(),
            )
            .map_err(error_string)
    });
    current_password.zeroize();
    new_password.zeroize();
    result
}

fn authorize(window: &WebviewWindow) -> Result<(), String> {
    if window.label() == MAIN_WINDOW {
        Ok(())
    } else {
        Err("IPC command is not authorized for this window".to_owned())
    }
}

fn authorize_tray_unlock(window: &WebviewWindow) -> Result<(), String> {
    if window.label() == TRAY_UNLOCK_WINDOW {
        Ok(())
    } else {
        Err("IPC command is not authorized for this window".to_owned())
    }
}

fn with_service<T>(
    state: &State<'_, AppState>,
    operation: impl FnOnce(&mut VaultService) -> Result<T, String>,
) -> Result<T, String> {
    let now = now_unix_ms()?;
    let (result, locked_by_idle) = {
        let mut service = state
            .service
            .lock()
            .map_err(|_| "application state lock was poisoned".to_owned())?;
        let was_unlocked = is_unlocked_session(service.state());
        service.lock_if_idle(now);
        let locked_by_idle = was_unlocked && service.state() == SessionState::Locked;
        let result = operation(&mut service);
        if result.is_ok() {
            service.record_activity(now);
        }
        (result, locked_by_idle)
    };
    if locked_by_idle {
        clear_extension_authorizations(state)?;
    }
    result
}

fn clear_extension_authorizations(state: &State<'_, AppState>) -> Result<(), String> {
    state
        .extension
        .lock()
        .map_err(|_| "extension service lock was poisoned".to_owned())?
        .clear_runtime_authorizations();
    Ok(())
}

const fn is_unlocked_session(state: SessionState) -> bool {
    matches!(state, SessionState::Unlocked | SessionState::Dirty)
}

fn now_unix_ms() -> Result<i64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(error_string)?;
    i64::try_from(duration.as_millis()).map_err(error_string)
}

fn validate_path(path: &str) -> Result<(), String> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES || !Path::new(path).is_absolute() {
        return Err("vault path must be a non-empty absolute path within size limits".to_owned());
    }
    Ok(())
}

fn extension_store_path() -> Result<PathBuf, String> {
    #[cfg(target_os = "macos")]
    let base = std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join("Library").join("Application Support"));
    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(all(unix, not(target_os = "macos")))]
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|home| home.join(".local").join("share"))
        });
    let base = base.ok_or("application data directory is unavailable".to_owned())?;
    Ok(base
        .join("com.vaultx.desktop")
        .join("browser-extension-v1.json"))
}

fn validate_csv_path(path: &str) -> Result<(), String> {
    validate_path(path)?;
    if !Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("csv"))
    {
        return Err("import path must point to a .csv file".to_owned());
    }
    Ok(())
}

fn validate_main_password(password: &str) -> Result<(), String> {
    validate_secret_length(password)
}

fn validate_secret_length(secret: &str) -> Result<(), String> {
    if secret.is_empty() || secret.len() > MAX_PASSWORD_BYTES {
        return Err("secret is empty or exceeds the accepted size".to_owned());
    }
    Ok(())
}

fn validate_title(title: &str) -> Result<(), String> {
    if title.trim().is_empty() || title.len() > MAX_TITLE_BYTES {
        return Err("title is empty or exceeds the accepted size".to_owned());
    }
    Ok(())
}

fn validate_text(value: &str, maximum: usize, field: &str) -> Result<(), String> {
    if value.len() > maximum {
        return Err(format!("{field} exceeds the accepted size"));
    }
    Ok(())
}

fn validate_collection(values: &[String], field: &str) -> Result<(), String> {
    if values.len() > MAX_COLLECTION_ITEMS {
        return Err(format!("{field} contains too many values"));
    }
    for value in values {
        validate_text(value, MAX_TEXT_BYTES, field)?;
    }
    Ok(())
}

fn validate_item_fields(
    title: &str,
    tags: &[String],
    usernames: &[String],
    urls: &[String],
    long_text: &str,
    custom_fields: &[CustomFieldDto],
) -> Result<(), String> {
    validate_title(title)?;
    validate_collection(tags, "tags")?;
    validate_collection(usernames, "usernames")?;
    validate_collection(urls, "URLs")?;
    validate_text(long_text, MAX_TEXT_BYTES, "text")?;
    if custom_fields.len() > MAX_COLLECTION_ITEMS {
        return Err("custom fields contain too many values".to_owned());
    }
    for field in custom_fields {
        validate_text(&field.name, MAX_TITLE_BYTES, "custom field name")?;
        validate_text(&field.value, MAX_TEXT_BYTES, "custom field value")?;
    }
    Ok(())
}

fn error_string(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn sleep_or_resume_gap_requires_lock(elapsed: Duration) -> bool {
    elapsed > Duration::from_secs(5)
}

fn persist_before_lock(service: &mut VaultService) -> bool {
    if service.state() == SessionState::Dirty && service.save().is_err() {
        return false;
    }
    matches!(
        service.state(),
        SessionState::Unlocked | SessionState::Locked
    )
}

const fn session_state_name(state: SessionState) -> &'static str {
    match state {
        SessionState::Locked => "locked",
        SessionState::Unlocked => "unlocked",
        SessionState::Dirty => "dirty",
        SessionState::Saving => "saving",
        SessionState::ConflictPending => "conflict_pending",
        SessionState::SaveResultUnknown => "save_result_unknown",
    }
}

fn show_main_window(app: &AppHandle) {
    #[cfg(target_os = "macos")]
    let _ = app.set_activation_policy(ActivationPolicy::Regular);
    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn lock_vault_from_tray(app: &AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    {
        let mut service = state
            .service
            .lock()
            .map_err(|_| "application state lock was poisoned".to_owned())?;
        if !persist_before_lock(&mut service) {
            return Err(
                "pending changes could not be saved; the vault remains unlocked".to_owned(),
            );
        }
        service.lock();
    }
    state
        .extension
        .lock()
        .map_err(|_| "extension service lock was poisoned".to_owned())?
        .clear_runtime_authorizations();
    Ok(())
}

#[cfg(target_os = "macos")]
fn show_tray_unlock(app: &AppHandle) -> tauri::Result<()> {
    let window = if let Some(window) = app.get_webview_window(TRAY_UNLOCK_WINDOW) {
        window
    } else {
        WebviewWindowBuilder::new(
            app,
            TRAY_UNLOCK_WINDOW,
            WebviewUrl::App("unlock.html".into()),
        )
        .title("Unlock StarAxis")
        .inner_size(360.0, 226.0)
        .resizable(false)
        .maximizable(false)
        .minimizable(false)
        .decorations(false)
        .always_on_top(true)
        .visible_on_all_workspaces(true)
        .skip_taskbar(true)
        .shadow(true)
        .visible(false)
        .build()?
    };
    let stored_anchor = app
        .state::<AppState>()
        .tray_anchor
        .lock()
        .ok()
        .and_then(|anchor| *anchor);
    let anchor = stored_anchor.or_else(|| {
        app.cursor_position()
            .ok()
            .map(|position| (position.x, position.y))
    });
    if let Some((x, y)) = anchor {
        let monitor = app.monitor_from_point(x, y).ok().flatten();
        let scale = monitor.as_ref().map_or_else(
            || window.scale_factor().unwrap_or(1.0),
            |value| value.scale_factor(),
        );
        let window_width = 360.0 * scale;
        let (minimum_left, maximum_left, top) = monitor.map_or_else(
            || (8.0 * scale, f64::MAX, y + 16.0 * scale),
            |value| {
                let monitor_left = f64::from(value.position().x);
                let monitor_top = f64::from(value.position().y);
                let monitor_right = monitor_left + f64::from(value.size().width);
                (
                    monitor_left + 8.0 * scale,
                    monitor_right - window_width - 8.0 * scale,
                    monitor_top + 30.0 * scale,
                )
            },
        );
        let left = (x - (window_width / 2.0)).clamp(minimum_left, maximum_left);
        let _ = window.set_position(Position::Physical(PhysicalPosition::new(
            left.round() as i32,
            top.round() as i32,
        )));
    }
    window.show()?;
    window.set_focus()?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn setup_macos_shortcuts(app: &mut tauri::App) -> tauri::Result<()> {
    // WKWebView routes standard editing shortcuts through native predefined
    // roles. Keep them in the single app submenu so Command+V works without
    // restoring the removed File/Edit/View top-level menus.
    let app_menu = SubmenuBuilder::new(app, "StarAxis")
        .undo_with_text("Undo")
        .redo_with_text("Redo")
        .separator()
        .cut_with_text("Cut")
        .copy_with_text("Copy")
        .paste_with_text("Paste")
        .select_all_with_text("Select All")
        .separator()
        .close_window_with_text("Close Window")
        .separator()
        .quit_with_text("Quit StarAxis")
        .build()?;
    let menu = MenuBuilder::new(app).item(&app_menu).build()?;
    app.set_menu(menu)?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn setup_macos_tray(app: &mut tauri::App) -> tauri::Result<()> {
    let menu = MenuBuilder::new(app)
        .text(TRAY_OPEN, "Open StarAxis")
        .text(TRAY_UNLOCK, "Unlock Vault…")
        .text(TRAY_LOCK, "Lock Vault")
        .separator()
        .text(TRAY_QUIT, "Quit StarAxis")
        .build()?;
    let mut tray = TrayIconBuilder::with_id("staraxis-menu-bar")
        .tooltip("StarAxis")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| match event.id().as_ref() {
            TRAY_OPEN => show_main_window(app),
            TRAY_UNLOCK => {
                if show_tray_unlock(app).is_err() {
                    show_main_window(app);
                }
            }
            TRAY_LOCK => {
                if lock_vault_from_tray(app).is_err() {
                    show_main_window(app);
                }
            }
            TRAY_QUIT => {
                if lock_vault_from_tray(app).is_ok() {
                    app.exit(0);
                } else {
                    show_main_window(app);
                }
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { position, .. } = event
                && let Ok(mut anchor) = tray.app_handle().state::<AppState>().tray_anchor.lock()
            {
                *anchor = Some((position.x, position.y));
            }
        });
    if let Some(icon) = app.default_window_icon().cloned() {
        tray = tray.icon(icon);
    }
    tray.build(app)?;
    Ok(())
}

/// Starts the StarAxis desktop application.
pub fn run() {
    let state = AppState::new().expect("failed to initialize StarAxis browser extension broker");
    let timer_state = state.clone();
    thread::spawn(move || {
        let mut previous_tick = Instant::now();
        loop {
            thread::sleep(Duration::from_secs(1));
            let elapsed = previous_tick.elapsed();
            previous_tick = Instant::now();
            let locked = if let Ok(mut service) = timer_state.service.lock() {
                let was_unlocked = is_unlocked_session(service.state());
                if sleep_or_resume_gap_requires_lock(elapsed) {
                    if persist_before_lock(&mut service) {
                        service.lock();
                    }
                } else if let Ok(now) = now_unix_ms() {
                    service.lock_if_idle(now);
                }
                was_unlocked && service.state() == SessionState::Locked
            } else {
                false
            };
            if locked && let Ok(mut extension) = timer_state.extension.lock() {
                extension.clear_runtime_authorizations();
            }
        }
    });
    let app = tauri::Builder::default()
        .enable_macos_default_menu(false)
        .plugin(tauri_plugin_dialog::init())
        .manage(state)
        .on_window_event(|window, event| {
            if window.label() == TRAY_UNLOCK_WINDOW {
                if matches!(event, tauri::WindowEvent::Focused(false))
                    && window.is_visible().unwrap_or(false)
                {
                    let _ = window.destroy();
                }
                return;
            }
            let state = window.state::<AppState>().inner().clone();
            let locked = if let Ok(mut service) = state.service.lock() {
                let was_unlocked = is_unlocked_session(service.state());
                match event {
                    tauri::WindowEvent::CloseRequested { api, .. } => {
                        #[cfg(target_os = "macos")]
                        {
                            api.prevent_close();
                            if window.hide().is_ok() {
                                let _ = window
                                    .app_handle()
                                    .set_activation_policy(ActivationPolicy::Accessory);
                            }
                        }
                        #[cfg(not(target_os = "macos"))]
                        {
                            if persist_before_lock(&mut service) {
                                service.lock();
                            } else {
                                api.prevent_close();
                            }
                        }
                    }
                    tauri::WindowEvent::Destroyed => {
                        if persist_before_lock(&mut service) {
                            service.lock();
                        }
                    }
                    tauri::WindowEvent::Focused(false) | tauri::WindowEvent::Resized(_) => {
                        let lock_on_minimize = service
                            .settings()
                            .map(|settings| settings.lock_on_minimize)
                            .unwrap_or(false);
                        if lock_on_minimize
                            && window.is_minimized().unwrap_or(false)
                            && persist_before_lock(&mut service)
                        {
                            service.lock();
                        }
                    }
                    _ => {}
                }
                was_unlocked && service.state() == SessionState::Locked
            } else {
                false
            };
            if locked && let Ok(mut extension) = state.extension.lock() {
                extension.clear_runtime_authorizations();
            }
        })
        .setup(|app| {
            let _main = app
                .get_webview_window(MAIN_WINDOW)
                .ok_or("main window was not created")?;
            #[cfg(target_os = "macos")]
            setup_macos_shortcuts(app)?;
            #[cfg(target_os = "macos")]
            setup_macos_tray(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_version,
            session_state,
            record_user_activity,
            list_recent_vaults,
            forget_recent_vault,
            create_vault,
            unlock_vault,
            tray_unlock_context,
            unlock_vault_from_tray,
            hide_tray_unlock,
            open_main_from_tray,
            lock_vault,
            list_groups,
            get_settings,
            update_settings,
            create_group,
            rename_group,
            delete_group,
            list_items,
            create_login,
            create_secure_note,
            update_login,
            update_secure_note,
            soft_delete_item,
            restore_item,
            permanently_delete_item,
            restore_item_history,
            save_vault,
            save_vault_as,
            backup_current_vault,
            save_vault_with_backup,
            restore_backup_as_new,
            replace_active_vault_from_backup,
            reveal_item_secret,
            get_item_detail,
            generate_password_value,
            generate_recovery_key_value,
            confirm_recovery_key_value,
            change_main_password,
            preview_csv_import_file,
            commit_csv_import_file,
            write_csv_import_template,
            list_pending_extension_pairs,
            list_paired_extensions,
            approve_extension_pairing,
            reject_extension_pairing,
            revoke_extension_pairing,
            revoke_all_extension_pairings,
        ])
        .build(tauri::generate_context!())
        .expect("failed to build StarAxis desktop application");
    app.run(|app, event| {
        #[cfg(target_os = "macos")]
        if let tauri::RunEvent::ExitRequested { api, .. } = event
            && lock_vault_from_tray(app).is_err()
        {
            api.prevent_exit();
            show_main_window(app);
        }
    });
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        MAX_PASSWORD_BYTES, app_version, sleep_or_resume_gap_requires_lock, validate_main_password,
        validate_path, validate_title,
    };

    #[test]
    fn exposes_package_version() {
        assert_eq!(app_version(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn rejects_unsafe_boundary_values() {
        assert!(validate_path("relative.vaultx").is_err());
        assert!(validate_main_password("").is_err());
        assert!(validate_title("  ").is_err());
    }

    #[test]
    fn main_password_has_no_complexity_or_minimum_length_rule() {
        assert!(validate_main_password("x").is_ok());
        assert!(validate_main_password("纯").is_ok());
        assert!(validate_main_password(" ").is_ok());
        assert!(validate_main_password(&"x".repeat(MAX_PASSWORD_BYTES + 1)).is_err());
    }

    #[test]
    fn production_security_configuration_stays_minimal() {
        let config = include_str!("../tauri.conf.json");
        let capability = include_str!("../capabilities/main.json");
        let tray_capability = include_str!("../capabilities/tray-unlock.json");
        let manifest = include_str!("../Cargo.toml");
        let executable_entry = include_str!("main.rs");
        let desktop_shell = include_str!("lib.rs");
        let vite_config = include_str!("../../vite.config.ts");

        assert!(config.contains(r#""devtools": false"#));
        assert!(config.contains("script-src 'self'"));
        assert!(config.contains("object-src 'none'"));
        assert!(config.contains("base-uri 'none'"));
        assert!(!config.contains("script-src 'unsafe-inline'"));
        assert!(!config.contains("script-src 'unsafe-eval'"));
        assert!(config.contains(r#""ext": ["panda8"]"#));
        assert!(config.contains(r#""identifier": "com.staraxis.vault""#));
        assert!(capability.contains(r#""windows": ["main"]"#));
        assert!(capability.contains(r#""core:default""#));
        assert!(capability.contains(r#""dialog:allow-open""#));
        assert!(capability.contains(r#""dialog:allow-save""#));
        assert!(tray_capability.contains(r#""windows": ["tray-unlock"]"#));
        assert!(tray_capability.contains(r#""permissions": ["core:default"]"#));
        assert!(!tray_capability.contains("dialog:"));
        assert!(!manifest.contains("tauri-plugin-shell"));
        assert!(!manifest.contains("tauri-plugin-http"));
        assert!(manifest.contains("authors.workspace = true"));
        assert!(manifest.contains(r#"default = ["custom-protocol"]"#));
        assert!(manifest.contains(r#"custom-protocol = ["tauri/custom-protocol"]"#));
        assert!(manifest.contains(r#"features = ["tray-icon"]"#));
        assert!(executable_entry.contains(r#"windows_subsystem = "windows""#));
        assert!(executable_entry.contains("not(debug_assertions)"));
        assert!(desktop_shell.contains(".enable_macos_default_menu(false)"));
        assert!(desktop_shell.contains("TrayIconBuilder::with_id"));
        assert!(desktop_shell.contains("ActivationPolicy::Accessory"));
        assert!(desktop_shell.contains("Open StarAxis"));
        assert!(desktop_shell.contains("Unlock Vault…"));
        assert!(desktop_shell.contains("Lock Vault"));
        assert!(desktop_shell.contains("Quit StarAxis"));
        assert!(desktop_shell.contains(".close_window_with_text(\"Close Window\")"));
        assert!(desktop_shell.contains(".quit_with_text(\"Quit StarAxis\")"));
        assert!(desktop_shell.contains(".undo_with_text(\"Undo\")"));
        assert!(desktop_shell.contains(".redo_with_text(\"Redo\")"));
        assert!(desktop_shell.contains(".cut_with_text(\"Cut\")"));
        assert!(desktop_shell.contains(".copy_with_text(\"Copy\")"));
        assert!(desktop_shell.contains(".paste_with_text(\"Paste\")"));
        assert!(desktop_shell.contains(".select_all_with_text(\"Select All\")"));
        assert!(vite_config.contains(r#"unlock: "unlock.html""#));
    }

    #[test]
    fn a_sleep_or_resume_timer_gap_requires_immediate_lock() {
        assert!(!sleep_or_resume_gap_requires_lock(Duration::from_secs(5)));
        assert!(sleep_or_resume_gap_requires_lock(Duration::from_secs(6)));
    }
}

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager as _};
use vault_platform::{atomic_replace_preserving_old, harden_private_file};

#[cfg(unix)]
use std::fs::File;

const MAX_RECENT_VAULTS: usize = 8;
const MAX_STORE_BYTES: u64 = 64 * 1024;
const MAX_PATH_BYTES: usize = 4_096;
const STORE_FILE_NAME: &str = "recent-vaults-v1.json";

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredRecentVault {
    path: String,
    last_opened_unix_ms: i64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct RecentVaultDto {
    path: String,
    name: String,
    parent: String,
    last_opened_unix_ms: i64,
    exists: bool,
}

pub(crate) fn list(app: &AppHandle) -> io::Result<Vec<RecentVaultDto>> {
    let entries = load(app)?;
    Ok(entries
        .into_iter()
        .map(|entry| {
            let path = Path::new(&entry.path);
            let exists = fs::symlink_metadata(path)
                .map(|metadata| metadata.file_type().is_file())
                .unwrap_or(false);
            RecentVaultDto {
                name: path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("未命名保险库")
                    .to_owned(),
                parent: path
                    .parent()
                    .map(|parent| parent.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                path: entry.path,
                last_opened_unix_ms: entry.last_opened_unix_ms,
                exists,
            }
        })
        .collect())
}

pub(crate) fn latest_existing_path(app: &AppHandle) -> io::Result<Option<String>> {
    Ok(list(app)?
        .into_iter()
        .find(|entry| entry.exists)
        .map(|entry| entry.path))
}

pub(crate) fn record(app: &AppHandle, path: &str, now_unix_ms: i64) -> io::Result<()> {
    validate_recent_path(path)?;
    let mut entries = load(app).unwrap_or_default();
    entries.retain(|entry| entry.path != path);
    entries.insert(
        0,
        StoredRecentVault {
            path: path.to_owned(),
            last_opened_unix_ms: now_unix_ms,
        },
    );
    persist(app, &normalize(entries))
}

pub(crate) fn forget(app: &AppHandle, path: &str) -> io::Result<()> {
    validate_recent_path(path)?;
    let mut entries = load(app).unwrap_or_default();
    entries.retain(|entry| entry.path != path);
    persist(app, &entries)
}

fn load(app: &AppHandle) -> io::Result<Vec<StoredRecentVault>> {
    let path = store_path(app)?;
    load_from_path(&path)
}

fn load_from_path(path: &Path) -> io::Result<Vec<StoredRecentVault>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file() || metadata.len() > MAX_STORE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "recent vault store is not a bounded regular file",
        ));
    }
    let entries: Vec<StoredRecentVault> = serde_json::from_slice(&fs::read(path)?)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(normalize(entries))
}

fn normalize(mut entries: Vec<StoredRecentVault>) -> Vec<StoredRecentVault> {
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.last_opened_unix_ms));
    let mut seen = HashSet::new();
    entries.retain(|entry| {
        validate_recent_path(&entry.path).is_ok() && seen.insert(entry.path.clone())
    });
    entries.truncate(MAX_RECENT_VAULTS);
    entries
}

fn validate_recent_path(path: &str) -> io::Result<()> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES || !Path::new(path).is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "recent vault path must be a bounded absolute path",
        ));
    }
    Ok(())
}

fn persist(app: &AppHandle, entries: &[StoredRecentVault]) -> io::Result<()> {
    let target = store_path(app)?;
    persist_to_path(&target, entries)
}

fn persist_to_path(target: &Path, entries: &[StoredRecentVault]) -> io::Result<()> {
    let directory = target
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid app config path"))?;
    fs::create_dir_all(&directory)?;
    harden_private_directory(&directory)?;

    let suffix = format!("{}-{}", std::process::id(), monotonic_suffix());
    let candidate = directory.join(format!(".{STORE_FILE_NAME}.{suffix}.tmp"));
    let rollback = directory.join(format!(".{STORE_FILE_NAME}.{suffix}.old"));
    let bytes = serde_json::to_vec(entries).map_err(io::Error::other)?;
    if bytes.len() as u64 > MAX_STORE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "recent vault store exceeds its size limit",
        ));
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&candidate)?;
    if let Err(error) = (|| {
        file.write_all(&bytes)?;
        file.sync_all()?;
        harden_private_file(&candidate)
    })() {
        let _ = fs::remove_file(&candidate);
        return Err(error);
    }
    drop(file);

    if target.exists() {
        if let Err(error) = atomic_replace_preserving_old(target, &candidate, &rollback) {
            let _ = fs::remove_file(&candidate);
            return Err(error);
        }
        let _ = fs::remove_file(rollback);
    } else {
        fs::rename(candidate, target)?;
    }
    sync_directory(&directory)
}

fn store_path(app: &AppHandle) -> io::Result<PathBuf> {
    app.path()
        .app_config_dir()
        .map(|directory| directory.join(STORE_FILE_NAME))
        .map_err(io::Error::other)
}

fn monotonic_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

#[cfg(unix)]
fn harden_private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn harden_private_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{
        MAX_RECENT_VAULTS, StoredRecentVault, load_from_path, monotonic_suffix, normalize,
        persist_to_path,
    };

    #[test]
    fn normalization_sorts_deduplicates_rejects_relative_and_caps() {
        let base = std::env::temp_dir();
        let mut entries = (0..MAX_RECENT_VAULTS + 3)
            .map(|index| StoredRecentVault {
                path: base
                    .join(format!("vault-{index}.vaultx"))
                    .to_string_lossy()
                    .into_owned(),
                last_opened_unix_ms: index as i64,
            })
            .collect::<Vec<_>>();
        entries.push(entries[2].clone());
        entries.push(StoredRecentVault {
            path: "relative.vaultx".to_owned(),
            last_opened_unix_ms: i64::MAX,
        });

        let normalized = normalize(entries);
        assert_eq!(normalized.len(), MAX_RECENT_VAULTS);
        assert!(
            normalized
                .windows(2)
                .all(|pair| pair[0].last_opened_unix_ms >= pair[1].last_opened_unix_ms)
        );
        assert!(
            normalized
                .iter()
                .all(|entry| entry.path != "relative.vaultx")
        );
    }

    #[test]
    fn recent_store_round_trips_and_replaces_without_temp_residue() {
        let directory = std::env::temp_dir().join(format!(
            "vaultx-recent-test-{}-{}",
            std::process::id(),
            monotonic_suffix()
        ));
        fs::create_dir(&directory).expect("test directory must exist");
        let target = directory.join("recent-vaults-v1.json");
        let first = StoredRecentVault {
            path: directory
                .join("first.vaultx")
                .to_string_lossy()
                .into_owned(),
            last_opened_unix_ms: 1,
        };
        persist_to_path(&target, std::slice::from_ref(&first))
            .expect("initial recent store write must succeed");
        assert_eq!(
            load_from_path(&target)
                .expect("recent store must load")
                .first()
                .map(|entry| entry.path.as_str()),
            Some(first.path.as_str())
        );

        let second = StoredRecentVault {
            path: directory
                .join("second.vaultx")
                .to_string_lossy()
                .into_owned(),
            last_opened_unix_ms: 2,
        };
        persist_to_path(&target, std::slice::from_ref(&second))
            .expect("replacement recent store write must succeed");
        assert_eq!(
            load_from_path(&target)
                .expect("replacement recent store must load")
                .first()
                .map(|entry| entry.path.as_str()),
            Some(second.path.as_str())
        );
        assert_eq!(
            fs::read_dir(&directory)
                .expect("test directory must list")
                .count(),
            1
        );
        fs::remove_dir_all(directory).expect("test directory must clean");
    }
}

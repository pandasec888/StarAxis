use std::time::Instant;

#[cfg(unix)]
use std::process::Command;

use tempfile::tempdir;
use vault_crypto::KdfParams;
use vault_import::ImportedLogin;
use vault_service::VaultService;

fn main() {
    let count = std::env::args()
        .nth(1)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(10_000);
    assert!(
        matches!(count, 10_000 | 50_000),
        "count must be 10000 or 50000"
    );
    let directory = tempdir().expect("temporary directory must exist");
    let path = directory.path().join(format!("benchmark-{count}.vaultx"));
    let mut service = VaultService::new();
    service
        .create(&path, b"benchmark password", 0, KdfParams::recommended())
        .expect("benchmark vault must be created");
    let root = service
        .groups()
        .expect("groups must list")
        .into_iter()
        .find(|group| group.parent_id.is_none())
        .expect("root group must exist")
        .id;

    let records = (0..count)
        .map(|index| ImportedLogin {
            title: format!("Benchmark entry {index:05}"),
            usernames: vec![format!("user-{index:05}@example.test")],
            password: format!("generated-secret-{index:05}-A9!"),
            urls: vec![format!("https://service-{index:05}.example.test/login")],
            notes: "representative benchmark note with local-only encrypted data".to_owned(),
            tags: vec!["benchmark".to_owned(), format!("bucket-{}", index % 100)],
        })
        .collect::<Vec<_>>();
    let import_start = Instant::now();
    service
        .import_logins(root, records, 1)
        .expect("bulk import must succeed");
    let import_ms = import_start.elapsed().as_millis();
    let rss_after_import = resident_bytes();

    let save_start = Instant::now();
    service.save().expect("benchmark vault must save");
    let save_ms = save_start.elapsed().as_millis();
    let file_bytes = std::fs::metadata(&path)
        .expect("benchmark file metadata must exist")
        .len();
    service.lock();

    let unlock_start = Instant::now();
    service
        .unlock(&path, b"benchmark password")
        .expect("benchmark vault must unlock");
    let unlock_ms = unlock_start.elapsed().as_millis();
    let rss_after_unlock = resident_bytes();
    let search_start = Instant::now();
    let found = service
        .list_items(&format!("user-{:05}", count - 1), false, 0, 20)
        .expect("benchmark search must succeed")
        .len();
    let search_micros = search_start.elapsed().as_micros();

    println!(
        "{{\"items\":{count},\"import_ms\":{import_ms},\"save_ms\":{save_ms},\"unlock_ms\":{unlock_ms},\"search_micros\":{search_micros},\"search_matches\":{found},\"rss_after_import_bytes\":{rss_after_import},\"rss_after_unlock_bytes\":{rss_after_unlock},\"file_bytes\":{file_bytes}}}"
    );
}

#[cfg(unix)]
fn resident_bytes() -> u64 {
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .expect("ps must run");
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u64>()
        .unwrap_or(0)
        .saturating_mul(1024)
}

#[cfg(windows)]
fn resident_bytes() -> u64 {
    0
}

#![doc = "Bounded, all-or-nothing importers for untrusted plaintext data."]
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const DEFAULT_RECORD_LIMIT: usize = 100_000;
pub const MAX_CSV_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_FIELD_BYTES: usize = 1024 * 1024;
pub const MAX_COLUMNS: usize = 256;
pub const CSV_IMPORT_TEMPLATE: &str = "name,login,password,url,notes,tags\nExample Account,person@example.com,replace-this-password,https://example.com,Optional notes,personal;example\n";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CsvMapping {
    pub title: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Option<String>,
}

#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct ImportedLogin {
    pub title: String,
    pub usernames: Vec<String>,
    pub password: String,
    pub urls: Vec<String>,
    pub notes: String,
    pub tags: Vec<String>,
}

/// Reads a user-selected CSV into zeroizing memory while enforcing the import size limit
/// before parsing or allocating an unbounded buffer.
pub fn read_csv_file_bounded(path: impl AsRef<Path>) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let file = File::open(path.as_ref()).map_err(|_| ImportError::FileRead)?;
    let metadata = file.metadata().map_err(|_| ImportError::FileRead)?;
    if !metadata.is_file() || metadata.len() > MAX_CSV_BYTES as u64 {
        return Err(ImportError::ResourceLimit);
    }

    let initial_capacity = usize::try_from(metadata.len())
        .unwrap_or(MAX_CSV_BYTES)
        .min(MAX_CSV_BYTES);
    let mut bytes = Zeroizing::new(Vec::with_capacity(initial_capacity));
    file.take((MAX_CSV_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ImportError::FileRead)?;
    if bytes.len() > MAX_CSV_BYTES {
        return Err(ImportError::ResourceLimit);
    }
    Ok(bytes)
}

impl fmt::Debug for ImportedLogin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ImportedLogin([REDACTED])")
    }
}

/// Parses the complete CSV before returning any records, so callers can commit atomically.
pub fn parse_csv_logins(
    bytes: &[u8],
    mapping: &CsvMapping,
    record_limit: usize,
) -> Result<Vec<ImportedLogin>, ImportError> {
    if bytes.len() > MAX_CSV_BYTES || record_limit == 0 || record_limit > DEFAULT_RECORD_LIMIT {
        return Err(ImportError::ResourceLimit);
    }
    let mut reader = csv::ReaderBuilder::new().flexible(false).from_reader(bytes);
    let headers = reader
        .headers()
        .map_err(|_| ImportError::InvalidCsv)?
        .clone();
    if headers.len() > MAX_COLUMNS {
        return Err(ImportError::ResourceLimit);
    }
    let indices = resolve_columns(&headers, mapping)?;
    let mut imported = Vec::new();
    for record in reader.records() {
        if imported.len() >= record_limit {
            return Err(ImportError::ResourceLimit);
        }
        let record = record.map_err(|_| ImportError::InvalidCsv)?;
        if record.iter().any(|field| field.len() > MAX_FIELD_BYTES) {
            return Err(ImportError::ResourceLimit);
        }
        let title = required(&record, indices.title)?;
        let password = required(&record, indices.password)?;
        if title.trim().is_empty() {
            return Err(ImportError::InvalidRecord);
        }
        imported.push(ImportedLogin {
            title: title.to_owned(),
            usernames: optional(&record, indices.username)
                .filter(|value| !value.is_empty())
                .map(|value| vec![value.to_owned()])
                .unwrap_or_default(),
            password: password.to_owned(),
            urls: optional(&record, indices.url)
                .filter(|value| !value.is_empty())
                .map(|value| vec![value.to_owned()])
                .unwrap_or_default(),
            notes: optional(&record, indices.notes)
                .unwrap_or_default()
                .to_owned(),
            tags: optional(&record, indices.tags)
                .unwrap_or_default()
                .split(';')
                .map(str::trim)
                .filter(|tag| !tag.is_empty())
                .map(str::to_owned)
                .collect(),
        });
    }
    Ok(imported)
}

struct ColumnIndices {
    title: usize,
    username: Option<usize>,
    password: usize,
    url: Option<usize>,
    notes: Option<usize>,
    tags: Option<usize>,
}

fn resolve_columns(
    headers: &csv::StringRecord,
    mapping: &CsvMapping,
) -> Result<ColumnIndices, ImportError> {
    let lookup = headers
        .iter()
        .enumerate()
        .map(|(index, header)| (header, index))
        .collect::<HashMap<_, _>>();
    let find_required = |name: &str| lookup.get(name).copied().ok_or(ImportError::MissingColumn);
    let find_optional = |name: &Option<String>| name.as_deref().map(find_required).transpose();
    Ok(ColumnIndices {
        title: find_required(&mapping.title)?,
        username: find_optional(&mapping.username)?,
        password: find_required(&mapping.password)?,
        url: find_optional(&mapping.url)?,
        notes: find_optional(&mapping.notes)?,
        tags: find_optional(&mapping.tags)?,
    })
}

fn required(record: &csv::StringRecord, index: usize) -> Result<&str, ImportError> {
    record.get(index).ok_or(ImportError::InvalidRecord)
}

fn optional(record: &csv::StringRecord, index: Option<usize>) -> Option<&str> {
    index.and_then(|index| record.get(index))
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ImportError {
    #[error("CSV file could not be read")]
    FileRead,
    #[error("CSV input is malformed")]
    InvalidCsv,
    #[error("CSV mapping refers to a missing column")]
    MissingColumn,
    #[error("CSV contains an invalid record")]
    InvalidRecord,
    #[error("CSV exceeds an import resource limit")]
    ResourceLimit,
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{
        CSV_IMPORT_TEMPLATE, CsvMapping, ImportError, MAX_CSV_BYTES, parse_csv_logins,
        read_csv_file_bounded,
    };

    fn mapping() -> CsvMapping {
        CsvMapping {
            title: "name".to_owned(),
            username: Some("login".to_owned()),
            password: "secret".to_owned(),
            url: Some("website".to_owned()),
            notes: Some("memo".to_owned()),
            tags: Some("labels".to_owned()),
        }
    }

    #[test]
    fn parses_quoted_csv_and_maps_fields() {
        let csv = b"name,login,secret,website,memo,labels\nPortal,alice,pw,https://example.test,\"line, two\",work;infra\n";
        let records = parse_csv_logins(csv, &mapping(), 20).expect("CSV must parse");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].notes, "line, two");
        assert_eq!(records[0].tags, vec!["work", "infra"]);
    }

    #[test]
    fn bundled_template_matches_the_default_mapping() {
        let template_mapping = CsvMapping {
            title: "name".to_owned(),
            username: Some("login".to_owned()),
            password: "password".to_owned(),
            url: Some("url".to_owned()),
            notes: Some("notes".to_owned()),
            tags: Some("tags".to_owned()),
        };
        let records = parse_csv_logins(CSV_IMPORT_TEMPLATE.as_bytes(), &template_mapping, 20)
            .expect("bundled CSV template must remain importable");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].title, "Example Account");
        assert_eq!(records[0].tags, vec!["personal", "example"]);
    }

    #[test]
    fn rejects_entire_import_when_any_row_is_invalid() {
        let csv = b"name,login,secret,website,memo,labels\nGood,a,pw,,,\n\"broken\n";
        assert_eq!(
            parse_csv_logins(csv, &mapping(), 20),
            Err(ImportError::InvalidCsv)
        );
    }

    #[test]
    fn errors_never_include_field_values() {
        let csv = b"other,secret\nprivate-title,private-password\n";
        assert_eq!(
            parse_csv_logins(csv, &mapping(), 20),
            Err(ImportError::MissingColumn)
        );
    }

    #[test]
    fn reads_selected_csv_with_a_hard_size_limit() {
        let directory = tempdir().expect("temporary directory must exist");
        let csv_path = directory.path().join("import.csv");
        fs::write(&csv_path, CSV_IMPORT_TEMPLATE).expect("fixture must be written");
        let bytes = read_csv_file_bounded(&csv_path).expect("CSV file must be read");
        assert_eq!(bytes.as_slice(), CSV_IMPORT_TEMPLATE.as_bytes());

        let oversized = directory.path().join("oversized.csv");
        let oversized_file = fs::File::create(&oversized).expect("fixture must be created");
        oversized_file
            .set_len((MAX_CSV_BYTES + 1) as u64)
            .expect("sparse fixture length must be set");
        assert_eq!(
            read_csv_file_bounded(&oversized),
            Err(ImportError::ResourceLimit)
        );
    }
}

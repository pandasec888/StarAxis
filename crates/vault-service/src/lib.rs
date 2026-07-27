#![doc = "StarAxis application services, session policy, search, and password tools."]
#![forbid(unsafe_code)]

mod passwords;
mod session;

pub use passwords::{
    GeneratedSecret, PassphrasePolicy, PasswordAnalysis, PasswordError, PasswordPolicy,
    analyze_password, generate_passphrase, generate_password,
};
pub use session::{
    AppSettings, GroupSummary, ItemFilter, ItemKind, ItemSort, ItemSummary, LoginInput, NewGroup,
    SecureNoteInput, ServiceError, SessionState, VaultService,
};
pub use vault_file::RecoveryKey;

/// Application display name shared by the desktop shell.
pub const APPLICATION_NAME: &str = "StarAxis";

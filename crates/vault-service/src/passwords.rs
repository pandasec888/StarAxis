use std::fmt;

use bip39::Language;
use thiserror::Error;
use vault_crypto::{CryptoError, fill_random};
use zeroize::{Zeroize, ZeroizeOnDrop};

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}:,.?";
const AMBIGUOUS: &[u8] = b"Il1O0o|`'\"";

/// Generated secret with redacted debug output and zeroization on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct GeneratedSecret(String);

impl GeneratedSecret {
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for GeneratedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GeneratedSecret([REDACTED])")
    }
}

/// Character password generation policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PasswordPolicy {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: true,
        }
    }
}

/// Word-based passphrase generation policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PassphrasePolicy {
    pub words: usize,
    pub separator: String,
}

impl Default for PassphrasePolicy {
    fn default() -> Self {
        Self {
            words: 6,
            separator: "-".to_owned(),
        }
    }
}

/// Local password-strength and exact-duplicate result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PasswordAnalysis {
    pub score: u8,
    pub estimated_guesses: u64,
    pub exact_duplicate_count: usize,
}

/// Generates a password using unbiased OS-CSPRNG sampling and guarantees every selected class.
pub fn generate_password(policy: PasswordPolicy) -> Result<GeneratedSecret, PasswordError> {
    if !(8..=128).contains(&policy.length) {
        return Err(PasswordError::InvalidLength);
    }
    let mut classes = Vec::new();
    if policy.lowercase {
        classes.push(filtered(LOWER, policy.exclude_ambiguous));
    }
    if policy.uppercase {
        classes.push(filtered(UPPER, policy.exclude_ambiguous));
    }
    if policy.digits {
        classes.push(filtered(DIGITS, policy.exclude_ambiguous));
    }
    if policy.symbols {
        classes.push(filtered(SYMBOLS, policy.exclude_ambiguous));
    }
    if classes.is_empty() || classes.iter().any(Vec::is_empty) || policy.length < classes.len() {
        return Err(PasswordError::NoUsableCharacters);
    }

    let all = classes.iter().flatten().copied().collect::<Vec<_>>();
    let mut output = Vec::with_capacity(policy.length);
    for class in &classes {
        output.push(class[random_index(class.len())?]);
    }
    while output.len() < policy.length {
        output.push(all[random_index(all.len())?]);
    }
    secure_shuffle(&mut output)?;
    let password = String::from_utf8(output).map_err(|_| PasswordError::Encoding)?;
    Ok(GeneratedSecret(password))
}

/// Generates a passphrase from the fixed 2048-word English BIP-39 list.
pub fn generate_passphrase(policy: &PassphrasePolicy) -> Result<GeneratedSecret, PasswordError> {
    if !(4..=12).contains(&policy.words)
        || policy.separator.len() > 8
        || policy.separator.chars().any(char::is_control)
    {
        return Err(PasswordError::InvalidPassphrasePolicy);
    }
    let words = Language::English.word_list();
    let selected = (0..policy.words)
        .map(|_| random_index(words.len()).map(|index| words[index]))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(GeneratedSecret(selected.join(&policy.separator)))
}

/// Runs local zxcvbn analysis and exact duplicate counting against caller-provided passwords.
#[must_use]
pub fn analyze_password(
    password: &str,
    user_inputs: &[&str],
    existing_passwords: impl IntoIterator<Item = impl AsRef<str>>,
) -> PasswordAnalysis {
    let entropy = zxcvbn::zxcvbn(password, user_inputs);
    PasswordAnalysis {
        score: u8::from(entropy.score()),
        estimated_guesses: entropy.guesses(),
        exact_duplicate_count: existing_passwords
            .into_iter()
            .filter(|existing| existing.as_ref() == password)
            .count(),
    }
}

fn filtered(source: &[u8], exclude_ambiguous: bool) -> Vec<u8> {
    source
        .iter()
        .copied()
        .filter(|character| !exclude_ambiguous || !AMBIGUOUS.contains(character))
        .collect()
}

fn random_index(upper_bound: usize) -> Result<usize, PasswordError> {
    if upper_bound == 0 || upper_bound > usize::from(u16::MAX) + 1 {
        return Err(PasswordError::NoUsableCharacters);
    }
    let zone = (usize::from(u16::MAX) + 1) / upper_bound * upper_bound;
    loop {
        let mut bytes = [0_u8; 2];
        fill_random(&mut bytes)?;
        let candidate = usize::from(u16::from_le_bytes(bytes));
        if candidate < zone {
            return Ok(candidate % upper_bound);
        }
    }
}

fn secure_shuffle(bytes: &mut [u8]) -> Result<(), PasswordError> {
    for index in (1..bytes.len()).rev() {
        let swap_with = random_index(index + 1)?;
        bytes.swap(index, swap_with);
    }
    Ok(())
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PasswordError {
    #[error("password length must be between 8 and 128")]
    InvalidLength,
    #[error("at least one non-empty character class is required")]
    NoUsableCharacters,
    #[error("passphrase policy is outside accepted bounds")]
    InvalidPassphrasePolicy,
    #[error("generated password encoding failed")]
    Encoding,
    #[error("operating system randomness failed: {0}")]
    Randomness(String),
}

impl From<CryptoError> for PasswordError {
    fn from(error: CryptoError) -> Self {
        Self::Randomness(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AMBIGUOUS, PassphrasePolicy, PasswordPolicy, analyze_password, generate_passphrase,
        generate_password,
    };

    #[test]
    fn password_obeys_all_selected_constraints() {
        let policy = PasswordPolicy::default();
        let generated = generate_password(policy).expect("generation must succeed");
        let value = generated.expose_secret().as_bytes();
        assert_eq!(value.len(), policy.length);
        assert!(value.iter().any(u8::is_ascii_lowercase));
        assert!(value.iter().any(u8::is_ascii_uppercase));
        assert!(value.iter().any(u8::is_ascii_digit));
        assert!(value.iter().any(|byte| !byte.is_ascii_alphanumeric()));
        assert!(value.iter().all(|byte| !AMBIGUOUS.contains(byte)));
    }

    #[test]
    fn passphrase_has_requested_word_count() {
        let policy = PassphrasePolicy::default();
        let generated = generate_passphrase(&policy).expect("generation must succeed");
        assert_eq!(
            generated.expose_secret().split(&policy.separator).count(),
            policy.words
        );
    }

    #[test]
    fn analysis_reports_exact_duplicates() {
        let analysis = analyze_password(
            "correct horse battery staple",
            &["alice"],
            ["other", "correct horse battery staple"],
        );
        assert_eq!(analysis.exact_duplicate_count, 1);
        assert!(analysis.score >= 2);
    }
}

#![doc = "StarAxis V1 canonical file-header codec and bounded envelope parser."]
#![forbid(unsafe_code)]

use std::collections::HashSet;

use thiserror::Error;

/// Eight-byte signature retained for `.panda8` and legacy `.vaultx` compatibility.
pub const MAGIC: [u8; 8] = *b"VAULTX\r\n";
pub const FORMAT_MAJOR: u16 = 1;
pub const FORMAT_MINOR: u16 = 0;
pub const PREAMBLE_LEN: usize = 16;
pub const HASH_LEN: usize = 32;
pub const HEADER_TAG_LEN: usize = 32;
pub const MAX_HEADER_LEN: usize = 16 * 1024;
pub const MAX_PAYLOAD_LEN: u64 = 256 * 1024 * 1024;
pub const MAX_SLOTS: usize = 8;
pub const MAX_SLOT_CIPHERTEXT: usize = 64;
pub const PASSWORD_SLOT_TYPE: u8 = 1;
pub const CIPHER_SUITE_XCHACHA20_POLY1305: u16 = 1;
pub const KDF_ARGON2ID_V13: u16 = 1;
pub const COMPRESSION_NONE: u8 = 0;
pub const HEADER_TAG_DOMAIN: &[u8] = b"vaultx/v1/header-tag";
pub const SLOT_AAD_DOMAIN: &[u8] = b"vaultx/v1/slot-aad";
pub const PAYLOAD_AAD_DOMAIN: &[u8] = b"vaultx/v1/payload-aad";

const MIN_MEMORY_KIB: u32 = 8 * 1024;
const MAX_MEMORY_KIB: u32 = 1024 * 1024;
const MAX_ITERATIONS: u32 = 10;
const MAX_PARALLELISM: u32 = 16;

/// Fixed file prefix parsed before any allocation or KDF work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Preamble {
    pub major: u16,
    pub minor: u16,
    pub header_len: u32,
}

impl Preamble {
    #[must_use]
    pub fn encode(self) -> [u8; PREAMBLE_LEN] {
        let mut output = [0_u8; PREAMBLE_LEN];
        output[..8].copy_from_slice(&MAGIC);
        output[8..10].copy_from_slice(&self.major.to_le_bytes());
        output[10..12].copy_from_slice(&self.minor.to_le_bytes());
        output[12..16].copy_from_slice(&self.header_len.to_le_bytes());
        output
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() < PREAMBLE_LEN {
            return Err(CodecError::Truncated);
        }
        if bytes[..8] != MAGIC {
            return Err(CodecError::BadMagic);
        }
        let major = u16::from_le_bytes(copy_array(&bytes[8..10])?);
        let minor = u16::from_le_bytes(copy_array(&bytes[10..12])?);
        let header_len = u32::from_le_bytes(copy_array(&bytes[12..16])?);
        if major != FORMAT_MAJOR || minor > FORMAT_MINOR {
            return Err(CodecError::UnsupportedVersion { major, minor });
        }
        if header_len == 0 || header_len as usize > MAX_HEADER_LEN {
            return Err(CodecError::HeaderTooLarge);
        }
        Ok(Self {
            major,
            minor,
            header_len,
        })
    }
}

/// Public KDF parameters. They are validated before Argon2 is invoked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KdfHeader {
    pub algorithm: u16,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: [u8; 16],
}

/// One authenticated Vault Key wrapping slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WrappingSlot {
    pub id: [u8; 16],
    pub slot_type: u8,
    pub key_generation: u32,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// Public header needed to select a wrapping slot and locate the payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicHeader {
    pub vault_id: [u8; 16],
    pub cipher_suite: u16,
    pub kdf: KdfHeader,
    pub slots: Vec<WrappingSlot>,
    pub payload_generation: u64,
    pub payload_nonce: [u8; 24],
    pub payload_len: u64,
    pub compression: u8,
    pub feature_flags: u64,
}

impl PublicHeader {
    /// Validates all attacker-controlled limits without invoking a KDF.
    pub fn validate(&self) -> Result<(), CodecError> {
        if all_zero(&self.vault_id) {
            return Err(CodecError::NilIdentifier);
        }
        if self.cipher_suite != CIPHER_SUITE_XCHACHA20_POLY1305 {
            return Err(CodecError::UnsupportedCipher(self.cipher_suite));
        }
        if self.kdf.algorithm != KDF_ARGON2ID_V13 {
            return Err(CodecError::UnsupportedKdf(self.kdf.algorithm));
        }
        if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&self.kdf.memory_kib)
            || !(1..=MAX_ITERATIONS).contains(&self.kdf.iterations)
            || !(1..=MAX_PARALLELISM).contains(&self.kdf.parallelism)
        {
            return Err(CodecError::InvalidKdfParameters);
        }
        if self.slots.is_empty() || self.slots.len() > MAX_SLOTS {
            return Err(CodecError::InvalidSlotCount);
        }
        let mut slot_ids = HashSet::with_capacity(self.slots.len());
        let mut password_slots = 0usize;
        for slot in &self.slots {
            if all_zero(&slot.id) || !slot_ids.insert(slot.id) {
                return Err(CodecError::DuplicateOrNilSlot);
            }
            if slot.key_generation == 0
                || slot.ciphertext.is_empty()
                || slot.ciphertext.len() > MAX_SLOT_CIPHERTEXT
            {
                return Err(CodecError::InvalidSlot);
            }
            if slot.slot_type == PASSWORD_SLOT_TYPE {
                password_slots += 1;
                if slot.ciphertext.len() != 48 {
                    return Err(CodecError::InvalidSlot);
                }
            }
        }
        if password_slots == 0 {
            return Err(CodecError::MissingPasswordSlot);
        }
        if self.payload_generation == 0 || !(16..=MAX_PAYLOAD_LEN).contains(&self.payload_len) {
            return Err(CodecError::InvalidPayloadLength);
        }
        if self.compression != COMPRESSION_NONE {
            return Err(CodecError::UnsupportedCompression(self.compression));
        }
        if self.feature_flags != 0 {
            return Err(CodecError::UnsupportedFeatures(self.feature_flags));
        }
        Ok(())
    }

    /// Produces the exact deterministic V1 header byte sequence.
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut output = Vec::with_capacity(256);
        output.extend_from_slice(&self.vault_id);
        push_u16(&mut output, self.cipher_suite);
        push_u16(&mut output, self.kdf.algorithm);
        push_u32(&mut output, self.kdf.memory_kib);
        push_u32(&mut output, self.kdf.iterations);
        push_u32(&mut output, self.kdf.parallelism);
        output.extend_from_slice(&self.kdf.salt);
        push_u16(
            &mut output,
            u16::try_from(self.slots.len()).map_err(|_| CodecError::InvalidSlotCount)?,
        );
        for slot in &self.slots {
            output.extend_from_slice(&slot.id);
            output.push(slot.slot_type);
            push_u32(&mut output, slot.key_generation);
            output.extend_from_slice(&slot.nonce);
            push_u16(
                &mut output,
                u16::try_from(slot.ciphertext.len()).map_err(|_| CodecError::InvalidSlot)?,
            );
            output.extend_from_slice(&slot.ciphertext);
        }
        push_u64(&mut output, self.payload_generation);
        output.extend_from_slice(&self.payload_nonce);
        push_u64(&mut output, self.payload_len);
        output.push(self.compression);
        push_u64(&mut output, self.feature_flags);
        if output.len() > MAX_HEADER_LEN {
            return Err(CodecError::HeaderTooLarge);
        }
        Ok(output)
    }

    /// Parses the deterministic V1 header and enforces all limits.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.is_empty() || bytes.len() > MAX_HEADER_LEN {
            return Err(CodecError::HeaderTooLarge);
        }
        let mut reader = Reader::new(bytes);
        let vault_id = reader.array()?;
        let cipher_suite = reader.u16()?;
        let kdf = KdfHeader {
            algorithm: reader.u16()?,
            memory_kib: reader.u32()?,
            iterations: reader.u32()?,
            parallelism: reader.u32()?,
            salt: reader.array()?,
        };
        let slot_count = usize::from(reader.u16()?);
        if slot_count == 0 || slot_count > MAX_SLOTS {
            return Err(CodecError::InvalidSlotCount);
        }
        let mut slots = Vec::with_capacity(slot_count);
        for _ in 0..slot_count {
            let id = reader.array()?;
            let slot_type = reader.u8()?;
            let key_generation = reader.u32()?;
            let nonce = reader.array()?;
            let ciphertext_len = usize::from(reader.u16()?);
            if ciphertext_len == 0 || ciphertext_len > MAX_SLOT_CIPHERTEXT {
                return Err(CodecError::InvalidSlot);
            }
            slots.push(WrappingSlot {
                id,
                slot_type,
                key_generation,
                nonce,
                ciphertext: reader.bytes(ciphertext_len)?.to_vec(),
            });
        }
        let header = Self {
            vault_id,
            cipher_suite,
            kdf,
            slots,
            payload_generation: reader.u64()?,
            payload_nonce: reader.array()?,
            payload_len: reader.u64()?,
            compression: reader.u8()?,
            feature_flags: reader.u64()?,
        };
        if !reader.is_finished() {
            return Err(CodecError::TrailingHeaderData);
        }
        header.validate()?;
        Ok(header)
    }

    /// Returns the first supported password slot.
    #[must_use]
    pub fn password_slot(&self) -> Option<&WrappingSlot> {
        self.slots
            .iter()
            .find(|slot| slot.slot_type == PASSWORD_SLOT_TYPE)
    }
}

/// Fully bounded view of one encoded vault envelope.
#[derive(Debug)]
pub struct ParsedEnvelope<'bytes> {
    pub preamble: Preamble,
    pub preamble_bytes: &'bytes [u8],
    pub header: PublicHeader,
    pub header_bytes: &'bytes [u8],
    pub corruption_hash: [u8; HASH_LEN],
    pub header_tag: [u8; HEADER_TAG_LEN],
    pub payload: &'bytes [u8],
}

/// Parses a complete envelope and rejects truncation or trailing bytes.
pub fn parse_envelope(bytes: &[u8]) -> Result<ParsedEnvelope<'_>, CodecError> {
    if bytes.len() < PREAMBLE_LEN + HASH_LEN + HEADER_TAG_LEN + 16 {
        return Err(CodecError::Truncated);
    }
    let preamble_bytes = &bytes[..PREAMBLE_LEN];
    let preamble = Preamble::parse(preamble_bytes)?;
    let header_end = PREAMBLE_LEN
        .checked_add(preamble.header_len as usize)
        .ok_or(CodecError::LengthOverflow)?;
    let hash_end = header_end
        .checked_add(HASH_LEN)
        .ok_or(CodecError::LengthOverflow)?;
    let tag_end = hash_end
        .checked_add(HEADER_TAG_LEN)
        .ok_or(CodecError::LengthOverflow)?;
    if tag_end > bytes.len() {
        return Err(CodecError::Truncated);
    }
    let header_bytes = &bytes[PREAMBLE_LEN..header_end];
    let header = PublicHeader::parse(header_bytes)?;
    let payload_len =
        usize::try_from(header.payload_len).map_err(|_| CodecError::InvalidPayloadLength)?;
    let expected_end = tag_end
        .checked_add(payload_len)
        .ok_or(CodecError::LengthOverflow)?;
    if expected_end != bytes.len() {
        return if expected_end > bytes.len() {
            Err(CodecError::Truncated)
        } else {
            Err(CodecError::TrailingFileData)
        };
    }
    Ok(ParsedEnvelope {
        preamble,
        preamble_bytes,
        header,
        header_bytes,
        corruption_hash: copy_array(&bytes[header_end..hash_end])?,
        header_tag: copy_array(&bytes[hash_end..tag_end])?,
        payload: &bytes[tag_end..expected_end],
    })
}

/// Encodes a complete envelope from already authenticated components.
pub fn encode_envelope(
    header: &PublicHeader,
    corruption_hash: &[u8; HASH_LEN],
    header_tag: &[u8; HEADER_TAG_LEN],
    payload: &[u8],
) -> Result<Vec<u8>, CodecError> {
    if header.payload_len != payload.len() as u64 {
        return Err(CodecError::InvalidPayloadLength);
    }
    let header_bytes = header.encode()?;
    let preamble = Preamble {
        major: FORMAT_MAJOR,
        minor: FORMAT_MINOR,
        header_len: u32::try_from(header_bytes.len()).map_err(|_| CodecError::HeaderTooLarge)?,
    }
    .encode();
    let mut output = Vec::with_capacity(
        PREAMBLE_LEN + header_bytes.len() + HASH_LEN + HEADER_TAG_LEN + payload.len(),
    );
    output.extend_from_slice(&preamble);
    output.extend_from_slice(&header_bytes);
    output.extend_from_slice(corruption_hash);
    output.extend_from_slice(header_tag);
    output.extend_from_slice(payload);
    Ok(output)
}

/// Exact bytes authenticated by the header HMAC.
#[must_use]
pub fn header_auth_input(
    preamble_bytes: &[u8],
    header_bytes: &[u8],
    corruption_hash: &[u8; HASH_LEN],
) -> Vec<u8> {
    let mut output = Vec::with_capacity(
        HEADER_TAG_DOMAIN.len() + preamble_bytes.len() + header_bytes.len() + HASH_LEN,
    );
    output.extend_from_slice(HEADER_TAG_DOMAIN);
    output.extend_from_slice(preamble_bytes);
    output.extend_from_slice(header_bytes);
    output.extend_from_slice(corruption_hash);
    output
}

/// Exact AAD for one wrapping slot, excluding its ciphertext.
#[must_use]
pub fn slot_aad(header: &PublicHeader, slot: &WrappingSlot) -> Vec<u8> {
    let mut output = Vec::with_capacity(128);
    output.extend_from_slice(SLOT_AAD_DOMAIN);
    output.extend_from_slice(&header.vault_id);
    push_u16(&mut output, FORMAT_MAJOR);
    push_u16(&mut output, FORMAT_MINOR);
    output.extend_from_slice(&slot.id);
    output.push(slot.slot_type);
    push_u32(&mut output, slot.key_generation);
    output.extend_from_slice(&slot.nonce);
    push_u16(&mut output, header.kdf.algorithm);
    push_u32(&mut output, header.kdf.memory_kib);
    push_u32(&mut output, header.kdf.iterations);
    push_u32(&mut output, header.kdf.parallelism);
    output.extend_from_slice(&header.kdf.salt);
    output
}

/// Exact AAD for the complete encrypted payload.
#[must_use]
pub fn payload_aad(header: &PublicHeader) -> Vec<u8> {
    let mut output = Vec::with_capacity(64);
    output.extend_from_slice(PAYLOAD_AAD_DOMAIN);
    output.extend_from_slice(&header.vault_id);
    push_u16(&mut output, FORMAT_MAJOR);
    push_u16(&mut output, FORMAT_MINOR);
    push_u16(&mut output, header.cipher_suite);
    push_u64(&mut output, header.payload_generation);
    output
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CodecError {
    #[error("file is truncated")]
    Truncated,
    #[error("file signature does not match the StarAxis vault format")]
    BadMagic,
    #[error("unsupported format version {major}.{minor}")]
    UnsupportedVersion { major: u16, minor: u16 },
    #[error("header length is outside accepted bounds")]
    HeaderTooLarge,
    #[error("length arithmetic overflow")]
    LengthOverflow,
    #[error("identifier must not be nil")]
    NilIdentifier,
    #[error("unsupported cipher suite {0}")]
    UnsupportedCipher(u16),
    #[error("unsupported KDF {0}")]
    UnsupportedKdf(u16),
    #[error("KDF parameters are outside accepted bounds")]
    InvalidKdfParameters,
    #[error("wrapping slot count is outside accepted bounds")]
    InvalidSlotCount,
    #[error("wrapping slot is invalid")]
    InvalidSlot,
    #[error("wrapping slot identifier is duplicate or nil")]
    DuplicateOrNilSlot,
    #[error("no supported password slot exists")]
    MissingPasswordSlot,
    #[error("payload length is outside accepted bounds")]
    InvalidPayloadLength,
    #[error("unsupported compression identifier {0}")]
    UnsupportedCompression(u8),
    #[error("unsupported feature flags 0x{0:x}")]
    UnsupportedFeatures(u64),
    #[error("header contains trailing bytes")]
    TrailingHeaderData,
    #[error("file contains trailing bytes")]
    TrailingFileData,
}

struct Reader<'bytes> {
    bytes: &'bytes [u8],
    position: usize,
}

impl<'bytes> Reader<'bytes> {
    const fn new(bytes: &'bytes [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn bytes(&mut self, length: usize) -> Result<&'bytes [u8], CodecError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(CodecError::LengthOverflow)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(CodecError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        copy_array(self.bytes(N)?)
    }

    fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, CodecError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    const fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }
}

fn copy_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], CodecError> {
    bytes.try_into().map_err(|_| CodecError::Truncated)
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::{
        CIPHER_SUITE_XCHACHA20_POLY1305, COMPRESSION_NONE, CodecError, FORMAT_MAJOR, FORMAT_MINOR,
        KDF_ARGON2ID_V13, KdfHeader, PASSWORD_SLOT_TYPE, Preamble, PublicHeader, WrappingSlot,
        encode_envelope, parse_envelope, payload_aad, slot_aad,
    };

    fn header() -> PublicHeader {
        PublicHeader {
            vault_id: [1_u8; 16],
            cipher_suite: CIPHER_SUITE_XCHACHA20_POLY1305,
            kdf: KdfHeader {
                algorithm: KDF_ARGON2ID_V13,
                memory_kib: 8 * 1024,
                iterations: 1,
                parallelism: 1,
                salt: [2_u8; 16],
            },
            slots: vec![WrappingSlot {
                id: [3_u8; 16],
                slot_type: PASSWORD_SLOT_TYPE,
                key_generation: 1,
                nonce: [4_u8; 24],
                ciphertext: vec![5_u8; 48],
            }],
            payload_generation: 1,
            payload_nonce: [6_u8; 24],
            payload_len: 16,
            compression: COMPRESSION_NONE,
            feature_flags: 0,
        }
    }

    #[test]
    fn header_encoding_is_deterministic() {
        let header = header();
        let first = header.encode().expect("valid header must encode");
        let second = header.encode().expect("same header must encode");
        assert_eq!(first, second);
        assert_eq!(PublicHeader::parse(&first), Ok(header));
    }

    #[test]
    fn complete_envelope_rejects_trailing_data() {
        let header = header();
        let mut bytes = encode_envelope(&header, &[7_u8; 32], &[8_u8; 32], &[9_u8; 16])
            .expect("valid envelope must encode");
        assert!(parse_envelope(&bytes).is_ok());
        bytes.push(0);
        assert_eq!(
            parse_envelope(&bytes).map(|_| ()),
            Err(CodecError::TrailingFileData)
        );
    }

    #[test]
    fn rejects_kdf_resource_attack_before_crypto() {
        let mut header = header();
        header.kdf.memory_kib = 1024 * 1024 + 1;
        assert_eq!(header.encode(), Err(CodecError::InvalidKdfParameters));
    }

    #[test]
    fn aad_binds_vault_and_generation() {
        let mut first = header();
        let slot = first.slots[0].clone();
        let first_slot_aad = slot_aad(&first, &slot);
        let first_payload_aad = payload_aad(&first);
        first.vault_id[0] ^= 1;
        first.payload_generation += 1;
        assert_ne!(first_slot_aad, slot_aad(&first, &slot));
        assert_ne!(first_payload_aad, payload_aad(&first));
    }

    #[test]
    fn future_major_is_rejected() {
        let bytes = Preamble {
            major: FORMAT_MAJOR + 1,
            minor: FORMAT_MINOR,
            header_len: 1,
        }
        .encode();
        assert!(matches!(
            Preamble::parse(&bytes),
            Err(CodecError::UnsupportedVersion { .. })
        ));
    }
}

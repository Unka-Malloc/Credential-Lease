//! Secret material at the lease boundary.
//!
//! [`SecretBytes`] is the only container this crate moves secret material
//! in. Its rules are structural, not advisory: the buffer zeroizes on drop,
//! `Debug` is a fixed redaction, and there is deliberately no `Clone` — the
//! explicit [`SecretBytes::copy_for_persistent_read`] is the only way a
//! second live buffer comes to exist, so every buffer has one accountable
//! owner. The bytes are arbitrary; nothing requires UTF-8 until
//! [`SecretBytes::expose_utf8`] is asked.
//!
//! Two size bounds apply, and they are not the same invariant.
//! [`MAX_SECRET_BYTES`] is the container's memory ceiling — it exists so a
//! corrupt or hostile length can never claim unbounded memory — while
//! `LeasedCredential::new` enforces the contract's tighter per-credential
//! [`MAX_CREDENTIAL_BYTES`](crate::MAX_CREDENTIAL_BYTES). A buffer this
//! module accepts may therefore still be refused by the credential
//! contract with `credential_lease_secret_invalid`: custody-side material
//! is not confined to a credential's payload size, and keeping the bounds
//! separate keeps the two refusals distinct.

use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// The largest buffer [`SecretBytes`] holds at all: 1 MiB.
///
/// This is the container bound, deliberately wider than the per-credential
/// [`MAX_CREDENTIAL_BYTES`](crate::MAX_CREDENTIAL_BYTES) — see the module
/// documentation for why the two bounds stay separate.
pub const MAX_SECRET_BYTES: usize = 1024 * 1024;

/// A refusal from the secret boundary. `Display` renders the stable
/// refusal code and never carries any part of the rejected material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretBytesError {
    /// An empty buffer: the contract never carries a zero-length secret.
    Empty,
    /// The buffer exceeded [`MAX_SECRET_BYTES`].
    Oversize,
    /// The bytes are not UTF-8: [`SecretBytes::expose_utf8`] refuses rather
    /// than lossy-converting secret material.
    NotUtf8,
}

impl fmt::Display for SecretBytesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "credential_lease_secret_empty",
            Self::Oversize => "credential_lease_secret_oversize",
            Self::NotUtf8 => "credential_lease_secret_not_utf8",
        })
    }
}

impl std::error::Error for SecretBytesError {}

/// Arbitrary secret bytes under the lease boundary's rules.
///
/// Admission is only through [`SecretBytes::try_from_bytes`] or
/// [`SecretBytes::try_from_string`], which refuse empty and oversize
/// buffers. The bytes are arbitrary — binary material is a first-class
/// secret. The buffer zeroizes on drop and `Debug` prints a fixed
/// redaction, so secret material never reaches a log line or an error
/// message.
pub struct SecretBytes {
    bytes: Zeroizing<Vec<u8>>,
}

impl SecretBytes {
    /// Take ownership of a buffer as secret material, refusing an empty or
    /// oversize one. The buffer is wrapped in `Zeroizing` before any check
    /// runs, so rejected material is still scrubbed on drop.
    ///
    /// The bound applied here is [`MAX_SECRET_BYTES`]; the tighter
    /// per-credential [`MAX_CREDENTIAL_BYTES`](crate::MAX_CREDENTIAL_BYTES)
    /// is enforced later by `LeasedCredential::new`.
    pub fn try_from_bytes(bytes: Vec<u8>) -> Result<Self, SecretBytesError> {
        let bytes = Zeroizing::new(bytes);
        if bytes.is_empty() {
            return Err(SecretBytesError::Empty);
        }
        if bytes.len() > MAX_SECRET_BYTES {
            return Err(SecretBytesError::Oversize);
        }
        Ok(Self { bytes })
    }

    /// The string spelling of [`Self::try_from_bytes`]: the string's bytes
    /// become the secret as its allocation moves into the zeroizing
    /// buffer.
    pub fn try_from_string(value: String) -> Result<Self, SecretBytesError> {
        Self::try_from_bytes(value.into_bytes())
    }

    /// Borrow the secret bytes — the only plaintext view the type gives.
    /// The borrow dies with `self`, so it can never outlive the owner that
    /// zeroizes on drop.
    pub fn expose_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrow the secret as UTF-8 text. Arbitrary binary material is
    /// refused with [`SecretBytesError::NotUtf8`] — secret bytes are never
    /// lossy-converted.
    pub fn expose_utf8(&self) -> Result<&str, SecretBytesError> {
        std::str::from_utf8(&self.bytes).map_err(|_| SecretBytesError::NotUtf8)
    }

    /// Produce an independently-owned copy for a persistent read — a
    /// handoff projection or a resolve result carries its own zeroizing
    /// buffer rather than aliasing the lease's. This explicit copy is the
    /// only duplication the contract allows, which is why the type is not
    /// `Clone`.
    pub fn copy_for_persistent_read(&self) -> Self {
        Self {
            bytes: Zeroizing::new(self.bytes.to_vec()),
        }
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([redacted])")
    }
}

impl Zeroize for SecretBytes {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

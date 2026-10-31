use std::fmt;
use zeroize::{Zeroize, Zeroizing};
pub const MAX_SECRET_BYTES: usize = 1024 * 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretBytesError {
    Empty,
    Oversize,
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
pub struct SecretBytes {
    bytes: Zeroizing<Vec<u8>>,
}
impl SecretBytes {
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
    pub fn try_from_string(value: String) -> Result<Self, SecretBytesError> {
        Self::try_from_bytes(value.into_bytes())
    }
    pub fn expose_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn expose_utf8(&self) -> Result<&str, SecretBytesError> {
        std::str::from_utf8(&self.bytes).map_err(|_| SecretBytesError::NotUtf8)
    }
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

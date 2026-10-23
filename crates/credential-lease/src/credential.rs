//! One leased credential.
//!
//! Identity and expiry travel with the secret so authorization selection and
//! storage validity remain enforceable after the receiving process has
//! started.

use anyhow::{ensure, Result};
use licoup_foundation::core::secret_bytes::SecretBytes;
use std::fmt;

/// Maximum credentials one handoff or lease may carry.
pub const MAX_LEASED_CREDENTIALS: usize = 64;

/// Maximum secret bytes one credential may carry.
pub const MAX_CREDENTIAL_BYTES: usize = 8 * 1024;

/// Upper bound for a lease duration. One year and a day covers long-lived
/// custody grants while keeping the wire value finite and bounded.
pub const MAX_LEASE_DURATION_SECONDS: u64 = 366 * 24 * 60 * 60;

/// One authorized credential carried by an ephemeral handoff.
pub struct LeasedCredential {
    credential_id: String,
    secret: SecretBytes,
    expires_at_epoch_seconds: Option<u64>,
}

impl LeasedCredential {
    /// Create a credential. The id must be a canonical UUID; the secret must
    /// be nonempty and within [`MAX_CREDENTIAL_BYTES`]; a storage expiry, when
    /// present, must be positive.
    pub fn new(
        credential_id: String,
        secret: SecretBytes,
        expires_at_epoch_seconds: Option<u64>,
    ) -> Result<Self> {
        ensure!(
            uuid::Uuid::parse_str(&credential_id)
                .is_ok_and(|value| value.to_string() == credential_id),
            "credential_lease_id_invalid"
        );
        let secret_len = secret.expose_bytes().len();
        ensure!(
            (1..=MAX_CREDENTIAL_BYTES).contains(&secret_len),
            "credential_lease_secret_invalid"
        );
        if let Some(expires_at) = expires_at_epoch_seconds {
            ensure!(expires_at > 0, "credential_lease_expires_at_invalid");
        }
        Ok(Self {
            credential_id,
            secret,
            expires_at_epoch_seconds,
        })
    }

    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    pub fn expires_at_epoch_seconds(&self) -> Option<u64> {
        self.expires_at_epoch_seconds
    }

    pub fn is_expired(&self, now_epoch_seconds: u64) -> bool {
        self.expires_at_epoch_seconds
            .is_some_and(|expires_at| now_epoch_seconds >= expires_at)
    }

    /// Copy the secret under `persistent_read` so a handoff projection or a
    /// resolve result owns its own zeroizing bytes.
    pub fn copy_secret(&self) -> SecretBytes {
        self.secret.copy_for_persistent_read()
    }
}

impl fmt::Debug for LeasedCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeasedCredential")
            .field("credential_id", &self.credential_id)
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .field("secret", &"[redacted]")
            .finish()
    }
}

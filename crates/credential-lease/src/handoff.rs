//! The custody-to-runtime handoff document.
//!
//! A handoff is a portable, JSON-encodable projection of unlocked
//! credentials. It carries secret material between the unlocking process and
//! one runtime over a process-local channel such as an inherited file
//! descriptor; it is never written to disk. Parsing fails closed so a
//! truncated or tampered document can never become a partial credential set.
//!
//! The document schema is pinned by the credential kind family, so a handoff
//! minted for one family cannot parse as another.

use crate::credential::{LeasedCredential, MAX_LEASED_CREDENTIALS, MAX_LEASE_DURATION_SECONDS};
use crate::kind::CredentialKind;
use anyhow::{anyhow, ensure, Result};
use licoup_foundation::core::secret_bytes::SecretBytes;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

/// A portable projection of unlocked credentials for one kind family.
pub struct CredentialHandoff<K: CredentialKind> {
    credentials: BTreeMap<K, Vec<LeasedCredential>>,
    lease_duration: Duration,
    epoch: String,
}

impl<K: CredentialKind> CredentialHandoff<K> {
    /// The kind families this handoff carries, in deterministic order.
    pub fn kinds(&self) -> impl Iterator<Item = K> + '_ {
        self.credentials.keys().copied()
    }

    /// Drop every credential whose id is not in the authorized set. Entries
    /// left empty are removed entirely.
    pub fn retain_credential_ids(&mut self, credential_ids: &BTreeSet<String>) {
        for credentials in self.credentials.values_mut() {
            credentials.retain(|credential| credential_ids.contains(credential.credential_id()));
        }
        self.credentials
            .retain(|_, credentials| !credentials.is_empty());
    }

    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }

    pub fn lease_duration(&self) -> Duration {
        self.lease_duration
    }

    pub fn epoch(&self) -> &str {
        &self.epoch
    }

    pub(crate) fn into_parts(self) -> (BTreeMap<K, Vec<LeasedCredential>>, Duration, String) {
        (self.credentials, self.lease_duration, self.epoch)
    }

    /// Construct a handoff. The epoch must be a canonical UUID; the
    /// credential map must satisfy the shared inventory bounds.
    pub fn new(
        credentials: BTreeMap<K, Vec<LeasedCredential>>,
        lease_duration: Duration,
        epoch: String,
    ) -> Result<Self> {
        ensure!(
            uuid::Uuid::parse_str(&epoch).is_ok_and(|value| value.to_string() == epoch),
            "credential_lease_epoch_invalid"
        );
        ensure!(
            (1..=MAX_LEASE_DURATION_SECONDS).contains(&lease_duration.as_secs()),
            "credential_lease_duration_invalid"
        );
        validate_credentials(&credentials, "credential_lease_inventory_invalid")?;
        Ok(Self {
            credentials,
            lease_duration,
            epoch,
        })
    }

    /// Serialize the handoff as a closed JSON document. Secret bytes appear
    /// only as arrays of byte numbers; no serde derive touches
    /// secret-bearing types.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        let credentials: Vec<serde_json::Value> = self
            .credentials
            .iter()
            .map(|(kind, keys)| {
                serde_json::json!({
                    "kind": kind.as_str(),
                    "keys": keys
                        .iter()
                        .map(|key| serde_json::json!({
                            "credentialId": key.credential_id(),
                            "expiresAtEpochSeconds": key.expires_at_epoch_seconds(),
                            "secret": key.copy_secret().expose_bytes().to_vec(),
                        }))
                        .collect::<Vec<serde_json::Value>>(),
                })
            })
            .collect();
        let document = serde_json::json!({
            "schemaVersion": K::HANDOFF_SCHEMA,
            "leaseDurationSeconds": self.lease_duration.as_secs(),
            "epoch": self.epoch,
            "credentials": credentials,
        });
        Ok(serde_json::to_vec(&document)?)
    }

    /// Parse and fully validate a handoff document for this kind family.
    /// Every malformed shape fails closed with the same
    /// `credential_lease_handoff_invalid` code, and a document minted under a
    /// different family's schema can never cross over.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let invalid = || anyhow!("credential_lease_handoff_invalid");
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        let object = value.as_object().ok_or_else(invalid)?;
        for key in object.keys() {
            ensure!(
                matches!(
                    key.as_str(),
                    "schemaVersion" | "leaseDurationSeconds" | "epoch" | "credentials"
                ),
                "credential_lease_handoff_invalid"
            );
        }
        ensure!(
            object
                .get("schemaVersion")
                .and_then(serde_json::Value::as_str)
                == Some(K::HANDOFF_SCHEMA),
            "credential_lease_handoff_invalid"
        );
        let lease_seconds = object
            .get("leaseDurationSeconds")
            .and_then(serde_json::Value::as_u64)
            .filter(|value| (1..=MAX_LEASE_DURATION_SECONDS).contains(value))
            .ok_or_else(invalid)?;
        let epoch = object
            .get("epoch")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(invalid)?
            .to_owned();
        ensure!(
            uuid::Uuid::parse_str(&epoch).is_ok_and(|value| value.to_string() == epoch),
            "credential_lease_handoff_invalid"
        );
        let entries = object
            .get("credentials")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(invalid)?;
        let mut credentials = BTreeMap::<K, Vec<LeasedCredential>>::new();
        let mut credential_ids = BTreeSet::new();
        let mut total_keys = 0usize;
        for entry in entries {
            let entry_object = entry.as_object().ok_or_else(invalid)?;
            ensure!(
                entry_object
                    .keys()
                    .all(|field| matches!(field.as_str(), "kind" | "keys")),
                "credential_lease_handoff_invalid"
            );
            let kind_value = entry_object
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(invalid)?;
            let kind = K::from_str(kind_value).ok_or_else(invalid)?;
            ensure!(
                !credentials.contains_key(&kind),
                "credential_lease_handoff_invalid"
            );
            let keys = entry_object
                .get("keys")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(invalid)?;
            ensure!(!keys.is_empty(), "credential_lease_handoff_invalid");
            let mut secrets = Vec::with_capacity(keys.len());
            for key in keys {
                let key_object = key.as_object().ok_or_else(invalid)?;
                ensure!(
                    key_object.keys().all(|field| matches!(
                        field.as_str(),
                        "credentialId" | "expiresAtEpochSeconds" | "secret"
                    )),
                    "credential_lease_handoff_invalid"
                );
                let credential_id = key_object
                    .get("credentialId")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(invalid)?
                    .to_owned();
                ensure!(
                    credential_ids.insert(credential_id.clone()),
                    "credential_lease_handoff_invalid"
                );
                let expires_at_epoch_seconds = match key_object.get("expiresAtEpochSeconds") {
                    Some(value) if value.is_null() => None,
                    Some(value) => Some(
                        value
                            .as_u64()
                            .filter(|value| *value > 0)
                            .ok_or_else(invalid)?,
                    ),
                    None => return Err(invalid()),
                };
                let key_bytes = key_object
                    .get("secret")
                    .and_then(serde_json::Value::as_array)
                    .ok_or_else(invalid)?
                    .iter()
                    .map(|byte| {
                        byte.as_u64()
                            .and_then(|value| u8::try_from(value).ok())
                            .ok_or_else(invalid)
                    })
                    .collect::<Result<Vec<u8>>>()?;
                secrets.push(
                    LeasedCredential::new(
                        credential_id,
                        SecretBytes::try_from_bytes(key_bytes).map_err(|_| invalid())?,
                        expires_at_epoch_seconds,
                    )
                    .map_err(|_| invalid())?,
                );
            }
            total_keys += secrets.len();
            ensure!(
                total_keys <= MAX_LEASED_CREDENTIALS,
                "credential_lease_handoff_invalid"
            );
            credentials.insert(kind, secrets);
        }
        Self::new(credentials, Duration::from_secs(lease_seconds), epoch).map_err(|_| invalid())
    }
}

impl<K: CredentialKind> fmt::Debug for CredentialHandoff<K> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialHandoff")
            .field("kind_count", &self.credentials.len())
            .field("lease_duration_seconds", &self.lease_duration.as_secs())
            .field("credentials", &"[redacted]")
            .finish()
    }
}

pub(crate) fn validate_credentials<K: CredentialKind>(
    credentials: &BTreeMap<K, Vec<LeasedCredential>>,
    error_code: &'static str,
) -> Result<()> {
    ensure!(
        credentials.values().all(|values| !values.is_empty())
            && credentials.values().map(Vec::len).sum::<usize>() <= MAX_LEASED_CREDENTIALS,
        error_code
    );
    let mut ids = BTreeSet::new();
    for credential in credentials.values().flatten() {
        ensure!(
            uuid::Uuid::parse_str(credential.credential_id())
                .is_ok_and(|value| value.to_string() == credential.credential_id())
                && ids.insert(credential.credential_id())
                && credential
                    .expires_at_epoch_seconds()
                    .is_none_or(|expires_at| expires_at > 0),
            error_code
        );
    }
    Ok(())
}

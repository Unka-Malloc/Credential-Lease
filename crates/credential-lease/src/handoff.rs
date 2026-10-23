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

use crate::credential::{
    LeasedCredential, MAX_CREDENTIAL_BYTES, MAX_LEASED_CREDENTIALS, MAX_LEASE_DURATION_SECONDS,
};
use crate::kind::CredentialKind;
use anyhow::{anyhow, ensure, Result};
use licoup_foundation::core::secret_bytes::SecretBytes;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

/// Upper bound on a kind family's schema name.
pub const MAX_HANDOFF_SCHEMA_BYTES: usize = 128;

/// Upper bound on one kind name inside a handoff document.
pub const MAX_KIND_NAME_BYTES: usize = 64;

/// Upper bound on a serialized handoff document, derived from the
/// credential inventory bounds: every credential serializes to an id, an
/// expiry, and a byte array of at most ~4 characters per secret byte, plus
/// per-entry, per-key, and document structure overhead. Inputs above the
/// bound are refused before any parsing work begins, and serialization
/// refuses to produce a document above it.
pub const MAX_HANDOFF_DOC_BYTES: usize =
    MAX_LEASED_CREDENTIALS * (MAX_CREDENTIAL_BYTES * 4 + 192) + 8192;

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

    /// Serialize the handoff as a closed JSON document. The output is a
    /// [`SecretBytes`] so the serialized secret material zeroizes on drop.
    ///
    /// The buffer is reserved to a computed upper bound before writing, so
    /// it never grows: exactly one allocation holds secret material, and it
    /// moves straight into the returned `SecretBytes` — no intermediate
    /// `Value`, `Vec<u8>`, or freed plaintext remnants are produced.
    pub fn to_json(&self) -> Result<SecretBytes> {
        ensure!(
            K::HANDOFF_SCHEMA.len() <= MAX_HANDOFF_SCHEMA_BYTES
                && self
                    .credentials
                    .keys()
                    .all(|kind| kind.as_str().len() <= MAX_KIND_NAME_BYTES),
            "credential_lease_handoff_invalid"
        );
        let mut document = String::with_capacity(self.serialized_len_upper_bound());
        document.push_str("{\"schemaVersion\":");
        push_json_string(&mut document, K::HANDOFF_SCHEMA);
        document.push_str(",\"leaseDurationSeconds\":");
        document.push_str(&self.lease_duration.as_secs().to_string());
        document.push_str(",\"epoch\":");
        push_json_string(&mut document, &self.epoch);
        document.push_str(",\"credentials\":[");
        for (index, (kind, keys)) in self.credentials.iter().enumerate() {
            if index > 0 {
                document.push(',');
            }
            document.push_str("{\"kind\":");
            push_json_string(&mut document, kind.as_str());
            document.push_str(",\"keys\":[");
            for (key_index, key) in keys.iter().enumerate() {
                if key_index > 0 {
                    document.push(',');
                }
                document.push_str("{\"credentialId\":");
                push_json_string(&mut document, key.credential_id());
                document.push_str(",\"expiresAtEpochSeconds\":");
                match key.expires_at_epoch_seconds() {
                    Some(expires_at) => document.push_str(&expires_at.to_string()),
                    None => document.push_str("null"),
                }
                document.push_str(",\"secret\":[");
                for (byte_index, byte) in key.expose_secret().iter().enumerate() {
                    if byte_index > 0 {
                        document.push(',');
                    }
                    push_decimal(&mut document, *byte);
                }
                document.push_str("]}");
            }
            document.push_str("]}");
        }
        document.push_str("]}");
        ensure!(
            document.len() <= MAX_HANDOFF_DOC_BYTES,
            "credential_lease_handoff_invalid"
        );
        SecretBytes::try_from_bytes(document.into_bytes())
            .map_err(|_| anyhow!("credential_lease_handoff_serialize_failed"))
    }

    /// An upper bound on this handoff's serialized length: every structural
    /// byte plus, for each embedded string, its exact escaped JSON length,
    /// and at most 4 characters per secret byte. Reserving this much means
    /// the document string never re-allocates while secrets are being
    /// written into it — escaping cannot exceed the reserve.
    pub(crate) fn serialized_len_upper_bound(&self) -> usize {
        let mut length = 96 + escaped_len(K::HANDOFF_SCHEMA) + escaped_len(&self.epoch) + 20;
        for (kind, keys) in &self.credentials {
            length += 32 + escaped_len(kind.as_str());
            for key in keys {
                length += 96
                    + escaped_len(key.credential_id())
                    + key.expires_at_epoch_seconds().map_or(4, decimal_digits)
                    + key.expose_secret().len() * 4;
            }
        }
        length
    }

    /// Parse and fully validate a handoff document for this kind family.
    /// Every malformed shape fails closed with the same
    /// `credential_lease_handoff_invalid` code, and a document minted under a
    /// different family's schema can never cross over. Inputs beyond
    /// [`MAX_HANDOFF_DOC_BYTES`] are refused before parsing, and duplicate
    /// object member names are refused — a closed contract has no
    /// last-wins semantics for a strict parser to guess at.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let invalid = || anyhow!("credential_lease_handoff_invalid");
        ensure!(
            bytes.len() <= MAX_HANDOFF_DOC_BYTES,
            "credential_lease_handoff_invalid"
        );
        let StrictValue(value): StrictValue =
            serde_json::from_slice(bytes).map_err(|_| invalid())?;
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
                .filter(|value| value.len() <= MAX_KIND_NAME_BYTES)
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

fn decimal_digits(mut value: u64) -> usize {
    let mut digits = 1;
    while value >= 10 {
        value /= 10;
        digits += 1;
    }
    digits
}

/// Append a byte's decimal form straight into the document — no temporary
/// allocation is produced per byte.
fn push_decimal(buffer: &mut String, value: u8) {
    if value >= 100 {
        buffer.push((b'0' + value / 100) as char);
    }
    if value >= 10 {
        buffer.push((b'0' + value / 10 % 10) as char);
    }
    buffer.push((b'0' + value % 10) as char);
}

/// The exact byte length [`push_json_string`] emits for `value`, including
/// the surrounding quotes. Sizing with escaped lengths — not raw lengths —
/// keeps the document buffer's no-growth invariant true for
/// control-character and multi-byte names.
fn escaped_len(value: &str) -> usize {
    2 + value
        .chars()
        .map(|character| match character {
            '"' | '\\' | '\n' | '\r' | '\t' => 2,
            character if character < ' ' => 6,
            character => character.len_utf8(),
        })
        .sum::<usize>()
}

/// Append `value` as a JSON string literal with the escaping the contract
/// requires — control characters, quotes, and backslashes are the only
/// escapes a conforming producer needs.
fn push_json_string(buffer: &mut String, value: &str) {
    buffer.push('"');
    for character in value.chars() {
        match character {
            '"' => buffer.push_str("\\\""),
            '\\' => buffer.push_str("\\\\"),
            '\n' => buffer.push_str("\\n"),
            '\r' => buffer.push_str("\\r"),
            '\t' => buffer.push_str("\\t"),
            character if character < ' ' => {
                buffer.push_str("\\u00");
                buffer.push((b'0' + (character as u8 >> 4)) as char);
                buffer.push(match character as u8 & 0x0f {
                    digit @ 0..=9 => (b'0' + digit) as char,
                    digit => (b'a' + digit - 10) as char,
                });
            }
            character => buffer.push(character),
        }
    }
    buffer.push('"');
}

/// A JSON value parsed under the contract's closed-document rules: every
/// object member name must be unique, so a duplicate name rejects the whole
/// document instead of silently keeping the last write.
struct StrictValue(serde_json::Value);

impl<'de> serde::Deserialize<'de> for StrictValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> serde::de::Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a handoff document")
    }

    fn visit_bool<E>(self, value: bool) -> Result<StrictValue, E> {
        Ok(StrictValue(serde_json::Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<StrictValue, E> {
        Ok(StrictValue(serde_json::Value::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<StrictValue, E> {
        Ok(StrictValue(serde_json::Value::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<StrictValue, E> {
        Ok(StrictValue(
            serde_json::Number::from_f64(value)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null),
        ))
    }

    fn visit_str<E>(self, value: &str) -> Result<StrictValue, E> {
        Ok(StrictValue(serde_json::Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<StrictValue, E> {
        Ok(StrictValue(serde_json::Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<StrictValue, E> {
        Ok(StrictValue(serde_json::Value::Null))
    }

    fn visit_unit<E>(self) -> Result<StrictValue, E> {
        Ok(StrictValue(serde_json::Value::Null))
    }

    fn visit_some<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<StrictValue, D::Error> {
        <StrictValue as serde::Deserialize>::deserialize(deserializer)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(
        self,
        mut access: A,
    ) -> Result<StrictValue, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = access.next_element::<StrictValue>()? {
            items.push(item.0);
        }
        Ok(StrictValue(serde_json::Value::Array(items)))
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(
        self,
        mut access: A,
    ) -> Result<StrictValue, A::Error> {
        let mut map = serde_json::Map::new();
        while let Some(key) = access.next_key::<String>()? {
            let value = access.next_value::<StrictValue>()?;
            if map.insert(key, value.0).is_some() {
                return Err(serde::de::Error::custom("duplicate member name"));
            }
        }
        Ok(StrictValue(serde_json::Value::Object(map)))
    }
}

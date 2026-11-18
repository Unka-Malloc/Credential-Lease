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
use crate::egress::{EgressScope, WireEgress, MAX_EGRESS_DOC_BYTES};
use crate::kind::CredentialKind;
use crate::SecretBytes;
use anyhow::{anyhow, ensure, Result};
use serde::de::{DeserializeSeed, Error as DeError, MapAccess, SeqAccess, Visitor};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

/// Upper bound on a kind family's schema name.
pub const MAX_HANDOFF_SCHEMA_BYTES: usize = 128;

/// Upper bound on one kind name inside a handoff document.
pub const MAX_KIND_NAME_BYTES: usize = 64;

/// Upper bound on a serialized handoff document, covering the worst case
/// every admitted inventory can produce: each credential serializes to an
/// id, an expiry, and at most 4 characters per secret byte; each kind entry
/// adds its structure plus a name that may escape to 6 bytes per name byte;
/// the document head adds the schema constant (escaping to at most 6 bytes
/// per schema byte), epoch, field names, and the largest egress scope the
/// constructor admits. Inputs above the bound are refused before any
/// parsing work begins, and every inventory the constructor admits
/// serializes within it.
pub const MAX_HANDOFF_DOC_BYTES: usize =
    MAX_LEASED_CREDENTIALS * (MAX_CREDENTIAL_BYTES * 4 + 576) + 16 * 1024 + MAX_EGRESS_DOC_BYTES;

/// A serialized handoff document. The document is secret-bearing — it
/// embeds every credential in the clear — so the buffer zeroizes on drop
/// like [`SecretBytes`], and [`Zeroize`] is implemented for explicit early
/// erasure. It is bounded by [`MAX_HANDOFF_DOC_BYTES`] rather than the
/// per-secret limit, which a full credential inventory can legitimately
/// exceed.
pub struct HandoffDocument(Vec<u8>);

impl HandoffDocument {
    /// Borrow the serialized document bytes.
    pub fn expose_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Test-only: explicitly zeroize and report whether every previously
    /// initialized byte is zero and the logical buffer is empty.
    #[cfg(test)]
    pub(crate) fn zeroize_and_inspect(&mut self) -> bool {
        let length = self.0.len();
        self.zeroize();
        // SAFETY: `Vec::zeroize` overwrites the initialized bytes before it
        // clears the length and does not release or shrink the allocation,
        // so `length` readable bytes remain at the same backing pointer.
        let scrubbed = unsafe { std::slice::from_raw_parts(self.0.as_ptr(), length) };
        self.0.is_empty() && scrubbed.iter().all(|byte| *byte == 0)
    }
}

impl Zeroize for HandoffDocument {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for HandoffDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HandoffDocument([redacted])")
    }
}

impl Drop for HandoffDocument {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The wall-clock deadline an owner grant authorizes, in epoch seconds:
/// `SystemTime` at grant time plus the granted duration. It travels in the
/// handoff document so a rebuilt lease can never outlive the original
/// grant — extending past it requires a fresh owner grant, not another
/// projection.
pub(crate) fn lease_deadline_epoch_seconds(lease_duration: Duration) -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow!("credential_lease_clock_invalid"))?
        .as_secs()
        .checked_add(lease_duration.as_secs())
        .ok_or_else(|| anyhow!("credential_lease_expiry_invalid"))
}

/// A portable projection of unlocked credentials for one kind family.
pub struct CredentialHandoff<K: CredentialKind> {
    credentials: BTreeMap<K, Vec<LeasedCredential>>,
    lease_duration: Duration,
    epoch: String,
    egress: EgressScope,
    lease_expires_at_epoch_seconds: u64,
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

    /// Whether the handoff carries no credentials at all.
    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }

    /// The lease duration the receiving runtime mints its lease with. For
    /// a lease projection this is the grant's remaining time, not the
    /// original duration — the runtime can never be granted back more than
    /// was left.
    pub fn lease_duration(&self) -> Duration {
        self.lease_duration
    }

    /// The custody epoch the handoff was minted under — the receiving
    /// lease dies the moment this no longer matches the active epoch.
    pub fn epoch(&self) -> &str {
        &self.epoch
    }

    /// The egress scope the custody owner declared: the only outbound
    /// targets a runtime's proxy may move this credential material to.
    /// A document that declared none carries the deny-all scope.
    pub fn egress(&self) -> &EgressScope {
        &self.egress
    }

    /// The owner-authorized deadline this grant ends at, in epoch seconds.
    /// It is carried verbatim through every projection and rebuild, so a
    /// chain of re-projected handoffs still dies at the original deadline;
    /// only a fresh owner grant can authorize beyond it.
    pub fn lease_expires_at_epoch_seconds(&self) -> u64 {
        self.lease_expires_at_epoch_seconds
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        BTreeMap<K, Vec<LeasedCredential>>,
        Duration,
        String,
        EgressScope,
        u64,
    ) {
        (
            self.credentials,
            self.lease_duration,
            self.epoch,
            self.egress,
            self.lease_expires_at_epoch_seconds,
        )
    }

    /// Construct a handoff as a fresh owner grant: the authorized deadline
    /// is now plus the granted duration. The epoch must be a canonical
    /// UUID; the credential map must satisfy the shared inventory bounds;
    /// the egress scope carries the caller-declared outbound boundary —
    /// [`EgressScope::deny_all`] when nothing may leave the runtime.
    pub fn new(
        credentials: BTreeMap<K, Vec<LeasedCredential>>,
        lease_duration: Duration,
        epoch: String,
        egress: EgressScope,
    ) -> Result<Self> {
        let lease_expires_at_epoch_seconds = lease_deadline_epoch_seconds(lease_duration)?;
        Self::with_deadline(
            credentials,
            lease_duration,
            epoch,
            egress,
            lease_expires_at_epoch_seconds,
        )
    }

    /// Construct a handoff carrying an explicit owner-authorized deadline —
    /// a projection's preserved deadline or one parsed from a document.
    /// The deadline is validated like every other field but not re-derived:
    /// it is the value the grant ends at, wherever this handoff is rebuilt.
    pub(crate) fn with_deadline(
        credentials: BTreeMap<K, Vec<LeasedCredential>>,
        lease_duration: Duration,
        epoch: String,
        egress: EgressScope,
        lease_expires_at_epoch_seconds: u64,
    ) -> Result<Self> {
        ensure!(
            uuid::Uuid::parse_str(&epoch).is_ok_and(|value| value.to_string() == epoch),
            "credential_lease_epoch_invalid"
        );
        ensure!(
            (1..=MAX_LEASE_DURATION_SECONDS).contains(&lease_duration.as_secs()),
            "credential_lease_duration_invalid"
        );
        ensure!(
            lease_expires_at_epoch_seconds > 0,
            "credential_lease_expiry_invalid"
        );
        validate_credentials(&credentials, "credential_lease_inventory_invalid")?;
        Ok(Self {
            credentials,
            lease_duration,
            epoch,
            egress,
            lease_expires_at_epoch_seconds,
        })
    }

    /// Serialize the handoff as a closed JSON document. The output is a
    /// [`HandoffDocument`] so the serialized secret material zeroizes on
    /// drop.
    ///
    /// The buffer is reserved to a computed upper bound before writing, so
    /// it never grows: exactly one allocation holds secret material, and it
    /// moves straight into the returned document — no intermediate `Value`,
    /// `Vec<u8>`, or freed plaintext remnants are produced.
    pub fn to_json(&self) -> Result<HandoffDocument> {
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
        document.push_str(",\"leaseExpiresAtEpochSeconds\":");
        document.push_str(&self.lease_expires_at_epoch_seconds.to_string());
        document.push_str(",\"epoch\":");
        push_json_string(&mut document, &self.epoch);
        document.push_str(",\"egress\":");
        self.egress.write_json(&mut document);
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
        Ok(HandoffDocument(document.into_bytes()))
    }

    /// An upper bound on this handoff's serialized length: every structural
    /// byte plus, for each embedded string, its exact escaped JSON length,
    /// and at most 4 characters per secret byte. Reserving this much means
    /// the document string never re-allocates while secrets are being
    /// written into it — escaping cannot exceed the reserve.
    pub(crate) fn serialized_len_upper_bound(&self) -> usize {
        let mut length = 144
            + escaped_len(K::HANDOFF_SCHEMA)
            + escaped_len(&self.epoch)
            + 20
            + self.egress.serialized_len_upper_bound();
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
    ///
    /// Deserialization is typed and bounded: the closed schema is read
    /// straight into the lease's own storage with no intermediate `Value`
    /// tree, so no recoverable representation of credential material is
    /// left in freed heap. Secret bytes land in a preallocated zeroizing
    /// buffer under a wiping owner from the first byte, and the entry,
    /// key-count, and payload limits are enforced while reading rather
    /// than after a claimed array length has already been materialized.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let invalid = || anyhow!("credential_lease_handoff_invalid");
        ensure!(
            bytes.len() <= MAX_HANDOFF_DOC_BYTES,
            "credential_lease_handoff_invalid"
        );
        let wire: WireDocument<K> = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        Self::with_deadline(
            wire.credentials,
            Duration::from_secs(wire.lease_duration_seconds),
            wire.epoch,
            wire.egress,
            wire.lease_expires_at_epoch_seconds,
        )
        .map_err(|_| invalid())
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

pub(crate) fn decimal_digits(mut value: u64) -> usize {
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
pub(crate) fn escaped_len(value: &str) -> usize {
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
pub(crate) fn push_json_string(buffer: &mut String, value: &str) {
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

/// The wire projection `from_json` accepts: the closed schema read
/// straight into bounded, already-validated storage — no intermediate
/// `serde_json::Value` tree ever materializes credential material.
struct WireDocument<K: CredentialKind> {
    lease_duration_seconds: u64,
    lease_expires_at_epoch_seconds: u64,
    epoch: String,
    egress: EgressScope,
    credentials: BTreeMap<K, Vec<LeasedCredential>>,
}

impl<'de, K: CredentialKind> serde::Deserialize<'de> for WireDocument<K> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(DocumentVisitor::<K> {
            inventory: WireInventory::new(),
        })
    }
}

/// Per-document limits threaded through the bounded visitors: the kind
/// map being built, every credential id seen, and the running key count.
/// Enforcing them while reading keeps a document below the byte bound but
/// over a field limit from materializing the allocation it claims.
struct WireInventory<K: CredentialKind> {
    credentials: BTreeMap<K, Vec<LeasedCredential>>,
    credential_ids: BTreeSet<String>,
    total_keys: usize,
}

impl<K: CredentialKind> WireInventory<K> {
    fn new() -> Self {
        Self {
            credentials: BTreeMap::new(),
            credential_ids: BTreeSet::new(),
            total_keys: 0,
        }
    }
}

fn duplicate_member<E: DeError>() -> E {
    DeError::custom("duplicate member name")
}

fn missing_member<E: DeError>() -> E {
    DeError::custom("missing required member")
}

/// The document's closed object shape: exactly `schemaVersion`,
/// `leaseDurationSeconds`, `leaseExpiresAtEpochSeconds`, `epoch`, and
/// `credentials`, plus the optional `egress` scope — in any order, each
/// at most once.
struct DocumentVisitor<K: CredentialKind> {
    inventory: WireInventory<K>,
}

impl<'de, K: CredentialKind> Visitor<'de> for DocumentVisitor<K> {
    type Value = WireDocument<K>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a closed credential handoff document")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut schema_version_seen = false;
        let mut lease_duration_seconds: Option<u64> = None;
        let mut lease_expires_at_epoch_seconds: Option<u64> = None;
        let mut epoch: Option<String> = None;
        let mut egress: Option<EgressScope> = None;
        let mut credentials_seen = false;
        let mut inventory = self.inventory;
        while let Some(field) = access.next_key::<String>()? {
            match field.as_str() {
                "schemaVersion" => {
                    if schema_version_seen {
                        return Err(duplicate_member());
                    }
                    schema_version_seen = true;
                    let value = access.next_value::<String>()?;
                    if value.len() > MAX_HANDOFF_SCHEMA_BYTES || value != K::HANDOFF_SCHEMA {
                        return Err(DeError::custom("handoff schema mismatch"));
                    }
                }
                "leaseDurationSeconds" => {
                    if lease_duration_seconds.is_some() {
                        return Err(duplicate_member());
                    }
                    lease_duration_seconds = Some(access.next_value::<u64>()?);
                }
                "leaseExpiresAtEpochSeconds" => {
                    if lease_expires_at_epoch_seconds.is_some() {
                        return Err(duplicate_member());
                    }
                    lease_expires_at_epoch_seconds = Some(access.next_value::<u64>()?);
                }
                "epoch" => {
                    if epoch.is_some() {
                        return Err(duplicate_member());
                    }
                    epoch = Some(access.next_value::<String>()?);
                }
                "egress" => {
                    if egress.is_some() {
                        return Err(duplicate_member());
                    }
                    egress = Some(access.next_value::<WireEgress>()?.0);
                }
                "credentials" => {
                    if credentials_seen {
                        return Err(duplicate_member());
                    }
                    credentials_seen = true;
                    access.next_value_seed(EntriesSeed {
                        inventory: &mut inventory,
                    })?;
                }
                _ => return Err(DeError::custom("unknown member name")),
            }
        }
        if !schema_version_seen || !credentials_seen {
            return Err(missing_member());
        }
        Ok(WireDocument {
            lease_duration_seconds: lease_duration_seconds.ok_or_else(missing_member)?,
            lease_expires_at_epoch_seconds: lease_expires_at_epoch_seconds
                .ok_or_else(missing_member)?,
            epoch: epoch.ok_or_else(missing_member)?,
            egress: egress.unwrap_or_else(EgressScope::deny_all),
            credentials: inventory.credentials,
        })
    }
}

/// `credentials` array elements, deserialized one closed entry at a time.
struct EntriesSeed<'a, K: CredentialKind> {
    inventory: &'a mut WireInventory<K>,
}

impl<'de, K: CredentialKind> DeserializeSeed<'de> for EntriesSeed<'_, K> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_seq(EntriesVisitor {
            inventory: self.inventory,
        })
    }
}

struct EntriesVisitor<'a, K: CredentialKind> {
    inventory: &'a mut WireInventory<K>,
}

impl<'de, K: CredentialKind> Visitor<'de> for EntriesVisitor<'_, K> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a credential entries array")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        while access
            .next_element_seed(EntrySeed {
                inventory: &mut *self.inventory,
            })?
            .is_some()
        {
            if self.inventory.credentials.len() > MAX_LEASED_CREDENTIALS {
                return Err(DeError::custom("too many credential entries"));
            }
        }
        Ok(())
    }
}

/// One `credentials` entry: the closed `kind`/`keys` object, inserted into
/// the inventory only after both members validated.
struct EntrySeed<'a, K: CredentialKind> {
    inventory: &'a mut WireInventory<K>,
}

impl<'de, K: CredentialKind> DeserializeSeed<'de> for EntrySeed<'_, K> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(EntryVisitor {
            inventory: self.inventory,
        })
    }
}

struct EntryVisitor<'a, K: CredentialKind> {
    inventory: &'a mut WireInventory<K>,
}

impl<'de, K: CredentialKind> Visitor<'de> for EntryVisitor<'_, K> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a credential entry")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut kind: Option<K> = None;
        let mut keys: Option<Vec<LeasedCredential>> = None;
        while let Some(field) = access.next_key::<String>()? {
            match field.as_str() {
                "kind" => {
                    if kind.is_some() {
                        return Err(duplicate_member());
                    }
                    let name = access.next_value::<String>()?;
                    if name.len() > MAX_KIND_NAME_BYTES {
                        return Err(DeError::custom("kind name too long"));
                    }
                    kind = Some(K::from_str(&name).ok_or_else(|| DeError::custom("unknown kind"))?);
                }
                "keys" => {
                    if keys.is_some() {
                        return Err(duplicate_member());
                    }
                    keys = Some(access.next_value_seed(KeysSeed {
                        inventory: &mut *self.inventory,
                    })?);
                }
                _ => return Err(DeError::custom("unknown member name")),
            }
        }
        let kind = kind.ok_or_else(missing_member)?;
        let keys = keys.ok_or_else(missing_member)?;
        if self.inventory.credentials.insert(kind, keys).is_some() {
            return Err(DeError::custom("duplicate kind entry"));
        }
        Ok(())
    }
}

/// An entry's `keys` array: a nonempty, bounded list of credentials.
struct KeysSeed<'a, K: CredentialKind> {
    inventory: &'a mut WireInventory<K>,
}

impl<'de, K: CredentialKind> DeserializeSeed<'de> for KeysSeed<'_, K> {
    type Value = Vec<LeasedCredential>;

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_seq(KeysVisitor {
            inventory: self.inventory,
        })
    }
}

struct KeysVisitor<'a, K: CredentialKind> {
    inventory: &'a mut WireInventory<K>,
}

impl<'de, K: CredentialKind> Visitor<'de> for KeysVisitor<'_, K> {
    type Value = Vec<LeasedCredential>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a nonempty credential keys array")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut keys = Vec::new();
        while let Some(credential) = access.next_element_seed(KeySeed {
            inventory: &mut *self.inventory,
        })? {
            keys.push(credential);
        }
        if keys.is_empty() {
            return Err(DeError::custom("empty keys array"));
        }
        Ok(keys)
    }
}

/// One credential key: the closed `credentialId`/`expiresAtEpochSeconds`/
/// `secret` object, validated and counted while it is read.
struct KeySeed<'a, K: CredentialKind> {
    inventory: &'a mut WireInventory<K>,
}

impl<'de, K: CredentialKind> DeserializeSeed<'de> for KeySeed<'_, K> {
    type Value = LeasedCredential;

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(KeyVisitor {
            inventory: self.inventory,
        })
    }
}

struct KeyVisitor<'a, K: CredentialKind> {
    inventory: &'a mut WireInventory<K>,
}

impl<'de, K: CredentialKind> Visitor<'de> for KeyVisitor<'_, K> {
    type Value = LeasedCredential;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a credential key")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut credential_id: Option<String> = None;
        let mut expires_at_epoch_seconds: Option<Option<u64>> = None;
        let mut secret: Option<SecretBytes> = None;
        while let Some(field) = access.next_key::<String>()? {
            match field.as_str() {
                "credentialId" => {
                    if credential_id.is_some() {
                        return Err(duplicate_member());
                    }
                    credential_id = Some(access.next_value::<String>()?);
                }
                "expiresAtEpochSeconds" => {
                    if expires_at_epoch_seconds.is_some() {
                        return Err(duplicate_member());
                    }
                    expires_at_epoch_seconds = Some(access.next_value::<Option<u64>>()?);
                }
                "secret" => {
                    if secret.is_some() {
                        return Err(duplicate_member());
                    }
                    secret = Some(access.next_value::<WireSecret>()?.0);
                }
                _ => return Err(DeError::custom("unknown member name")),
            }
        }
        let credential = LeasedCredential::new(
            credential_id.ok_or_else(missing_member)?,
            secret.ok_or_else(missing_member)?,
            expires_at_epoch_seconds.ok_or_else(missing_member)?,
        )
        .map_err(|_| DeError::custom("invalid credential key"))?;
        if self.inventory.total_keys >= MAX_LEASED_CREDENTIALS {
            return Err(DeError::custom("too many credentials"));
        }
        self.inventory.total_keys += 1;
        if !self
            .inventory
            .credential_ids
            .insert(credential.credential_id().to_owned())
        {
            return Err(DeError::custom("duplicate credential id"));
        }
        Ok(credential)
    }
}

/// A `secret` byte array read straight into the credential's final
/// zeroizing buffer. The allocation is reserved to the contract's payload
/// bound before the first byte lands, so it can never reallocate mid-read,
/// and the material lives under a wiping owner for its whole existence.
/// Elements deserialize as `u8`, so the `0..=255` range is enforced by the
/// reader itself; the buffer's length bound is enforced while reading.
struct WireSecret(SecretBytes);

impl<'de> serde::Deserialize<'de> for WireSecret {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_seq(WireSecretVisitor)
    }
}

struct WireSecretVisitor;

impl<'de> Visitor<'de> for WireSecretVisitor {
    type Value = WireSecret;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded secret byte array")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_CREDENTIAL_BYTES));
        while let Some(byte) = access.next_element::<u8>()? {
            if bytes.len() >= MAX_CREDENTIAL_BYTES {
                return Err(DeError::custom("secret payload too large"));
            }
            bytes.push(byte);
        }
        SecretBytes::try_from_zeroizing_bytes(bytes)
            .map(WireSecret)
            .map_err(|_| DeError::custom("invalid secret payload"))
    }
}

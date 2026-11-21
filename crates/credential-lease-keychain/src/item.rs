//! Item identity, item results, and the add outcome.
//!
//! A [`KeychainItemQuery`] names exactly one protected generic-password
//! item — service, account, and the optional storage attributes the host's
//! item contract requires. The query is validated once at construction;
//! the platform calls never guess at an item.

use crate::error::{KeychainError, KeychainErrorKind};

#[cfg(target_os = "macos")]
use credential_lease::SecretBytes;

/// What [`Keychain::add_item`](crate::Keychain::add_item) reported.
///
/// `Duplicate` is a first-class outcome, not an error — append-only item
/// contracts resolve it by comparing the existing record instead of
/// overwriting it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddItemOutcome {
    /// The item was added.
    Added,
    /// An item with the same identity already existed; nothing was
    /// overwritten.
    Duplicate,
}

/// Identity and storage attributes of one protected item.
///
/// `use_data_protection` selects which Keychain the query routes to:
/// `None` follows the [`Keychain`](crate::Keychain)'s probed backend,
/// while `Some` forces the routing outright. The emitted routing flag is
/// always explicit — `true` on Data Protection, `false` on Classic — so
/// no operation can drift onto a store it was not built for. Hosts that
/// always target the Data Protection Keychain pass `Some(true)`; only
/// the legacy migration path forces `Some(false)`.
#[derive(Clone, Debug)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub struct KeychainItemQuery<'a> {
    pub(crate) service: &'a str,
    pub(crate) account: &'a str,
    pub(crate) access_group: Option<&'a str>,
    pub(crate) synchronizable: Option<bool>,
    pub(crate) use_data_protection: Option<bool>,
}

impl<'a> KeychainItemQuery<'a> {
    /// One item named by its service and account. Empty names are refused —
    /// the backend never builds a query it cannot fully name.
    pub fn new(service: &'a str, account: &'a str) -> Result<Self, KeychainError> {
        if service.trim().is_empty() || account.trim().is_empty() {
            return Err(KeychainError::new(
                "credential_lease_keychain_item_invalid",
                KeychainErrorKind::Failed,
                None,
            ));
        }
        Ok(Self {
            service,
            account,
            access_group: None,
            synchronizable: None,
            use_data_protection: None,
        })
    }

    /// Scope the item to a Keychain access group.
    pub fn with_access_group(mut self, access_group: &'a str) -> Self {
        self.access_group = Some(access_group);
        self
    }

    /// Emit an explicit `kSecAttrSynchronizable` flag.
    ///
    /// A `true` flag narrows the operation surface: the platform serves
    /// the item only from the Data Protection Keychain, and the backend's
    /// device-only `SecAccessControl` cannot attach to it — reads and
    /// deletes of existing synchronizable items are supported, writes
    /// refuse `credential_lease_keychain_synchronizable_write_invalid`
    /// before any SecItem call.
    pub fn with_synchronizable(mut self, synchronizable: bool) -> Self {
        self.synchronizable = Some(synchronizable);
        self
    }

    /// Force the data-protection routing flag instead of following the
    /// selected backend.
    pub fn with_data_protection(mut self, use_data_protection: bool) -> Self {
        self.use_data_protection = Some(use_data_protection);
        self
    }

    /// The item's `kSecAttrService`.
    pub fn service(&self) -> &str {
        self.service
    }

    /// The item's `kSecAttrAccount`.
    pub fn account(&self) -> &str {
        self.account
    }
}

/// The provenance attributes of one copied item: what the platform reports
/// about where and how the item is stored.
///
/// A typed projection, never the raw platform dictionary: it carries no
/// value data, so secret bytes stay reachable only through
/// [`KeychainItem::secret`]. Validating provenance — which service,
/// account, access group, and protection the item must carry — is the
/// host's contract, expressed over these fields. A field the platform did
/// not return, or returned with an unexpected type, is `None` (or `false`),
/// never a guess.
///
/// macOS only — no platform store exists elsewhere.
#[cfg(target_os = "macos")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeychainItemProvenance {
    pub(crate) service: Option<String>,
    pub(crate) account: Option<String>,
    pub(crate) access_group: Option<String>,
    pub(crate) accessible: Option<String>,
    pub(crate) synchronizable: Option<bool>,
    pub(crate) backend_access_control: bool,
}

#[cfg(target_os = "macos")]
impl KeychainItemProvenance {
    /// The item's `kSecAttrService`.
    pub fn service(&self) -> Option<&str> {
        self.service.as_deref()
    }

    /// The item's `kSecAttrAccount`.
    pub fn account(&self) -> Option<&str> {
        self.account.as_deref()
    }

    /// The item's `kSecAttrAccessGroup`.
    pub fn access_group(&self) -> Option<&str> {
        self.access_group.as_deref()
    }

    /// The item's `kSecAttrAccessible` class, spelled as the platform's
    /// constant value (for example the value of
    /// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`).
    pub fn accessible(&self) -> Option<&str> {
        self.accessible.as_deref()
    }

    /// The item's `kSecAttrSynchronizable` flag.
    pub fn synchronizable(&self) -> Option<bool> {
        self.synchronizable
    }

    /// Whether the item carries exactly the `SecAccessControl` this backend
    /// writes: user presence, accessible when unlocked, this device only.
    pub fn has_backend_access_control(&self) -> bool {
        self.backend_access_control
    }
}

/// One item copied out of the store: its secret bytes, persistent
/// reference, and the provenance attributes the host's checks consume.
///
/// macOS only — no platform store exists elsewhere.
#[cfg(target_os = "macos")]
pub struct KeychainItem {
    secret: SecretBytes,
    persistent_reference: Option<Vec<u8>>,
    provenance: KeychainItemProvenance,
}

#[cfg(target_os = "macos")]
impl KeychainItem {
    pub(crate) fn new(
        secret: SecretBytes,
        persistent_reference: Option<Vec<u8>>,
        provenance: KeychainItemProvenance,
    ) -> Self {
        Self {
            secret,
            persistent_reference,
            provenance,
        }
    }

    /// The item's value bytes, in the boundary's zeroizing container — the
    /// only way this type exposes them.
    pub fn secret(&self) -> &SecretBytes {
        &self.secret
    }

    /// The item's persistent reference, when the platform returned one.
    /// A synchronizable item never carries one — the platform serves it
    /// only as attributes and data — so it is always `None` there.
    /// Whether a reference is required is the host's provenance decision.
    pub fn persistent_reference(&self) -> Option<&[u8]> {
        self.persistent_reference.as_deref()
    }

    /// The item's provenance attributes, without any value data.
    pub fn provenance(&self) -> &KeychainItemProvenance {
        &self.provenance
    }
}

#[cfg(target_os = "macos")]
impl std::fmt::Debug for KeychainItem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("KeychainItem([redacted])")
    }
}

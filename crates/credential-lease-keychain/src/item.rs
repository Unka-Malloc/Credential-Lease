//! Item identity, item results, and the add outcome.
//!
//! A [`KeychainItemQuery`] names exactly one protected generic-password
//! item — service, account, and the optional storage attributes the host's
//! item contract requires. The query is validated once at construction;
//! the platform calls never guess at an item.

#[cfg(target_os = "macos")]
use core_foundation::dictionary::CFDictionary;

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
/// `None` follows the [`Keychain`](crate::Keychain)'s probed backend —
/// explicit `true` on Data Protection, an unset flag on Classic — while
/// `Some` forces the routing flag outright. Hosts that always target the
/// Data Protection Keychain pass `Some(true)`; only the legacy migration
/// path forces `Some(false)`.
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

/// One item copied out of the store: its secret bytes, persistent
/// reference, and the raw attribute dictionary the host's provenance checks
/// consume.
///
/// macOS only — no platform store exists elsewhere.
#[cfg(target_os = "macos")]
pub struct KeychainItem {
    secret: SecretBytes,
    persistent_reference: Option<Vec<u8>>,
    attributes: CFDictionary,
}

#[cfg(target_os = "macos")]
impl KeychainItem {
    pub(crate) fn new(
        secret: SecretBytes,
        persistent_reference: Option<Vec<u8>>,
        attributes: CFDictionary,
    ) -> Self {
        Self {
            secret,
            persistent_reference,
            attributes,
        }
    }

    /// The item's value bytes, in the boundary's zeroizing container.
    pub fn secret(&self) -> &SecretBytes {
        &self.secret
    }

    /// The item's persistent reference, when the platform returned one.
    /// Whether it is required is the host's provenance decision.
    pub fn persistent_reference(&self) -> Option<&[u8]> {
        self.persistent_reference.as_deref()
    }

    /// The raw returned attribute dictionary. Validation of provenance —
    /// which service, account, access group, and protection the item must
    /// carry — is the host's contract, expressed over these attributes.
    pub fn attributes(&self) -> &CFDictionary {
        &self.attributes
    }
}

#[cfg(target_os = "macos")]
impl std::fmt::Debug for KeychainItem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("KeychainItem([redacted])")
    }
}

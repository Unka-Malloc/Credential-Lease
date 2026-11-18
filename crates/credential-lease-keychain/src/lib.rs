//! OS keychain custody backend for the Credential-Lease surface.
//!
//! Custody — the system keyring — has one backend surface here so every
//! secret a host persists takes the same path. On macOS the backend stores
//! protected generic-password items in the selected Keychain: the Data
//! Protection Keychain is preferred and the classic file-based Keychain is
//! the local-build fallback, exactly the pairing Security.framework exposes.
//! Everywhere else [`Keychain::selected`] returns `None` and no item
//! operation exists, so custody fails closed instead of degrading.
//!
//! Owner authorization is deliberately not part of this crate: prompts,
//! sessions, and revocation belong to the host. Every item operation
//! consumes an already-authorized [`KeychainAuthContext`] the host hands in
//! — on macOS it is the host's authorized `LAContext`, passed to SecItem as
//! `kSecUseAuthenticationContext`. Secret material only ever moves inside
//! [`credential_lease::SecretBytes`]; it is never serialized, logged, or
//! placed in an error message, and [`KeychainError`] reduces every platform
//! refusal to a stable code plus an optional OS status number.

#![warn(missing_docs)]

mod context;
mod error;
mod item;
#[cfg(target_os = "macos")]
mod macos;

pub use context::KeychainAuthContext;
pub use error::{KeychainError, KeychainErrorKind};
pub use item::{AddItemOutcome, KeychainItemQuery};
#[cfg(target_os = "macos")]
pub use item::{KeychainItem, KeychainItemProvenance};

/// Which concrete store a [`Keychain`] dispatches to.
///
/// The Data Protection Keychain is the production target — a signed build
/// selects it and items land under `kSecUseDataProtectionKeychain`. The
/// classic file-based Keychain is the local-build fallback: local builds
/// that cannot hold the required access-group entitlement still get a
/// protected store, and the explicit classic legacy path is what the
/// migration reads and deletes through.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeychainBackend {
    /// `kSecUseDataProtectionKeychain = true`: the iOS-style Keychain with
    /// `SecAccessControl` item protection.
    DataProtection,
    /// The classic file-based macOS Keychain. Item queries leave the data
    /// protection flag unset; its separate application ACLs cannot be
    /// rewritten by `SecAccessControl`.
    Classic,
}

/// The platform store the process probes and then reuses.
///
/// Construction is only through [`Keychain::selected`]; a value exists only
/// when the silent round-trip probe proved a protected item can be added,
/// read back, and deleted. Item operations are macOS-only — see the
/// `cfg(target_os = "macos")` impl block below.
#[derive(Clone, Copy, Debug)]
pub struct Keychain {
    backend: KeychainBackend,
}

impl Keychain {
    /// The store this process may use, or `None` when no usable platform
    /// backend exists right now. Selection is cached only once the probe
    /// reaches a definite answer — a proven store, or a store verifiably
    /// unsupported. A temporarily unavailable store (for example a locked
    /// Data Protection Keychain) reports `None` for that call without
    /// falling back, so the next explicit call re-probes after the owner
    /// unlocks it.
    pub fn selected() -> Option<Self> {
        #[cfg(target_os = "macos")]
        {
            macos::selected_backend().map(|backend| Self { backend })
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }

    /// Bounded runtime evidence that protected custody is usable: one
    /// silent synthetic add/read/delete round trip. A definite answer is
    /// cached for the process lifetime; an undecidable probe is re-asked
    /// on the next call.
    pub fn probe_available() -> bool {
        Self::selected().is_some()
    }

    /// Which concrete store this `Keychain` dispatches to.
    pub fn backend(&self) -> KeychainBackend {
        self.backend
    }
}

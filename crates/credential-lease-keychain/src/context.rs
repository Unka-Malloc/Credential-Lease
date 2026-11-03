//! The already-authorized native context item operations consume.
//!
//! Owner authorization — biometric prompts, policy evaluation, session
//! caching — belongs to the host. This type is only a carrier: the host
//! hands in its authorized native context and the backend passes it to the
//! platform call untouched. It is never created, evaluated, or retained
//! here.

#[cfg(target_os = "macos")]
use core_foundation::base::CFType;

/// An already-authorized native context for protected item operations.
///
/// On macOS it wraps the `LAContext` the host authorized, passed to SecItem
/// as `kSecUseAuthenticationContext`. On every other platform the type is
/// uninhabited: [`Keychain::selected`](crate::Keychain::selected) never
/// yields a store there, so no operation can be reached.
#[cfg(target_os = "macos")]
pub struct KeychainAuthContext {
    context: CFType,
}

#[cfg(target_os = "macos")]
impl KeychainAuthContext {
    /// Wrap the host's authorized native context. The caller retains
    /// ownership of the underlying object; the wrapper clones the retained
    /// reference for the duration of one operation.
    pub fn from_cf_type(context: CFType) -> Self {
        Self { context }
    }

    pub(crate) fn as_cf_type(&self) -> CFType {
        self.context.clone()
    }
}

impl std::fmt::Debug for KeychainAuthContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("KeychainAuthContext([redacted])")
    }
}

/// The non-macOS context: uninhabited, since no platform store exists and
/// no item operation can be reached.
#[cfg(not(target_os = "macos"))]
#[non_exhaustive]
pub struct KeychainAuthContext;

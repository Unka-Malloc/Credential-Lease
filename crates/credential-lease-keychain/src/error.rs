//! Refusals from the keychain boundary.
//!
//! [`KeychainError`] is the only error this crate produces. `Display` and
//! `Debug` render the stable refusal code and nothing else — no platform
//! message text, no item names, and never any part of rejected secret
//! material. The optional OS status number travels separately so a host can
//! keep its own diagnostic format without parsing strings.

use std::fmt;

/// What kind of refusal a [`KeychainError`] carries.
///
/// The host maps each kind to its own stable public code — the backend
/// never dictates the host's vocabulary, only the classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeychainErrorKind {
    /// The platform refused the effect until the owner re-authorizes: a
    /// lock, logout, credential change, or an invalidated native context.
    /// The host should invalidate its cached authorization so the next
    /// explicit operation authenticates again instead of silently falling
    /// back to a password prompt.
    AuthorizationRequired,
    /// A classic macOS Keychain item cannot be read or removed without the
    /// explicit, user-consented migration flow — the legacy item's
    /// application ACL is asking for interaction the ordinary path
    /// suppresses.
    ClassicAccessRequiresUserAction,
    /// The process-wide classic Keychain UI policy could not be inspected,
    /// changed, or restored. No keychain effect ran, so nothing was left
    /// half-applied.
    InteractionControlFailed,
    /// The operation failed at the platform layer. `code` carries the
    /// stable detail and `os_status` the platform status when one was
    /// returned.
    Failed,
}

/// A refusal from the keychain boundary.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct KeychainError {
    code: &'static str,
    kind: KeychainErrorKind,
    os_status: Option<i32>,
}

impl KeychainError {
    /// The stable refusal code.
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// The refusal classification the host maps to its own surface.
    pub fn kind(&self) -> KeychainErrorKind {
        self.kind
    }

    /// The platform status the refusal carried, when one exists. This is a
    /// status number, never a message — it contains no secret material.
    pub fn os_status(&self) -> Option<i32> {
        self.os_status
    }

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn new(code: &'static str, kind: KeychainErrorKind, os_status: Option<i32>) -> Self {
        Self {
            code,
            kind,
            os_status,
        }
    }
}

impl fmt::Display for KeychainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code)
    }
}

impl fmt::Debug for KeychainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code)
    }
}

impl std::error::Error for KeychainError {}

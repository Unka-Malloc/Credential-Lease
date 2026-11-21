//! Host-facing classification of lease refusals.
//!
//! The runtime contract's refusal codes are stable text. A host that routes
//! failures also needs the cross-product `failureClass` vocabulary shared by
//! A4AA, AwP and Fairliny-Gateway, so recovery policy never depends on the
//! exact wording of an error. The mapping here is deliberately narrow: only
//! refusals that mean the credential itself is unusable become
//! `auth_expired`; a local integrity failure or a revocation source that
//! cannot be read stays an operational error.

use anyhow::Error;

/// The shared `failureClass` value for missing, invalid, expired or revoked
/// credentials.
///
/// This is the A4AA/AwP wire spelling (`auth_expired`) used by host recovery
/// policy to stop using a credential and request a fresh authorized handoff.
pub const AUTH_EXPIRED_FAILURE_CLASS: &str = "auth_expired";

/// Map a lease refusal to the host's `failureClass` vocabulary.
///
/// `credential_lease_unavailable` (no credential is currently resolvable),
/// `credential_lease_expired` (the lease lifetime elapsed), and
/// `credential_lease_revoked` (the active epoch is absent or rotated) all
/// mean the host must stop using this credential and renew or switch. They
/// map to [`AUTH_EXPIRED_FAILURE_CLASS`].
///
/// Local integrity failures such as `credential_lease_process_mismatch`,
/// and infrastructure failures such as an unreadable epoch source or a
/// poisoned slot lock, return `None`: the host must surface those directly
/// rather than silently renewing credentials across a broken boundary.
pub fn auth_failure_class(error: &Error) -> Option<&'static str> {
    // Match the root cause so a host that adds its own context to a resolve
    // error still gets the contract classification.
    match error.root_cause().to_string().as_str() {
        "credential_lease_unavailable"
        | "credential_lease_expired"
        | "credential_lease_revoked" => Some(AUTH_EXPIRED_FAILURE_CLASS),
        _ => None,
    }
}

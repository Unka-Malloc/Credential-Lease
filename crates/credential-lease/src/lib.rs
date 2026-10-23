//! Host-neutral credential lease contract.
//!
//! Custody — the system keyring, persistence, and owner authorization —
//! belongs to the host. This crate supplies the boundary the other side
//! consumes: a [`handoff::CredentialHandoff`] document carries credential
//! material from the unlocking process to one runtime, which rebuilds a
//! process-bound, revocable, time-limited [`lease::CredentialLease`].
//!
//! Secret bytes never appear in an inventory, configuration document, debug
//! projection, or command result produced by this crate. The handoff is the
//! only serialized form that may carry secrets, and it is intended for a
//! process-local channel such as an inherited file descriptor — never disk.
//!
//! What is leased is parameterized by [`kind::CredentialKind`]. Each kind
//! family pins its own handoff schema, so a document for one family can
//! never parse as another.

pub mod credential;
pub mod epoch;
pub mod handoff;
pub mod kind;
pub mod lease;
pub mod port;

pub use credential::{
    LeasedCredential, MAX_CREDENTIAL_BYTES, MAX_LEASED_CREDENTIALS, MAX_LEASE_DURATION_SECONDS,
};
pub use epoch::LeaseEpochSource;
pub use handoff::CredentialHandoff;
pub use kind::CredentialKind;
pub use lease::{CredentialLease, CredentialSlot};
pub use port::CustodyPort;

#[cfg(test)]
mod tests;

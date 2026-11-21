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
//! On Unix, [`handoff_fd`] receives that document from the descriptor named
//! by `FAIRLINY_HANDOFF_FD`; the environment carries only the number.
//!
//! What is leased is parameterized by [`kind::CredentialKind`]. Each kind
//! family pins its own handoff schema, so a document for one family can
//! never parse as another.

#![warn(missing_docs)]

pub mod credential;
pub mod egress;
pub mod epoch;
pub mod failure;
pub mod handoff;
#[cfg(unix)]
pub mod handoff_fd;
pub mod kind;
pub mod lease;
pub mod port;
pub mod secret;

pub use credential::{
    LeasedCredential, MAX_CREDENTIAL_BYTES, MAX_LEASED_CREDENTIALS, MAX_LEASE_DURATION_SECONDS,
};
pub use egress::{EgressScope, EgressTarget, HeaderTemplate};
pub use epoch::LeaseEpochSource;
pub use failure::{auth_failure_class, AUTH_EXPIRED_FAILURE_CLASS};
pub use handoff::{CredentialHandoff, HandoffDocument};
#[cfg(unix)]
pub use handoff_fd::{receive_handoff, receive_handoff_from_env, HANDOFF_FD_ENV, MIN_HANDOFF_FD};
pub use kind::CredentialKind;
pub use lease::{CredentialLease, CredentialSlot};
pub use port::CustodyPort;
pub use secret::{SecretBytes, SecretBytesError, MAX_SECRET_BYTES};

#[cfg(test)]
mod tests;

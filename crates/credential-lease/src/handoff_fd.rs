//! Inherited-descriptor handoff intake.
//!
//! A runtime spawned by the unlocking process receives its handoff document
//! over exactly one inherited, read-only descriptor. The environment carries
//! only that descriptor's number, under [`HANDOFF_FD_ENV`] — never the
//! document, a credential, or any custody root key. This module is the
//! receiving half of that contract:
//!
//! - the value is a plain decimal descriptor number and nothing else;
//! - descriptors below [`MIN_HANDOFF_FD`] are refused, so a missing or
//!   misspelled setup can never fall back to reading standard input;
//! - the document is read to end of file, refused before it can grow past
//!   [`MAX_HANDOFF_DOC_BYTES`], and
//!   parsed under the same closed rules as any other handoff;
//! - the descriptor is closed as soon as the read finishes, and every
//!   secret-bearing buffer — the read scratch and the accumulated document —
//!   zeroizes before the parsed handoff takes ownership of the secrets.
//!
//! The descriptor channel is a Unix concept. Hosts on other platforms use
//! their native process-local handle-passing mechanism with the same rule:
//! the inherited environment names the handle but never carries the
//! document.

use crate::handoff::{CredentialHandoff, MAX_HANDOFF_DOC_BYTES};
use crate::kind::CredentialKind;
use anyhow::{anyhow, ensure, Result};
use std::ffi::OsString;
use std::io::ErrorKind;
use std::os::fd::RawFd;
use zeroize::Zeroizing;

/// The environment variable naming the inherited read-only descriptor that
/// carries the handoff document.
pub const HANDOFF_FD_ENV: &str = "FAIRLINY_HANDOFF_FD";

/// The smallest descriptor [`receive_handoff`] accepts.
///
/// Standard input, output and error are already open in every process, so a
/// value below 3 cannot prove the host explicitly granted the descriptor —
/// it is refused as a malformed handoff channel instead of being read.
pub const MIN_HANDOFF_FD: RawFd = 3;

/// Receive a handoff from the descriptor named by [`HANDOFF_FD_ENV`].
///
/// Returns `Ok(None)` when the variable is absent: a runtime may legitimately
/// start disconnected and receive a handoff later through a slot.
pub fn receive_handoff_from_env<K: CredentialKind>() -> Result<Option<CredentialHandoff<K>>> {
    match std::env::var_os(HANDOFF_FD_ENV) {
        None => Ok(None),
        Some(value) => Ok(Some(receive_handoff(parse_descriptor(&value)?)?)),
    }
}

/// Receive a handoff from an inherited read-only descriptor.
///
/// The descriptor is consumed — closed once the read finishes, including
/// when the document is refused. The returned handoff owns its own secret
/// copies; every secret-bearing buffer this intake touches zeroizes on
/// drop, on the success path and on every refusal path.
///
/// The document accumulator is reserved to [`MAX_HANDOFF_DOC_BYTES`] before
/// the first read, so it is exactly one allocation that can never grow:
/// appending never relocates the buffer and never releases an unscrubbed
/// copy of the secret material read so far. The read scratch is a
/// [`Zeroizing`] array, so the last chunk's bytes are wiped on every exit
/// path too.
///
/// The descriptor is read and closed through the platform call directly
/// rather than through an owning [`std::fs::File`]: an invalid descriptor
/// must become the stable `credential_lease_handoff_fd_unavailable` refusal,
/// and the standard library treats an ownable descriptor that turns out to
/// be closed as a process-wide I/O safety violation instead.
pub fn receive_handoff<K: CredentialKind>(descriptor: RawFd) -> Result<CredentialHandoff<K>> {
    ensure!(
        descriptor >= MIN_HANDOFF_FD,
        "credential_lease_handoff_fd_invalid"
    );
    let owned = OwnedDescriptor(descriptor);
    // Reserved to the intake bound: the bound check below then guarantees
    // `extend_from_slice` never reallocates, so no superseded allocation
    // holding secret material is ever released unwiped.
    let mut document = Zeroizing::new(Vec::with_capacity(MAX_HANDOFF_DOC_BYTES));
    let mut chunk = Zeroizing::new([0u8; 16 * 1024]);
    loop {
        // SAFETY: `owned` has exclusive ownership of the descriptor for the
        // whole loop, and the buffer is valid for `chunk.len()` writes.
        let read = unsafe {
            libc::read(
                owned.0,
                chunk.as_mut_ptr().cast::<libc::c_void>(),
                chunk.len(),
            )
        };
        if read == 0 {
            break;
        }
        if read < 0 {
            // A signal can interrupt a blocking read; anything else —
            // including a closed descriptor — is an unavailable channel.
            if std::io::Error::last_os_error().kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(anyhow!("credential_lease_handoff_fd_unavailable"));
        }
        let read = read.unsigned_abs();
        ensure!(
            document.len() + read <= MAX_HANDOFF_DOC_BYTES,
            "credential_lease_handoff_invalid"
        );
        document.extend_from_slice(&chunk[..read]);
    }
    drop(owned);
    CredentialHandoff::from_json(&document)
}

/// Closes the received descriptor exactly once, on every exit path.
struct OwnedDescriptor(RawFd);

impl Drop for OwnedDescriptor {
    fn drop(&mut self) {
        // SAFETY: `self.0` is owned by this value and is not used again.
        unsafe { libc::close(self.0) };
    }
}

/// Parse the environment value as a decimal descriptor number. A value that
/// is not a plain unsigned decimal — a path, a JSON document, anything that
/// might hold material — is refused with a stable code and never echoed.
fn parse_descriptor(value: &OsString) -> Result<RawFd> {
    let text = value
        .to_str()
        .ok_or_else(|| anyhow!("credential_lease_handoff_fd_invalid"))?;
    ensure!(
        !text.is_empty() && text.len() <= 10 && text.bytes().all(|byte| byte.is_ascii_digit()),
        "credential_lease_handoff_fd_invalid"
    );
    let descriptor = text
        .parse::<i32>()
        .map_err(|_| anyhow!("credential_lease_handoff_fd_invalid"))?;
    ensure!(
        descriptor >= MIN_HANDOFF_FD,
        "credential_lease_handoff_fd_invalid"
    );
    Ok(descriptor)
}

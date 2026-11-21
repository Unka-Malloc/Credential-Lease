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
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
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

/// The process-local one-time intake claim: the first caller to observe the
/// variable wins the descriptor outright, before its value is even parsed.
/// The environment itself is never mutated — removing a variable is not
/// synchronized with readers outside Rust's environment API — so the number
/// stays in place but can never drive a second intake.
static HANDOFF_CHANNEL_CLAIMED: AtomicBool = AtomicBool::new(false);

/// Receive a handoff from the descriptor named by [`HANDOFF_FD_ENV`].
///
/// Returns `Ok(None)` when the variable is absent — and when an earlier
/// call already claimed the channel, which a disconnected runtime or a
/// second concurrent caller observes identically.
///
/// Intake is one-time: the first caller claims the channel through a
/// process-local latch before touching the descriptor, so concurrent
/// callers can never both take ownership of the same descriptor, and a
/// later call can never act on a descriptor number the OS may have
/// reassigned since the first intake closed it.
///
/// The parsed number stays a plain [`RawFd`] until the platform proves it
/// names an open descriptor; only then is it claimed as an [`OwnedFd`].
/// Ownership itself is the spawn contract — the host must grant this
/// process exclusive ownership of the descriptor the variable names, the
/// same transfer [`receive_handoff`] requires of a direct caller.
pub fn receive_handoff_from_env<K: CredentialKind>() -> Result<Option<CredentialHandoff<K>>> {
    let Some(value) = std::env::var_os(HANDOFF_FD_ENV) else {
        return Ok(None);
    };
    if HANDOFF_CHANNEL_CLAIMED.swap(true, Ordering::AcqRel) {
        return Ok(None);
    }
    let descriptor = parse_descriptor(&value)?;
    // The number stays outside `OwnedFd` until it is proven open:
    // `from_raw_fd` requires a live descriptor its caller exclusively
    // owns, so an unverified number can never be wrapped.
    ensure!(
        // SAFETY: `fcntl` accepts any number and reports whether it
        // currently names an open descriptor.
        unsafe { libc::fcntl(descriptor, libc::F_GETFD) } != -1,
        "credential_lease_handoff_fd_unavailable"
    );
    // SAFETY: the spawn contract grants this process exclusive ownership
    // of the descriptor the variable names — the same ownership transfer
    // `receive_handoff` requires of a direct caller — and the probe just
    // proved the descriptor open.
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    receive_handoff(descriptor).map(Some)
}

/// Receive a handoff from an inherited read-only descriptor.
///
/// The descriptor's ownership transfers to this call — an [`OwnedFd`], not
/// a borrowed number — so it can never close a descriptor the caller still
/// owns. It is closed once the read finishes, including when the document
/// is refused. The returned handoff owns its own secret copies; every
/// secret-bearing buffer this intake touches zeroizes on drop, on the
/// success path and on every refusal path.
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
pub fn receive_handoff<K: CredentialKind>(descriptor: OwnedFd) -> Result<CredentialHandoff<K>> {
    ensure!(
        descriptor.as_raw_fd() >= MIN_HANDOFF_FD,
        "credential_lease_handoff_fd_invalid"
    );
    let owned = OwnedDescriptor(descriptor.into_raw_fd());
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

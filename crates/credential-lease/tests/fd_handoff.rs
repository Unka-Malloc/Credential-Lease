//! End-to-end inherited-descriptor handoff: the parent mints a lease,
//! projects it into a handoff document, and writes that document to a
//! one-way pipe whose read end is inherited by an exec'd child. The child
//! rebuilds its own process-bound lease from `FAIRLINY_HANDOFF_FD`, resolves
//! the secret, and reports it back over a second pipe.
//!
//! The child also proves the negative half of the contract: the environment
//! carries the descriptor number and nothing else, the read end is not
//! writable, the descriptor is closed once read, and malformed or oversized
//! documents fail closed with stable codes.
//!
//! The parent test binary is reused as the child. The `fd_handoff_child_entry`
//! test is inert during an ordinary run and only acts when the parent sets
//! `CREDENTIAL_LEASE_FD_TEST_MODE`.

#![cfg(unix)]

use anyhow::Result;
use credential_lease::credential::LeasedCredential;
use credential_lease::egress::EgressScope;
use credential_lease::epoch::LeaseEpochSource;
use credential_lease::handoff_fd::{receive_handoff_from_env, HANDOFF_FD_ENV};
use credential_lease::kind::CredentialKind;
use credential_lease::lease::CredentialLease;
use credential_lease::SecretBytes;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;

/// Selects the child role. The value is a role name, never material.
const CHILD_MODE_ENV: &str = "CREDENTIAL_LEASE_FD_TEST_MODE";
/// Names the descriptor the child writes its report to.
const RESULT_FD_ENV: &str = "CREDENTIAL_LEASE_RESULT_FD";

/// The synthetic leased secret. Custody's root key is a different secret that
/// never crosses this contract; the environment may not receive either one,
/// so the test scans for exactly the material that does cross: the lease.
/// ASCII so the environment scan can look for its exact bytes without an
/// escaping ambiguity.
const LEASED_VALUE: &[u8] = b"fd-handoff-synthetic-value-3f9c1b7e";
const EPOCH: &str = "00000000-0000-4000-8000-0000000000fd";
const CREDENTIAL_ID: &str = "00000000-0000-4000-8000-0000000000aa";
const DOCUMENT_MARKER: &[u8] = b"\"schemaVersion\"";
const OK_FRAME: &[u8] = b"OK\n";
const REFUSED_FRAME: &[u8] = b"REFUSED ";

/// A descriptor the child guarantees is closed before it starts: the parent
/// closes it in the child's pre-exec and requests it by number.
const CLOSED_DESCRIPTOR: RawFd = 200;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Kind {
    Api,
}

impl CredentialKind for Kind {
    const HANDOFF_SCHEMA: &'static str = "test.credential-lease.handoff.v1";

    fn as_str(self) -> &'static str {
        "api"
    }

    fn from_str(value: &str) -> Option<Self> {
        (value == "api").then_some(Self::Api)
    }
}

struct FixedEpoch(String);

impl LeaseEpochSource for FixedEpoch {
    fn active_epoch(&self) -> Result<Option<String>> {
        Ok(Some(self.0.clone()))
    }
}

fn epoch_source() -> Arc<dyn LeaseEpochSource> {
    Arc::new(FixedEpoch(EPOCH.to_owned()))
}

fn lease_with(secret: &[u8]) -> CredentialLease<Kind> {
    let mut credentials = BTreeMap::new();
    credentials.insert(
        Kind::Api,
        vec![LeasedCredential::new(
            CREDENTIAL_ID.to_owned(),
            SecretBytes::try_from_bytes(secret.to_vec()).unwrap(),
            None,
        )
        .unwrap()],
    );
    CredentialLease::new(
        credentials,
        Duration::from_secs(60),
        EPOCH.to_owned(),
        epoch_source(),
        EgressScope::deny_all(),
    )
    .unwrap()
}

fn handoff_document() -> Vec<u8> {
    let lease = lease_with(LEASED_VALUE);
    lease
        .handoff_projection()
        .unwrap()
        .to_json()
        .unwrap()
        .expose_bytes()
        .to_vec()
}

fn pipe() -> (RawFd, RawFd) {
    let mut descriptors = [0; 2];
    // SAFETY: `pipe` writes exactly two descriptors into the array.
    assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
    close_on_exec(descriptors[0]);
    close_on_exec(descriptors[1]);
    (descriptors[0], descriptors[1])
}

fn close_on_exec(descriptor: RawFd) {
    // SAFETY: `descriptor` was just created by this process.
    assert_eq!(
        unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) },
        0
    );
}

fn close_fd(descriptor: RawFd) {
    // SAFETY: the caller owns `descriptor` and does not use it afterwards.
    unsafe { libc::close(descriptor) };
}

/// The parent's side of one spawned child.
struct SpawnedChild {
    child: Child,
    handoff: Option<File>,
    result: File,
}

impl SpawnedChild {
    fn spawn(mode: &str, descriptor_value: &str) -> Self {
        let (handoff_read, handoff_write) = pipe();
        let (result_read, result_write) = pipe();
        let executable = std::env::current_exe().expect("test binary path");
        let mut command = Command::new(executable);
        command
            .args(["--exact", "fd_handoff_child_entry", "--nocapture"])
            .env(CHILD_MODE_ENV, mode)
            .env(HANDOFF_FD_ENV, descriptor_value)
            .env(RESULT_FD_ENV, "4")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        // SAFETY: the closure only performs async-signal-safe descriptor
        // operations between fork and exec.
        unsafe {
            command.pre_exec(move || {
                // Move both sources out of the 3/4 target range first, so a
                // source that happens to already be 3 or 4 cannot be
                // clobbered by the other duplication.
                let handoff_source = libc::fcntl(handoff_read, libc::F_DUPFD, 60);
                if handoff_source < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let result_source = libc::fcntl(result_write, libc::F_DUPFD, 61);
                if result_source < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::dup2(handoff_source, 3) < 0 || libc::dup2(result_source, 4) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // dup2 clears close-on-exec on the target already; set it
                // explicitly so the inherited pair is exactly 3 and 4.
                if libc::fcntl(3, libc::F_SETFD, 0) < 0 || libc::fcntl(4, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                libc::close(handoff_source);
                libc::close(result_source);
                // Guarantee the "unavailable descriptor" case is closed even
                // if the runner happened to leave this high number open.
                libc::close(CLOSED_DESCRIPTOR);
                Ok(())
            });
        }
        let child = command.spawn().expect("spawn handoff child");
        close_fd(handoff_read);
        close_fd(result_write);
        // SAFETY: the two kept descriptors are owned by this struct and are
        // closed exactly once through the `File` values.
        unsafe {
            Self {
                child,
                handoff: Some(File::from_raw_fd(handoff_write)),
                result: File::from_raw_fd(result_read),
            }
        }
    }

    fn send(mut self, document: &[u8]) -> Self {
        let mut handoff = self.handoff.take().expect("handoff already sent");
        match handoff.write_all(document) {
            Ok(()) => {}
            // The child refuses an oversized document before reading it all,
            // so the tail of the write can meet a closed read end.
            Err(error) if error.kind() == ErrorKind::BrokenPipe => {}
            Err(error) => panic!("writing handoff document: {error}"),
        }
        // Closing the write end is the child's end-of-file.
        drop(handoff);
        self
    }

    fn finish(mut self) -> (ExitStatus, Vec<u8>) {
        self.handoff = None;
        let mut result = Vec::new();
        self.result
            .read_to_end(&mut result)
            .expect("read child report");
        let status = self.child.wait().expect("wait for handoff child");
        (status, result)
    }
}

fn assert_env_holds_no(needle: &[u8]) {
    for (name, value) in std::env::vars_os() {
        let value = value.to_string_lossy();
        assert!(
            !value
                .as_bytes()
                .windows(needle.len())
                .any(|part| part == needle),
            "environment value for {name:?} carried handoff material"
        );
    }
}

fn assert_env_is_clean() {
    assert_env_holds_no(LEASED_VALUE);
    assert_env_holds_no(DOCUMENT_MARKER);
}

fn report_descriptor() -> RawFd {
    std::env::var(RESULT_FD_ENV)
        .expect("result descriptor")
        .parse::<RawFd>()
        .expect("decimal result descriptor")
}

fn write_report(frame: &[u8]) {
    // SAFETY: the result descriptor is granted by the parent exactly once
    // and is owned here; closing it with the `File` ends the report.
    let mut report = unsafe { File::from_raw_fd(report_descriptor()) };
    report.write_all(frame).expect("write child report");
}

fn refuse(expected: &str, error: anyhow::Error) {
    assert_eq!(error.to_string(), expected);
    assert_env_is_clean();
    let mut frame = REFUSED_FRAME.to_vec();
    frame.extend_from_slice(expected.as_bytes());
    write_report(&frame);
}

#[test]
fn child_reads_handoff_from_an_inherited_descriptor() {
    let document = handoff_document();

    // The parent never holds the secret in its own environment either.
    assert_env_is_clean();

    let (status, report) = SpawnedChild::spawn("valid", "3").send(&document).finish();

    assert!(status.success(), "child exited with {status}");
    let mut expected = OK_FRAME.to_vec();
    expected.extend_from_slice(LEASED_VALUE);
    assert_eq!(report, expected, "child must resolve the same secret bytes");
    assert_env_is_clean();
}

#[test]
fn non_numeric_descriptor_value_fails_closed() {
    let (status, report) = SpawnedChild::spawn("invalid-fd", "not-a-descriptor").finish();
    assert!(status.success(), "child exited with {status}");
    assert_eq!(
        report,
        [REFUSED_FRAME, b"credential_lease_handoff_fd_invalid"].concat()
    );
}

#[test]
fn standard_descriptor_number_fails_closed() {
    // 2 is stderr: a missing setup must never fall back to a stream the
    // process already had open.
    let (status, report) = SpawnedChild::spawn("invalid-fd", "2").finish();
    assert!(status.success(), "child exited with {status}");
    assert_eq!(
        report,
        [REFUSED_FRAME, b"credential_lease_handoff_fd_invalid"].concat()
    );
}

#[test]
fn unavailable_descriptor_fails_closed() {
    let (status, report) = SpawnedChild::spawn("unavailable-fd", "200").finish();
    assert!(status.success(), "child exited with {status}");
    assert_eq!(
        report,
        [REFUSED_FRAME, b"credential_lease_handoff_fd_unavailable"].concat()
    );
}

#[test]
fn truncated_document_fails_closed() {
    let document = handoff_document();
    let truncated = &document[..document.len() / 2];
    let (status, report) = SpawnedChild::spawn("invalid-document", "3")
        .send(truncated)
        .finish();
    assert!(status.success(), "child exited with {status}");
    assert_eq!(
        report,
        [REFUSED_FRAME, b"credential_lease_handoff_invalid"].concat()
    );
}

#[test]
fn oversized_document_fails_closed() {
    let oversize = vec![b' '; credential_lease::handoff::MAX_HANDOFF_DOC_BYTES + 1];
    let (status, report) = SpawnedChild::spawn("invalid-document", "3")
        .send(&oversize)
        .finish();
    assert!(status.success(), "child exited with {status}");
    assert_eq!(
        report,
        [REFUSED_FRAME, b"credential_lease_handoff_invalid"].concat()
    );
}

/// The child half. In an ordinary test run the mode is absent and this test
/// does nothing; the parent re-executes the binary with the mode set.
#[test]
fn fd_handoff_child_entry() {
    let Ok(mode) = std::env::var(CHILD_MODE_ENV) else {
        return;
    };
    assert_env_is_clean();

    match mode.as_str() {
        "valid" => {
            let descriptor = std::env::var(HANDOFF_FD_ENV).expect("descriptor variable");
            assert!(
                !descriptor.is_empty() && descriptor.bytes().all(|byte| byte.is_ascii_digit()),
                "{HANDOFF_FD_ENV} must carry only a descriptor number"
            );
            assert_eq!(descriptor, "3");
            // The inherited descriptor is read-only: writing to it fails.
            // SAFETY: fd 3 is the inherited handoff read end.
            assert_eq!(
                unsafe { libc::write(3, b"x".as_ptr().cast(), 1) },
                -1,
                "the handoff descriptor must be a one-way read end"
            );
            let handoff = receive_handoff_from_env::<Kind>()
                .expect("receiving the handoff")
                .expect("the descriptor is named");
            // SAFETY: fd 3 was owned by `receive_handoff` and must be closed.
            assert_eq!(
                unsafe { libc::fcntl(3, libc::F_GETFD) },
                -1,
                "the receiver must close the descriptor after reading"
            );
            // Intake is one-time: the variable was consumed, so a second
            // call sees the channel as absent and can never re-close a
            // descriptor number the OS may have reassigned.
            assert!(
                receive_handoff_from_env::<Kind>()
                    .expect("the second intake")
                    .is_none(),
                "a consumed handoff variable must read as absent"
            );
            let lease = CredentialLease::from_handoff(handoff, epoch_source())
                .expect("rebuild the child's own lease");
            let secret = lease
                .resolve(Kind::Api)
                .expect("resolve the received lease");
            // The environment is inspected after resolution, when the child
            // holds the secret in memory, and must still be clean.
            assert_env_is_clean();
            assert!(!secret.expose_bytes().is_empty());
            let mut frame = OK_FRAME.to_vec();
            frame.extend_from_slice(secret.expose_bytes());
            write_report(&frame);
        }
        "invalid-fd" => {
            let error = receive_handoff_from_env::<Kind>().expect_err("descriptor refused");
            refuse("credential_lease_handoff_fd_invalid", error);
        }
        "unavailable-fd" => {
            let error = receive_handoff_from_env::<Kind>().expect_err("descriptor refused");
            refuse("credential_lease_handoff_fd_unavailable", error);
        }
        "invalid-document" => {
            let error = receive_handoff_from_env::<Kind>().expect_err("document refused");
            refuse("credential_lease_handoff_invalid", error);
        }
        other => panic!("unknown child mode {other:?}"),
    }
}

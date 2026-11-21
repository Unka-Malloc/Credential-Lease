//! Language sample: receive a handoff over `FAIRLINY_HANDOFF_FD`, validate it
//! through the crate's closed contract, and report only non-secret shape.
//!
//! The sibling Go and TypeScript samples implement the same interface
//! signature against the same conformance vectors; `scripts/verify-samples.sh`
//! requires every language to reach the same verdict.

#[cfg(unix)]
use credential_lease::handoff_fd::receive_handoff_from_env;
#[cfg(unix)]
use credential_lease::CredentialKind;
#[cfg(unix)]
use std::process::ExitCode;

/// The sample's kind family. A runtime supplies its own family; this one
/// pins the contract test schema used by the vectors.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum SampleKind {
    Api,
}

#[cfg(unix)]
impl CredentialKind for SampleKind {
    const HANDOFF_SCHEMA: &'static str = "test.credential-lease.handoff.v1";

    fn as_str(self) -> &'static str {
        "api"
    }

    fn from_str(value: &str) -> Option<Self> {
        (value == "api").then_some(Self::Api)
    }
}

#[cfg(unix)]
fn main() -> ExitCode {
    match receive_handoff_from_env::<SampleKind>() {
        Ok(Some(handoff)) => {
            println!("valid kinds={}", handoff.kinds().count());
            ExitCode::SUCCESS
        }
        // The descriptor variable is absent: the runtime is disconnected.
        Ok(None) => {
            println!("refused credential_lease_handoff_fd_missing");
            ExitCode::from(2)
        }
        Err(error) if error.to_string() == "credential_lease_handoff_invalid" => {
            println!("invalid");
            ExitCode::FAILURE
        }
        // Any other refusal is a channel problem, not a document verdict.
        Err(error) => {
            println!("refused {error}");
            ExitCode::from(2)
        }
    }
}

/// The descriptor channel is Unix-only; other platforms use their native
/// process-local handle mechanism, which this sample does not implement.
#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    println!("refused credential_lease_handoff_fd_unsupported");
    std::process::ExitCode::from(2)
}

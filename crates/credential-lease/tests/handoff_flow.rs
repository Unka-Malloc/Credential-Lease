//! Consumer-facing behavior: custody mints a lease, projects it into a
//! closed handoff document, and the receiving runtime rebuilds a lease that
//! resolves secrets — until expiry or an owner-initiated epoch revocation.

use anyhow::Result;
use credential_lease::credential::LeasedCredential;
use credential_lease::epoch::LeaseEpochSource;
use credential_lease::handoff::CredentialHandoff;
use credential_lease::kind::CredentialKind;
use credential_lease::lease::CredentialLease;
use credential_lease::SecretBytes;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

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

fn epoch() -> String {
    "00000000-0000-4000-8000-000000000001".to_owned()
}

fn lease_with(secret: &str, expires_at: Option<u64>) -> CredentialLease<Kind> {
    let mut credentials = BTreeMap::new();
    credentials.insert(
        Kind::Api,
        vec![LeasedCredential::new(
            "00000000-0000-4000-8000-0000000000aa".to_owned(),
            SecretBytes::try_from_string(secret.to_owned()).unwrap(),
            expires_at,
        )
        .unwrap()],
    );
    CredentialLease::new(
        credentials,
        Duration::from_secs(60),
        epoch(),
        Arc::new(FixedEpoch(epoch())),
    )
    .unwrap()
}

#[test]
fn lease_projects_to_handoff_and_receiver_resolves() {
    // given custody mints a lease, when it crosses the process boundary as a
    // handoff document, then the runtime resolves the same secret bytes
    let custody = lease_with("synthetic-secret-01", None);
    let document = custody.handoff_projection().unwrap().to_json().unwrap();
    let received = CredentialHandoff::<Kind>::from_json(document.expose_bytes()).unwrap();
    let runtime = CredentialLease::from_handoff(received, Arc::new(FixedEpoch(epoch()))).unwrap();
    let resolved = runtime.resolve(Kind::Api).unwrap();
    assert_eq!(resolved.expose_bytes(), b"synthetic-secret-01");
}

#[test]
fn handoff_carries_arbitrary_secret_bytes_verbatim() {
    // given a secret that is not text at all — a NUL, a high byte and a
    // bare continuation byte — when the handoff crosses the process
    // boundary, then the rebuilt lease resolves the exact same bytes
    let mut credentials = BTreeMap::new();
    credentials.insert(
        Kind::Api,
        vec![LeasedCredential::new(
            "00000000-0000-4000-8000-0000000000ab".to_owned(),
            SecretBytes::try_from_bytes(vec![0x00, 0xff, 0x80]).unwrap(),
            None,
        )
        .unwrap()],
    );
    let custody = CredentialLease::new(
        credentials,
        Duration::from_secs(60),
        epoch(),
        Arc::new(FixedEpoch(epoch())),
    )
    .unwrap();
    let document = custody.handoff_projection().unwrap().to_json().unwrap();
    let received = CredentialHandoff::<Kind>::from_json(document.expose_bytes()).unwrap();
    let runtime = CredentialLease::from_handoff(received, Arc::new(FixedEpoch(epoch()))).unwrap();
    let resolved = runtime.resolve(Kind::Api).unwrap();
    assert_eq!(resolved.expose_bytes(), [0x00, 0xff, 0x80]);
}

#[test]
fn revoked_epoch_fails_the_next_resolution() {
    // given a lease minted under epoch A, when custody rotates to epoch B,
    // then the receiver's very next resolution fails closed
    let custody = lease_with("synthetic-secret-02", None);
    let document = custody.handoff_projection().unwrap().to_json().unwrap();
    let received = CredentialHandoff::<Kind>::from_json(document.expose_bytes()).unwrap();
    let stale_epoch = Arc::new(FixedEpoch(
        "00000000-0000-4000-8000-0000000000bb".to_owned(),
    ));
    let runtime = CredentialLease::from_handoff(received, stale_epoch).unwrap();
    assert!(runtime.resolve(Kind::Api).is_err());
}

#[test]
fn expired_credential_never_resolves() {
    // given a credential past its storage expiry, it stays unavailable even
    // while the lease itself is live
    let custody = lease_with("synthetic-secret-03", Some(1));
    assert!(custody.resolve(Kind::Api).is_err());
}

//! AuthExpired mapping consistency across the lease refusal surface.
//!
//! AwP and Fairliny-Gateway route recovery on the shared A4AA
//! `failureClass` vocabulary. The contract must classify missing, expired
//! and revoked credentials as `auth_expired`, while local integrity and
//! infrastructure failures stay operational errors that must not silently
//! trigger a credential refresh.

use anyhow::Result;
use credential_lease::credential::LeasedCredential;
use credential_lease::egress::EgressScope;
use credential_lease::epoch::LeaseEpochSource;
use credential_lease::failure::{auth_failure_class, AUTH_EXPIRED_FAILURE_CLASS};
use credential_lease::handoff::CredentialHandoff;
use credential_lease::kind::CredentialKind;
use credential_lease::lease::CredentialLease;
use credential_lease::SecretBytes;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Kind {
    Api,
}

impl CredentialKind for Kind {
    const HANDOFF_SCHEMA: &'static str = "test.credential-lease.auth-expired.handoff.v1";

    fn as_str(self) -> &'static str {
        "api"
    }

    fn from_str(value: &str) -> Option<Self> {
        (value == "api").then_some(Self::Api)
    }
}

struct SharedEpoch(Mutex<Option<String>>);

impl SharedEpoch {
    fn new(epoch: &str) -> Self {
        Self(Mutex::new(Some(epoch.to_owned())))
    }

    fn rotate(&self, epoch: &str) {
        *self.0.lock().unwrap() = Some(epoch.to_owned());
    }
}

impl LeaseEpochSource for SharedEpoch {
    fn active_epoch(&self) -> Result<Option<String>> {
        Ok(self.0.lock().unwrap().clone())
    }
}

struct FailingEpoch;

impl LeaseEpochSource for FailingEpoch {
    fn active_epoch(&self) -> Result<Option<String>> {
        Err(anyhow::anyhow!("credential_lease_epoch_unavailable"))
    }
}

fn epoch(value: u128) -> String {
    format!("00000000-0000-4000-8000-{value:012x}")
}

fn lease(epoch: &str, source: Arc<dyn LeaseEpochSource>, secret: &str) -> CredentialLease<Kind> {
    let credentials = BTreeMap::from([(
        Kind::Api,
        vec![LeasedCredential::new(
            "00000000-0000-4000-8000-0000000000aa".to_owned(),
            SecretBytes::try_from_string(secret.to_owned()).unwrap(),
            None,
        )
        .unwrap()],
    )]);
    CredentialLease::new(
        credentials,
        Duration::from_secs(3600),
        epoch.to_owned(),
        source,
        EgressScope::deny_all(),
    )
    .unwrap()
}

#[test]
fn auth_expired_uses_the_shared_wire_spelling() {
    assert_eq!(AUTH_EXPIRED_FAILURE_CLASS, "auth_expired");
}

#[test]
fn unavailable_expired_and_revoked_credentials_all_map_to_auth_expired() {
    // Missing authorization: a disconnected lease has nothing to resolve.
    let disconnected = CredentialLease::<Kind>::disconnected();
    let unavailable = disconnected.resolve(Kind::Api).unwrap_err();
    assert_eq!(unavailable.to_string(), "credential_lease_unavailable");
    assert_eq!(
        auth_failure_class(&unavailable),
        Some(AUTH_EXPIRED_FAILURE_CLASS)
    );

    // Lease lifetime elapsed. Construction requires a positive whole-second
    // bound, so this is the shortest real expiry the public contract admits.
    let epoch_a = epoch(0xa001);
    let expiring_source = Arc::new(SharedEpoch::new(&epoch_a));
    let expiring = CredentialLease::new(
        BTreeMap::from([(
            Kind::Api,
            vec![LeasedCredential::new(
                "00000000-0000-4000-8000-0000000000bb".to_owned(),
                SecretBytes::try_from_string("synthetic-expiry-secret".to_owned()).unwrap(),
                None,
            )
            .unwrap()],
        )]),
        Duration::from_secs(1),
        epoch_a,
        expiring_source,
        EgressScope::deny_all(),
    )
    .unwrap();
    assert!(expiring.resolve(Kind::Api).is_ok());
    std::thread::sleep(Duration::from_millis(1_200));
    let expired = expiring.resolve(Kind::Api).unwrap_err();
    assert_eq!(expired.to_string(), "credential_lease_expired");
    assert_eq!(
        auth_failure_class(&expired),
        Some(AUTH_EXPIRED_FAILURE_CLASS)
    );
    // A host may add its own context around a resolve error; the contract
    // classification must still see the root refusal code.
    let expired_with_context = expired.context("resolving the provider credential");
    assert_eq!(
        auth_failure_class(&expired_with_context),
        Some(AUTH_EXPIRED_FAILURE_CLASS)
    );

    // Custody epoch rotation: the credential is revoked, not merely late.
    let epoch_b = epoch(0xb002);
    let rotating_source = Arc::new(SharedEpoch::new(&epoch_b));
    let revoked_lease = lease(
        &epoch_b,
        rotating_source.clone(),
        "synthetic-revoked-secret",
    );
    assert!(revoked_lease.resolve(Kind::Api).is_ok());
    rotating_source.rotate(&epoch(0xc003));
    let revoked = revoked_lease.resolve(Kind::Api).unwrap_err();
    assert_eq!(revoked.to_string(), "credential_lease_revoked");
    assert_eq!(
        auth_failure_class(&revoked),
        Some(AUTH_EXPIRED_FAILURE_CLASS)
    );

    // The host policy needs one class for both renewal and safe switching.
    assert_eq!(
        auth_failure_class(&expired_with_context),
        auth_failure_class(&revoked),
        "expiry and revocation must share one recovery class"
    );
}

#[test]
fn integrity_and_infrastructure_refusals_do_not_map_to_auth_expired() {
    // A malformed handoff is a contract violation, not a stale credential.
    let invalid_handoff = CredentialHandoff::<Kind>::from_json(b"not-a-handoff").unwrap_err();
    assert_eq!(
        invalid_handoff.to_string(),
        "credential_lease_handoff_invalid"
    );
    assert_eq!(auth_failure_class(&invalid_handoff), None);

    // An unreadable revocation source means authorization cannot be
    // established; that is an operational failure, not proof of expiry.
    let epoch_a = epoch(0xd004);
    let failing = lease(&epoch_a, Arc::new(FailingEpoch), "synthetic-failing-secret");
    let epoch_failure = failing.resolve(Kind::Api).unwrap_err();
    assert_eq!(
        epoch_failure.to_string(),
        "credential_lease_epoch_unavailable"
    );
    assert_eq!(auth_failure_class(&epoch_failure), None);

    // Constructor refusals are caller errors and never auth failures.
    let invalid_epoch = CredentialLease::<Kind>::new(
        BTreeMap::new(),
        Duration::from_secs(3600),
        "not-a-uuid".to_owned(),
        Arc::new(FailingEpoch),
        EgressScope::deny_all(),
    )
    .unwrap_err();
    assert_eq!(invalid_epoch.to_string(), "credential_lease_epoch_invalid");
    assert_eq!(auth_failure_class(&invalid_epoch), None);
}

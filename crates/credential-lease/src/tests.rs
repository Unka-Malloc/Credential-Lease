use super::*;
use crate::handoff::{CredentialHandoff, MAX_HANDOFF_DOC_BYTES};
use crate::SecretBytes;
use anyhow::Result;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum TestKind {
    Alpha,
    Beta,
}

impl CredentialKind for TestKind {
    const HANDOFF_SCHEMA: &'static str = "test.credential-lease.handoff.v1";

    fn as_str(self) -> &'static str {
        match self {
            Self::Alpha => "alpha",
            Self::Beta => "beta",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "alpha" => Some(Self::Alpha),
            "beta" => Some(Self::Beta),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum EscapedKind {
    Control,
}

impl CredentialKind for EscapedKind {
    const HANDOFF_SCHEMA: &'static str = "test.escaped-family.handoff.v1";

    fn as_str(self) -> &'static str {
        "es\u{1}cap\"e\\d"
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "es\u{1}cap\"e\\d" => Some(Self::Control),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum MaxEscapedKind {
    Only,
}

impl CredentialKind for MaxEscapedKind {
    // Exactly the 128-byte bound: 32 control bytes escape to 6 JSON bytes
    // each, so the emitted schema spans 290 bytes.
    const HANDOFF_SCHEMA: &'static str =
        "\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\
         \u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\
         test.schema.family.name.padded.to.the.bound.exactly.for.the.escape.test.zzzzzzzzzzzzzzzzzzzzzzzz";

    fn as_str(self) -> &'static str {
        // Exactly the 64-byte bound: 16 control bytes plus 48 name bytes
        // escape to a 146-byte emitted name.
        "\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\u{7}\
         kind.name.padded.to.the.bound.for.escape.test.zz"
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            v if v == Self::Only.as_str() => Some(Self::Only),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum OversizeSchemaKind {
    Only,
}

impl CredentialKind for OversizeSchemaKind {
    // Over the contract's 128-byte schema-name bound.
    const HANDOFF_SCHEMA: &'static str = "test.oversize.schema.family.this.constant.is.made.deliberately.longer.than.one.hundred.and.twenty.eight.bytes.for.the.rejection.test";

    fn as_str(self) -> &'static str {
        "only"
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "only" => Some(Self::Only),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum OtherKind {
    Gamma,
}

impl CredentialKind for OtherKind {
    const HANDOFF_SCHEMA: &'static str = "other.family.handoff.v1";

    fn as_str(self) -> &'static str {
        "gamma"
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "gamma" => Some(Self::Gamma),
            _ => None,
        }
    }
}

#[derive(Default)]
struct TestEpochSource(StdMutex<Option<String>>);

impl LeaseEpochSource for TestEpochSource {
    fn active_epoch(&self) -> Result<Option<String>> {
        Ok(self.0.lock().unwrap().clone())
    }
}

struct FailingEpochSource;

impl LeaseEpochSource for FailingEpochSource {
    fn active_epoch(&self) -> Result<Option<String>> {
        Err(anyhow::anyhow!("credential_lease_epoch_unavailable"))
    }
}

fn test_credential(secret: &str) -> LeasedCredential {
    LeasedCredential::new(
        uuid::Uuid::new_v4().to_string(),
        SecretBytes::try_from_string(secret.to_owned()).unwrap(),
        None,
    )
    .unwrap()
}

fn handoff_test_credentials() -> BTreeMap<TestKind, Vec<LeasedCredential>> {
    let mut credentials = BTreeMap::new();
    credentials.insert(
        TestKind::Alpha,
        vec![
            test_credential("synthetic-alpha-key-1"),
            test_credential("synthetic-alpha-key-2"),
        ],
    );
    credentials.insert(
        TestKind::Beta,
        vec![test_credential("synthetic-beta-key-1")],
    );
    credentials
}

#[test]
fn disconnected_lease_fails_closed_without_authorization() {
    let lease = CredentialLease::<TestKind>::disconnected();

    assert!(!lease.contains_kind(TestKind::Alpha));
    assert_eq!(
        lease.resolve(TestKind::Alpha).unwrap_err().to_string(),
        "credential_lease_unavailable"
    );
}

#[test]
fn credential_slot_hot_applies_handoff_without_replacing_the_arc() {
    let slot = CredentialSlot::<TestKind>::disconnected();
    assert!(!slot.connected());
    let mut credentials = BTreeMap::new();
    credentials.insert(TestKind::Beta, vec![test_credential("fixture-key-123456")]);
    let epoch = uuid::Uuid::new_v4().to_string();
    let handoff = CredentialHandoff::new(
        credentials,
        Duration::from_secs(3600),
        epoch.clone(),
        EgressScope::deny_all(),
    )
    .unwrap();
    slot.install_handoff(
        handoff,
        Arc::new(TestEpochSource(StdMutex::new(Some(epoch)))),
    )
    .unwrap();
    assert!(slot.connected());
    assert!(slot.contains_kind(TestKind::Beta));
    assert!(slot.resolve(TestKind::Beta).is_ok());
    slot.clear().unwrap();
    assert!(!slot.connected());
    assert!(slot.resolve(TestKind::Beta).is_err());
}

#[test]
fn lease_fails_closed_after_epoch_revocation() {
    let epoch = uuid::Uuid::new_v4().to_string();
    let source = Arc::new(TestEpochSource(StdMutex::new(Some(epoch.clone()))));
    let mut credentials = BTreeMap::new();
    credentials.insert(TestKind::Beta, vec![test_credential("synthetic-key-12345")]);
    let lease = CredentialLease::new(
        credentials,
        Duration::from_secs(3600),
        epoch,
        source.clone(),
        EgressScope::deny_all(),
    )
    .unwrap();
    assert_eq!(
        lease
            .resolve(TestKind::Beta)
            .unwrap()
            .expose_utf8()
            .unwrap(),
        "synthetic-key-12345"
    );
    // A rotated epoch kills the lease on its very next use, not only a full
    // lock (`None`) does.
    *source.0.lock().unwrap() = Some(uuid::Uuid::new_v4().to_string());
    assert_eq!(
        lease.resolve(TestKind::Beta).unwrap_err().to_string(),
        "credential_lease_revoked"
    );
    assert_eq!(
        lease
            .resolve_candidates(TestKind::Beta)
            .unwrap_err()
            .to_string(),
        "credential_lease_revoked"
    );
    assert_eq!(
        lease.handoff_projection().unwrap_err().to_string(),
        "credential_lease_revoked"
    );
    *source.0.lock().unwrap() = None;
    assert_eq!(
        lease.resolve(TestKind::Beta).unwrap_err().to_string(),
        "credential_lease_revoked"
    );
}

#[test]
fn epoch_source_failure_fails_closed_without_resolving() {
    let epoch = uuid::Uuid::new_v4().to_string();
    let mut credentials = BTreeMap::new();
    credentials.insert(
        TestKind::Beta,
        vec![test_credential("synthetic-epoch-error")],
    );
    let lease = CredentialLease::new(
        credentials,
        Duration::from_secs(3600),
        epoch,
        Arc::new(FailingEpochSource),
        EgressScope::deny_all(),
    )
    .unwrap();
    assert_eq!(
        lease.resolve(TestKind::Beta).unwrap_err().to_string(),
        "credential_lease_epoch_unavailable"
    );
    assert_eq!(
        lease
            .resolve_candidates(TestKind::Beta)
            .unwrap_err()
            .to_string(),
        "credential_lease_epoch_unavailable"
    );
    assert_eq!(
        lease.handoff_projection().unwrap_err().to_string(),
        "credential_lease_epoch_unavailable"
    );
}

#[test]
fn lease_bound_to_another_process_fails_closed_on_every_secret_use() {
    let epoch = uuid::Uuid::new_v4().to_string();
    let source = Arc::new(TestEpochSource(StdMutex::new(Some(epoch.clone()))));
    let mut credentials = BTreeMap::new();
    credentials.insert(
        TestKind::Beta,
        vec![test_credential("synthetic-cross-pid-key")],
    );
    let foreign_process = std::process::id().wrapping_add(1);
    assert_ne!(foreign_process, std::process::id());
    let lease = CredentialLease::new_with_binding_for_test(
        credentials,
        Duration::from_secs(3600),
        epoch,
        source,
        EgressScope::deny_all(),
        foreign_process,
        Instant::now() + Duration::from_secs(3600),
    )
    .unwrap();

    // The secret is live and within TTL under a valid epoch, but the lease
    // is bound to another process: every path that could expose or copy it
    // fails closed.
    assert_eq!(
        lease.resolve(TestKind::Beta).unwrap_err().to_string(),
        "credential_lease_process_mismatch"
    );
    assert_eq!(
        lease
            .resolve_candidates(TestKind::Beta)
            .unwrap_err()
            .to_string(),
        "credential_lease_process_mismatch"
    );
    assert_eq!(
        lease.handoff_projection().unwrap_err().to_string(),
        "credential_lease_process_mismatch"
    );
    // A local integrity refusal is not a credential-expiry signal: the host
    // must surface it instead of renewing across a broken boundary.
    assert_eq!(
        auth_failure_class(&lease.resolve(TestKind::Beta).unwrap_err()),
        None
    );

    let slot = CredentialSlot::new(lease);
    assert!(!slot.connected());
    assert_eq!(
        slot.resolve(TestKind::Beta).unwrap_err().to_string(),
        "credential_lease_process_mismatch"
    );
    assert_eq!(
        slot.resolve_candidates(TestKind::Beta)
            .unwrap_err()
            .to_string(),
        "credential_lease_process_mismatch"
    );
}

#[test]
fn expired_lease_fails_closed_before_touching_the_epoch() {
    let epoch = uuid::Uuid::new_v4().to_string();
    let mut credentials = BTreeMap::new();
    credentials.insert(
        TestKind::Beta,
        vec![test_credential("synthetic-expired-key")],
    );
    let lease = CredentialLease::new_with_binding_for_test(
        credentials,
        Duration::from_secs(3600),
        epoch,
        // This source would fail if consulted: an expired lease must refuse
        // before any epoch answer is requested.
        Arc::new(FailingEpochSource),
        EgressScope::deny_all(),
        std::process::id(),
        Instant::now() - Duration::from_secs(1),
    )
    .unwrap();

    assert_eq!(
        lease.resolve(TestKind::Beta).unwrap_err().to_string(),
        "credential_lease_expired"
    );
    assert_eq!(
        lease
            .resolve_candidates(TestKind::Beta)
            .unwrap_err()
            .to_string(),
        "credential_lease_expired"
    );
    // Projection is a credential use too: an expired lease cannot restart
    // its lifetime by re-minting a fresh handoff.
    assert_eq!(
        lease.handoff_projection().unwrap_err().to_string(),
        "credential_lease_expired"
    );
    let slot = CredentialSlot::new(lease);
    assert!(!slot.connected());
    assert_eq!(
        slot.resolve(TestKind::Beta).unwrap_err().to_string(),
        "credential_lease_expired"
    );
}

#[test]
fn secret_bytes_zeroize_scrubs_the_buffer_and_clears_its_length() {
    let mut secret = SecretBytes::try_from_bytes(vec![0xAA; 64]).unwrap();
    let copy = secret.copy_for_persistent_read();
    assert!(secret.zeroize_and_inspect());
    assert!(secret.expose_bytes().is_empty());
    // An independently owned copy keeps its own bytes: zeroizing the lease's
    // buffer never reaches a value another owner already holds.
    assert_eq!(copy.expose_bytes(), &[0xAA; 64]);
}

#[test]
fn handoff_document_zeroize_scrubs_serialized_secret_material() {
    let epoch = uuid::Uuid::new_v4().to_string();
    let source = Arc::new(TestEpochSource(StdMutex::new(Some(epoch.clone()))));
    let lease = CredentialLease::new(
        handoff_test_credentials(),
        Duration::from_secs(3600),
        epoch,
        source,
        EgressScope::new(
            vec!["api.example.com".to_owned()],
            vec![443],
            vec!["/v1/".to_owned()],
            vec!["GET".to_owned()],
            vec![
                HeaderTemplate::new("Authorization".to_owned(), "Bearer {secret}".to_owned())
                    .unwrap(),
            ],
            true,
        )
        .unwrap(),
    )
    .unwrap();
    let mut document = lease.handoff_projection().unwrap().to_json().unwrap();
    // The first alpha secret starts with `s` (115) and is decimal-encoded;
    // the declared egress scope serializes into the same secret-bearing
    // document and is scrubbed with it.
    assert!(String::from_utf8_lossy(document.expose_bytes()).contains("\"secret\":[115,"));
    assert!(String::from_utf8_lossy(document.expose_bytes()).contains("\"allowRedirects\":true"));
    assert!(document.zeroize_and_inspect());
    assert!(document.expose_bytes().is_empty());
}

#[test]
fn lease_filters_expired_credentials_and_rotates_valid_candidates() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let epoch = uuid::Uuid::new_v4().to_string();
    let source = Arc::new(TestEpochSource(StdMutex::new(Some(epoch.clone()))));
    let credentials = BTreeMap::from([(
        TestKind::Alpha,
        vec![
            LeasedCredential::new(
                uuid::Uuid::new_v4().to_string(),
                SecretBytes::try_from_string("expired-key-12345".to_owned()).unwrap(),
                Some(now),
            )
            .unwrap(),
            LeasedCredential::new(
                uuid::Uuid::new_v4().to_string(),
                SecretBytes::try_from_string("active-key-one-12345".to_owned()).unwrap(),
                Some(now + 60),
            )
            .unwrap(),
            LeasedCredential::new(
                uuid::Uuid::new_v4().to_string(),
                SecretBytes::try_from_string("active-key-two-12345".to_owned()).unwrap(),
                None,
            )
            .unwrap(),
        ],
    )]);
    let slot = CredentialSlot::new(
        CredentialLease::new(
            credentials,
            Duration::from_secs(3600),
            epoch,
            source,
            EgressScope::deny_all(),
        )
        .unwrap(),
    );

    let first = slot.resolve_candidates(TestKind::Alpha).unwrap();
    let second = slot.resolve_candidates(TestKind::Alpha).unwrap();
    assert_eq!(first.len(), 2);
    assert_eq!(second.len(), 2);
    assert_ne!(first[0].expose_bytes(), second[0].expose_bytes());
    assert!(first
        .iter()
        .all(|credential| credential.expose_bytes() != b"expired-key-12345"));
}

fn handoff_document(credentials: serde_json::Value) -> Vec<u8> {
    let deadline = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": TestKind::HANDOFF_SCHEMA,
        "leaseDurationSeconds": 3600,
        "leaseExpiresAtEpochSeconds": deadline,
        "epoch": "11111111-1111-4111-8111-111111111111",
        "credentials": credentials,
    }))
    .unwrap()
}

fn handoff_key(secret: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "credentialId": uuid::Uuid::new_v4().to_string(),
        "expiresAtEpochSeconds": null,
        "secret": secret,
    })
}

fn assert_handoff_invalid(payload: &[u8]) {
    let error = CredentialHandoff::<TestKind>::from_json(payload).unwrap_err();
    assert_eq!(error.to_string(), "credential_lease_handoff_invalid");
}

#[test]
fn handoff_round_trip_preserves_credentials_duration_and_epoch() {
    let epoch = uuid::Uuid::new_v4().to_string();
    let source = Arc::new(TestEpochSource(StdMutex::new(Some(epoch.clone()))));
    let lease = CredentialLease::new(
        handoff_test_credentials(),
        Duration::from_secs(7200),
        epoch.clone(),
        source,
        EgressScope::deny_all(),
    )
    .unwrap();
    let payload = lease.handoff_projection().unwrap().to_json().unwrap();
    assert!(String::from_utf8_lossy(payload.expose_bytes()).contains(TestKind::HANDOFF_SCHEMA));

    let parsed = CredentialHandoff::<TestKind>::from_json(payload.expose_bytes()).unwrap();
    // A projection carries the grant's remaining duration — at most what
    // was left of the original 7200 seconds, never a fresh full term.
    assert!(parsed.lease_duration() <= Duration::from_secs(7200));
    assert!(parsed.lease_duration() >= Duration::from_secs(7199));
    assert_eq!(parsed.epoch(), epoch.as_str());
    assert_eq!(parsed.kinds().count(), 2);
    // The serialized secret bytes round-trip intact: a lease rebuilt from
    // the parsed handoff resolves the same credentials.
    let rebuilt = CredentialLease::from_handoff(
        parsed,
        Arc::new(TestEpochSource(StdMutex::new(Some(epoch)))),
    )
    .unwrap();
    assert_eq!(
        rebuilt.resolve(TestKind::Alpha).unwrap().expose_bytes(),
        b"synthetic-alpha-key-1"
    );
    assert_eq!(
        rebuilt.resolve(TestKind::Beta).unwrap().expose_bytes(),
        b"synthetic-beta-key-1"
    );
}

#[test]
fn projection_and_rebuild_preserve_the_owner_authorized_deadline() {
    // A chained projection must not extend the grant: the deadline stamped
    // by the original mint travels verbatim into every later projection,
    // so a lease rebuilt twice still dies at the first grant's deadline.
    let epoch = uuid::Uuid::new_v4().to_string();
    let source = Arc::new(TestEpochSource(StdMutex::new(Some(epoch.clone()))));
    let lease = CredentialLease::new(
        handoff_test_credentials(),
        Duration::from_secs(3600),
        epoch.clone(),
        source.clone(),
        EgressScope::deny_all(),
    )
    .unwrap();
    let first = lease.handoff_projection().unwrap();
    let deadline = first.lease_expires_at_epoch_seconds();
    let rebuilt =
        CredentialLease::from_handoff(first, Arc::new(TestEpochSource(StdMutex::new(Some(epoch)))))
            .unwrap();
    let second = rebuilt.handoff_projection().unwrap();
    assert_eq!(second.lease_expires_at_epoch_seconds(), deadline);
    // The second projection's duration is bounded by what remained of the
    // original grant, not a fresh full term.
    assert!(second.lease_duration() <= Duration::from_secs(3600));
    let document = second.to_json().unwrap();
    let reparsed = CredentialHandoff::<TestKind>::from_json(document.expose_bytes()).unwrap();
    assert_eq!(reparsed.lease_expires_at_epoch_seconds(), deadline);
}

#[test]
fn rebuilt_lease_never_outlives_the_documents_deadline() {
    // A document granting one hour with a deadline two seconds out must
    // rebuild to a lease that projects at most that sliver — the deadline
    // caps the monotonic expiry, it does not extend it.
    let epoch = uuid::Uuid::new_v4().to_string();
    let deadline = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 2;
    let document = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": TestKind::HANDOFF_SCHEMA,
        "leaseDurationSeconds": 3600,
        "leaseExpiresAtEpochSeconds": deadline,
        "epoch": epoch,
        "credentials": [{"kind": "alpha", "keys": [handoff_key(serde_json::json!([1, 2, 3]))]}],
    }))
    .unwrap();
    let handoff = CredentialHandoff::<TestKind>::from_json(&document).unwrap();
    let rebuilt = CredentialLease::from_handoff(
        handoff,
        Arc::new(TestEpochSource(StdMutex::new(Some(epoch)))),
    )
    .unwrap();
    match rebuilt.handoff_projection() {
        Ok(projected) => {
            assert_eq!(projected.lease_expires_at_epoch_seconds(), deadline);
            assert!(projected.lease_duration() <= Duration::from_secs(2));
        }
        // A sub-second remainder cannot mint a document at all.
        Err(error) => assert_eq!(error.to_string(), "credential_lease_duration_invalid"),
    }
    // A lapsed deadline yields a dead-on-arrival lease: parsing succeeds
    // but every use fails closed.
    let past = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 1;
    let epoch = uuid::Uuid::new_v4().to_string();
    let document = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": TestKind::HANDOFF_SCHEMA,
        "leaseDurationSeconds": 3600,
        "leaseExpiresAtEpochSeconds": past,
        "epoch": epoch,
        "credentials": [{"kind": "alpha", "keys": [handoff_key(serde_json::json!([1, 2, 3]))]}],
    }))
    .unwrap();
    let handoff = CredentialHandoff::<TestKind>::from_json(&document).unwrap();
    let dead = CredentialLease::from_handoff(
        handoff,
        Arc::new(TestEpochSource(StdMutex::new(Some(epoch)))),
    )
    .unwrap();
    assert_eq!(
        dead.resolve(TestKind::Alpha).unwrap_err().to_string(),
        "credential_lease_expired"
    );
}

#[test]
fn handoff_rejects_missing_or_malformed_deadline() {
    let alpha_entry =
        serde_json::json!({"kind": "alpha", "keys": [handoff_key(serde_json::json!([1, 2, 3]))]});
    // Missing the required deadline member.
    let mut missing: serde_json::Value =
        serde_json::from_slice(&handoff_document(serde_json::json!([alpha_entry]))).unwrap();
    missing
        .as_object_mut()
        .unwrap()
        .remove("leaseExpiresAtEpochSeconds");
    assert_handoff_invalid(&serde_json::to_vec(&missing).unwrap());
    // Zero, null, negative, non-integer, and string deadlines all refuse.
    for bad in [
        serde_json::json!(0),
        serde_json::json!(null),
        serde_json::json!(-1),
        serde_json::json!(1.5),
        serde_json::json!("soon"),
    ] {
        let mut document: serde_json::Value =
            serde_json::from_slice(&handoff_document(serde_json::json!([alpha_entry]))).unwrap();
        document["leaseExpiresAtEpochSeconds"] = bad;
        assert_handoff_invalid(&serde_json::to_vec(&document).unwrap());
    }
}

#[test]
fn handoff_size_estimate_covers_escaped_names() {
    // A kind name carrying a control character and quotes escapes to more
    // bytes than its raw length; the serialized reserve must still cover the
    // emitted document, or the buffer would grow after secrets were written.
    let epoch = uuid::Uuid::new_v4().to_string();
    let mut credentials = BTreeMap::new();
    credentials.insert(
        EscapedKind::Control,
        vec![test_credential("synthetic-esc-key")],
    );
    let handoff = CredentialHandoff::<EscapedKind>::new(
        credentials,
        Duration::from_secs(60),
        epoch.clone(),
        EgressScope::deny_all(),
    )
    .unwrap();
    let payload = handoff.to_json().unwrap();
    assert!(payload.expose_bytes().len() <= handoff.serialized_len_upper_bound());
    let reparsed = CredentialHandoff::<EscapedKind>::from_json(payload.expose_bytes()).unwrap();
    assert_eq!(reparsed.epoch(), epoch.as_str());
}

#[test]
fn handoff_rejects_oversize_schema_name() {
    // A family whose schema constant exceeds the contract's 128-byte bound
    // must be refused at parse time, matching the producer-side refusal.
    let document = serde_json::json!({
        "schemaVersion": OversizeSchemaKind::HANDOFF_SCHEMA,
        "leaseDurationSeconds": 60,
        "leaseExpiresAtEpochSeconds": SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60,
        "epoch": uuid::Uuid::new_v4().to_string(),
        "credentials": [{"kind": "only", "keys": [handoff_key(serde_json::json!([120]))]}],
    });
    assert!(CredentialHandoff::<OversizeSchemaKind>::from_json(
        &serde_json::to_vec(&document).unwrap()
    )
    .is_err());
}

#[test]
fn maximal_inventory_serializes_within_document_bound() {
    // The documented bound must cover the largest inventory the contract
    // admits: 64 credentials of 8192 secret bytes with maximal expiries,
    // under a schema and kind name at their byte bounds with heavy
    // escaping.
    let epoch = uuid::Uuid::new_v4().to_string();
    let mut credentials = BTreeMap::new();
    credentials.insert(
        MaxEscapedKind::Only,
        (0..MAX_LEASED_CREDENTIALS)
            .map(|_| {
                LeasedCredential::new(
                    uuid::Uuid::new_v4().to_string(),
                    SecretBytes::try_from_bytes(vec![0xAA; MAX_CREDENTIAL_BYTES]).unwrap(),
                    Some(u64::MAX),
                )
                .unwrap()
            })
            .collect::<Vec<_>>(),
    );
    let handoff = CredentialHandoff::<MaxEscapedKind>::new(
        credentials,
        Duration::from_secs(MAX_LEASE_DURATION_SECONDS),
        epoch,
        EgressScope::deny_all(),
    )
    .unwrap();
    let payload = handoff.to_json().unwrap();
    assert!(payload.expose_bytes().len() <= handoff.serialized_len_upper_bound());
    assert!(payload.expose_bytes().len() <= MAX_HANDOFF_DOC_BYTES);
}

#[test]
fn handoff_rejects_malformed_documents() {
    let alpha_entry =
        serde_json::json!({"kind": "alpha", "keys": [handoff_key(serde_json::json!([1, 2, 3]))]});
    // Unparseable payload.
    assert_handoff_invalid(b"not-json");
    // Wrong schema version.
    let mut wrong_schema: serde_json::Value =
        serde_json::from_slice(&handoff_document(serde_json::json!([alpha_entry]))).unwrap();
    wrong_schema["schemaVersion"] = serde_json::json!("other.schema.v1");
    assert_handoff_invalid(&serde_json::to_vec(&wrong_schema).unwrap());
    // Unknown top-level field.
    let mut extra_field: serde_json::Value =
        serde_json::from_slice(&handoff_document(serde_json::json!([alpha_entry]))).unwrap();
    extra_field["extra"] = serde_json::json!(true);
    assert_handoff_invalid(&serde_json::to_vec(&extra_field).unwrap());
    // Zero and over-max lease duration.
    for seconds in [0u64, MAX_LEASE_DURATION_SECONDS + 1] {
        let mut bad_duration: serde_json::Value =
            serde_json::from_slice(&handoff_document(serde_json::json!([alpha_entry]))).unwrap();
        bad_duration["leaseDurationSeconds"] = serde_json::json!(seconds);
        assert_handoff_invalid(&serde_json::to_vec(&bad_duration).unwrap());
    }
    // Non-canonical epoch.
    let mut bad_epoch: serde_json::Value =
        serde_json::from_slice(&handoff_document(serde_json::json!([alpha_entry]))).unwrap();
    bad_epoch["epoch"] = serde_json::json!("AAAAAAAA-1111-4111-8111-111111111111");
    assert_handoff_invalid(&serde_json::to_vec(&bad_epoch).unwrap());
    // Unknown kind.
    assert_handoff_invalid(&handoff_document(
        serde_json::json!([{"kind": "unknown", "keys": [handoff_key(serde_json::json!([1, 2, 3]))]}]),
    ));
    // Duplicate kind entry.
    assert_handoff_invalid(&handoff_document(serde_json::json!([
        alpha_entry,
        alpha_entry
    ])));
    // Empty keys array.
    assert_handoff_invalid(&handoff_document(
        serde_json::json!([{"kind": "alpha", "keys": []}]),
    ));
    // Empty key byte array.
    assert_handoff_invalid(&handoff_document(
        serde_json::json!([{"kind": "alpha", "keys": [handoff_key(serde_json::json!([]))]}]),
    ));
    // Byte value outside 0-255.
    assert_handoff_invalid(&handoff_document(
        serde_json::json!([{"kind": "alpha", "keys": [handoff_key(serde_json::json!([256]))]}]),
    ));
    // One key exceeding MAX_CREDENTIAL_BYTES.
    let oversize_key = vec![0u8; MAX_CREDENTIAL_BYTES + 1];
    assert_handoff_invalid(&handoff_document(
        serde_json::json!([{"kind": "alpha", "keys": [handoff_key(serde_json::json!(oversize_key))]}]),
    ));
    // Total key count above MAX_LEASED_CREDENTIALS.
    let too_many_keys = (0..=MAX_LEASED_CREDENTIALS)
        .map(|_| handoff_key(serde_json::json!([1, 2, 3])))
        .collect::<Vec<_>>();
    assert_handoff_invalid(&handoff_document(
        serde_json::json!([{"kind": "alpha", "keys": too_many_keys}]),
    ));
    // Non-canonical credential id.
    assert_handoff_invalid(&handoff_document(
        serde_json::json!([{"kind": "alpha", "keys": [
            {"credentialId": "not-a-uuid", "expiresAtEpochSeconds": null, "secret": [1, 2, 3]}
        ]}]),
    ));
    // Duplicate credential ids across kinds.
    let shared_id = uuid::Uuid::new_v4().to_string();
    assert_handoff_invalid(&handoff_document(serde_json::json!([
        {"kind": "alpha", "keys": [
            {"credentialId": shared_id, "expiresAtEpochSeconds": null, "secret": [1, 2, 3]}
        ]},
        {"kind": "beta", "keys": [
            {"credentialId": shared_id, "expiresAtEpochSeconds": null, "secret": [4, 5, 6]}
        ]},
    ])));
}

#[test]
fn handoff_rejects_duplicate_member_names_and_oversized_documents() {
    // Duplicate member names reject the whole document at every level —
    // the closed contract has no last-wins semantics.
    let mut top_level_dup = br#"{"schemaVersion":""#.to_vec();
    top_level_dup.extend_from_slice(TestKind::HANDOFF_SCHEMA.as_bytes());
    top_level_dup.extend_from_slice(
        br#"","schemaVersion":"x","leaseDurationSeconds":1,"epoch":"11111111-1111-4111-8111-111111111111","credentials":[]}"#,
    );
    assert_handoff_invalid(&top_level_dup);
    let dup_inside_keys = handoff_document(serde_json::json!([
        {"kind": "alpha", "keys": [handoff_key(serde_json::json!([1, 2, 3]))]}
    ]));
    let text = String::from_utf8(dup_inside_keys).unwrap();
    let dup = text.replacen(
        "\"kind\":\"alpha\"",
        "\"kind\":\"alpha\",\"kind\":\"beta\"",
        1,
    );
    assert_handoff_invalid(dup.as_bytes());
    // Inputs above the documented byte bound are refused before parsing.
    let oversized = vec![b' '; MAX_HANDOFF_DOC_BYTES + 1];
    assert_handoff_invalid(&oversized);
}

#[test]
fn handoff_never_crosses_kind_families() {
    let epoch = uuid::Uuid::new_v4().to_string();
    let source = Arc::new(TestEpochSource(StdMutex::new(Some(epoch.clone()))));
    let lease = CredentialLease::new(
        handoff_test_credentials(),
        Duration::from_secs(3600),
        epoch,
        source,
        EgressScope::deny_all(),
    )
    .unwrap();
    let payload = lease.handoff_projection().unwrap().to_json().unwrap();

    // A document minted under the TestKind schema must not parse as
    // OtherKind — the schema pin is what keeps families apart.
    assert_eq!(
        CredentialHandoff::<OtherKind>::from_json(payload.expose_bytes())
            .unwrap_err()
            .to_string(),
        "credential_lease_handoff_invalid"
    );
}

#[test]
fn handoff_and_lease_debug_never_include_secret_material() {
    let epoch = uuid::Uuid::new_v4().to_string();
    let source = Arc::new(TestEpochSource(StdMutex::new(Some(epoch.clone()))));
    let lease = CredentialLease::new(
        handoff_test_credentials(),
        Duration::from_secs(3600),
        epoch,
        source,
        EgressScope::deny_all(),
    )
    .unwrap();
    let handoff = lease.handoff_projection().unwrap();
    let debug = format!("{handoff:?}");
    assert!(!debug.contains("synthetic-alpha-key-1"));
    assert!(!debug.contains("synthetic-beta-key-1"));
    let lease_debug = format!("{lease:?}");
    assert!(!lease_debug.contains("synthetic-alpha-key-1"));
    let slot_debug = format!("{:?}", CredentialSlot::new(lease));
    assert!(!slot_debug.contains("synthetic-alpha-key-1"));
}

struct RebuildingPort;

impl CustodyPort<TestKind> for RebuildingPort {
    fn lease_from_handoff(
        &self,
        handoff: CredentialHandoff<TestKind>,
    ) -> Result<CredentialLease<TestKind>> {
        let epoch = handoff.epoch().to_owned();
        CredentialLease::from_handoff(
            handoff,
            Arc::new(TestEpochSource(StdMutex::new(Some(epoch)))),
        )
    }
}

struct OtherPort;

impl CustodyPort<TestKind> for OtherPort {
    fn lease_from_handoff(
        &self,
        _handoff: CredentialHandoff<TestKind>,
    ) -> Result<CredentialLease<TestKind>> {
        Ok(CredentialLease::disconnected())
    }
}

#[test]
fn custody_port_installs_per_kind_family_and_rebuilds_leases() {
    port::clear();
    assert!(!port::installed::<TestKind>());
    assert_eq!(
        port::require::<TestKind>().err().unwrap().to_string(),
        "custody_port_unavailable"
    );

    let port_impl = Arc::new(RebuildingPort);
    port::install::<TestKind, _>(port_impl.clone()).unwrap();
    assert!(port::installed::<TestKind>());
    // Same port reinstall is harmless.
    port::install::<TestKind, _>(port_impl).unwrap();
    // A different port for the same family is refused.
    assert_eq!(
        port::install::<TestKind, _>(Arc::new(OtherPort)).unwrap_err(),
        "custody_port_already_installed"
    );
    // Another family installs independently.
    assert!(!port::installed::<OtherKind>());

    // The installed port rebuilds a working lease from a handoff.
    let epoch = uuid::Uuid::new_v4().to_string();
    let handoff = CredentialHandoff::new(
        handoff_test_credentials(),
        Duration::from_secs(3600),
        epoch,
        EgressScope::deny_all(),
    )
    .unwrap();
    let lease = port::require::<TestKind>()
        .unwrap()
        .lease_from_handoff(handoff)
        .unwrap();
    assert_eq!(
        lease.resolve(TestKind::Alpha).unwrap().expose_bytes(),
        b"synthetic-alpha-key-1"
    );
    port::clear();
}

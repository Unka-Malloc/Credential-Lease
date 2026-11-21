use super::*;
use crate::handoff::{
    projected_monotonic_deadline_seconds, CredentialHandoff, MAX_HANDOFF_DOC_BYTES,
};
use crate::lease::{
    deadline_remaining, projected_expiry_epoch_seconds, LeaseClockSource, SystemLeaseClocks,
};
use crate::SecretBytes;
use anyhow::Result;
use std::collections::{BTreeMap, VecDeque};
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

/// A scripted clock pair: wall and monotonic readings each come off a
/// script in order — the final one repeats once the script is spent —
/// and the monotonic clock can be made to fail after mint, so suspend
/// and clock-failure paths are exercised deterministically instead of
/// by sleeping or racing a live second boundary.
struct TestClocks {
    wall_readings: StdMutex<VecDeque<Duration>>,
    monotonic_readings: StdMutex<VecDeque<Result<Option<Duration>, &'static str>>>,
}

impl TestClocks {
    fn new(wall_now: Duration, monotonic_now: Option<Duration>) -> Self {
        Self {
            wall_readings: StdMutex::new(VecDeque::from(vec![wall_now])),
            monotonic_readings: StdMutex::new(VecDeque::from(vec![Ok(monotonic_now)])),
        }
    }

    /// A wall clock that answers successive reads off `wall_readings` in
    /// order, then keeps answering the final reading.
    fn with_wall_sequence(wall_readings: Vec<Duration>, monotonic_now: Option<Duration>) -> Self {
        Self {
            wall_readings: StdMutex::new(VecDeque::from(wall_readings)),
            monotonic_readings: StdMutex::new(VecDeque::from(vec![Ok(monotonic_now)])),
        }
    }

    /// A monotonic clock that answers successive reads off
    /// `monotonic_readings` in order, then keeps answering the final
    /// one — so a script can fail exactly the read under test while the
    /// reads before and after it keep seeing a healthy clock.
    fn with_monotonic_sequence(
        wall_now: Duration,
        monotonic_readings: Vec<Result<Option<Duration>, &'static str>>,
    ) -> Self {
        Self {
            wall_readings: StdMutex::new(VecDeque::from(vec![wall_now])),
            monotonic_readings: StdMutex::new(VecDeque::from(monotonic_readings)),
        }
    }

    /// The monotonic clock starts failing its reads — the operational
    /// answer, distinct from a platform that honestly has no clock.
    fn lose_monotonic(&self) {
        let mut readings = self.monotonic_readings.lock().unwrap();
        readings.clear();
        readings.push_back(Err("credential_lease_clock_unavailable"));
    }
}

impl LeaseClockSource for TestClocks {
    fn wall_now(&self) -> Result<Duration> {
        let mut readings = self.wall_readings.lock().unwrap();
        Ok(if readings.len() > 1 {
            readings.pop_front().unwrap()
        } else {
            *readings.front().unwrap()
        })
    }

    fn monotonic_now(&self) -> Result<Option<Duration>> {
        let mut readings = self.monotonic_readings.lock().unwrap();
        let reading = if readings.len() > 1 {
            readings.pop_front().unwrap()
        } else {
            *readings.front().unwrap()
        };
        reading.map_err(anyhow::Error::msg)
    }
}

/// An epoch source that answers only after a delay — long enough that a
/// nearly-expired lease crosses its deadline while the lookup is in
/// flight.
struct SlowEpochSource {
    epoch: String,
    delay: Duration,
}

impl LeaseEpochSource for SlowEpochSource {
    fn active_epoch(&self) -> Result<Option<String>> {
        std::thread::sleep(self.delay);
        Ok(Some(self.epoch.clone()))
    }
}

fn test_credential(material: u8) -> LeasedCredential {
    LeasedCredential::new(
        uuid::Uuid::new_v4().to_string(),
        SecretBytes::try_from_bytes(vec![material; 16]).unwrap(),
        None,
    )
    .unwrap()
}

fn handoff_test_credentials() -> BTreeMap<TestKind, Vec<LeasedCredential>> {
    let mut credentials = BTreeMap::new();
    credentials.insert(
        TestKind::Alpha,
        vec![test_credential(0xA1), test_credential(0xA2)],
    );
    credentials.insert(TestKind::Beta, vec![test_credential(0xB1)]);
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
    credentials.insert(TestKind::Beta, vec![test_credential(0xC1)]);
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
#[cfg(unix)]
fn an_expired_handoff_refuses_install_and_preserves_the_installed_lease() {
    // A rebuild can succeed with zero remaining lifetime: the
    // owner-authorized deadline it honors may already have elapsed on
    // either clock domain. Installing that dead-on-arrival lease would
    // report success while disconnecting a slot that still holds a valid
    // grant — the replacement proves its expiry before the swap, and the
    // installed lease survives the refusal.
    let epoch = uuid::Uuid::new_v4().to_string();
    let source = Arc::new(TestEpochSource(StdMutex::new(Some(epoch.clone()))));
    let slot = CredentialSlot::<TestKind>::disconnected();
    let mut credentials = BTreeMap::new();
    credentials.insert(TestKind::Beta, vec![test_credential(0xC8)]);
    slot.install_handoff(
        CredentialHandoff::new(
            credentials,
            Duration::from_secs(3600),
            epoch.clone(),
            EgressScope::deny_all(),
        )
        .unwrap(),
        source.clone(),
    )
    .unwrap();
    assert!(slot.connected());
    // A delayed refresh arrives after the grant's deadline: the document
    // still parses and rebuilds, but the result is dead on arrival.
    let past = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 1;
    let mut document = serde_json::json!({
        "schemaVersion": TestKind::HANDOFF_SCHEMA,
        "leaseDurationSeconds": 3600,
        "leaseExpiresAtEpochSeconds": past,
        "epoch": epoch,
        "credentials": [{"kind": "alpha", "keys": [handoff_key(serde_json::json!([7, 8, 9]))]}],
    });
    if let Ok(Some(now)) = crate::handoff::monotonic_now() {
        document["leaseMonotonicDeadlineSeconds"] = serde_json::json!(now.as_secs() + 3600);
    }
    let stale =
        CredentialHandoff::<TestKind>::from_json(&serde_json::to_vec(&document).unwrap()).unwrap();
    assert_eq!(
        slot.install_handoff(stale, source).unwrap_err().to_string(),
        "credential_lease_expired"
    );
    assert!(slot.connected());
    assert_eq!(
        slot.resolve(TestKind::Beta).unwrap().expose_bytes(),
        &[0xC8u8; 16]
    );
}

#[test]
fn lease_fails_closed_after_epoch_revocation() {
    let epoch = uuid::Uuid::new_v4().to_string();
    let source = Arc::new(TestEpochSource(StdMutex::new(Some(epoch.clone()))));
    let mut credentials = BTreeMap::new();
    credentials.insert(TestKind::Beta, vec![test_credential(0xC2)]);
    let lease = CredentialLease::new(
        credentials,
        Duration::from_secs(3600),
        epoch,
        source.clone(),
        EgressScope::deny_all(),
    )
    .unwrap();
    assert_eq!(
        lease.resolve(TestKind::Beta).unwrap().expose_bytes(),
        &[0xC2u8; 16]
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
    credentials.insert(TestKind::Beta, vec![test_credential(0xC3)]);
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
    credentials.insert(TestKind::Beta, vec![test_credential(0xC4)]);
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
        u64::MAX,
        crate::handoff::monotonic_deadline_seconds(Duration::from_secs(3600)).unwrap(),
        Arc::new(SystemLeaseClocks),
    )
    .unwrap();

    // The secret is live and within TTL under a valid epoch, but the lease
    // is bound to another process: every path that could expose or copy it
    // fails closed.
    assert_eq!(
        lease.resolve(TestKind::Beta).unwrap_err().to_string(),
        "credential_lease_process_mismatch"
    );
    // A kind the lease does not carry refuses as a boundary violation
    // first — the process check precedes the inventory lookup, so a
    // missing kind can never masquerade as the ordinary `auth_expired`
    // renewal signal a misdirected retry would trigger.
    assert_eq!(
        lease.resolve(TestKind::Alpha).unwrap_err().to_string(),
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
    credentials.insert(TestKind::Beta, vec![test_credential(0xE1)]);
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
        u64::MAX,
        crate::handoff::monotonic_deadline_seconds(Duration::from_secs(3600)).unwrap(),
        Arc::new(SystemLeaseClocks),
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
fn a_slow_epoch_lookup_never_releases_an_expired_credential() {
    // The lease is still live when the epoch consultation starts, but the
    // answer arrives after the expiry passes: resolution must refuse as
    // expired, not release credentials the matching epoch just vouched
    // for. The expiry check therefore runs again after the epoch answers.
    let epoch = uuid::Uuid::new_v4().to_string();
    let mut credentials = BTreeMap::new();
    credentials.insert(TestKind::Beta, vec![test_credential(0xC6)]);
    let lease = CredentialLease::new_with_binding_for_test(
        credentials,
        Duration::from_secs(3600),
        epoch.clone(),
        Arc::new(SlowEpochSource {
            epoch,
            delay: Duration::from_millis(150),
        }),
        EgressScope::deny_all(),
        std::process::id(),
        Instant::now() + Duration::from_millis(30),
        u64::MAX,
        crate::handoff::monotonic_deadline_seconds(Duration::from_secs(3600)).unwrap(),
        Arc::new(SystemLeaseClocks),
    )
    .unwrap();
    assert_eq!(
        lease.resolve(TestKind::Beta).unwrap_err().to_string(),
        "credential_lease_expired"
    );
    // The same holds for a projection minted through the same gate.
    assert_eq!(
        lease.handoff_projection().unwrap_err().to_string(),
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
    // The first alpha secret starts with 0xA1 (161) and is decimal-encoded;
    // the declared egress scope serializes into the same secret-bearing
    // document and is scrubbed with it.
    assert!(String::from_utf8_lossy(document.expose_bytes()).contains("\"secret\":[161,"));
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
                SecretBytes::try_from_bytes(vec![0xE1; 16]).unwrap(),
                Some(now),
            )
            .unwrap(),
            LeasedCredential::new(
                uuid::Uuid::new_v4().to_string(),
                SecretBytes::try_from_bytes(vec![0xA3; 16]).unwrap(),
                Some(now + 60),
            )
            .unwrap(),
            LeasedCredential::new(
                uuid::Uuid::new_v4().to_string(),
                SecretBytes::try_from_bytes(vec![0xA4; 16]).unwrap(),
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
        .all(|credential| credential.expose_bytes() != [0xE1u8; 16]));
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
        &[0xA1u8; 16]
    );
    assert_eq!(
        rebuilt.resolve(TestKind::Beta).unwrap().expose_bytes(),
        &[0xB1u8; 16]
    );
}

#[test]
fn projection_and_rebuild_preserve_the_owner_authorized_deadline() {
    // A chained projection must not extend the grant: the deadline stamped
    // by the original mint caps every later projection. The stamped value
    // is the earlier of the received deadline and the rebuilt lease's own
    // conservatively measured expiry, so a chain can only stamp the same
    // deadline or an earlier one — never a later one.
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
    assert!(second.lease_expires_at_epoch_seconds() <= deadline);
    // The second projection's duration is bounded by what remained of the
    // original grant, not a fresh full term.
    assert!(second.lease_duration() <= Duration::from_secs(3600));
    let document = second.to_json().unwrap();
    let reparsed = CredentialHandoff::<TestKind>::from_json(document.expose_bytes()).unwrap();
    assert!(reparsed.lease_expires_at_epoch_seconds() <= deadline);
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
    let mut document = serde_json::json!({
        "schemaVersion": TestKind::HANDOFF_SCHEMA,
        "leaseDurationSeconds": 3600,
        "leaseExpiresAtEpochSeconds": deadline,
        "epoch": epoch,
        "credentials": [{"kind": "alpha", "keys": [handoff_key(serde_json::json!([1, 2, 3]))]}],
    });
    // Where the platform can compare a same-host monotonic deadline, the
    // document must carry one for a rebuild to be possible at all.
    if let Ok(Some(now)) = crate::handoff::monotonic_now() {
        document["leaseMonotonicDeadlineSeconds"] = serde_json::json!(now.as_secs() + 2);
    }
    let document = serde_json::to_vec(&document).unwrap();
    let handoff = CredentialHandoff::<TestKind>::from_json(&document).unwrap();
    let rebuilt = CredentialLease::from_handoff(
        handoff,
        Arc::new(TestEpochSource(StdMutex::new(Some(epoch)))),
    )
    .unwrap();
    match rebuilt.handoff_projection() {
        Ok(projected) => {
            // The conservative expiry estimate can floor one second under
            // the deadline — the cap holds, and the stamp never lands
            // later than the deadline the document carried.
            assert!(projected.lease_expires_at_epoch_seconds() <= deadline);
            assert!(projected.lease_duration() <= Duration::from_secs(2));
        }
        // An expiry already behind the wall clock refuses before minting.
        Err(error) => assert_eq!(error.to_string(), "credential_lease_expired"),
    }
    // A lapsed deadline yields a dead-on-arrival lease: parsing succeeds
    // but every use fails closed.
    let past = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 1;
    let epoch = uuid::Uuid::new_v4().to_string();
    let mut document = serde_json::json!({
        "schemaVersion": TestKind::HANDOFF_SCHEMA,
        "leaseDurationSeconds": 3600,
        "leaseExpiresAtEpochSeconds": past,
        "epoch": epoch,
        "credentials": [{"kind": "alpha", "keys": [handoff_key(serde_json::json!([1, 2, 3]))]}],
    });
    if let Ok(Some(now)) = crate::handoff::monotonic_now() {
        document["leaseMonotonicDeadlineSeconds"] = serde_json::json!(now.as_secs() + 3600);
    }
    let document = serde_json::to_vec(&document).unwrap();
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
fn deadline_remaining_preserves_full_wall_clock_precision() {
    // The deadline math subtracts the wall clock at full precision: a
    // deadline one epoch second out with the clock 0.9s into the current
    // second leaves 100ms — a rounded-down second-level subtraction would
    // leave the lease usable for nearly a whole extra second.
    let now = Duration::new(1_700_000_000, 900_000_000);
    assert_eq!(
        deadline_remaining(1_700_000_001, now),
        Duration::from_millis(100)
    );
    // Exact-boundary and lapsed deadlines both leave nothing.
    assert_eq!(
        deadline_remaining(1_700_000_001, now + Duration::from_secs(1)),
        Duration::ZERO
    );
    assert_eq!(deadline_remaining(1_700_000_000, now), Duration::ZERO);
}

#[test]
fn projected_expiry_stays_on_the_early_side_of_a_second_boundary_delay() {
    // The paired samples work because the wall clock is read first: a
    // wall sample at 100.9s followed by a pause means the monotonic
    // remainder was measured with the true clock already across the
    // boundary — 50ms left, a true expiry in second 101. The stamp uses
    // the early reading, floor(100.9 + 0.05) = 100, so the deadline can
    // only sit at or before the real expiry second, never beyond it.
    // Reading the wall clock after the delay would instead add the stale
    // remainder to a later reading — floor(101.05 + 0.2) = 101 — letting
    // a rebuild that restarts the ceiled wire duration outlive the
    // source lease.
    assert_eq!(
        projected_expiry_epoch_seconds(Duration::new(100, 900_000_000), Duration::from_millis(50))
            .unwrap(),
        100
    );
    // Whole-second math and the exact-boundary case.
    assert_eq!(
        projected_expiry_epoch_seconds(Duration::from_secs(100), Duration::from_secs(1)).unwrap(),
        101
    );
    assert_eq!(
        projected_expiry_epoch_seconds(Duration::from_secs(100), Duration::ZERO).unwrap(),
        100
    );
    // An unrepresentable sum refuses rather than wrapping.
    assert!(projected_expiry_epoch_seconds(Duration::MAX, Duration::from_secs(1)).is_err());
}

#[test]
fn live_subsecond_remainder_projects_as_a_whole_second() {
    // The wire format has no fractional seconds: a lease with 500ms of
    // life left is still live, so projection must succeed — mapping the
    // remainder up to one whole second. Here the lease's own expiry is
    // the tighter bound, so the stamped deadline is that expiry floored,
    // not the later owner deadline: a rebuild that restarted the
    // rounded-up second would outlive the lease it came from.
    let epoch = uuid::Uuid::new_v4().to_string();
    let source = Arc::new(TestEpochSource(StdMutex::new(Some(epoch.clone()))));
    let mut credentials = BTreeMap::new();
    credentials.insert(TestKind::Beta, vec![test_credential(0xD1)]);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let deadline = now + 2;
    let lease = CredentialLease::new_with_binding_for_test(
        credentials,
        Duration::from_secs(3600),
        epoch.clone(),
        source,
        EgressScope::deny_all(),
        std::process::id(),
        Instant::now() + Duration::from_millis(500),
        deadline,
        crate::handoff::monotonic_deadline_seconds(Duration::from_secs(3600)).unwrap(),
        Arc::new(SystemLeaseClocks),
    )
    .unwrap();
    let projected = lease.handoff_projection().unwrap();
    assert_eq!(projected.lease_duration(), Duration::from_secs(1));
    let stamped = projected.lease_expires_at_epoch_seconds();
    // floor(now + 500ms) is the current second or the next — never the
    // owner deadline, and never beyond the lease's real expiry second.
    assert!(stamped <= now + 1 && stamped < deadline);
    // A rebuild stays inside the original expiry: the rounded-up wire
    // value and the stamped deadline both bound it — and when the stamped
    // deadline is already the current second, the rebuild is dead on
    // arrival and refuses instead of minting extra life.
    let rebuilt = CredentialLease::from_handoff(
        projected,
        Arc::new(TestEpochSource(StdMutex::new(Some(epoch)))),
    )
    .unwrap();
    match rebuilt.handoff_projection() {
        Ok(projected_again) => {
            // A chained projection can never stamp a later deadline than
            // it received.
            assert!(projected_again.lease_expires_at_epoch_seconds() <= stamped);
            assert!(projected_again.lease_duration() <= Duration::from_secs(1));
        }
        Err(error) => assert_eq!(error.to_string(), "credential_lease_expired"),
    }
}

#[test]
#[cfg(unix)]
fn rebuild_requires_the_same_host_monotonic_deadline() {
    // A document without the monotonic anchor cannot prove clock
    // continuity: a backward wall-clock step between projection and
    // rebuild would inflate the deadline remainder and let the restarted
    // duration outlive the grant — so a rebuild that can compare the
    // anchor refuses a document that omits it.
    let epoch = uuid::Uuid::new_v4().to_string();
    let wall_deadline = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let mut document = serde_json::json!({
        "schemaVersion": TestKind::HANDOFF_SCHEMA,
        "leaseDurationSeconds": 3600,
        "leaseExpiresAtEpochSeconds": wall_deadline,
        "epoch": epoch,
        "credentials": [{"kind": "alpha", "keys": [handoff_key(serde_json::json!([1, 2, 3]))]}],
    });
    // The member is optional in the wire shape — a document parses either
    // way — but the rebuild refuses where clock continuity cannot be
    // established.
    let handoff =
        CredentialHandoff::<TestKind>::from_json(&serde_json::to_vec(&document).unwrap()).unwrap();
    assert_eq!(
        CredentialLease::from_handoff(
            handoff,
            Arc::new(TestEpochSource(StdMutex::new(Some(epoch.clone())))),
        )
        .unwrap_err()
        .to_string(),
        "credential_lease_expiry_invalid"
    );
    // Carried, the same-host deadline caps the rebuild on its own clock —
    // a domain wall-clock rollback cannot deceive. Two monotonic seconds
    // out lets the rebuild live at most that long, however far the wire
    // duration and the wall deadline stretch.
    let monotonic_now = crate::handoff::monotonic_now().unwrap().unwrap().as_secs();
    document["leaseMonotonicDeadlineSeconds"] = serde_json::json!(monotonic_now + 2);
    let handoff =
        CredentialHandoff::<TestKind>::from_json(&serde_json::to_vec(&document).unwrap()).unwrap();
    let rebuilt = CredentialLease::from_handoff(
        handoff,
        Arc::new(TestEpochSource(StdMutex::new(Some(epoch)))),
    )
    .unwrap();
    match rebuilt.handoff_projection() {
        Ok(projected) => {
            assert!(projected.lease_duration() <= Duration::from_secs(2));
            assert!(projected.lease_expires_at_epoch_seconds() <= wall_deadline);
        }
        Err(error) => assert_eq!(error.to_string(), "credential_lease_expired"),
    }
    // A malformed anchor refuses at parse like every other deadline.
    for bad in [
        serde_json::json!(0),
        serde_json::json!(null),
        serde_json::json!(-1),
        serde_json::json!(1.5),
        serde_json::json!("soon"),
    ] {
        let mut bad_document = document.clone();
        bad_document["leaseMonotonicDeadlineSeconds"] = bad;
        assert_handoff_invalid(&serde_json::to_vec(&bad_document).unwrap());
    }
    // And a projected document carries the anchor end to end — stamped,
    // serialized, parsed, enforced.
    let epoch = uuid::Uuid::new_v4().to_string();
    let source = Arc::new(TestEpochSource(StdMutex::new(Some(epoch.clone()))));
    let lease = CredentialLease::new(
        handoff_test_credentials(),
        Duration::from_secs(3600),
        epoch.clone(),
        source,
        EgressScope::deny_all(),
    )
    .unwrap();
    let projected = lease.handoff_projection().unwrap();
    assert!(projected.lease_monotonic_deadline_seconds().is_some());
    let document = projected.to_json().unwrap();
    let reparsed = CredentialHandoff::<TestKind>::from_json(document.expose_bytes()).unwrap();
    assert!(reparsed.lease_monotonic_deadline_seconds().is_some());
    CredentialLease::from_handoff(
        reparsed,
        Arc::new(TestEpochSource(StdMutex::new(Some(epoch)))),
    )
    .unwrap();
}

#[test]
#[cfg(unix)]
fn rebuild_keeps_subsecond_precision_against_the_monotonic_deadline() {
    // The wire deadline is whole seconds but the comparison clock is
    // not: a rebuild must subtract the monotonic reading at full
    // precision. The clocks are injected at fixed samples — monotonic
    // 200.6s against a deadline of 201 leaves exactly 400 ms — and the
    // mint instant is injected as well, so the minted lifetime is an
    // exact equality instead of a window a scheduling pause between
    // mint and assertion could step out of.
    let epoch = uuid::Uuid::new_v4().to_string();
    let clock_source = Arc::new(TestClocks::new(
        Duration::from_secs(1_700_000_000),
        Some(Duration::new(200, 600_000_000)),
    ));
    let document = serde_json::json!({
        "schemaVersion": TestKind::HANDOFF_SCHEMA,
        "leaseDurationSeconds": 3600,
        "leaseExpiresAtEpochSeconds": 1_700_003_600,
        "leaseMonotonicDeadlineSeconds": 201,
        "epoch": epoch,
        "credentials": [{"kind": "alpha", "keys": [handoff_key(serde_json::json!([1, 2, 3]))]}],
    });
    let handoff =
        CredentialHandoff::<TestKind>::from_json(&serde_json::to_vec(&document).unwrap()).unwrap();
    let minted_at = Instant::now();
    let rebuilt = CredentialLease::from_handoff_with_clock_source_at(
        handoff,
        Arc::new(TestEpochSource(StdMutex::new(Some(epoch)))),
        minted_at,
        clock_source,
    )
    .unwrap();
    // deadline(201) - sample(200.6) mints exactly 400 ms of life; a
    // floored clock reading would land the expiry almost a second later.
    assert_eq!(
        rebuilt.expires_at_for_test(),
        minted_at + Duration::from_millis(400)
    );
}

#[test]
#[cfg(unix)]
fn a_lapsed_wall_deadline_expires_while_the_runtime_clocks_pause() {
    // The Linux suspend shape: `Instant` and `CLOCK_MONOTONIC` both stop
    // across suspend while the wall clock keeps running, so a lease minted
    // before sleep wakes with both runtime clocks still inside their
    // bounds and its absolute deadline already crossed. The wall deadline
    // is enforced on the wall clock on every use — a mint-time conversion
    // alone would resolve credentials past the deadline.
    let epoch = uuid::Uuid::new_v4().to_string();
    let mut credentials = BTreeMap::new();
    credentials.insert(TestKind::Beta, vec![test_credential(0xE4)]);
    let wall_deadline = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Post-wake readings: the wall clock is 60s past the deadline while
    // the injected monotonic reading and the lease's `Instant` expiry
    // still report an hour of life — exactly the paused-clock shape a
    // mint-time wall check would miss.
    let clock_source = Arc::new(TestClocks::new(
        Duration::from_secs(wall_deadline + 60),
        crate::handoff::monotonic_now()
            .unwrap()
            .map(|now| now + Duration::from_secs(3600)),
    ));
    let monotonic_deadline = crate::handoff::monotonic_now()
        .unwrap()
        .map(|now| now.as_secs() + 7200);
    let lease = CredentialLease::new_with_binding_for_test(
        credentials,
        Duration::from_secs(3600),
        epoch,
        // This source would fail if consulted: the wall deadline is
        // enforced before any epoch answer.
        Arc::new(FailingEpochSource),
        EgressScope::deny_all(),
        std::process::id(),
        Instant::now() + Duration::from_secs(3600),
        wall_deadline,
        monotonic_deadline,
        clock_source,
    )
    .unwrap();
    for error in [
        lease.resolve(TestKind::Beta).unwrap_err(),
        lease.resolve_candidates(TestKind::Beta).unwrap_err(),
        lease.handoff_projection().unwrap_err(),
    ] {
        assert_eq!(error.to_string(), "credential_lease_expired");
    }
    let slot = CredentialSlot::new(lease);
    assert!(!slot.connected());
    assert_eq!(
        slot.resolve(TestKind::Beta).unwrap_err().to_string(),
        "credential_lease_expired"
    );
}

#[test]
#[cfg(unix)]
fn an_unreadable_shared_clock_refuses_closed_as_a_clock_failure() {
    // A lease minted while the shared monotonic clock was readable keeps
    // enforcing the wire deadline on every use. When the clock later
    // becomes unreadable the refusal is the distinct operational clock
    // code — not `credential_lease_expired`, which `auth_failure_class`
    // would route into credential renewal over a broken clock.
    let epoch = uuid::Uuid::new_v4().to_string();
    let mut credentials = BTreeMap::new();
    credentials.insert(TestKind::Beta, vec![test_credential(0xE3)]);
    let wall_now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let monotonic_deadline = crate::handoff::monotonic_now()
        .unwrap()
        .map(|now| now.as_secs() + 3600);
    let clock_source = Arc::new(TestClocks::new(
        wall_now,
        monotonic_deadline.map(|deadline| Duration::from_secs(deadline - 1800)),
    ));
    let lease = CredentialLease::new_with_binding_for_test(
        credentials,
        Duration::from_secs(3600),
        epoch,
        // This source would fail if consulted: the clock refusal precedes
        // any epoch answer.
        Arc::new(FailingEpochSource),
        EgressScope::deny_all(),
        std::process::id(),
        Instant::now() + Duration::from_secs(3600),
        wall_now.as_secs() + 3600,
        monotonic_deadline,
        clock_source.clone(),
    )
    .unwrap();
    // The shared clock becomes unreadable after mint.
    clock_source.lose_monotonic();
    for error in [
        lease.resolve(TestKind::Beta).unwrap_err(),
        lease.resolve_candidates(TestKind::Beta).unwrap_err(),
        lease.handoff_projection().unwrap_err(),
    ] {
        assert_eq!(error.to_string(), "credential_lease_clock_unavailable");
        // A broken clock is operational, never a credential-expiry signal.
        assert_eq!(auth_failure_class(&error), None);
    }
    let slot = CredentialSlot::new(lease);
    assert!(!slot.connected());
    let slot_error = slot.resolve(TestKind::Beta).unwrap_err();
    assert_eq!(slot_error.to_string(), "credential_lease_clock_unavailable");
    assert_eq!(auth_failure_class(&slot_error), None);
}

#[test]
#[cfg(unix)]
fn a_deadline_crossed_after_the_epoch_answer_still_refuses_the_resolution() {
    // The wall clock is read once more after the post-epoch recheck —
    // for per-credential expiry — and that last reading is enforced
    // against the lease deadlines like every other. A host suspended
    // between the epoch answer and the credential read can resume past
    // the deadline: the scripted readings stay inside it through both
    // epoch-bracketing checks and land past it on the final one, so the
    // grant must refuse instead of spending the late reading on
    // per-credential expiry alone.
    let epoch = uuid::Uuid::new_v4().to_string();
    let source = Arc::new(TestEpochSource(StdMutex::new(Some(epoch.clone()))));
    let mut credentials = BTreeMap::new();
    credentials.insert(TestKind::Beta, vec![test_credential(0xE5)]);
    let wall_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let monotonic_reading = crate::handoff::monotonic_now().unwrap();
    // Mint, then both epoch-bracketing reads stay inside the deadline;
    // the reading per-credential expiry consults lands past it.
    let clock_source = Arc::new(TestClocks::with_wall_sequence(
        vec![
            Duration::from_secs(wall_now),
            Duration::from_secs(wall_now),
            Duration::from_secs(wall_now),
            Duration::from_secs(wall_now + 120),
        ],
        monotonic_reading.map(|now| now + Duration::from_secs(3600)),
    ));
    let lease = CredentialLease::new_with_binding_for_test(
        credentials,
        Duration::from_secs(3600),
        epoch,
        source,
        EgressScope::deny_all(),
        std::process::id(),
        Instant::now() + Duration::from_secs(3600),
        wall_now + 60,
        monotonic_reading.map(|now| now.as_secs() + 7200),
        clock_source,
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
    let slot = CredentialSlot::new(lease);
    assert!(!slot.connected());
    assert_eq!(
        slot.resolve(TestKind::Beta).unwrap_err().to_string(),
        "credential_lease_expired"
    );
}

#[test]
#[cfg(unix)]
fn a_deadline_crossed_during_projection_refuses_the_secret_bearing_handoff() {
    // Projection samples the wire clocks for its stamps after the
    // post-epoch recheck: a suspend anywhere in between — before those
    // samples or across the credential copies — lands past the deadline
    // before the document is produced. The deadlines are enforced one
    // final time on fresh readings right before the handoff is built,
    // so a grant that lapsed in between refuses rather than returning a
    // secret-bearing projection.
    let epoch = uuid::Uuid::new_v4().to_string();
    let source = Arc::new(TestEpochSource(StdMutex::new(Some(epoch.clone()))));
    let mut credentials = BTreeMap::new();
    credentials.insert(TestKind::Beta, vec![test_credential(0xE6)]);
    let wall_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let monotonic_reading = crate::handoff::monotonic_now().unwrap();
    // Mint, both epoch-bracketing reads, and the stamp sample stay
    // inside the deadline; the freshness recheck lands past it.
    let clock_source = Arc::new(TestClocks::with_wall_sequence(
        vec![
            Duration::from_secs(wall_now),
            Duration::from_secs(wall_now),
            Duration::from_secs(wall_now),
            Duration::from_secs(wall_now),
            Duration::from_secs(wall_now + 120),
        ],
        monotonic_reading.map(|now| now + Duration::from_secs(3600)),
    ));
    let lease = CredentialLease::new_with_binding_for_test(
        credentials,
        Duration::from_secs(3600),
        epoch,
        source,
        EgressScope::deny_all(),
        std::process::id(),
        Instant::now() + Duration::from_secs(3600),
        wall_now + 60,
        monotonic_reading.map(|now| now.as_secs() + 7200),
        clock_source,
    )
    .unwrap();
    assert_eq!(
        lease.handoff_projection().unwrap_err().to_string(),
        "credential_lease_expired"
    );
}

#[test]
#[cfg(unix)]
fn a_failed_shared_clock_read_refuses_instead_of_passing_as_no_clock() {
    // `Ok(None)` — the platform truthfully has no comparable clock — and
    // a failed read are different answers. A rebuild over a failed read
    // cannot tell whether the document's omitted deadline is platform
    // truth or a producer's loss, so it refuses the operational failure
    // instead of minting a wall-only lease the anchor was meant to cap.
    let epoch = uuid::Uuid::new_v4().to_string();
    let wall_now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let document = serde_json::json!({
        "schemaVersion": TestKind::HANDOFF_SCHEMA,
        "leaseDurationSeconds": 3600,
        "leaseExpiresAtEpochSeconds": wall_now.as_secs() + 3600,
        "epoch": epoch,
        "credentials": [{"kind": "alpha", "keys": [handoff_key(serde_json::json!([1, 2, 3]))]}],
    });
    let handoff =
        CredentialHandoff::<TestKind>::from_json(&serde_json::to_vec(&document).unwrap()).unwrap();
    let clock_source = Arc::new(TestClocks::new(wall_now, None));
    clock_source.lose_monotonic();
    assert_eq!(
        CredentialLease::from_handoff_with_clock_source(
            handoff,
            Arc::new(TestEpochSource(StdMutex::new(Some(epoch.clone())))),
            clock_source.clone(),
        )
        .unwrap_err()
        .to_string(),
        "credential_lease_clock_unavailable"
    );
    // The same failed read refuses when the deadline is carried — the
    // continuity question it answers is identical.
    let mut anchored = document.clone();
    anchored["leaseMonotonicDeadlineSeconds"] =
        serde_json::json!(crate::handoff::monotonic_now().unwrap().unwrap().as_secs() + 3600);
    let handoff =
        CredentialHandoff::<TestKind>::from_json(&serde_json::to_vec(&anchored).unwrap()).unwrap();
    assert_eq!(
        CredentialLease::from_handoff_with_clock_source(
            handoff,
            Arc::new(TestEpochSource(StdMutex::new(Some(epoch.clone())))),
            clock_source,
        )
        .unwrap_err()
        .to_string(),
        "credential_lease_clock_unavailable"
    );
    // An honest absent clock still mints a deadline-less rebuild:
    // `Ok(None)` is the platform truth the continuity check trusts.
    let handoff =
        CredentialHandoff::<TestKind>::from_json(&serde_json::to_vec(&document).unwrap()).unwrap();
    let clock_source = Arc::new(TestClocks::new(wall_now, None));
    assert!(CredentialLease::from_handoff_with_clock_source(
        handoff,
        Arc::new(TestEpochSource(StdMutex::new(Some(epoch)))),
        clock_source,
    )
    .is_ok());
}

#[test]
#[cfg(unix)]
fn a_failed_shared_clock_read_refuses_projection_even_without_a_carried_deadline() {
    // A lease carrying no monotonic deadline still samples the shared
    // clock at projection to stamp the document's anchor. A failed read
    // there is the same operational refusal — the projection cannot
    // silently mint an unanchored handoff off a broken clock.
    // Resolution is unaffected: with no deadline riding the clock it is
    // never read on that path.
    let epoch = uuid::Uuid::new_v4().to_string();
    let source = Arc::new(TestEpochSource(StdMutex::new(Some(epoch.clone()))));
    let mut credentials = BTreeMap::new();
    credentials.insert(TestKind::Beta, vec![test_credential(0xE7)]);
    let wall_now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let clock_source = Arc::new(TestClocks::new(wall_now, None));
    let lease = CredentialLease::new_with_binding_for_test(
        credentials,
        Duration::from_secs(3600),
        epoch,
        source,
        EgressScope::deny_all(),
        std::process::id(),
        Instant::now() + Duration::from_secs(3600),
        wall_now.as_secs() + 3600,
        None,
        clock_source.clone(),
    )
    .unwrap();
    clock_source.lose_monotonic();
    assert_eq!(
        lease.handoff_projection().unwrap_err().to_string(),
        "credential_lease_clock_unavailable"
    );
    assert!(lease.resolve(TestKind::Beta).is_ok());
}

#[test]
#[cfg(unix)]
fn a_failed_stamp_sample_refuses_projection_on_a_deadline_carrying_lease() {
    // The projection's monotonic stamp is a fresh sample on the shared
    // clock, not the carried wire deadline: the deadline the lease was
    // minted with may sit later than its true monotonic expiry, so
    // preserving it when the sample cannot be taken would let a
    // wall-clock rollback before rebuild grant the document time the
    // source lease did not have. The script answers the mint and both
    // epoch-bracketing liveness reads, then fails exactly the stamp
    // read — both failure answers, a read error and an absent clock,
    // refuse under the clock code while the reads around them keep
    // seeing a healthy clock.
    for failing_sample in [Err("synthetic_monotonic_failure"), Ok(None)] {
        let epoch = uuid::Uuid::new_v4().to_string();
        let source = Arc::new(TestEpochSource(StdMutex::new(Some(epoch.clone()))));
        let mut credentials = BTreeMap::new();
        credentials.insert(TestKind::Beta, vec![test_credential(0xE8)]);
        let wall_now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let monotonic_reading = crate::handoff::monotonic_now().unwrap().unwrap();
        // Mint, then both liveness reads inside the deadline; the stamp
        // read fails; the tail keeps answering so only that one read is
        // unavailable.
        let clock_source = Arc::new(TestClocks::with_monotonic_sequence(
            wall_now,
            vec![
                Ok(Some(monotonic_reading)),
                Ok(Some(monotonic_reading)),
                Ok(Some(monotonic_reading)),
                failing_sample,
                Ok(Some(monotonic_reading)),
            ],
        ));
        let lease = CredentialLease::new_with_binding_for_test(
            credentials,
            Duration::from_secs(3600),
            epoch,
            source,
            EgressScope::deny_all(),
            std::process::id(),
            Instant::now() + Duration::from_secs(3600),
            wall_now.as_secs() + 3600,
            Some(monotonic_reading.as_secs() + 3600),
            clock_source,
        )
        .unwrap();
        assert_eq!(
            lease.handoff_projection().unwrap_err().to_string(),
            "credential_lease_clock_unavailable"
        );
    }
}

#[test]
#[cfg(unix)]
fn a_lapsed_monotonic_deadline_expires_in_its_own_clock_domain() {
    // The `Instant` expiry is the mint-time conversion of every limit,
    // but the shared monotonic deadline is enforced on the clock it was
    // declared on. Where those clocks diverge — Darwin CLOCK_MONOTONIC
    // advances across suspend while the uptime clock `Instant` reads
    // pauses — an `Instant` that has not caught up must never release a
    // grant whose monotonic deadline already passed. A lapsed monotonic
    // deadline paired with a long `Instant` lifetime is exactly the
    // post-wake shape.
    let epoch = uuid::Uuid::new_v4().to_string();
    let mut credentials = BTreeMap::new();
    credentials.insert(TestKind::Beta, vec![test_credential(0xE2)]);
    let lease = CredentialLease::new_with_binding_for_test(
        credentials,
        Duration::from_secs(3600),
        epoch,
        // This source would fail if consulted: the domain check precedes
        // the epoch lookup — and runs again after it — so every use
        // refuses as expired, never as an epoch error.
        Arc::new(FailingEpochSource),
        EgressScope::deny_all(),
        std::process::id(),
        Instant::now() + Duration::from_secs(3600),
        u64::MAX,
        crate::handoff::monotonic_now()
            .unwrap()
            .map(|now| now.as_secs()),
        Arc::new(SystemLeaseClocks),
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
#[cfg(unix)]
fn a_projection_never_stamps_beyond_the_leases_monotonic_expiry() {
    // The shared clock is sampled before the `Instant` remainder, so a
    // pause while copying credentials can only shrink the stamped
    // deadline — it can never add a stale remainder to a later reading.
    // Bound the stamp by the expiry estimated from samples taken before
    // the call: anything later is time the source lease did not have.
    let epoch = uuid::Uuid::new_v4().to_string();
    let source = Arc::new(TestEpochSource(StdMutex::new(Some(epoch.clone()))));
    let mut credentials = BTreeMap::new();
    credentials.insert(TestKind::Beta, vec![test_credential(0xD2)]);
    let monotonic_before = crate::handoff::monotonic_now().unwrap().unwrap();
    let instant_before = Instant::now();
    let expires_at = instant_before + Duration::from_secs(60);
    // The preserved wire deadline is far looser than the lease's own
    // expiry: the tighter expiry is the bound the stamp must reflect —
    // this is exactly the case where a late clock sample could stamp
    // past the source lease.
    let lease = CredentialLease::new_with_binding_for_test(
        credentials,
        Duration::from_secs(3600),
        epoch,
        source,
        EgressScope::deny_all(),
        std::process::id(),
        expires_at,
        u64::MAX,
        Some(monotonic_before.as_secs() + 3600),
        Arc::new(SystemLeaseClocks),
    )
    .unwrap();
    let stamped = lease
        .handoff_projection()
        .unwrap()
        .lease_monotonic_deadline_seconds()
        .unwrap();
    // The stamp is floored from the early shared-clock sample plus the
    // remainder, so it can sit at most at the estimate of the true
    // expiry — and strictly under the looser preserved deadline. A
    // one-second tolerance covers the sampling order between the two
    // test reads, never the loose bound.
    let upper = monotonic_before
        .saturating_add(expires_at - instant_before)
        .as_secs();
    assert!(stamped <= upper + 1);
    assert!(stamped > monotonic_before.as_secs());
}

#[test]
fn projected_monotonic_deadline_stays_on_the_early_side_of_a_sample_boundary() {
    // A shared-clock reading at 200.9s with 100 ms of life left stamps
    // floor(200.9 + 0.1) = 201: the full-precision pair keeps the
    // sub-second remainder instead of truncating either side.
    assert_eq!(
        projected_monotonic_deadline_seconds(
            Some(u64::MAX),
            Some(Duration::new(200, 900_000_000)),
            Duration::from_millis(100),
        ),
        Some(201)
    );
    // The preserved wire deadline caps the estimate, and an absent clock
    // preserves the minted deadline verbatim.
    assert_eq!(
        projected_monotonic_deadline_seconds(
            Some(150),
            Some(Duration::from_secs(200)),
            Duration::from_secs(100),
        ),
        Some(150)
    );
    assert_eq!(
        projected_monotonic_deadline_seconds(Some(42), None, Duration::from_secs(1)),
        Some(42)
    );
    assert_eq!(
        projected_monotonic_deadline_seconds(None, None, Duration::from_secs(1)),
        None
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
    credentials.insert(EscapedKind::Control, vec![test_credential(0xC5)]);
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
    assert!(!debug.contains(&format!("{:?}", [0xA1u8; 16])));
    assert!(!debug.contains(&format!("{:?}", [0xB1u8; 16])));
    let lease_debug = format!("{lease:?}");
    assert!(!lease_debug.contains(&format!("{:?}", [0xA1u8; 16])));
    let slot_debug = format!("{:?}", CredentialSlot::new(lease));
    assert!(!slot_debug.contains(&format!("{:?}", [0xA1u8; 16])));
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
        &[0xA1u8; 16]
    );
    port::clear();
}

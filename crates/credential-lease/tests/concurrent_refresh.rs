//! Integration coverage for concurrent hot-apply refresh and epoch-wide
//! revocation across several independent leases.
//!
//! The slot is the host's live credential surface: workers resolve while
//! custody installs a fresh authorized lease. Refresh must be atomic, and a
//! single epoch rotation must reach every lease built from that source.

use anyhow::Result;
use credential_lease::credential::LeasedCredential;
use credential_lease::egress::EgressScope;
use credential_lease::epoch::LeaseEpochSource;
use credential_lease::failure::{auth_failure_class, AUTH_EXPIRED_FAILURE_CLASS};
use credential_lease::handoff::CredentialHandoff;
use credential_lease::kind::CredentialKind;
use credential_lease::lease::{CredentialLease, CredentialSlot};
use credential_lease::SecretBytes;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::Duration;

const SLOT_COUNT: usize = 4;
const READERS_PER_SLOT: usize = 2;
const REFRESH_ROUNDS: usize = 400;
const READS_AFTER_REFRESH: usize = 600;
const TAIL_READS: usize = 100;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Kind {
    Api,
}

impl CredentialKind for Kind {
    const HANDOFF_SCHEMA: &'static str = "test.credential-lease.concurrent.handoff.v1";

    fn as_str(self) -> &'static str {
        "api"
    }

    fn from_str(value: &str) -> Option<Self> {
        (value == "api").then_some(Self::Api)
    }
}

struct SharedEpoch(Mutex<Option<String>>);

impl SharedEpoch {
    fn new(epoch: Option<&str>) -> Self {
        Self(Mutex::new(epoch.map(str::to_owned)))
    }

    fn set(&self, epoch: Option<&str>) {
        *self.0.lock().unwrap() = epoch.map(str::to_owned);
    }
}

impl LeaseEpochSource for SharedEpoch {
    fn active_epoch(&self) -> Result<Option<String>> {
        Ok(self.0.lock().unwrap().clone())
    }
}

fn credential_id(seed: u128) -> String {
    format!("00000000-0000-4000-8000-{seed:012x}")
}

fn seed(slot: usize, round: usize) -> u128 {
    ((slot as u128) << 40) + round as u128 + 1
}

fn secret(slot: usize, version: usize) -> String {
    format!("slot-{slot}-v{version}")
}

fn credential(seed: u128, secret: &str) -> LeasedCredential {
    LeasedCredential::new(
        credential_id(seed),
        SecretBytes::try_from_string(secret.to_owned()).unwrap(),
        None,
    )
    .unwrap()
}

fn credentials(seed: u128, secret: &str) -> BTreeMap<Kind, Vec<LeasedCredential>> {
    BTreeMap::from([(Kind::Api, vec![credential(seed, secret)])])
}

fn lease_for(
    epoch: &str,
    source: Arc<SharedEpoch>,
    seed: u128,
    secret: &str,
) -> CredentialLease<Kind> {
    CredentialLease::new(
        credentials(seed, secret),
        Duration::from_secs(3600),
        epoch.to_owned(),
        source,
        EgressScope::deny_all(),
    )
    .unwrap()
}

fn handoff_for(epoch: &str, seed: u128, secret: &str) -> CredentialHandoff<Kind> {
    CredentialHandoff::new(
        credentials(seed, secret),
        Duration::from_secs(3600),
        epoch.to_owned(),
        EgressScope::deny_all(),
    )
    .unwrap()
}

/// Alternate the two resolution surfaces so both are exercised while the
/// slot is being refreshed.
fn resolve_one(slot: &CredentialSlot<Kind>, turn: &mut usize) -> Vec<u8> {
    let use_candidates = *turn % 2 == 1;
    *turn += 1;
    let secret = if use_candidates {
        slot.resolve_candidates(Kind::Api)
            .expect("a live lease must enumerate candidates during refresh")
            .into_iter()
            .next()
            .expect("the lease carries one credential")
    } else {
        slot.resolve(Kind::Api)
            .expect("a live lease must resolve during refresh")
    };
    secret.expose_bytes().to_vec()
}

fn wait_for(mut condition: impl FnMut() -> bool, description: &str) {
    for attempt in 0..5_000 {
        if condition() {
            return;
        }
        if attempt % 64 == 63 {
            thread::sleep(Duration::from_millis(1));
        } else {
            thread::yield_now();
        }
    }
    panic!("timed out waiting for {description}");
}

#[test]
fn concurrent_refresh_of_multiple_slots_never_exposes_a_torn_lease() {
    let epoch = credential_id(0xe000);
    let source = Arc::new(SharedEpoch::new(Some(&epoch)));
    let slots: Vec<Arc<CredentialSlot<Kind>>> = (0..SLOT_COUNT)
        .map(|slot| {
            Arc::new(CredentialSlot::new(lease_for(
                &epoch,
                source.clone(),
                seed(slot, 0),
                &secret(slot, 0),
            )))
        })
        .collect();
    let start = Arc::new(Barrier::new(SLOT_COUNT * (READERS_PER_SLOT + 1) + 1));
    let mut readers = Vec::with_capacity(SLOT_COUNT * READERS_PER_SLOT);
    let mut writers = Vec::with_capacity(SLOT_COUNT);

    for (slot_index, initial_slot) in slots.iter().enumerate() {
        let ready = Arc::new(AtomicUsize::new(0));
        let writer_started = Arc::new(AtomicBool::new(false));
        let new_seen = Arc::new(AtomicUsize::new(0));
        let old = secret(slot_index, 0);
        let new = secret(slot_index, 1);

        for _ in 0..READERS_PER_SLOT {
            let slot = initial_slot.clone();
            let start = start.clone();
            let ready = ready.clone();
            let writer_started = writer_started.clone();
            let new_seen = new_seen.clone();
            let old = old.clone();
            let new = new.clone();
            readers.push(thread::spawn(move || {
                let mut turn = 0;
                start.wait();
                // Everyone snapshots the initial lease before any refresh
                // begins, so both the old and the new value are known.
                let first = resolve_one(&slot, &mut turn);
                assert_eq!(
                    first.as_slice(),
                    old.as_bytes(),
                    "the initial snapshot was not the installed lease"
                );
                ready.fetch_add(1, Ordering::AcqRel);
                wait_for(
                    || writer_started.load(Ordering::Acquire),
                    "the refresher to install its first snapshot",
                );
                // The writer installs the new snapshot before releasing this
                // gate and then waits for every reader to observe it, so the
                // refreshed value is not merely a scheduling accident.
                let mut observed_new = false;
                for _ in 0..READS_AFTER_REFRESH {
                    let bytes = resolve_one(&slot, &mut turn);
                    assert!(
                        bytes.as_slice() == old.as_bytes() || bytes.as_slice() == new.as_bytes(),
                        "a concurrent refresh exposed a lease that was neither the old nor the new snapshot"
                    );
                    if bytes.as_slice() == new.as_bytes() {
                        observed_new = true;
                        break;
                    }
                }
                assert!(
                    observed_new,
                    "the reader never observed the refreshed lease"
                );
                new_seen.fetch_add(1, Ordering::AcqRel);
                for _ in 0..TAIL_READS {
                    let bytes = resolve_one(&slot, &mut turn);
                    assert!(
                        bytes.as_slice() == old.as_bytes() || bytes.as_slice() == new.as_bytes(),
                        "a concurrent refresh exposed a lease that was neither the old nor the new snapshot"
                    );
                }
            }));
        }

        let slot = initial_slot.clone();
        let source = source.clone();
        let start = start.clone();
        let ready = ready.clone();
        let writer_started = writer_started.clone();
        let new_seen = new_seen.clone();
        let old = old.clone();
        let new = new.clone();
        let epoch = epoch.clone();
        writers.push(thread::spawn(move || {
            start.wait();
            wait_for(
                || ready.load(Ordering::Acquire) == READERS_PER_SLOT,
                "the readers to snapshot the initial lease",
            );
            slot.install_handoff(
                handoff_for(&epoch, seed(slot_index, 1_000), &new),
                source.clone(),
            )
            .unwrap();
            writer_started.store(true, Ordering::Release);
            wait_for(
                || new_seen.load(Ordering::Acquire) == READERS_PER_SLOT,
                "the readers to observe the first refreshed lease",
            );
            for round in 1..REFRESH_ROUNDS {
                let value = if round % 2 == 0 { &new } else { &old };
                if round % 2 == 0 {
                    slot.install_handoff(
                        handoff_for(&epoch, seed(slot_index, 1_000 + round), value),
                        source.clone(),
                    )
                    .unwrap();
                } else {
                    slot.replace(lease_for(
                        &epoch,
                        source.clone(),
                        seed(slot_index, 1_000 + round),
                        value,
                    ))
                    .unwrap();
                }
                thread::yield_now();
            }
            // Leave the refreshed snapshot installed for the final assertion.
            slot.replace(lease_for(&epoch, source, seed(slot_index, 9_999), &new))
                .unwrap();
        }));
    }

    start.wait();
    for reader in readers {
        reader.join().unwrap();
    }
    for writer in writers {
        writer.join().unwrap();
    }
    for (slot_index, slot) in slots.iter().enumerate() {
        assert_eq!(
            slot.resolve(Kind::Api).unwrap().expose_bytes(),
            secret(slot_index, 1).as_bytes(),
            "the last refresh was not installed atomically"
        );
    }
}

/// Assert one slot refuses every resolution surface with the same stable
/// revocation code and the host-facing `auth_expired` classification.
fn assert_slot_revoked(slot: &CredentialSlot<Kind>) {
    let error = slot.resolve(Kind::Api).unwrap_err();
    assert_eq!(error.to_string(), "credential_lease_revoked");
    assert_eq!(
        auth_failure_class(&error),
        Some(AUTH_EXPIRED_FAILURE_CLASS),
        "revocation must classify as auth_expired"
    );
    assert_eq!(
        slot.resolve_candidates(Kind::Api).unwrap_err().to_string(),
        "credential_lease_revoked"
    );
}

fn assert_lease_revoked(lease: &CredentialLease<Kind>) {
    let error = lease.resolve(Kind::Api).unwrap_err();
    assert_eq!(error.to_string(), "credential_lease_revoked");
    assert_eq!(
        auth_failure_class(&error),
        Some(AUTH_EXPIRED_FAILURE_CLASS),
        "revocation must classify as auth_expired"
    );
    assert_eq!(
        lease.resolve_candidates(Kind::Api).unwrap_err().to_string(),
        "credential_lease_revoked"
    );
    assert_eq!(
        lease.handoff_projection().unwrap_err().to_string(),
        "credential_lease_revoked"
    );
}

#[test]
fn epoch_revocation_broadcasts_to_every_lease_and_concurrent_refresh_recovers() {
    let epoch_a = credential_id(0xa000);
    let epoch_b = credential_id(0xb000);
    let source = Arc::new(SharedEpoch::new(Some(&epoch_a)));
    let slots: Vec<Arc<CredentialSlot<Kind>>> = (0..SLOT_COUNT)
        .map(|slot| {
            Arc::new(CredentialSlot::new(lease_for(
                &epoch_a,
                source.clone(),
                seed(slot, 0),
                &format!("before-{slot}"),
            )))
        })
        .collect();
    let standalone: Vec<CredentialLease<Kind>> = (0..SLOT_COUNT)
        .map(|slot| {
            lease_for(
                &epoch_a,
                source.clone(),
                seed(slot, 50_000),
                &format!("standalone-{slot}"),
            )
        })
        .collect();

    for (slot_index, slot) in slots.iter().enumerate() {
        assert_eq!(
            slot.resolve(Kind::Api).unwrap().expose_bytes(),
            format!("before-{slot_index}").as_bytes()
        );
    }
    for lease in &standalone {
        assert!(lease.resolve(Kind::Api).is_ok());
    }

    // One custody rotation is the whole revocation broadcast: every lease
    // sharing the source dies on its next use, with no per-lease notify.
    source.set(Some(&epoch_b));
    for slot in &slots {
        assert_slot_revoked(slot);
    }
    for lease in &standalone {
        assert_lease_revoked(lease);
    }

    // Refresh every slot concurrently under the new epoch. A fresh handoff
    // is the only way back; the old standalone leases stay revoked.
    let start = Arc::new(Barrier::new(SLOT_COUNT + 1));
    let refreshers: Vec<_> = slots
        .iter()
        .enumerate()
        .map(|(slot_index, slot)| {
            let slot = slot.clone();
            let source = source.clone();
            let start = start.clone();
            let epoch_b = epoch_b.clone();
            thread::spawn(move || {
                start.wait();
                slot.install_handoff(
                    handoff_for(
                        &epoch_b,
                        seed(slot_index, 60_000),
                        &format!("after-{slot_index}"),
                    ),
                    source,
                )
                .unwrap();
            })
        })
        .collect();
    start.wait();
    for refresher in refreshers {
        refresher.join().unwrap();
    }

    for (slot_index, slot) in slots.iter().enumerate() {
        assert_eq!(
            slot.resolve(Kind::Api).unwrap().expose_bytes(),
            format!("after-{slot_index}").as_bytes()
        );
    }
    for lease in &standalone {
        assert_lease_revoked(lease);
    }

    // Locking custody (`None`) is a second broadcast: the refreshed leases
    // fail closed exactly like the stale ones did.
    source.set(None);
    for slot in &slots {
        assert_slot_revoked(slot);
    }
}

#[test]
fn resolve_scoped_never_pairs_a_secret_with_another_grants_scope() {
    // Two grants pair distinct secrets with distinct egress scopes. A
    // forwarding runtime resolves both through `resolve_scoped`; under a
    // concurrent install the pair must always come from one lease
    // snapshot — a fresh credential can never travel under the previous
    // grant's boundary.
    let epoch = credential_id(0xf000);
    let source = Arc::new(SharedEpoch::new(Some(&epoch)));
    let deny = EgressScope::deny_all();
    let admit = EgressScope::new(
        vec!["api.example.com".to_owned()],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        false,
    )
    .unwrap();
    let slot = Arc::new(CredentialSlot::new(
        CredentialLease::new(
            credentials(seed(0, 0), "pair-deny"),
            Duration::from_secs(3600),
            epoch.clone(),
            source.clone(),
            deny.clone(),
        )
        .unwrap(),
    ));
    let start = Arc::new(Barrier::new(4));
    let writer = {
        let slot = slot.clone();
        let source = source.clone();
        let start = start.clone();
        let epoch = epoch.clone();
        let deny = deny.clone();
        let admit = admit.clone();
        thread::spawn(move || {
            start.wait();
            for round in 1..=REFRESH_ROUNDS {
                let (value, scope) = if round % 2 == 0 {
                    ("pair-deny", deny.clone())
                } else {
                    ("pair-admit", admit.clone())
                };
                slot.install_handoff(
                    CredentialHandoff::new(
                        credentials(seed(0, 70_000 + round), value),
                        Duration::from_secs(3600),
                        epoch.clone(),
                        scope,
                    )
                    .unwrap(),
                    source.clone(),
                )
                .unwrap();
                thread::yield_now();
            }
        })
    };
    let readers: Vec<_> = (0..2)
        .map(|_| {
            let slot = slot.clone();
            let start = start.clone();
            let deny = deny.clone();
            let admit = admit.clone();
            thread::spawn(move || {
                start.wait();
                let mut seen = 0usize;
                for _ in 0..READS_AFTER_REFRESH {
                    let (secret, scope) = slot
                        .resolve_scoped(Kind::Api)
                        .expect("a live lease resolves during refresh");
                    let bytes = secret.expose_bytes();
                    assert!(
                        (bytes == b"pair-deny" && scope == deny)
                            || (bytes == b"pair-admit" && scope == admit),
                        "a concurrent install paired a credential with another grant's scope"
                    );
                    seen += 1;
                }
                seen
            })
        })
        .collect();
    start.wait();
    writer.join().unwrap();
    for reader in readers {
        assert_eq!(reader.join().unwrap(), READS_AFTER_REFRESH);
    }
}

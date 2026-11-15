//! The process-bound lease.
//!
//! A lease never survives process exit. Its duration is an upper bound for
//! one running process, not a persisted bypass of host authorization. Three
//! independent checks apply on every credential use:
//!
//! 1. Process identity — the OS process id that minted the lease is recorded
//!    and compared with the current process. A child forked with the lease
//!    in its inherited address space therefore fails closed instead of
//!    replaying the parent's credentials.
//! 2. The lease's own `Instant` expiry.
//! 3. The custody epoch, consulted on every resolution so an owner-initiated
//!    revocation lands on the very next use.
//!
//! The process check governs use of *this lease object*. A fork still
//! inherits the address space, so secret buffers already copied into the
//! child are outside this type's control; the check keeps the inherited
//! lease itself from resolving or projecting them.

use crate::credential::LeasedCredential;
use crate::epoch::LeaseEpochSource;
use crate::handoff::{validate_credentials, CredentialHandoff};
use crate::kind::CredentialKind;
use crate::SecretBytes;
use anyhow::{anyhow, ensure, Result};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A process-local snapshot of custody-held credentials for one kind family.
pub struct CredentialLease<K: CredentialKind> {
    credentials: BTreeMap<K, Vec<LeasedCredential>>,
    lease_duration: Duration,
    expires_at: Instant,
    epoch: String,
    epoch_source: Arc<dyn LeaseEpochSource>,
    process_id: u32,
}

impl<K: CredentialKind> CredentialLease<K> {
    /// A lease with no credentials and a dead epoch source. Runtimes are
    /// allowed to start disconnected — uses fail closed with
    /// `credential_lease_unavailable` until an authorized handoff is
    /// installed into a slot (hot apply) or supplied at spawn.
    pub fn disconnected() -> Self {
        Self {
            credentials: BTreeMap::new(),
            lease_duration: Duration::ZERO,
            expires_at: Instant::now(),
            epoch: String::new(),
            epoch_source: Arc::new(DisconnectedEpochSource),
            process_id: std::process::id(),
        }
    }

    /// Mint a lease. The epoch must be a canonical UUID and the duration a
    /// positive bound within the contract's maximum. The current process id
    /// is recorded as the lease's process binding.
    pub fn new(
        credentials: BTreeMap<K, Vec<LeasedCredential>>,
        lease_duration: Duration,
        epoch: String,
        epoch_source: Arc<dyn LeaseEpochSource>,
    ) -> Result<Self> {
        Self::new_bound(
            credentials,
            lease_duration,
            epoch,
            epoch_source,
            std::process::id(),
        )
    }

    fn new_bound(
        credentials: BTreeMap<K, Vec<LeasedCredential>>,
        lease_duration: Duration,
        epoch: String,
        epoch_source: Arc<dyn LeaseEpochSource>,
        process_id: u32,
    ) -> Result<Self> {
        ensure!(
            uuid::Uuid::parse_str(&epoch).is_ok_and(|value| value.to_string() == epoch),
            "credential_lease_epoch_invalid"
        );
        ensure!(
            (1..=crate::credential::MAX_LEASE_DURATION_SECONDS).contains(&lease_duration.as_secs()),
            "credential_lease_duration_invalid"
        );
        validate_credentials(&credentials, "credential_lease_inventory_invalid")?;
        let expires_at = Instant::now()
            .checked_add(lease_duration)
            .ok_or_else(|| anyhow!("credential_lease_expiry_invalid"))?;
        Ok(Self {
            credentials,
            lease_duration,
            expires_at,
            epoch,
            epoch_source,
            process_id,
        })
    }

    /// Test-only construction with an explicit process binding and expiry so
    /// cross-PID replay and timeout paths are exercised deterministically
    /// instead of by sleeping.
    #[cfg(test)]
    pub(crate) fn new_with_binding_for_test(
        credentials: BTreeMap<K, Vec<LeasedCredential>>,
        lease_duration: Duration,
        epoch: String,
        epoch_source: Arc<dyn LeaseEpochSource>,
        process_id: u32,
        expires_at: Instant,
    ) -> Result<Self> {
        let mut lease =
            Self::new_bound(credentials, lease_duration, epoch, epoch_source, process_id)?;
        lease.expires_at = expires_at;
        Ok(lease)
    }

    /// Whether this lease object belongs to the process currently running.
    fn is_current_process(&self) -> bool {
        std::process::id() == self.process_id
    }

    /// Fail closed when a lease crossed a process boundary, for example by
    /// being inherited across `fork`.
    fn ensure_current_process(&self) -> Result<()> {
        ensure!(
            self.is_current_process(),
            "credential_lease_process_mismatch"
        );
        Ok(())
    }

    /// The duration the lease was minted with — the upper bound this
    /// process may use it for, never a persisted grant.
    pub fn lease_duration(&self) -> Duration {
        self.lease_duration
    }

    /// Project the lease into a portable handoff, copying every secret so
    /// the lease itself keeps its own zeroizing bytes. Projection is a
    /// credential use: the lease must still be live, so an expired or
    /// revoked lease cannot be re-minted into a fresh handoff that restarts
    /// its lifetime. A lease inherited across a process boundary refuses to
    /// project; only the process that minted it may reproduce its secrets.
    pub fn handoff_projection(&self) -> Result<CredentialHandoff<K>> {
        self.ensure_active()?;
        let mut credentials = BTreeMap::new();
        for (kind, keys) in &self.credentials {
            let mut copied = Vec::with_capacity(keys.len());
            for key in keys {
                copied.push(LeasedCredential::new(
                    key.credential_id().to_owned(),
                    key.copy_secret(),
                    key.expires_at_epoch_seconds(),
                )?);
            }
            credentials.insert(*kind, copied);
        }
        CredentialHandoff::new(credentials, self.lease_duration, self.epoch.clone())
    }

    /// Rebuild a lease from a received handoff under the local epoch source.
    /// Construction reuses the same closed validations as a custody unlock.
    pub fn from_handoff(
        handoff: CredentialHandoff<K>,
        epoch_source: Arc<dyn LeaseEpochSource>,
    ) -> Result<Self> {
        let (credentials, lease_duration, epoch) = handoff.into_parts();
        Self::new(credentials, lease_duration, epoch, epoch_source)
    }

    /// Whether the lease currently carries at least one credential for
    /// `kind` — presence only, not validity: expiry and revocation are
    /// checked on resolution.
    pub fn contains_kind(&self, kind: K) -> bool {
        self.credentials
            .get(&kind)
            .is_some_and(|values| !values.is_empty())
    }

    /// The credentials currently valid for `kind`: lease expiry, custody
    /// epoch, and each credential's own storage expiry all enforced. The
    /// iterator borrows the lease so callers copy only the secrets they
    /// actually select.
    fn valid_candidates(&self, kind: K) -> Result<impl Iterator<Item = &LeasedCredential> + '_> {
        let kind_credentials = self
            .credentials
            .get(&kind)
            .filter(|values| !values.is_empty())
            .ok_or_else(|| anyhow!("credential_lease_unavailable"))?;
        self.ensure_active()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| anyhow!("credential_lease_clock_invalid"))?
            .as_secs();
        Ok(kind_credentials
            .iter()
            .filter(move |credential| !credential.is_expired(now)))
    }

    /// Resolve one currently valid secret for `kind`, copying only the
    /// selected credential.
    pub fn resolve(&self, kind: K) -> Result<SecretBytes> {
        self.valid_candidates(kind)?
            .next()
            .map(LeasedCredential::copy_secret)
            .ok_or_else(|| anyhow!("credential_lease_unavailable"))
    }

    /// Every currently valid credential for `kind`, in declaration order.
    ///
    /// Fails closed when the lease is expired or revoked, and credentials
    /// past their own storage expiry never resolve.
    pub fn resolve_candidates(&self, kind: K) -> Result<Vec<SecretBytes>> {
        let credentials = self
            .valid_candidates(kind)?
            .map(LeasedCredential::copy_secret)
            .collect::<Vec<_>>();
        ensure!(!credentials.is_empty(), "credential_lease_unavailable");
        Ok(credentials)
    }

    /// The custody epoch is consulted on every use so an owner-initiated
    /// revocation lands on the very next resolution — there is no cached
    /// authorization window. Hosts supply the epoch source and choose how
    /// cheap that consultation is.
    fn ensure_active(&self) -> Result<()> {
        self.ensure_current_process()?;
        ensure!(Instant::now() < self.expires_at, "credential_lease_expired");
        ensure!(
            self.epoch_source.active_epoch()?.as_deref() == Some(self.epoch.as_str()),
            "credential_lease_revoked"
        );
        Ok(())
    }
}

struct DisconnectedEpochSource;

impl LeaseEpochSource for DisconnectedEpochSource {
    fn active_epoch(&self) -> Result<Option<String>> {
        Ok(None)
    }
}

impl<K: CredentialKind> fmt::Debug for CredentialLease<K> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialLease")
            .field("kind_count", &self.credentials.len())
            .field("lease_duration_seconds", &self.lease_duration.as_secs())
            .field("credentials", &"[redacted]")
            .finish()
    }
}

/// Process-local, replaceable credential lease for a running runtime.
///
/// Workers resolve secrets under a short read lock; authorize/clear
/// hot-apply replaces the whole lease without restarting the process.
/// Candidate lists rotate per kind so callers may fail over across a bounded
/// list without repeatedly unlocking or favoring one credential forever.
pub struct CredentialSlot<K: CredentialKind> {
    inner: Mutex<CredentialLease<K>>,
    selection_cursors: Mutex<BTreeMap<K, usize>>,
}

impl<K: CredentialKind> CredentialSlot<K> {
    /// Install `lease` as the slot's current lease.
    pub fn new(lease: CredentialLease<K>) -> Self {
        Self {
            inner: Mutex::new(lease),
            selection_cursors: Mutex::new(BTreeMap::new()),
        }
    }

    /// A slot holding a disconnected lease: it starts unauthorized and
    /// every resolution fails closed until a handoff is installed.
    pub fn disconnected() -> Self {
        Self::new(CredentialLease::disconnected())
    }

    /// Whether the installed lease carries `kind`; a poisoned lock reads
    /// as absent rather than answering from unverifiable state.
    pub fn contains_kind(&self, kind: K) -> bool {
        self.inner
            .lock()
            .map(|lease| lease.contains_kind(kind))
            .unwrap_or(false)
    }

    /// Resolve one currently valid secret for `kind`, rotating the
    /// selection across candidates and copying only the chosen secret. The
    /// candidate list is snapshotted once so counting and selection cannot
    /// disagree across an expiry boundary.
    pub fn resolve(&self, kind: K) -> Result<SecretBytes> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| anyhow!("credential_lease_validation_unavailable"))?;
        let candidates: Vec<&LeasedCredential> = guard.valid_candidates(kind)?.collect();
        ensure!(!candidates.is_empty(), "credential_lease_unavailable");
        let start = {
            let mut cursors = self
                .selection_cursors
                .lock()
                .map_err(|_| anyhow!("credential_lease_validation_unavailable"))?;
            let cursor = cursors.entry(kind).or_insert(0);
            let start = *cursor % candidates.len();
            *cursor = cursor.wrapping_add(1);
            start
        };
        Ok(candidates[start].copy_secret())
    }

    /// Returns every currently valid credential in rotating order.
    pub fn resolve_candidates(&self, kind: K) -> Result<Vec<SecretBytes>> {
        let mut candidates = self
            .inner
            .lock()
            .map_err(|_| anyhow!("credential_lease_validation_unavailable"))?
            .resolve_candidates(kind)?;
        let start = {
            let mut cursors = self
                .selection_cursors
                .lock()
                .map_err(|_| anyhow!("credential_lease_validation_unavailable"))?;
            let cursor = cursors.entry(kind).or_insert(0);
            let start = *cursor % candidates.len();
            *cursor = cursor.wrapping_add(1);
            start
        };
        candidates.rotate_left(start);
        Ok(candidates)
    }

    /// Atomically swap the installed lease — hot apply without restarting
    /// the process.
    pub fn replace(&self, lease: CredentialLease<K>) -> Result<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| anyhow!("credential_lease_validation_unavailable"))?;
        *guard = lease;
        Ok(())
    }

    /// Disconnect the slot: the lease is replaced by a disconnected one and
    /// every subsequent resolution fails closed.
    pub fn clear(&self) -> Result<()> {
        self.replace(CredentialLease::disconnected())
    }

    /// Install a received handoff under the local epoch source, replacing the
    /// current lease in one atomic swap.
    pub fn install_handoff(
        &self,
        handoff: CredentialHandoff<K>,
        epoch_source: Arc<dyn LeaseEpochSource>,
    ) -> Result<()> {
        self.replace(CredentialLease::from_handoff(handoff, epoch_source)?)
    }

    /// Whether the slot holds a live, non-empty lease in the current
    /// process. A poisoned lock, an expired lease, or a lease inherited
    /// across a process boundary reads as disconnected.
    pub fn connected(&self) -> bool {
        self.inner
            .lock()
            .map(|lease| {
                lease.is_current_process()
                    && !lease.credentials.is_empty()
                    && Instant::now() < lease.expires_at
            })
            .unwrap_or(false)
    }
}

impl<K: CredentialKind> fmt::Debug for CredentialSlot<K> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialSlot")
            .field("connected", &self.connected())
            .finish()
    }
}

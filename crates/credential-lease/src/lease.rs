//! The process-bound lease.
//!
//! A lease never survives process exit. Its duration is an upper bound for
//! one running process, not a persisted bypass of host authorization. Two
//! independent liveness checks apply: the lease's own `Instant` expiry, and
//! the custody epoch, rechecked lazily at most once per validation interval
//! so an owner-initiated revocation lands on the next use.

use crate::credential::LeasedCredential;
use crate::epoch::LeaseEpochSource;
use crate::handoff::{validate_credentials, CredentialHandoff};
use crate::kind::CredentialKind;
use anyhow::{anyhow, ensure, Result};
use licoup_foundation::core::secret_bytes::SecretBytes;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const LEASE_VALIDATION_INTERVAL: Duration = Duration::from_secs(1);

struct LeaseValidationState {
    checked_at: Option<Instant>,
    valid: bool,
}

/// A process-local snapshot of custody-held credentials for one kind family.
pub struct CredentialLease<K: CredentialKind> {
    credentials: BTreeMap<K, Vec<LeasedCredential>>,
    lease_duration: Duration,
    expires_at: Instant,
    epoch: String,
    epoch_source: Arc<dyn LeaseEpochSource>,
    validation: Mutex<LeaseValidationState>,
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
            validation: Mutex::new(LeaseValidationState {
                checked_at: None,
                valid: false,
            }),
        }
    }

    /// Mint a lease. The epoch must be a canonical UUID and the duration a
    /// positive bound within the contract's maximum.
    pub fn new(
        credentials: BTreeMap<K, Vec<LeasedCredential>>,
        lease_duration: Duration,
        epoch: String,
        epoch_source: Arc<dyn LeaseEpochSource>,
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
            validation: Mutex::new(LeaseValidationState {
                checked_at: None,
                valid: false,
            }),
        })
    }

    pub fn lease_duration(&self) -> Duration {
        self.lease_duration
    }

    /// Project the lease into a portable handoff, copying every secret so
    /// the lease itself keeps its own zeroizing bytes.
    pub fn handoff_projection(&self) -> Result<CredentialHandoff<K>> {
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

    pub fn contains_kind(&self, kind: K) -> bool {
        self.credentials
            .get(&kind)
            .is_some_and(|values| !values.is_empty())
    }

    /// Resolve one currently valid secret for `kind`.
    pub fn resolve(&self, kind: K) -> Result<SecretBytes> {
        self.resolve_candidates(kind)?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("credential_lease_unavailable"))
    }

    /// Every currently valid credential for `kind`, in declaration order.
    ///
    /// Fails closed when the lease is expired or revoked, and credentials
    /// past their own storage expiry never resolve.
    pub fn resolve_candidates(&self, kind: K) -> Result<Vec<SecretBytes>> {
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
        let credentials = kind_credentials
            .iter()
            .filter(|credential| !credential.is_expired(now))
            .map(LeasedCredential::copy_secret)
            .collect::<Vec<_>>();
        ensure!(!credentials.is_empty(), "credential_lease_unavailable");
        Ok(credentials)
    }

    #[cfg(test)]
    pub(crate) fn reset_epoch_check(&self) {
        self.validation.lock().unwrap().checked_at = None;
    }

    fn ensure_active(&self) -> Result<()> {
        ensure!(Instant::now() < self.expires_at, "credential_lease_expired");
        let mut state = self
            .validation
            .lock()
            .map_err(|_| anyhow!("credential_lease_validation_unavailable"))?;
        if state
            .checked_at
            .is_some_and(|checked| checked.elapsed() < LEASE_VALIDATION_INTERVAL)
        {
            ensure!(state.valid, "credential_lease_revoked");
            return Ok(());
        }
        state.valid = self.epoch_source.active_epoch()?.as_deref() == Some(self.epoch.as_str());
        state.checked_at = Some(Instant::now());
        ensure!(state.valid, "credential_lease_revoked");
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
    pub fn new(lease: CredentialLease<K>) -> Self {
        Self {
            inner: Mutex::new(lease),
            selection_cursors: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn disconnected() -> Self {
        Self::new(CredentialLease::disconnected())
    }

    pub fn contains_kind(&self, kind: K) -> bool {
        self.inner
            .lock()
            .map(|lease| lease.contains_kind(kind))
            .unwrap_or(false)
    }

    pub fn resolve(&self, kind: K) -> Result<SecretBytes> {
        self.resolve_candidates(kind)?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("credential_lease_unavailable"))
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

    pub fn replace(&self, lease: CredentialLease<K>) -> Result<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| anyhow!("credential_lease_validation_unavailable"))?;
        *guard = lease;
        Ok(())
    }

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

    pub fn connected(&self) -> bool {
        self.inner
            .lock()
            .map(|lease| !lease.credentials.is_empty() && Instant::now() < lease.expires_at)
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

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
//! 2. The lease's deadlines — its own `Instant` expiry plus the wall-clock
//!    and shared-monotonic deadlines it carries — each enforced in the
//!    clock domain it was declared in, on every use.
//! 3. The custody epoch, consulted on every resolution so an owner-initiated
//!    revocation lands on the very next use.
//!
//! The process check governs use of *this lease object*. A fork still
//! inherits the address space, so secret buffers already copied into the
//! child are outside this type's control; the check keeps the inherited
//! lease itself from resolving or projecting them.

use crate::credential::LeasedCredential;
use crate::egress::EgressScope;
use crate::epoch::LeaseEpochSource;
use crate::handoff::{validate_credentials, CredentialHandoff};
use crate::kind::CredentialKind;
use crate::SecretBytes;
use anyhow::{anyhow, bail, ensure, Result};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The clocks a lease enforces its deadlines on: the wall clock the
/// owner-authorized deadline was stamped in and the process-shared
/// monotonic clock the wire deadline rides. Production installs the system
/// pair; the test seam substitutes fixed or failing readings so suspend and
/// clock-failure paths are exercised deterministically instead of by
/// sleeping or racing a live second boundary.
pub(crate) trait LeaseClockSource: Send + Sync {
    /// The wall clock at full precision, as seconds since the Unix epoch.
    fn wall_now(&self) -> Result<Duration>;
    /// The process-shared monotonic clock at full precision — `Ok(None)`
    /// where the platform has no comparable clock at all, `Err` where
    /// the clock exists but the read failed. The two are never
    /// conflated: an absent clock decides which deadlines the wire can
    /// carry; a failed read is an operational refusal propagated to the
    /// caller.
    fn monotonic_now(&self) -> Result<Option<Duration>>;
}

/// The host's real clock pair.
pub(crate) struct SystemLeaseClocks;

impl LeaseClockSource for SystemLeaseClocks {
    fn wall_now(&self) -> Result<Duration> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| anyhow!("credential_lease_clock_invalid"))
    }

    fn monotonic_now(&self) -> Result<Option<Duration>> {
        crate::handoff::monotonic_now()
    }
}

/// A process-local snapshot of custody-held credentials for one kind family.
pub struct CredentialLease<K: CredentialKind> {
    credentials: BTreeMap<K, Vec<LeasedCredential>>,
    lease_duration: Duration,
    expires_at: Instant,
    lease_deadline_epoch_seconds: u64,
    lease_monotonic_deadline_seconds: Option<u64>,
    deadline_expired: AtomicBool,
    epoch: String,
    epoch_source: Arc<dyn LeaseEpochSource>,
    clock_source: Arc<dyn LeaseClockSource>,
    process_id: u32,
    egress: EgressScope,
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
            lease_deadline_epoch_seconds: 0,
            lease_monotonic_deadline_seconds: None,
            deadline_expired: AtomicBool::new(false),
            epoch: String::new(),
            epoch_source: Arc::new(DisconnectedEpochSource),
            clock_source: Arc::new(SystemLeaseClocks),
            process_id: std::process::id(),
            egress: EgressScope::deny_all(),
        }
    }

    /// Mint a lease. The epoch must be a canonical UUID and the duration a
    /// positive bound within the contract's maximum. The current process id
    /// is recorded as the lease's process binding. The egress scope is the
    /// outbound boundary the custody owner declared for this material —
    /// [`EgressScope::deny_all`] when nothing may leave the runtime.
    pub fn new(
        credentials: BTreeMap<K, Vec<LeasedCredential>>,
        lease_duration: Duration,
        epoch: String,
        epoch_source: Arc<dyn LeaseEpochSource>,
        egress: EgressScope,
    ) -> Result<Self> {
        crate::handoff::ensure_lease_duration_bounds(lease_duration)?;
        let lease_deadline_epoch_seconds =
            crate::handoff::lease_deadline_epoch_seconds(lease_duration)?;
        let lease_monotonic_deadline_seconds =
            crate::handoff::monotonic_deadline_seconds(lease_duration)?;
        Self::new_bound(
            credentials,
            lease_duration,
            epoch,
            epoch_source,
            std::process::id(),
            egress,
            lease_deadline_epoch_seconds,
            lease_monotonic_deadline_seconds,
            Instant::now(),
            Arc::new(SystemLeaseClocks),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_bound(
        credentials: BTreeMap<K, Vec<LeasedCredential>>,
        lease_duration: Duration,
        epoch: String,
        epoch_source: Arc<dyn LeaseEpochSource>,
        process_id: u32,
        egress: EgressScope,
        lease_deadline_epoch_seconds: u64,
        lease_monotonic_deadline_seconds: Option<u64>,
        minted_at: Instant,
        clock_source: Arc<dyn LeaseClockSource>,
    ) -> Result<Self> {
        ensure!(
            uuid::Uuid::parse_str(&epoch).is_ok_and(|value| value.to_string() == epoch),
            "credential_lease_epoch_invalid"
        );
        crate::handoff::ensure_lease_duration_bounds(lease_duration)?;
        validate_credentials(&credentials, "credential_lease_inventory_invalid")?;
        // The monotonic expiry honors both bounds: the granted duration
        // exactly as offered and the owner-authorized deadline carried in
        // from the handoff. A rebuild can therefore never mint a lease
        // that outlives the original grant, and a lapsed deadline yields a
        // dead-on-arrival lease that fails closed on every use.
        //
        // Paired clock samples in the conservative direction: the mint
        // instant is sampled before the wall clock, so the deadline
        // subtraction runs against a wall reading no earlier than the
        // instant the expiry is anchored to — a pause between the
        // samples can only shrink the minted lifetime, never stretch it
        // past the deadline.
        let now = clock_source.wall_now()?;
        let mut effective_duration =
            lease_duration.min(deadline_remaining(lease_deadline_epoch_seconds, now));
        // The same-host anchor: a monotonic deadline is enforced on the
        // clock domain it was stamped in, so a backward wall-clock step
        // between projection and rebuild can never stretch the grant the
        // wall deadline alone would have allowed. A rebuild that can
        // compare such a deadline requires it; a rebuild that cannot
        // compare refuses one that is carried — clock continuity cannot
        // be established either way, and refusing is the fail-closed
        // answer. A failed read is an operational refusal, not evidence
        // of an absent clock: it propagates instead of falling into a
        // continuity arm it cannot prove.
        let monotonic_now = clock_source.monotonic_now()?;
        effective_duration = match (lease_monotonic_deadline_seconds, monotonic_now) {
            (Some(deadline), Some(now)) => {
                effective_duration.min(deadline_remaining(deadline, now))
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(anyhow!("credential_lease_expiry_invalid"))
            }
            (None, None) => effective_duration,
        };
        let expires_at = minted_at
            .checked_add(effective_duration)
            .ok_or_else(|| anyhow!("credential_lease_expiry_invalid"))?;
        Ok(Self {
            credentials,
            // The lease carries the whole-second duration the wire format
            // carries: a fractional grant maps up to the next second for
            // serialization, while the exact offered duration above still
            // bounds the real expiry.
            lease_duration: crate::handoff::whole_seconds_ceiling(lease_duration),
            expires_at,
            lease_deadline_epoch_seconds,
            lease_monotonic_deadline_seconds,
            deadline_expired: AtomicBool::new(false),
            epoch,
            epoch_source,
            clock_source,
            process_id,
            egress,
        })
    }

    /// Test-only construction with an explicit process binding, expiry,
    /// owner deadline and clock pair so cross-PID replay, timeout,
    /// sub-second-deadline, suspend and clock-failure paths are exercised
    /// deterministically instead of by sleeping.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_binding_for_test(
        credentials: BTreeMap<K, Vec<LeasedCredential>>,
        lease_duration: Duration,
        epoch: String,
        epoch_source: Arc<dyn LeaseEpochSource>,
        egress: EgressScope,
        process_id: u32,
        expires_at: Instant,
        lease_deadline_epoch_seconds: u64,
        lease_monotonic_deadline_seconds: Option<u64>,
        clock_source: Arc<dyn LeaseClockSource>,
    ) -> Result<Self> {
        let mut lease = Self::new_bound(
            credentials,
            lease_duration,
            epoch,
            epoch_source,
            process_id,
            egress,
            lease_deadline_epoch_seconds,
            lease_monotonic_deadline_seconds,
            Instant::now(),
            clock_source,
        )?;
        lease.expires_at = expires_at;
        Ok(lease)
    }

    /// Test-only: the minted `Instant` expiry, so sub-second deadline
    /// arithmetic is asserted exactly instead of through sleeping.
    #[cfg(test)]
    pub(crate) fn expires_at_for_test(&self) -> Instant {
        self.expires_at
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
    ///
    /// The document carries the grant's remaining duration and the grant's
    /// effective deadline — the earlier of the preserved owner-authorized
    /// deadline and this lease's own expiry expressed on the wall clock —
    /// so a lease rebuilt from this projection can never outlive the
    /// original grant. Extension requires a fresh owner grant, not another
    /// projection. The wire format is whole seconds: a live fractional
    /// remainder maps up to the next second, which the stamped deadline
    /// still caps on rebuild.
    pub fn handoff_projection(&self) -> Result<CredentialHandoff<K>> {
        self.ensure_active()?;
        // Paired clock samples in the conservative direction: the wall
        // clock and the shared monotonic clock are both read before the
        // `Instant` remainder is measured, so the projected expiry
        // estimates below sit at or before the lease's true expiry — a
        // credential copy or a scheduling pause after the samples can
        // only shrink the stamped deadlines. Adding a stale remainder to
        // a later monotonic reading would stamp a deadline past the
        // grant it projects whenever the preserved deadline is looser.
        let projected_at = self.clock_source.wall_now()?;
        // A lease carrying a shared-clock deadline can stamp it only
        // from a fresh sample on that same clock: the preserved wire
        // deadline may sit later than this lease's true monotonic
        // expiry, so carrying it forward unsampled would let a
        // wall-clock rollback before rebuild grant the document time
        // its source lease did not have. A failed or absent reading on
        // such a lease refuses under the clock code — the same refusal
        // `ensure_unexpired` applies to a deadline it cannot compare.
        let monotonic_now = match (
            self.lease_monotonic_deadline_seconds,
            self.clock_source.monotonic_now(),
        ) {
            (Some(_), Ok(Some(now))) => Some(now),
            (Some(_), _) => return Err(anyhow!("credential_lease_clock_unavailable")),
            (None, reading) => reading?,
        };
        let remaining = self.expires_at.saturating_duration_since(Instant::now());
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
        // The paired samples feed the stamps; they are not the freshness
        // proof. A suspend can park the process anywhere between the
        // post-epoch recheck and the copies, so every deadline is
        // enforced one final time on fresh readings immediately before
        // the secret-bearing document is produced — a projection whose
        // grant lapsed in between refuses rather than returning one.
        self.ensure_unexpired()?;
        // When the lease's own expiry — not the owner deadline — is the
        // tighter bound, the stamped deadline must be that expiry floored
        // to whole seconds: otherwise a rebuild would restart the
        // rounded-up wire duration and outlive the lease it came from.
        let expires_at_epoch_seconds = self
            .lease_deadline_epoch_seconds
            .min(projected_expiry_epoch_seconds(projected_at, remaining)?);
        // The same bound in the producing host's monotonic clock domain:
        // floored from the early sample plus the later instant remainder,
        // so the stamp sits at or before the lease's true monotonic
        // expiry. A rebuild compares it against that same clock — a
        // domain a wall-clock rollback cannot deceive. Where the platform
        // has no comparable clock a deadline-less lease keeps carrying
        // none; a lease carrying one never reaches this stamp unsampled
        // — the clock refusal above stands first.
        let monotonic_deadline_seconds = crate::handoff::projected_monotonic_deadline_seconds(
            self.lease_monotonic_deadline_seconds,
            monotonic_now,
            remaining,
        );
        // The egress scope is part of the grant: a projection carries it
        // forward verbatim so forwarding can never silently widen it.
        CredentialHandoff::with_deadline(
            credentials,
            remaining,
            self.epoch.clone(),
            self.egress.clone(),
            expires_at_epoch_seconds,
            monotonic_deadline_seconds,
        )
    }

    /// Rebuild a lease from a received handoff under the local epoch source.
    /// Construction reuses the same closed validations as a custody unlock,
    /// and the rebuilt lease expires at the earlier of the document's
    /// duration and the owner-authorized deadline it carries. Where the
    /// document carries the same-host monotonic deadline, the rebuild is
    /// capped by that clock as well — and where the platform can compare
    /// one but the document omits it, the rebuild refuses, since clock
    /// continuity cannot be established.
    pub fn from_handoff(
        handoff: CredentialHandoff<K>,
        epoch_source: Arc<dyn LeaseEpochSource>,
    ) -> Result<Self> {
        Self::rebuild(handoff, epoch_source, Arc::new(SystemLeaseClocks))
    }

    fn rebuild(
        handoff: CredentialHandoff<K>,
        epoch_source: Arc<dyn LeaseEpochSource>,
        clock_source: Arc<dyn LeaseClockSource>,
    ) -> Result<Self> {
        Self::rebuild_at(handoff, epoch_source, Instant::now(), clock_source)
    }

    /// `rebuild` with the mint instant supplied: the test seam anchors the
    /// minted expiry to an injected instant so deadline arithmetic is
    /// asserted exactly instead of against whatever time elapsed before
    /// the assertion ran.
    fn rebuild_at(
        handoff: CredentialHandoff<K>,
        epoch_source: Arc<dyn LeaseEpochSource>,
        minted_at: Instant,
        clock_source: Arc<dyn LeaseClockSource>,
    ) -> Result<Self> {
        let (
            credentials,
            lease_duration,
            epoch,
            egress,
            lease_deadline_epoch_seconds,
            lease_monotonic_deadline_seconds,
        ) = handoff.into_parts();
        Self::new_bound(
            credentials,
            lease_duration,
            epoch,
            epoch_source,
            std::process::id(),
            egress,
            lease_deadline_epoch_seconds,
            lease_monotonic_deadline_seconds,
            minted_at,
            clock_source,
        )
    }

    /// Test-only rebuild under an injected clock pair: the production mint
    /// calculation runs against fixed samples instead of racing a live
    /// second boundary.
    #[cfg(test)]
    pub(crate) fn from_handoff_with_clock_source(
        handoff: CredentialHandoff<K>,
        epoch_source: Arc<dyn LeaseEpochSource>,
        clock_source: Arc<dyn LeaseClockSource>,
    ) -> Result<Self> {
        Self::rebuild(handoff, epoch_source, clock_source)
    }

    /// Test-only rebuild under an injected clock pair and mint instant:
    /// the minted lifetime comes out exact, so sub-second deadline
    /// arithmetic is asserted as an equality rather than a
    /// scheduling-dependent window.
    #[cfg(test)]
    pub(crate) fn from_handoff_with_clock_source_at(
        handoff: CredentialHandoff<K>,
        epoch_source: Arc<dyn LeaseEpochSource>,
        minted_at: Instant,
        clock_source: Arc<dyn LeaseClockSource>,
    ) -> Result<Self> {
        Self::rebuild_at(handoff, epoch_source, minted_at, clock_source)
    }

    /// The egress scope this lease's material may leave through — the
    /// boundary a runtime's outbound proxy enforces on every forward.
    pub fn egress(&self) -> &EgressScope {
        &self.egress
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
        // Process identity precedes the inventory lookup: an inherited
        // lease must refuse as a boundary violation — never as a missing
        // kind, which would read as the ordinary `auth_expired` renewal
        // signal to a child replaying its parent's lease.
        self.ensure_current_process()?;
        let kind_credentials = self
            .credentials
            .get(&kind)
            .filter(|values| !values.is_empty())
            .ok_or_else(|| anyhow!("credential_lease_unavailable"))?;
        self.ensure_active()?;
        // The credential-expiry reading is also the last deadline check
        // before the secrets answer: `ensure_unexpired` returns the wall
        // sample it just enforced against every deadline, so a grant
        // that lapsed between the post-epoch recheck and this read still
        // refuses instead of releasing credentials — the reading can
        // never be spent on per-credential expiry alone.
        let now = self.ensure_unexpired()?.as_secs();
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
        self.ensure_unexpired()?;
        ensure!(
            self.epoch_source.active_epoch()?.as_deref() == Some(self.epoch.as_str()),
            "credential_lease_revoked"
        );
        // The epoch consultation may take arbitrarily long: a lease that
        // was alive when it started can cross either deadline while
        // waiting, so expiry is rechecked before credentials answer — a
        // slow lookup must never release an expired grant.
        self.ensure_unexpired()?;
        Ok(())
    }

    /// The lease's time bounds, each enforced in the clock domain it was
    /// declared in. The `Instant` expiry is the mint-time conversion of
    /// every limit; the owner-authorized wall deadline and the wire-carried
    /// monotonic deadline are compared against their own clocks on every
    /// use. Those clocks can diverge both ways — Darwin `CLOCK_MONOTONIC`
    /// advances across suspend while the uptime clock `Instant` reads
    /// pauses, and on Linux both runtime clocks pause across suspend while
    /// the wall clock keeps running — so neither wire deadline can be left
    /// to the `Instant` conversion alone: a lease minted before sleep must
    /// still refuse once a deadline passed during sleep. A clock that
    /// cannot be read back refuses closed under its own refusal code, not
    /// as an elapsed grant.
    ///
    /// An expiry once observed is terminal: the lease records it, so a
    /// backward wall-clock correction — while both monotonic bounds are
    /// still live — can never revive a grant already seen elapsed. Clock
    /// read failures refuse without being recorded: an operational
    /// failure is not an elapsed grant, and a recovered clock must be
    /// allowed to answer the still-live bounds again.
    ///
    /// The wall sample the check just enforced is returned so the
    /// caller's own clock use — per-credential expiry, stamp math — can
    /// run on an already-validated reading instead of an unchecked one.
    fn ensure_unexpired(&self) -> Result<Duration> {
        ensure!(
            !self.deadline_expired.load(Ordering::Acquire),
            "credential_lease_expired"
        );
        if Instant::now() >= self.expires_at {
            self.deadline_expired.store(true, Ordering::Release);
            bail!("credential_lease_expired");
        }
        let wall_now = self.clock_source.wall_now()?;
        if wall_now >= Duration::from_secs(self.lease_deadline_epoch_seconds) {
            self.deadline_expired.store(true, Ordering::Release);
            bail!("credential_lease_expired");
        }
        if let Some(deadline) = self.lease_monotonic_deadline_seconds {
            // An unreadable shared clock — a failed read, or a platform
            // reporting no comparable clock while a deadline rides it —
            // is an operational failure, not an elapsed grant: refuse
            // closed under the distinct clock code so
            // `auth_failure_class` never routes it into credential
            // renewal.
            let now = self
                .clock_source
                .monotonic_now()?
                .ok_or_else(|| anyhow!("credential_lease_clock_unavailable"))?;
            if now >= Duration::from_secs(deadline) {
                self.deadline_expired.store(true, Ordering::Release);
                bail!("credential_lease_expired");
            }
        }
        Ok(wall_now)
    }
}

/// The exact time left before an owner-authorized deadline: the clock
/// reading — wall or shared monotonic — is subtracted at full precision
/// so a sub-second remainder can never round up into nearly a whole
/// extra second of use.
pub(crate) fn deadline_remaining(
    deadline_epoch_seconds: u64,
    now_since_epoch: Duration,
) -> Duration {
    Duration::from_secs(deadline_epoch_seconds)
        .checked_sub(now_since_epoch)
        .unwrap_or(Duration::ZERO)
}

/// A lease's own expiry projected onto the wall clock, floored to whole
/// seconds. `wall_now` must be sampled no later than the monotonic
/// instant `remaining` was measured against: the estimate then sits at
/// or before the true expiry, so a delay between the two samples can
/// only move the stamp earlier — it can never stamp a deadline past the
/// real one.
pub(crate) fn projected_expiry_epoch_seconds(
    wall_now: Duration,
    remaining: Duration,
) -> Result<u64> {
    wall_now
        .checked_add(remaining)
        .map(|expiry| expiry.as_secs())
        .ok_or_else(|| anyhow!("credential_lease_expiry_invalid"))
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

    /// The next candidate index for `kind`, advancing the rotation cursor
    /// under its own lock.
    fn selection_start(&self, kind: K, count: usize) -> Result<usize> {
        let mut cursors = self
            .selection_cursors
            .lock()
            .map_err(|_| anyhow!("credential_lease_validation_unavailable"))?;
        let cursor = cursors.entry(kind).or_insert(0);
        let start = *cursor % count;
        *cursor = cursor.wrapping_add(1);
        Ok(start)
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
        let start = self.selection_start(kind, candidates.len())?;
        Ok(candidates[start].copy_secret())
    }

    /// Resolve one currently valid secret for `kind` together with the
    /// egress scope of the lease that produced it. The credential and the
    /// scope come out of the same lease snapshot under one lock, so a
    /// concurrent handoff install can never pair a fresh credential with
    /// the previous grant's outbound boundary — a forwarding runtime reads
    /// both through this call, not through `resolve` and `egress`
    /// separately.
    pub fn resolve_scoped(&self, kind: K) -> Result<(SecretBytes, EgressScope)> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| anyhow!("credential_lease_validation_unavailable"))?;
        let candidates: Vec<&LeasedCredential> = guard.valid_candidates(kind)?.collect();
        ensure!(!candidates.is_empty(), "credential_lease_unavailable");
        let start = self.selection_start(kind, candidates.len())?;
        Ok((candidates[start].copy_secret(), guard.egress.clone()))
    }

    /// Returns every currently valid credential in rotating order.
    pub fn resolve_candidates(&self, kind: K) -> Result<Vec<SecretBytes>> {
        let mut candidates = self
            .inner
            .lock()
            .map_err(|_| anyhow!("credential_lease_validation_unavailable"))?
            .resolve_candidates(kind)?;
        let start = self.selection_start(kind, candidates.len())?;
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
    /// current lease in one atomic swap. A rebuild can succeed with no
    /// lifetime left — the owner-authorized deadline it honors may already
    /// have elapsed on either clock domain. Swapping such a dead-on-arrival
    /// lease in would report success while disconnecting a slot whose
    /// installed grant is still live, so the replacement proves its own
    /// expiry before the swap and the installed lease is preserved on
    /// refusal.
    pub fn install_handoff(
        &self,
        handoff: CredentialHandoff<K>,
        epoch_source: Arc<dyn LeaseEpochSource>,
    ) -> Result<()> {
        let lease = CredentialLease::from_handoff(handoff, epoch_source)?;
        lease.ensure_unexpired()?;
        self.replace(lease)
    }

    /// The installed lease's egress scope — the deny-all scope when the
    /// slot is poisoned or holds a disconnected lease.
    ///
    /// A runtime that forwards a resolved credential must read the scope
    /// together with the secret through [`Self::resolve_scoped`]; reading
    /// the scope on its own here and resolving separately can observe two
    /// different grants across a concurrent handoff install.
    pub fn egress(&self) -> EgressScope {
        self.inner
            .lock()
            .map(|lease| lease.egress.clone())
            .unwrap_or_else(|_| EgressScope::deny_all())
    }

    /// Whether the slot holds a live, non-empty lease in the current
    /// process. A poisoned lock, an expired lease — on either clock
    /// domain — or a lease inherited across a process boundary reads as
    /// disconnected.
    pub fn connected(&self) -> bool {
        self.inner
            .lock()
            .map(|lease| {
                lease.is_current_process()
                    && !lease.credentials.is_empty()
                    && lease.ensure_unexpired().is_ok()
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

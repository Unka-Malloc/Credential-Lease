//! The revocation signal behind a lease.
//!
//! A lease is valid only while the custody owner's active epoch still equals
//! the epoch the lease was minted under. The host supplies the epoch; the
//! lease consults it on every credential resolution — there is no cached
//! authorization window — so the source should be cheap to consult.
//!
//! A custody owner rotates the epoch to revoke every outstanding lease at
//! once — credential rotation, lock, or reset all mint a new epoch, so a
//! stale lease dies on its next use without the runtime restarting.

use anyhow::Result;

/// The custody owner's current epoch.
///
/// `Ok(None)` means no epoch is active — nothing is unlocked, so every lease
/// fails closed as revoked.
pub trait LeaseEpochSource: Send + Sync {
    fn active_epoch(&self) -> Result<Option<String>>;
}

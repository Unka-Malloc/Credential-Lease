//! The custody port.
//!
//! Custody — reading the system keyring and asking for owner authorization —
//! belongs to the host. The runtime only rebuilds a live lease from the
//! handoff the host already authorized, through this port.
//!
//! Ports are registered per kind family in one process-wide registry keyed
//! by the kind type, so a runtime hosting several credential families gets
//! exactly one custody answer per family.

use crate::handoff::CredentialHandoff;
use crate::kind::CredentialKind;
use crate::lease::CredentialLease;
use anyhow::{anyhow, Result};
use std::any::{Any, TypeId};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

/// The custody owner's lease answer for one kind family.
pub trait CustodyPort<K: CredentialKind>: Send + Sync {
    /// Rebuild a lease from a handoff produced by the custody owner.
    fn lease_from_handoff(&self, handoff: CredentialHandoff<K>) -> Result<CredentialLease<K>>;
}

type Registry = BTreeMap<TypeId, Arc<dyn Any + Send + Sync>>;

static PORTS: RwLock<Option<Registry>> = RwLock::new(None);

fn with_registry<R>(
    access: impl FnOnce(&mut Registry) -> R,
) -> std::result::Result<R, &'static str> {
    let mut guard = PORTS.write().map_err(|_| "custody_port_lock_failed")?;
    let registry = guard.get_or_insert_with(Registry::new);
    Ok(access(registry))
}

/// Install the custody owner's lease answer for kind family `K`.
/// Reinstalling the same port is accepted so repeated startup is harmless;
/// a different port for the same family is refused.
pub fn install<K, P>(port: Arc<P>) -> Result<(), &'static str>
where
    K: CredentialKind,
    P: CustodyPort<K> + 'static,
{
    let port: Arc<dyn CustodyPort<K>> = port;
    with_registry(|registry| {
        if let Some(existing) = registry.get(&TypeId::of::<K>()) {
            let same = existing
                .downcast_ref::<Arc<dyn CustodyPort<K>>>()
                .is_some_and(|installed| Arc::ptr_eq(installed, &port));
            return if same {
                Ok(())
            } else {
                Err("custody_port_already_installed")
            };
        }
        registry.insert(TypeId::of::<K>(), Arc::new(port));
        Ok(())
    })?
}

pub fn installed<K: CredentialKind>() -> bool {
    PORTS
        .read()
        .ok()
        .and_then(|guard| {
            guard
                .as_ref()
                .map(|registry| registry.contains_key(&TypeId::of::<K>()))
        })
        .unwrap_or(false)
}

/// Consume the installed port for kind family `K`; fails closed when
/// nothing is installed.
pub fn require<K>() -> Result<Arc<dyn CustodyPort<K>>>
where
    K: CredentialKind,
{
    let entry = PORTS.read().ok().and_then(|guard| {
        guard
            .as_ref()
            .and_then(|registry| registry.get(&TypeId::of::<K>()).cloned())
    });
    entry
        .and_then(|any| any.downcast::<Arc<dyn CustodyPort<K>>>().ok())
        .map(|port| (*port).clone())
        .ok_or_else(|| anyhow!("custody_port_unavailable"))
}

#[cfg(test)]
pub fn clear() {
    if let Ok(mut guard) = PORTS.write() {
        *guard = None;
    }
}

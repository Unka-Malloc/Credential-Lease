# Integration modes

One way to consume this workspace: **SDK — embed the crate**. The crate is
a contract layer — handoff document, process-bound lease, epoch revocation
signal, custody port — not a daemon, so there is no sidecar to run.

## SDK — embed the crate

```toml
[dependencies]
credential-lease = "0.3"
```

Construct credentials with SecretBytes and LeasedCredential::new, validate a
CredentialHandoff::new, and rebuild the receiving lease with
CredentialLease::from_handoff(handoff, epoch_source). Resolve a declared
CredentialKind through lease.resolve(kind). The complete deterministic flow is in
crates/credential-lease/tests/handoff_flow.rs.

Boundary rules the consumer relies on:

- **Custody stays with the host** — system keyring access, persistence and
  owner authorization are host ports; they never enter this crate.
- **Secret bytes serialize only in `HandoffDocument`** — the secret-bearing
  document travels only through a process-local channel, never disks, logs or
  configuration. Inventories, debug projections and error output contain no
  secret material.
- **Process-bound** — a lease is bound to the granting process and epoch;
  revocation is a signal the host reads, not a callback it must trust.

## Skills

- `skills/sdk/` — embedding guidance (handoff, leases, epochs, custody port).

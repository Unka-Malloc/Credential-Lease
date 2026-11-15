---
name: credential-lease-sdk
description: Embed credential-lease in a Rust host — handoff documents, process-bound leases, epoch revocation, host custody ports.
---

# credential-lease SDK mode

Embed `credential-lease`; it owns handoff documents, lease lifetime and
revocation checks. Custody of persisted secrets goes through the workspace's
`credential-lease-keychain` backend, and owner authorization stays with the
host. There is no daemon to install.

## When to use

- A runtime needs process-bound credential access without owning custody.
- The host can supply a credential-kind family and a live epoch source.

## Canonical calls

```rust
let handoff = credential_lease::CredentialHandoff::<Kind>::from_json(document.expose_bytes())?;
let lease = credential_lease::CredentialLease::from_handoff(handoff, epoch_source)?;
let secret = lease.resolve(kind)?;
```

The host supplies `Kind`, the authorized secret-bearing document, the epoch
source and the selected kind. Use `SecretBytes` and `LeasedCredential::new`
when constructing the handoff. See `crates/credential-lease/tests/handoff_flow.rs`
for an executable synthetic flow. Hosts that need process-wide port lookup
can install their `CustodyPort` through `port::install` and access it through
`port::require`.

## Rules that keep the contract

- Secrets use the crate-owned zeroizing, redacted `SecretBytes` type. Convert
  other custody buffer types at the host boundary, not inside this crate.
- The only secret-bearing serialized form is `HandoffDocument`, carried over
  an explicitly authorized process-local channel, never a file, log, inventory
  or configuration document.
- Every resolution checks the lease's process identity, its own lifetime,
  and the host's current custody epoch. A lease inherited across a fork and
  a revoked or expired lease are all refusals; obtaining another lease
  requires host authorization.
- The `credential-lease` contract crate performs no custody. The workspace
  ships the keyring backend as `credential-lease-keychain`: protected macOS
  Keychain items, fail-closed (`Keychain::selected()` is `None`) elsewhere.
  Read item values only through `SecretBytes` and check provenance through
  `KeychainItem::provenance()`.
- Owner authorization stays host-side: the host runs prompts, sessions and
  revocation and hands the backend an already-authorized
  `KeychainAuthContext`. Host ports must preserve that custody boundary.

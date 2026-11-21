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
// Spawned runtime: consume the inherited descriptor named by
// FAIRLINY_HANDOFF_FD (environment carries only the descriptor number).
let handoff = credential_lease::handoff_fd::receive_handoff_from_env::<Kind>()?
    .expect("the host granted a handoff descriptor");
let lease = credential_lease::CredentialLease::from_handoff(handoff, epoch_source)?;
let secret = lease.resolve(kind)?;
```

When the host already resolved the descriptor, call
`credential_lease::handoff_fd::receive_handoff(owned_fd)` — it takes an
`OwnedFd` so ownership transfer is explicit. The receiver bounds the read,
parses the closed document, and closes the descriptor on every path. See
`docs/fd-handoff.md` for the channel contract
and the shared Rust/Go/TypeScript validation samples.

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
  or configuration document. The environment names the explicitly granted channel
  (`FAIRLINY_HANDOFF_FD`) by descriptor number only; it never carries the
  document or a root key.
- The `FAIRLINY_HANDOFF_FD` grant rule applies at every exec, not only the
  first spawn: set the variable only together with the descriptor the child
  is actually granted, and remove it from the environment of any child that
  receives no handoff. Intake consumes the channel but never removes the
  variable, so a descendant spawned with the default environment inherits a
  stale number — a fresh latch could read a closed descriptor or one the OS
  reassigned to something unrelated.
- Every resolution checks the lease's process identity, its own lifetime,
  and the host's current custody epoch. A lease inherited across a fork and
  a revoked or expired lease are all refusals; obtaining another lease
  requires host authorization.
- Map credential refusals with `credential_lease::auth_failure_class`.
  Unavailable, expired and revoked credentials become the shared
  `auth_expired` `failureClass` that AwP and Fairliny-Gateway use to renew or
  switch safely. Process-integrity and epoch-source failures return `None`
  and must not trigger an automatic renewal.
- A handoff also carries the owner-declared `EgressScope`: when forwarding
  a resolved credential, take the secret and the scope from the same lease
  snapshot through `slot.resolve_scoped(kind)` — resolving and reading
  `slot.egress()` separately can observe two different grants across a
  concurrent handoff install. Gate every outbound target through
  `scope.permits(&target)` (or `lease.egress()` / `handoff.egress()` for a
  single lease), honor `allow_redirects()` (off
  unless explicitly enabled), and render header injections through
  `HeaderTemplate::render` with the `{secret}` marker. An undeclared scope
  denies every target — it is a boundary, not a hint.
- The `credential-lease` contract crate performs no custody. The workspace
  ships the keyring backend as `credential-lease-keychain`: protected macOS
  Keychain items, fail-closed (`Keychain::selected()` is `None`) elsewhere.
  Read item values only through `SecretBytes` and check provenance through
  `KeychainItem::provenance()`.
- Owner authorization stays host-side: the host runs prompts, sessions and
  revocation and hands the backend an already-authorized
  `KeychainAuthContext`. Host ports must preserve that custody boundary.

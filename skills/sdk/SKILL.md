---
name: credential-lease-sdk
description: Embed credential-lease in a Rust host — handoff documents, process-bound leases, epoch revocation, host custody ports.
---

# credential-lease SDK mode

Embed `credential-lease`; the host owns custody and authorization, while the
crate owns handoff documents, lease lifetime and revocation checks. There is
no daemon to install.

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
- Every resolution checks lease lifetime and the host's current custody epoch.
  Revocation is a refusal; obtaining another lease requires host authorization.
- The framework neither implements a keyring nor chooses an authorization
  policy. Its host ports must preserve the host's actual custody boundary.

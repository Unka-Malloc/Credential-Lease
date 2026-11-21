# Integration modes

One way to consume this workspace: **SDK — embed the crates**. The
`credential-lease` crate is a contract layer — handoff document,
process-bound lease, epoch revocation signal, custody port — not a daemon,
so there is no sidecar to run. The `credential-lease-keychain` crate is the
workspace's OS-keychain custody backend; a host that keeps secrets in the
system keyring embeds it as well.

## SDK — embed the crate

```toml
[dependencies]
credential-lease = "0.3"
credential-lease-keychain = "0.1" # OS-keychain custody backend
```

Construct credentials with SecretBytes and LeasedCredential::new, validate a
CredentialHandoff::new, and rebuild the receiving lease with
CredentialLease::from_handoff(handoff, epoch_source). Resolve a declared
CredentialKind through lease.resolve(kind). The complete deterministic flow is in
crates/credential-lease/tests/handoff_flow.rs.

Boundary rules the consumer relies on:

- **Custody goes through `credential-lease-keychain`** — the backend stores
  protected items in the system keyring (the macOS Keychain; `None`, so
  fail-closed, elsewhere). Item values cross its API only as `SecretBytes`;
  copied items expose a typed provenance projection, never the raw platform
  dictionary.
- **Owner authorization stays with the host** — prompts, sessions and
  revocation never enter this workspace; the backend only consumes an
  already-authorized `KeychainAuthContext`. The `credential-lease` contract
  crate itself performs no custody.
- **Secret bytes serialize only in `HandoffDocument`** — the secret-bearing
  document travels only through a process-local channel, never disks, logs or
  configuration. Inventories, debug projections and error output contain no
  secret material. On Unix the channel is an inherited read-only descriptor
  named by `FAIRLINY_HANDOFF_FD`; `receive_handoff_from_env` consumes the
  variable once, closes the descriptor, and bounds the read. The environment
  carries only the descriptor number. The grant rule applies at every exec:
  a spawned child either receives the matching descriptor with the variable
  set to its number, or starts without the variable — an inherited stale
  number must never reach a descendant.
- **Process-bound** — a lease is bound to the process that minted it, its
  own lifetime, and the custody epoch. A fork inheriting the lease fails
  closed (`credential_lease_process_mismatch`); revocation is a signal the
  host reads, not a callback it must trust.
- **Failure classification** — `credential_lease::auth_failure_class` maps
  unavailable, expired and revoked credentials to the shared `auth_expired`
  `failureClass` used by AwP and Fairliny-Gateway for renewal or safe
  switching. Local integrity and infrastructure failures return `None` and
  stay operational errors.
- **Outbound scope rides the handoff** — an `EgressScope` declares the
  host/port/path-prefix/method matchers, header injection templates and
  `allow_redirects` flag a runtime's outbound HTTP/TCP proxy enforces per
  target (`EgressScope::permits`). An undeclared scope fails closed; a
  lease carries it through projection unchanged so forwarding can never
  widen the grant.

## Skills

- `skills/sdk/` — embedding guidance (handoff, leases, epochs, custody port,
  keychain backend).

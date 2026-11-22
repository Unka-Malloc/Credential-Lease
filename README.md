# Credential-Lease

Host-neutral Rust contract and OS keychain custody backend for issuing process-bound, time-limited, revocable credential leases. Each lease carries only the credential material the host authorizes for that runtime.

Following the IAM session-credential model:

- **Custody and authorization.** `credential-lease-keychain` reads protected items from the OS keychain using a host-authorized `KeychainAuthContext`. Owner prompts, sessions, and revocation belong to the host.
- **Process-local handoff.** A closed JSON handoff passes credential material and owner-declared `EgressScope` rules over a process-local channel. On Unix, `FAIRLINY_HANDOFF_FD` carries the number of an inherited read-only descriptor. The outbound proxy enforces the scope's host, port, path prefix, and method matchers, applies header templates, and denies redirects by default.
- **Process-bound leases.** The receiving process rebuilds a `CredentialLease` bound to its PID, deadlines, and custody epoch. Each resolution checks the host's active epoch, so rotating it invalidates leases issued under the previous epoch.
- **Secret handling.** The handoff document is the only serialized form that carries credential bytes. Configs, inventories, debug formatting, and error output omit them. Each `CredentialKind` defines its own handoff schema.

## Crates

| Crate | Contents |
| --- | --- |
| `credential-lease` | `SecretBytes`, `LeasedCredential`, `CredentialHandoff<K>`, `EgressScope`/`EgressTarget`/`HeaderTemplate`, `CredentialLease<K>`, `CredentialSlot<K>`, `LeaseEpochSource`, and `CustodyPort` |
| `credential-lease-keychain` | OS-keychain custody backend (`Keychain`, `KeychainItemQuery`, `KeychainAuthContext`, `KeychainItem`, `KeychainItemProvenance`). Uses macOS Keychain and fails closed on unsupported platforms. |

## Quick Usage

```toml
[dependencies]
credential-lease = "0.3"
credential-lease-keychain = "0.1"
```

Given a decoded `CredentialHandoff<K>`, a host-provided `Arc<dyn LeaseEpochSource>`, and a requested credential kind, the runtime rebuilds the lease and resolves the credential.

```rust
use credential_lease::CredentialLease;

let lease = CredentialLease::from_handoff(handoff, epoch_source)?;
let resolved = lease.resolve(kind)?;
```

See [crates/credential-lease/tests/handoff_flow.rs](crates/credential-lease/tests/handoff_flow.rs) for the complete end-to-end flow.

## Cross-Language Contract

Non-Rust hosts (Go, TypeScript) interoperate against the exact wire contract and descriptor protocol:

- [docs/handoff.md](docs/handoff.md) — `CredentialHandoff` closed JSON schema and monotonic clock rules.
- [docs/fd-handoff.md](docs/fd-handoff.md) — `FAIRLINY_HANDOFF_FD` descriptor handoff rules and Rust/Go/TypeScript samples.
- [docs/integration-modes.md](docs/integration-modes.md) — embedding guide and boundary guarantees.

## Verify

Requires Rust 1.89+ and `jq` (Go and Node.js are optional; `scripts/verify-samples.sh` skips missing toolchains):

```sh
./scripts/verify.sh
```

## License

Apache-2.0.

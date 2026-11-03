# Credential-Lease

Host-neutral credential lease contract: custody holds root credentials;
runtimes receive process-bound, revocable, time-limited leases.

The crate owns its SecretBytes boundary type and depends on no product framework.
Hosts supply credential-kind families, custody authorization and revocation sources;
the runtime receives only authorized ephemeral lease material.

The model follows the IAM session-credential shape rather than "give the
application the key":

- **Custody** (system keyring, persistence, owner authorization) belongs to
  the host and never enters this crate.
- A **`CredentialHandoff`** — a closed JSON document — carries credential
  material from the unlocking process to one runtime over a process-local
  channel.
- The runtime rebuilds a **`CredentialLease`**: process-bound, time-limited,
  and revoked the moment the custody epoch rotates.
- Secret bytes never appear in inventories, configuration documents, debug
  projections, or command results.

What is leased is parameterized by `CredentialKind`: provider API keys are
the first family; signed identity assertions are the designed-for next
family. Each family pins its own handoff schema so documents can never
cross families.

## Crates

| Crate | Contents |
| --- | --- |
| `credential-lease` | `SecretBytes`, `LeasedCredential`, `CredentialHandoff<K>`, `CredentialLease<K>`, `CredentialSlot<K>`, `LeaseEpochSource`, `CustodyPort` registry |
| `credential-lease-keychain` | OS-keychain custody backend: protected SecItem operations on macOS (`Keychain`, `KeychainItemQuery`, `KeychainAuthContext`), fail-closed `None` elsewhere |

## Language-neutral contract

The handoff document is specified in [docs/handoff.md](docs/handoff.md).
Rust consumers link the crate; Go, TypeScript, and other consumers
implement the contract against that document.

## Verify

```sh
./scripts/verify.sh
```

## License

Apache-2.0

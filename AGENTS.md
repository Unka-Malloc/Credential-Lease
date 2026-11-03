# Agent rules for Credential-Lease

## Boundary

This repository owns the contract the runtime side consumes: the handoff
document, the process-bound lease, the epoch revocation signal, and the
custody port (`credential-lease`). The contract crate itself performs no
custody.

Custody — system keyring access and persistence — lives in the
`credential-lease-keychain` backend crate: one OS-keychain surface every
host secret takes, platform-`cfg`-isolated and fail-closed where no
backend exists. Owner authorization still belongs to the host: prompts,
sessions, and revocation never enter this repository; the backend only
consumes an already-authorized native context.

Secret bytes never appear in any serialized inventory, configuration,
debug projection, or error output produced here.

## Verify

`scripts/verify.sh`

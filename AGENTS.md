# Agent rules for Credential-Lease

## Boundary

Custody — system keyring access, persistence, owner authorization —
belongs to the host and never enters this crate. This repository owns
the contract the runtime side consumes: the handoff document, the
process-bound lease, the epoch revocation signal, and the custody port.
Secret bytes never appear in any serialized inventory, configuration,
debug projection, or error output produced here.

## Verify

`scripts/verify.sh`

# Credential Handoff Contract

The handoff is the only serialized form that may carry secret material. It
travels from the unlocking process to exactly one runtime over a
process-local channel (for example an inherited file descriptor); it is
never written to disk. This document is the language-neutral specification:
the Rust crate is the reference implementation, and non-Rust custody owners
or runtimes implement this contract to interoperate.

## Document

```json
{
  "schemaVersion": "<family schema>",
  "leaseDurationSeconds": 3600,
  "epoch": "11111111-1111-4111-8111-111111111111",
  "credentials": [
    {
      "kind": "alpha",
      "keys": [
        {
          "credentialId": "22222222-2222-4222-8222-222222222222",
          "expiresAtEpochSeconds": null,
          "secret": [115, 101, 99, 114, 101, 116]
        }
      ]
    }
  ]
}
```

### Top-level fields

Closed set — any additional or missing field rejects the document.

| Field | Type | Rule |
| --- | --- | --- |
| `schemaVersion` | string | Must equal the family schema constant pinned by the kind family. A document minted under one family's schema must never parse as another family. |
| `leaseDurationSeconds` | unsigned integer | `1..=31622400` (366 days). The upper bound of the runtime lease minted from this handoff. |
| `epoch` | string | Canonical lowercase UUID; identifies the custody epoch this handoff was minted under. |
| `credentials` | array | Entries below; may be empty when a disconnected projection is serialized. |

### Credentials entry fields

Closed set — `kind`, `keys` only.

| Field | Type | Rule |
| --- | --- | --- |
| `kind` | string | Must resolve through the family's kind table. Unknown names reject the document. No two entries may share a kind. |
| `keys` | array | Nonempty. Every key below. |

### Key fields

Closed set — `credentialId`, `expiresAtEpochSeconds`, `secret` only.

| Field | Type | Rule |
| --- | --- | --- |
| `credentialId` | string | Canonical lowercase UUID, unique across the whole document (not only within one kind). |
| `expiresAtEpochSeconds` | unsigned integer or null | Required field; `null` means no storage expiry; when present must be `> 0`. |
| `secret` | array of integers | Each element `0..=255`; total length `1..=8192` bytes. Total key count across the document `<= 64`. |

## Failure semantics

Every malformed shape fails closed with a single indistinguishable
rejection — no partial credential set may ever be constructed from a
truncated or tampered document. Three contract rules apply before and
during parsing:

- **Size.** A serialized document is at most `2117632` bytes
  (`64 * (8192 * 4 + 192) + 8192`); larger inputs are refused before any
  parsing work begins, and producers refuse to emit above it.
- **Name bounds.** `schemaVersion` values are at most 128 bytes; `kind`
  names are at most 64 bytes. Larger values reject the document.
- **Duplicate member names.** Every object member name must be unique;
  a duplicate name rejects the whole document — the closed contract has
  no last-wins semantics.
- **Closed fields.** Only the fields listed above may appear, at every
  level.

## Lease semantics (runtime side)

A lease rebuilt from a handoff is process-bound and never survives process
exit. Two independent liveness checks apply on every use:

1. The lease's own duration — an `Instant`-relative upper bound minted at
   rebuild time.
2. The custody epoch — the runtime's epoch source is consulted on every
   resolution and must still report the handoff's epoch. An
   owner-initiated revocation rotates the epoch and kills every
   outstanding lease on its very next use; there is no cached
   authorization window.

Credentials past their own `expiresAtEpochSeconds` never resolve. Resolving
yields copies of secret material; the lease retains its own bytes.

## Portability notes

- Memory zeroization of secret material is a Rust implementation property
  (`SecretBytes` zeroizes on drop), not a contract term. Non-Rust
  implementations cannot portably guarantee erasure; the contract requires
  only that secrets never appear in inventories, configuration documents,
  debug projections, or command results.
- `Instant`-relative expiry is a process-local monotonic concept; non-Rust
  implementations use their runtime's monotonic clock.

## Family schemas

Each kind family pins its own `schemaVersion`. Known families:

| Family | Schema constant | Owner |
| --- | --- | --- |
| Contract test family | `test.credential-lease.handoff.v1` | this repository (tests) |

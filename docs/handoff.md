# Credential Handoff Contract

The handoff is the only serialized form that may carry secret material. It
travels from the unlocking process to exactly one runtime over a
process-local channel (for example an inherited file descriptor); it is
never written to disk. This document is the language-neutral specification:
the Rust crate is the reference implementation, and non-Rust custody owners
or runtimes implement this contract to interoperate.

## Transport

The document travels over exactly one process-local channel. In the Unix
model that channel is an inherited, read-only file descriptor named by the
`FAIRLINY_HANDOFF_FD` environment variable; the environment carries only the
descriptor number, never the document or any secret. See
[fd-handoff.md](fd-handoff.md) for the channel rules, the stable refusal
codes, and the executable Rust, Go, and TypeScript signature samples.

## Document

```json
{
  "schemaVersion": "<family schema>",
  "leaseDurationSeconds": 3600,
  "leaseExpiresAtEpochSeconds": 1780003600,
  "leaseMonotonicDeadlineSeconds": 10450,
  "epoch": "11111111-1111-4111-8111-111111111111",
  "egress": {
    "hosts": ["api.example.com", "*.example.org"],
    "ports": [443],
    "pathPrefixes": ["/v1/"],
    "methods": ["GET"],
    "headerTemplates": [
      {"name": "Authorization", "value": "Bearer {secret}"}
    ],
    "allowRedirects": false
  },
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
| `leaseDurationSeconds` | unsigned integer | `1..=31622400` (366 days). The upper bound of the runtime lease minted from this handoff. For a lease projection this is the grant's remaining time, not the original duration. The wire has no fractional seconds: a live remainder maps up to the next whole second, and `leaseExpiresAtEpochSeconds` still caps the rebuild so rounding up cannot extend the grant. |
| `leaseExpiresAtEpochSeconds` | unsigned integer | `> 0`. The deadline the grant ends at. A fresh owner grant stamps `now + leaseDurationSeconds` floored to whole seconds; a projection stamps the earlier of the deadline it received and its own lease expiry projected onto the wall clock. A rebuilt lease expires at the earlier of `leaseDurationSeconds` and this deadline, so chained projections can never extend the grant — only a fresh owner grant can. |
| `leaseMonotonicDeadlineSeconds` | unsigned integer | Optional; `> 0` when present. The same deadline expressed on the producing host's process-shared monotonic clock (Unix `CLOCK_MONOTONIC`), comparable only between processes on the same host. A producer stamps it when its platform exposes that clock and omits it where no such clock exists. A rebuild that can compare the clock requires the member and expires at the earliest of the wire duration, the wall deadline, and this deadline — a wall-clock rollback between projection and rebuild therefore cannot inflate the grant. A rebuild that cannot compare the clock refuses a document carrying the member, and a rebuild that can refuses one omitting it: clock continuity cannot be established either way. |
| `epoch` | string | Canonical lowercase UUID; identifies the custody epoch this handoff was minted under. |
| `egress` | object | Optional. The egress scope below; absent declares the deny-all scope — no outbound target is admitted. |
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

## Egress scope

The `egress` member is the custody owner's outbound boundary: a runtime
that forwards traffic — an HTTP proxy injecting leased credentials or a
TCP dialer gating connect calls — may move the leased material only to
targets the scope admits. It is fail-closed by construction: an absent
`egress` member denies every target, and nothing in the descriptor names
a particular provider or transport.

Closed member set — `hosts`, `ports`, `pathPrefixes`, `methods`,
`headerTemplates`, `allowRedirects` only. Every member is optional; each
list is at most 32 entries.

| Member | Type | Rule |
| --- | --- | --- |
| `hosts` | array of strings | Exact host names or `*.` suffix wildcards, each at most 253 bytes after lowercasing; labels are alphanumeric or hyphen. An empty or absent list admits no target — hosts are always required. |
| `ports` | array of unsigned integers | Each `1..=65535`. Empty or absent constrains nothing. |
| `pathPrefixes` | array of strings | Each nonempty, at most 512 bytes, starting with `/` and control-character free. Empty or absent constrains nothing. A target without a path never satisfies a declared prefix list. |
| `methods` | array of strings | HTTP method tokens, at most 64 bytes each. Empty or absent constrains nothing. A target without a method (a raw TCP dial) never satisfies a declared method list. Methods compare exactly. |
| `headerTemplates` | array of objects | `{"name", "value"}` only. `name` is an HTTP token at most 64 bytes; `value` is a template at most 512 bytes, control-character free. The `{secret}` marker is replaced with the resolved secret at injection time. |
| `allowRedirects` | boolean | `false` unless explicitly `true`: a redirect may never carry the credential to a target the scope did not name. |

Matching is conjunctive: a target is admitted only when its host fits one
declared pattern, and every other *declared* axis also matches. `*.`
patterns match subdomains of the suffix — never the apex itself — and
exact names never widen to subdomains. Host comparison is case-insensitive.

## Failure semantics

Every malformed shape fails closed with a single indistinguishable
rejection — no partial credential set may ever be constructed from a
truncated or tampered document. Three contract rules apply before and
during parsing:

- **Size.** A serialized document is at most `2229554` bytes
  (`64 * (8192 * 4 + 576) + 16384` for the head and credentials, plus
  `79154` for the largest admissible egress scope). The bound covers the
  worst case the inventory rules admit — including kind and schema names
  that escape to six bytes per name byte — so every well-formed inventory
  serializes within it. Larger inputs are refused before any parsing work
  begins.
- **Name bounds.** `schemaVersion` values are at most 128 bytes; `kind`
  names are at most 64 bytes. Larger values reject the document.
- **Duplicate member names.** Every object member name must be unique;
  a duplicate name rejects the whole document — the closed contract has
  no last-wins semantics.
- **Closed fields.** Only the fields listed above may appear, at every
  level.

## Lease semantics (runtime side)

A lease rebuilt from a handoff is process-bound and never survives process
exit. Three independent checks apply on every credential use:

1. Process identity — the lease records the OS process id that minted it
   and compares it with the current process on every resolution and
   handoff projection. A child forked with the lease in its inherited
   address space fails closed instead of replaying the parent's
   credentials.
2. The lease's own duration — an `Instant`-relative upper bound minted at
   rebuild time, capped by the document's `leaseExpiresAtEpochSeconds`
   deadline so the rebuilt lease cannot outlive the original grant. Where
   the document carries `leaseMonotonicDeadlineSeconds`, the rebuild is
   capped by that deadline on the same monotonic clock as well: the wall
   clock plays no part in the comparison, so a backward wall-clock step
   between projection and rebuild cannot stretch the grant. Both wire
   deadlines are then enforced in their own clock domains on every
   credential use — before and after the epoch consultation — not only
   at rebuild time, because the runtime clocks can diverge from each
   other across suspend in either direction: on Darwin `CLOCK_MONOTONIC`
   advances while the uptime clock `Instant` reads pauses, and on Linux
   both runtime clocks pause while the wall clock keeps running. A lease
   minted before sleep must still refuse once a wire deadline passed
   during sleep — the wall deadline guards the case where every
   monotonic-domain clock stopped. A platform that can compare the
   shared monotonic clock refuses a document that omits the member, and
   one that cannot refuses a document that carries it — the rebuild
   fails closed with `credential_lease_expiry_invalid` whenever clock
   continuity cannot be established. A failed read of the clock is a
   different answer from an absent clock: it refuses with
   `credential_lease_clock_unavailable` at mint, rebuild, and
   projection instead of masquerading as the platform truth that
   legitimately omits the member.
3. The custody epoch — the runtime's epoch source is consulted on every
   resolution and must still report the handoff's epoch. An
   owner-initiated revocation rotates the epoch and kills every
   outstanding lease on its very next use; there is no cached
   authorization window.

Credentials past their own `expiresAtEpochSeconds` never resolve. Resolving
yields copies of secret material; the lease retains its own bytes.

Projection back into a handoff is a credential use as well: it re-checks
all three conditions, so an expired or revoked lease cannot be re-minted
into a fresh handoff that restarts its lifetime. A lease carrying
`leaseMonotonicDeadlineSeconds` stamps the projected bound from a fresh
sample of that same clock; when the sample cannot be taken — a failed
read or no comparable clock — the projection refuses
`credential_lease_clock_unavailable` rather than carry a deadline
forward that a wall-clock rollback could stretch past the source grant.

The contract's runtime refusals are stable codes:

| Refusal | Meaning |
| --- | --- |
| `credential_lease_unavailable` | No credential of the requested kind is currently resolvable. |
| `credential_lease_expired` | The grant's lifetime has elapsed on any of its clock domains — the `Instant` expiry, the wall-clock deadline, or the shared monotonic deadline — checked both before and after the epoch consultation, so a slow epoch lookup can never release an expired grant. |
| `credential_lease_expiry_invalid` | The grant's deadline shape is malformed or its clock continuity cannot be established: a deadline at or before the epoch, a deadline of zero, or a monotonic deadline the rebuild cannot compare or must require but is absent. |
| `credential_lease_clock_invalid` | The wall clock cannot produce a usable reading (for example it precedes the Unix epoch). An operational failure, not an elapsed grant. |
| `credential_lease_clock_unavailable` | The shared monotonic clock exists but a read of it failed — at mint, rebuild, projection, or the in-domain deadline check on a lease that carries `leaseMonotonicDeadlineSeconds`. An operational failure, not an elapsed grant, and never silently treated as an absent clock. |
| `credential_lease_revoked` | The active epoch is absent or no longer matches the lease's epoch. |
| `credential_lease_process_mismatch` | The lease object is being used from a process other than the one that minted it. |

The process check governs this lease object. A fork still inherits the
address space, so secret buffers already copied into the child are outside
the lease's control; the check keeps the inherited lease itself from
resolving or projecting them.

### Host failure classification

Hosts that route recovery through the A4AA `failureClass` vocabulary — AwP
and Fairliny-Gateway both do — map the runtime refusals with
`credential_lease::failure::auth_failure_class` (re-exported at the crate
root). `credential_lease_unavailable`, `credential_lease_expired`, and
`credential_lease_revoked` all mean the credential is unusable and map to
`auth_expired`, so the host stops using it and requests a fresh authorized
handoff. Local integrity failures (`credential_lease_process_mismatch`) and
infrastructure failures (an unreadable epoch source, an unreadable clock, a
poisoned slot lock) return `None` and stay operational errors: a host must
not silently renew credentials across a broken boundary.

## Portability notes

- Memory zeroization of secret material is a Rust implementation property
  (`SecretBytes` and `HandoffDocument` zeroize on drop), not a contract
  term. Non-Rust implementations cannot portably guarantee erasure; the
  contract requires only that secrets never appear in inventories,
  configuration documents, debug projections, or command results.
- `Instant`-relative expiry is a process-local monotonic concept; non-Rust
  implementations use their runtime's monotonic clock.
- Process identity is the operating system's process id (or an equivalent
  unforgeable per-process identity). Implementations that cannot observe a
  process identity must fail closed rather than skip the check.

## Family schemas

Each kind family pins its own `schemaVersion`. Known families:

| Family | Schema constant | Owner |
| --- | --- | --- |
| Contract test family | `test.credential-lease.handoff.v1` | this repository (tests) |

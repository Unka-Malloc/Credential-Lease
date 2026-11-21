# Inherited-descriptor handoff channel

The handoff document is the only serialized form that may carry secret
material. Its transport is a process-local channel — in the Unix model, one
inherited, read-only file descriptor — and never a file, an argument, or an
environment value.

## Environment contract

The receiving process learns which descriptor to read from one variable:

| Variable | Value | Rule |
| --- | --- | --- |
| `FAIRLINY_HANDOFF_FD` | decimal integer | The number of an inherited read-only descriptor. Plain ASCII digits only; empty, signed, non-numeric, or out-of-range values are refused. |

The variable carries the descriptor **number** and nothing else. The document,
any credential, and any custody root key must never be placed in the
environment, in an argument, or in a file. A runtime that receives the
descriptor does not need the secret in its environment to resolve it.

Descriptor numbers below `3` are refused. Standard input, output, and error
are already open in every process, so a value below 3 cannot prove the host
explicitly granted the channel; refusing it keeps a missing or misspelled
setup from silently reading standard input as a handoff.

## Receiver behavior

1. Parse `FAIRLINY_HANDOFF_FD` as a plain decimal descriptor number.
2. Read the descriptor to end of file, refusing the document before the
   accumulated size can exceed `MAX_HANDOFF_DOC_BYTES` (2,229,554 bytes).
3. Close the descriptor once the read finishes — on the success path and on
   every refusal path.
4. Parse and validate under the closed document rules in
   [handoff.md](handoff.md). The document is secret-bearing, so the receiver
   reserves the accumulator to the bound before the first read — growth can
   never release an unscrubbed copy — and both the read scratch and the
   accumulated buffer zeroize on every exit path, before the parsed handoff
   takes ownership of its secrets.

The parent writes the document, closes its write end, and waits for the child
to finish. The child reads until end of file, closes its read end, rebuilds
its **own** process-bound lease (the process binding belongs to the child, not
the parent), and resolves through that lease. A one-way pipe is the intended
shape: the read end is not writable, so the receiver cannot send material
back through the handoff channel.

The receiver does not authenticate the writer. It trusts the host that
spawned it and granted the descriptor; access control belongs to that host.

### Refusal codes

| Refusal | Meaning |
| --- | --- |
| `credential_lease_handoff_fd_invalid` | `FAIRLINY_HANDOFF_FD` is not a plain decimal descriptor number, or names a number below 3. |
| `credential_lease_handoff_fd_unavailable` | The descriptor cannot be read: closed, unreadable, or interrupted by an error other than a retryable signal. |
| `credential_lease_handoff_invalid` | The document is oversized, truncated, non-UTF-8, or violates any closed-document rule. |

The codes are stable; implementations must not include descriptor contents,
document bytes, or OS error strings in them.

## Rust reference implementation

`credential_lease::handoff_fd` is the receiving half:

```rust
use credential_lease::handoff_fd::receive_handoff_from_env;

let handoff = receive_handoff_from_env::<Kind>()?.expect("descriptor is granted");
let lease = CredentialLease::from_handoff(handoff, epoch_source)?;
let secret = lease.resolve(kind)?;
```

`receive_handoff_from_env` returns `Ok(None)` when the variable is absent, so
a disconnected runtime can start and receive a handoff later through a slot.
`receive_handoff(descriptor)` is the same intake for a descriptor the host
already resolved.

The end-to-end parent/child test lives in
`crates/credential-lease/tests/fd_handoff.rs`: it spawns a real child process
over a one-way pipe, verifies the child resolves the same secret bytes, and
scans the parent and child environments for the secret and the document. It
also covers a non-numeric value, a standard-stream descriptor number, a closed
descriptor, a truncated document, and an oversized document.

## Rust / Go / TypeScript signature samples

The contract is language-neutral, so the interface signature is executable in
each language. The samples read `FAIRLINY_HANDOFF_FD`, apply the same size
bound and closed-document rules, and print only non-secret shape:

| Sample | Command |
| --- | --- |
| Rust (`crates/credential-lease/examples/validate_handoff.rs`) | `cargo build -q -p credential-lease --example validate_handoff`, then `target/debug/examples/validate_handoff` |
| Go (`samples/go/`) | `cd samples/go && go build -o validate .` |
| TypeScript (`samples/typescript/handoff.ts`) | `node --experimental-strip-types samples/typescript/handoff.ts` |

Invoke any of them with the vector on descriptor 3:

```sh
FAIRLINY_HANDOFF_FD=3 <sample> 3< samples/vectors/valid.json
# valid kinds=1
```

`samples/vectors/` holds the shared conformance set. The valid documents are
the base fixture, an expiry at the `u64` maximum, and a document carrying a
declared `egress` scope; every one carries the required
`leaseExpiresAtEpochSeconds` owner deadline. The invalid documents cover an
unknown field, a foreign schema, a malformed epoch, a zero duration, a
missing owner deadline, a zero owner deadline, an out-of-range secret byte,
a missing required field, a duplicate object member, trailing data after
the document, a decimal and an exponent duration literal (`60.0` / `6e1`),
a fractional secret byte, an expiry beyond `u64`, an egress member outside
the closed axis set, and an out-of-range egress port. A numeric member must
be a plain unsigned integer literal: JSON's number model alone would accept
`60.0` as the integer 60, so every sample validates the lexical form and
rejects it. Document refusals print `invalid` and exit `1`; channel
refusals print `refused <code>` and exit `2`.

`scripts/verify-samples.sh` builds and runs every available language against
every vector and requires identical verdicts. It skips a language whose
toolchain is absent rather than pretending it ran.

## Portability

Inherited descriptors are a Unix mechanism. Hosts on other platforms use their
native process-local handle-passing mechanism with the same two rules: the
environment names the handle but never carries the document, and the receiving
side closes the handle after one bounded read. Implementations that cannot
pass a handle process-locally must fail closed instead of falling back to an
environment value or a file.

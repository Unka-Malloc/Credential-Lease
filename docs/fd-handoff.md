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
2. Verify the descriptor's access mode is read-only before the first
   read: the grant is a one-way channel, so a descriptor that permits
   writing — a read-write socket end, a write-only end — is refused as
   `credential_lease_handoff_fd_invalid` even where its read side would
   supply a valid document.
3. Claim the descriptor close-on-exec before the first read: a descendant
   exec'd while the document is still arriving can never inherit the read
   end, so the secret-bearing channel cannot escape past intake.
4. Read the descriptor to end of file, refusing the document before the
   accumulated size can exceed `MAX_HANDOFF_DOC_BYTES` (2,229,554 bytes).
5. Close the descriptor once the read finishes — on the success path and on
   every refusal path.
6. Parse and validate under the closed document rules in
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

## Descendant processes

Intake consumes the channel but never removes the variable — environment
mutation is not synchronized with readers outside the process — so a process
that took its handoff still carries the consumed descriptor number. A
descendant spawned with the default inherited environment then sees
`FAIRLINY_HANDOFF_FD` under a fresh latch, naming a descriptor that was
never granted to it: at best it refuses the closed number as
`credential_lease_handoff_fd_unavailable`; worse, the OS may have reassigned
the number and the descendant would read a descriptor meant for something
else.

The grant rule therefore applies at every exec, not only the first spawn:
a spawner either hands the child a matching descriptor and sets the
variable to its number, or removes the variable from the child's
environment (`env -u`, `Command::env_remove`, or an explicit environment
list). A runtime that spawns further processes with no handoff for them
must clear the variable instead of letting the inherited value through.

Removing the variable alone was never the whole protection: a descriptor
stays inheritable until intake claims it, and a child exec'd inside that
window would carry the read end regardless of its environment. Intake
therefore marks the descriptor close-on-exec at the claim, before the
first read — a descendant spawned afterwards can never inherit the
channel. The ordering obligation sits with startup: a receiving process
must run intake before spawning any child the grant does not cover, so
no ungranted exec can happen while the descriptor is still inheritable.

### Refusal codes

| Refusal | Meaning |
| --- | --- |
| `credential_lease_handoff_fd_invalid` | `FAIRLINY_HANDOFF_FD` is not a plain decimal descriptor number, names a number below 3, or the descriptor's access mode is not read-only. |
| `credential_lease_handoff_fd_unavailable` | The descriptor cannot be read: closed, unreadable, or interrupted by an error other than a retryable signal. |
| `credential_lease_handoff_invalid` | The document is oversized, truncated, non-UTF-8, or violates any closed-document rule. |

The codes are stable; implementations must not include descriptor contents,
document bytes, or OS error strings in them.

## Rust reference implementation

`credential_lease::handoff_fd` is the receiving half:

```rust
use credential_lease::handoff_fd::receive_handoff_from_env;

// SAFETY: the spawn contract grants this process exclusive ownership of
// the descriptor the variable names.
let handoff =
    unsafe { receive_handoff_from_env::<Kind>() }?.expect("descriptor is granted");
let lease = CredentialLease::from_handoff(handoff, epoch_source)?;
let secret = lease.resolve(kind)?;
```

`receive_handoff_from_env` returns `Ok(None)` when the variable is absent, so
a disconnected runtime can start and receive a handoff later through a slot.
Environment intake is one-time: the first call claims the channel through a
process-local latch before the descriptor is touched — the environment itself
is never mutated — so concurrent callers can never both take the descriptor,
and a later call can never act on a descriptor number the OS may have
reassigned since the first intake closed it. The parsed number is checked
against an actually open descriptor before it is claimed as owned: a closed
number is refused as `credential_lease_handoff_fd_unavailable` without ever
being treated as an owned descriptor.

The probe proves the number is open — never who owns it — so
`receive_handoff_from_env` is `unsafe`: the caller asserts the spawn
contract, that the named descriptor is exclusively owned by this process
and may be claimed, read, and closed. A number another component still
owns is a contract violation the function cannot detect; closing under it
would corrupt that component's channel. A host that resolved the
descriptor itself calls `receive_handoff(owned_fd)` — the safe intake —
which takes an `OwnedFd`, not a borrowed `RawFd`, so ownership transfer is
explicit and the receiver never closes a descriptor the caller still owns.

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
| Rust (`crates/credential-lease/examples/validate_handoff.rs`) | `cargo build -q -p credential-lease --example validate_handoff`, then the executable path the build reports (`target/debug/examples/validate_handoff` under the default target directory) |
| Go (`samples/go/`) | `cd samples/go && go build -o validate .` |
| TypeScript (`samples/typescript/handoff.ts`) | `node --experimental-strip-types samples/typescript/handoff.ts` |

Invoke any of them with the vector on descriptor 3:

```sh
FAIRLINY_HANDOFF_FD=3 <sample> 3< samples/vectors/valid.json
# valid kinds=1
```

`samples/vectors/` holds the shared conformance set. The valid documents are
the base fixture, an expiry at the `u64` maximum, a document carrying a
declared `egress` scope, and a document carrying the optional
`leaseMonotonicDeadlineSeconds` same-host anchor; every one carries the
required `leaseExpiresAtEpochSeconds` owner deadline. The invalid documents
cover an unknown field, a foreign schema, a malformed epoch, a zero
duration, a missing owner deadline, a zero owner deadline, a zero
monotonic deadline, an out-of-range secret byte,
a missing required field, a duplicate object member, trailing data after
the document, a decimal and an exponent duration literal (`60.0` / `6e1`),
a fractional secret byte, an expiry beyond `u64`, an egress member outside
the closed axis set, and an out-of-range egress port. A numeric member must
be a plain unsigned integer literal: JSON's number model alone would accept
`60.0` as the integer 60, so every sample validates the lexical form and
rejects it. Document refusals print `invalid` and exit `1`; channel
refusals print `refused <code>` and exit `2`.

`scripts/verify-samples.sh` builds and runs every available language against
every vector and requires identical verdicts — on the channel refusal cases
too: an absent or malformed variable, a standard-stream number, a closed
descriptor, and a write-capable channel all answer the same refusal in every
language. The socket cases go further: a socket end is refused without the
check ever writing to it, and the peer end is observed to prove the refusal
delivered nothing. It skips a language whose toolchain is absent rather
than pretending it ran.

## Portability

Inherited descriptors are a Unix mechanism. Hosts on other platforms use their
native process-local handle-passing mechanism with the same two rules: the
environment names the handle but never carries the document, and the receiving
side closes the handle after one bounded read. Implementations that cannot
pass a handle process-locally must fail closed instead of falling back to an
environment value or a file.

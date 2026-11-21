#!/usr/bin/env bash
# Cross-language conformance for the handoff interface signature: the Rust
# reference implementation, the Go sample and the TypeScript sample must reach
# the same verdict on every shared vector while reading the document from
# FAIRLINY_HANDOFF_FD.
#
# The samples only report shape (`valid kinds=N` / `invalid`); no vector's
# secret bytes may appear in any output.
set -euo pipefail

cd "$(dirname "$0")/.."
root="$PWD"
vectors="$root/samples/vectors"
checks=0
failures=0

# The executable path comes from this build's own artifact report, so a
# relocated target directory (CARGO_TARGET_DIR, build.target-dir) can
# never point the runner at a missing or stale binary. The report is
# decoded as JSON — a text-level extraction would truncate an escaped
# quote in the path and leave a backslash unexpanded.
if ! command -v jq >/dev/null 2>&1; then
  echo "FAIL samples: jq is required to decode Cargo's JSON artifact report" >&2
  exit 1
fi
rust_sample="$(cargo build --quiet --message-format=json \
  -p credential-lease --example validate_handoff \
  | jq -r 'select(.reason == "compiler-artifact"
      and .target.name == "validate_handoff"
      and (.target.kind | index("example") != null))
      | .executable // empty' | tail -n 1)"
if [ ! -x "$rust_sample" ]; then
  echo "FAIL samples: cargo build did not produce a validate_handoff executable" >&2
  exit 1
fi

go_sample=""
if command -v go >/dev/null 2>&1; then
  mkdir -p "$root/target/samples"
  (
    cd "$root/samples/go"
    GOCACHE="${GOCACHE:-$root/target/go-cache}" GOPROXY=off \
      go build -o "$root/target/samples/go-validate" .
  )
  go_sample="$root/target/samples/go-validate"
else
  echo "SKIP go sample: go toolchain not found"
fi

ts_command=()
if command -v node >/dev/null 2>&1; then
  probe_dir="$(mktemp -d)"
  printf 'const probe: number = 1;\n' > "$probe_dir/probe.ts"
  if node --experimental-strip-types "$probe_dir/probe.ts" >/dev/null 2>&1; then
    ts_command=(node --experimental-strip-types)
  elif node "$probe_dir/probe.ts" >/dev/null 2>&1; then
    ts_command=(node)
  else
    echo "SKIP typescript sample: node cannot strip TypeScript types"
  fi
  rm -rf "$probe_dir"
else
  echo "SKIP typescript sample: node not found"
fi

# A freshly linked locally-built executable sits in Apple System Policy's
# assessment queue on macOS; while the verdict is pending the kernel
# answers every exec of that file with SIGKILL (status 137). Under host
# load the queue can outlast the whole check loop. Run each built binary
# once until the verdict lands — any exit other than 137 proves exec is
# allowed and lets the checks below judge conformance themselves.
warm_sample() {
  local label="$1" binary="$2" deadline status
  deadline=$((SECONDS + 300))
  while :; do
    if env -u FAIRLINY_HANDOFF_FD "$binary" 200<&- >/dev/null 2>&1; then
      status=0
    else
      status=$?
    fi
    [ "$status" -ne 137 ] && return 0
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "FAIL samples: $label sample exec denied by system policy" >&2
      exit 1
    fi
    sleep 2
  done
}
warm_sample rust "$rust_sample"
[ -n "$go_sample" ] && warm_sample go "$go_sample"

check() {
  # language, vector, expected exit status, expected output, command...
  local language="$1"
  local vector="$2"
  local expected_status="$3"
  local expected_output="$4"
  shift 4
  if [ "$#" -eq 0 ]; then
    return 0
  fi
  checks=$((checks + 1))
  local output
  local status
  if output=$(FAIRLINY_HANDOFF_FD=3 "$@" 3<"$vector" 2>/dev/null); then
    status=0
  else
    status=$?
  fi
  if [ "$status" -ne "$expected_status" ] || [ "$output" != "$expected_output" ]; then
    echo "FAIL $language $(basename "$vector"): status=$status output=$output (expected $expected_status/$expected_output)"
    failures=$((failures + 1))
  fi
}

check_all() {
  local vector="$1"
  local expected_status="$2"
  local expected_output="$3"
  check rust "$vector" "$expected_status" "$expected_output" "$rust_sample"
  if [ -n "$go_sample" ]; then
    check go "$vector" "$expected_status" "$expected_output" "$go_sample"
  fi
  if [ "${#ts_command[@]}" -gt 0 ]; then
    check typescript "$vector" "$expected_status" "$expected_output" \
      "${ts_command[@]}" "$root/samples/typescript/handoff.ts"
  fi
}

check_channel() {
  # language, variable spec ("ABSENT" or a value), expected status,
  # expected output, command...
  local language="$1"
  local spec="$2"
  local expected_status="$3"
  local expected_output="$4"
  shift 4
  if [ "$#" -eq 0 ]; then
    return 0
  fi
  checks=$((checks + 1))
  local output
  local status
  if [ "$spec" = "ABSENT" ]; then
    if output=$(env -u FAIRLINY_HANDOFF_FD "$@" 200<&- 2>/dev/null); then
      status=0
    else
      status=$?
    fi
  else
    if output=$(FAIRLINY_HANDOFF_FD="$spec" "$@" 200<&- 2>/dev/null); then
      status=0
    else
      status=$?
    fi
  fi
  if [ "$status" -ne "$expected_status" ] || [ "$output" != "$expected_output" ]; then
    echo "FAIL $language fd=$spec: status=$status output=$output (expected $expected_status/$expected_output)"
    failures=$((failures + 1))
  fi
}

check_channel_all() {
  local spec="$1"
  local expected_status="$2"
  local expected_output="$3"
  check_channel rust "$spec" "$expected_status" "$expected_output" "$rust_sample"
  if [ -n "$go_sample" ]; then
    check_channel go "$spec" "$expected_status" "$expected_output" "$go_sample"
  fi
  if [ "${#ts_command[@]}" -gt 0 ]; then
    check_channel typescript "$spec" "$expected_status" "$expected_output" \
      "${ts_command[@]}" "$root/samples/typescript/handoff.ts"
  fi
}

check_writable_channel() {
  # language, open mode ("RDWR" over the valid vector or "WRONLY" to
  # /dev/null), expected status, expected output, command...
  local language="$1"
  local mode="$2"
  local expected_status="$3"
  local expected_output="$4"
  shift 4
  if [ "$#" -eq 0 ]; then
    return 0
  fi
  checks=$((checks + 1))
  local output
  local status
  # The channel is write-capable: the access-mode check must refuse it as
  # fd_invalid before the first read, even where — read-write over the
  # real valid vector — the bytes behind the descriptor would pass.
  if [ "$mode" = "RDWR" ]; then
    if output=$(FAIRLINY_HANDOFF_FD=3 "$@" 3<>"$vectors/valid.json" 2>/dev/null); then
      status=0
    else
      status=$?
    fi
  else
    if output=$(FAIRLINY_HANDOFF_FD=3 "$@" 3>/dev/null 2>/dev/null); then
      status=0
    else
      status=$?
    fi
  fi
  if [ "$status" -ne "$expected_status" ] || [ "$output" != "$expected_output" ]; then
    echo "FAIL $language channel=$mode: status=$status output=$output (expected $expected_status/$expected_output)"
    failures=$((failures + 1))
  fi
}

check_writable_channel_all() {
  local mode="$1"
  local expected_status="$2"
  local expected_output="$3"
  check_writable_channel rust "$mode" "$expected_status" "$expected_output" "$rust_sample"
  if [ -n "$go_sample" ]; then
    check_writable_channel go "$mode" "$expected_status" "$expected_output" "$go_sample"
  fi
  if [ "${#ts_command[@]}" -gt 0 ]; then
    check_writable_channel typescript "$mode" "$expected_status" "$expected_output" \
      "${ts_command[@]}" "$root/samples/typescript/handoff.ts"
  fi
}

for vector in "$vectors"/*.json; do
  case "$(basename "$vector")" in
    valid.json | valid-*.json)
      expected_status=0
      expected_output="valid kinds=1"
      ;;
    *)
      expected_status=1
      expected_output="invalid"
      ;;
  esac
  check_all "$vector" "$expected_status" "$expected_output"
done

# A document over the contract bound is a document refusal, not a channel
# failure. Generate it so the repository does not carry a 2 MiB vector.
oversized="$root/target/samples/oversized-document.json"
mkdir -p "$root/target/samples"
dd if=/dev/zero of="$oversized" bs=1024 count=2178 2>/dev/null
check_all "$oversized" 1 invalid

# Channel verdicts must agree too: an absent variable, a malformed value, a
# standard-stream number and a granted-but-unreadable descriptor each get
# the same refusal from every language.
check_channel_all "ABSENT" 2 "refused credential_lease_handoff_fd_missing"
check_channel_all "not-a-descriptor" 2 "refused credential_lease_handoff_fd_invalid"
check_channel_all "2" 2 "refused credential_lease_handoff_fd_invalid"
check_channel_all "200" 2 "refused credential_lease_handoff_fd_unavailable"

# A write-capable channel is refused before the first read even where the
# document behind it is valid: read-write over the real vector, and
# write-only to /dev/null, each get the same refusal from every language.
check_writable_channel_all "RDWR" 2 "refused credential_lease_handoff_fd_invalid"
check_writable_channel_all "WRONLY" 2 "refused credential_lease_handoff_fd_invalid"

if [ "$checks" -eq 0 ]; then
  echo "FAIL samples: no language sample ran" >&2
  exit 1
fi

if [ "$failures" -ne 0 ]; then
  echo "FAIL samples: $failures of $checks checks failed" >&2
  exit 1
fi

echo "samples: $checks checks passed (Rust, Go, TypeScript)"

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

cargo build --quiet -p credential-lease --example validate_handoff
rust_sample="$root/target/debug/examples/validate_handoff"

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

if [ "$checks" -eq 0 ]; then
  echo "FAIL samples: no language sample ran" >&2
  exit 1
fi

if [ "$failures" -ne 0 ]; then
  echo "FAIL samples: $failures of $checks checks failed" >&2
  exit 1
fi

echo "samples: $checks checks passed (Rust, Go, TypeScript)"

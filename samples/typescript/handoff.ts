// Language sample: receive a handoff over FAIRLINY_HANDOFF_FD, validate the
// closed document contract, and report only non-secret shape.
//
// This is the TypeScript half of the Rust/Go/TypeScript interface-signature
// samples. It uses the standard library only:
//
//	node --experimental-strip-types handoff.ts < document.json
//	FAIRLINY_HANDOFF_FD=3 node --experimental-strip-types handoff.ts 3< document.json
//
// Duplicate object member names are refused at every level, matching the Rust
// reference implementation rather than JSON's usual last-wins behaviour.

import { closeSync, readSync } from "node:fs";

const HANDOFF_FD_ENV = "FAIRLINY_HANDOFF_FD";
const MAX_DOCUMENT_BYTES = 2229554;
const MAX_LEASE_SECONDS = 31622400n;
const MAX_SECRET_BYTES = 8192;
const MAX_KEYS = 64;
const MAX_SCHEMA_BYTES = 128;
const MAX_KIND_BYTES = 64;
const MAX_DEPTH = 64;
// The egress scope axes and their per-axis bounds.
const MAX_EGRESS_MATCHERS = 32;
const MAX_EGRESS_HOST_BYTES = 253;
const MAX_EGRESS_PREFIX_BYTES = 512;
const MAX_EGRESS_TOKEN_BYTES = 64;
const MAX_EGRESS_TEMPLATE_BYTES = 512;
// The Rust reference implementation reads every numeric member as a `u64`;
// the Go sample parses the same lexical integer with `strconv.ParseUint`.
const MAX_U64 = 18446744073709551615n;
const MAX_U64_DIGITS = 20;
// A descriptor is the platform's signed raw descriptor value; a decimal
// number outside that range is a malformed channel, not an unavailable one.
const MAX_HANDOFF_DESCRIPTOR = 2147483647;
// The contract test family schema pinned by the reference vectors.
const SAMPLE_SCHEMA = "test.credential-lease.handoff.v1";
// The only kind in this sample's host-supplied kind table.
const SAMPLE_KIND = "api";
const CANONICAL_UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

type Json = null | boolean | string | bigint | Json[] | { [key: string]: Json };

class Rejected extends Error {}

class StrictParser {
  text: string;
  index: number;

  constructor(text: string) {
    this.text = text;
    this.index = 0;
  }

  parse(): Json {
    const value = this.value(0);
    this.whitespace();
    if (this.index !== this.text.length) {
      throw new Rejected();
    }
    return value;
  }

  whitespace(): void {
    while (this.index < this.text.length) {
      const character = this.text[this.index];
      if (
        character !== " " &&
        character !== "\t" &&
        character !== "\n" &&
        character !== "\r"
      ) {
        return;
      }
      this.index += 1;
    }
  }

  value(depth: number): Json {
    if (depth > MAX_DEPTH) {
      throw new Rejected();
    }
    this.whitespace();
    const character = this.text[this.index];
    if (character === "{") {
      return this.object(depth + 1);
    }
    if (character === "[") {
      return this.array(depth + 1);
    }
    if (character === '"') {
      return this.string();
    }
    if (character === "t") {
      return this.literal("true", true);
    }
    if (character === "f") {
      return this.literal("false", false);
    }
    if (character === "n") {
      return this.literal("null", null);
    }
    if (character === "-" || (character >= "0" && character <= "9")) {
      return this.number();
    }
    throw new Rejected();
  }

  literal<T>(word: string, value: T): T {
    if (!this.text.startsWith(word, this.index)) {
      throw new Rejected();
    }
    this.index += word.length;
    return value;
  }

  number(): bigint {
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(
      this.text.slice(this.index),
    );
    if (match === null) {
      throw new Rejected();
    }
    const token = match[0];
    this.index += token.length;
    // Every numeric member in the closed document contract is an unsigned
    // integer. A decimal or exponent token (`60.0`, `6e1`) denotes a
    // floating-point literal even when its value is integral, and the Rust
    // reference implementation and Go sample refuse it. Reject by lexeme so
    // JSON's number model cannot silently turn it into integer 60.
    if (
      token.startsWith("-") ||
      token.includes(".") ||
      token.includes("e") ||
      token.includes("E")
    ) {
      throw new Rejected();
    }
    if (token.length > MAX_U64_DIGITS) {
      throw new Rejected();
    }
    const parsed = BigInt(token);
    if (parsed > MAX_U64) {
      throw new Rejected();
    }
    return parsed;
  }

  string(): string {
    const start = this.index;
    this.index += 1;
    while (this.index < this.text.length) {
      const character = this.text[this.index];
      if (character === "\\") {
        this.index += 2;
        continue;
      }
      if (character === '"') {
        this.index += 1;
        const decoded = JSON.parse(this.text.slice(start, this.index)) as string;
        for (const part of decoded) {
          const code = part.codePointAt(0);
          if (code !== undefined && code >= 0xd800 && code <= 0xdfff) {
            throw new Rejected();
          }
        }
        return decoded;
      }
      if (character.charCodeAt(0) < 0x20) {
        throw new Rejected();
      }
      this.index += 1;
    }
    throw new Rejected();
  }

  object(depth: number): { [key: string]: Json } {
    const object: { [key: string]: Json } = Object.create(null);
    this.index += 1;
    this.whitespace();
    if (this.text[this.index] === "}") {
      this.index += 1;
      return object;
    }
    for (;;) {
      this.whitespace();
      if (this.text[this.index] !== '"') {
        throw new Rejected();
      }
      const key = this.string();
      this.whitespace();
      if (this.text[this.index] !== ":") {
        throw new Rejected();
      }
      this.index += 1;
      const value = this.value(depth);
      if (Object.prototype.hasOwnProperty.call(object, key)) {
        throw new Rejected();
      }
      object[key] = value;
      this.whitespace();
      const separator = this.text[this.index];
      this.index += 1;
      if (separator === "}") {
        return object;
      }
      if (separator !== ",") {
        throw new Rejected();
      }
    }
  }

  array(depth: number): Json[] {
    const array: Json[] = [];
    this.index += 1;
    this.whitespace();
    if (this.text[this.index] === "]") {
      this.index += 1;
      return array;
    }
    for (;;) {
      array.push(this.value(depth));
      this.whitespace();
      const separator = this.text[this.index];
      this.index += 1;
      if (separator === "]") {
        return array;
      }
      if (separator !== ",") {
        throw new Rejected();
      }
    }
  }
}

function exactFields(value: Json, names: string[]): Record<string, Json> {
  return closedFields(value, names, []);
}

function closedFields(
  value: Json,
  required: string[],
  optional: string[],
): Record<string, Json> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Rejected();
  }
  const object = value as Record<string, Json>;
  const allowed = new Set([...required, ...optional]);
  for (const name of Object.keys(object)) {
    if (!allowed.has(name)) {
      throw new Rejected();
    }
  }
  for (const name of required) {
    if (!Object.prototype.hasOwnProperty.call(object, name)) {
      throw new Rejected();
    }
  }
  return object;
}

function isHttpToken(value: string): boolean {
  if (value.length === 0) {
    return false;
  }
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    const alphanumeric =
      (code >= 0x30 && code <= 0x39) ||
      (code >= 0x41 && code <= 0x5a) ||
      (code >= 0x61 && code <= 0x7a);
    if (!alphanumeric && !"!#$%&'*+-.^_`|~".includes(character)) {
      return false;
    }
  }
  return true;
}

function isHeaderValue(value: string): boolean {
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) {
      return false;
    }
  }
  return true;
}

function isHostPattern(value: string): boolean {
  if (value.length === 0 || Buffer.byteLength(value) > MAX_EGRESS_HOST_BYTES) {
    return false;
  }
  const normalized = value.toLowerCase();
  const name = normalized.startsWith("*.")
    ? normalized.slice(2)
    : normalized;
  if (name.length === 0 || name.includes("*")) {
    return false;
  }
  for (const label of name.split(".")) {
    if (
      label.length === 0 ||
      label.startsWith("-") ||
      label.endsWith("-") ||
      !/^[a-z0-9-]+$/.test(label)
    ) {
      return false;
    }
  }
  return true;
}

function matcherList(object: Record<string, Json>, name: string): Json[] {
  const raw = object[name];
  if (raw === undefined) {
    return [];
  }
  if (!Array.isArray(raw) || raw.length > MAX_EGRESS_MATCHERS) {
    throw new Rejected();
  }
  return raw;
}

function validateEgress(value: Json): void {
  const top = closedFields(
    value,
    [],
    [
      "hosts",
      "ports",
      "pathPrefixes",
      "methods",
      "headerTemplates",
      "allowRedirects",
    ],
  );
  for (const raw of matcherList(top, "hosts")) {
    if (typeof raw !== "string" || !isHostPattern(raw)) {
      throw new Rejected();
    }
  }
  for (const raw of matcherList(top, "ports")) {
    const port = unsigned(raw);
    if (port === undefined || port === 0n || port > 65535n) {
      throw new Rejected();
    }
  }
  for (const raw of matcherList(top, "pathPrefixes")) {
    if (
      typeof raw !== "string" ||
      Buffer.byteLength(raw) > MAX_EGRESS_PREFIX_BYTES ||
      !raw.startsWith("/") ||
      !isHeaderValue(raw)
    ) {
      throw new Rejected();
    }
  }
  for (const raw of matcherList(top, "methods")) {
    if (
      typeof raw !== "string" ||
      Buffer.byteLength(raw) > MAX_EGRESS_TOKEN_BYTES ||
      !isHttpToken(raw)
    ) {
      throw new Rejected();
    }
  }
  for (const raw of matcherList(top, "headerTemplates")) {
    const template = exactFields(raw, ["name", "value"]);
    const name = template["name"];
    if (
      typeof name !== "string" ||
      Buffer.byteLength(name) > MAX_EGRESS_TOKEN_BYTES ||
      !isHttpToken(name)
    ) {
      throw new Rejected();
    }
    const templateValue = template["value"];
    if (
      typeof templateValue !== "string" ||
      Buffer.byteLength(templateValue) > MAX_EGRESS_TEMPLATE_BYTES ||
      !isHeaderValue(templateValue)
    ) {
      throw new Rejected();
    }
  }
  const redirects = top["allowRedirects"];
  if (redirects !== undefined && typeof redirects !== "boolean") {
    throw new Rejected();
  }
}

function unsigned(value: Json | undefined): bigint | undefined {
  if (typeof value !== "bigint" || value < 0n) {
    return undefined;
  }
  return value;
}

function validate(document: Json): number {
  const top = closedFields(
    document,
    [
      "schemaVersion",
      "leaseDurationSeconds",
      "leaseExpiresAtEpochSeconds",
      "epoch",
      "credentials",
    ],
    ["egress"],
  );
  const schema = top["schemaVersion"];
  if (
    typeof schema !== "string" ||
    schema.length > MAX_SCHEMA_BYTES ||
    schema !== SAMPLE_SCHEMA
  ) {
    throw new Rejected();
  }
  const duration = unsigned(top["leaseDurationSeconds"]);
  if (duration === undefined || duration < 1n || duration > MAX_LEASE_SECONDS) {
    throw new Rejected();
  }
  const deadline = unsigned(top["leaseExpiresAtEpochSeconds"]);
  if (deadline === undefined || deadline === 0n) {
    throw new Rejected();
  }
  if (top["egress"] !== undefined) {
    validateEgress(top["egress"]);
  }
  const epoch = top["epoch"];
  if (typeof epoch !== "string" || !CANONICAL_UUID.test(epoch)) {
    throw new Rejected();
  }
  const entries = top["credentials"];
  if (!Array.isArray(entries)) {
    throw new Rejected();
  }
  let kinds = 0;
  let totalKeys = 0;
  const seenKinds = new Set<string>();
  const seenIds = new Set<string>();
  for (const rawEntry of entries) {
    const entry = exactFields(rawEntry, ["kind", "keys"]);
    const kind = entry["kind"];
    if (
      typeof kind !== "string" ||
      kind.length > MAX_KIND_BYTES ||
      kind !== SAMPLE_KIND ||
      seenKinds.has(kind)
    ) {
      throw new Rejected();
    }
    seenKinds.add(kind);
    const keys = entry["keys"];
    if (!Array.isArray(keys) || keys.length === 0) {
      throw new Rejected();
    }
    for (const rawKey of keys) {
      const key = exactFields(rawKey, [
        "credentialId",
        "expiresAtEpochSeconds",
        "secret",
      ]);
      const credentialId = key["credentialId"];
      if (
        typeof credentialId !== "string" ||
        !CANONICAL_UUID.test(credentialId) ||
        seenIds.has(credentialId)
      ) {
        throw new Rejected();
      }
      seenIds.add(credentialId);
      const expires = key["expiresAtEpochSeconds"];
      if (expires !== null) {
        const seconds = unsigned(expires);
        if (seconds === undefined || seconds === 0n) {
          throw new Rejected();
        }
      }
      const secret = key["secret"];
      if (
        !Array.isArray(secret) ||
        secret.length === 0 ||
        secret.length > MAX_SECRET_BYTES
      ) {
        throw new Rejected();
      }
      for (const rawByte of secret) {
        const byte = unsigned(rawByte);
        if (byte === undefined || byte > 255n) {
          throw new Rejected();
        }
      }
      totalKeys += 1;
    }
    kinds += 1;
  }
  if (totalKeys > MAX_KEYS) {
    throw new Rejected();
  }
  return kinds;
}

function handoffDescriptor(): number | undefined {
  const raw = process.env[HANDOFF_FD_ENV];
  if (raw === undefined || !/^[0-9]{1,10}$/.test(raw)) {
    return undefined;
  }
  const descriptor = Number(raw);
  if (
    !Number.isSafeInteger(descriptor) ||
    descriptor < 3 ||
    descriptor > MAX_HANDOFF_DESCRIPTOR
  ) {
    return undefined;
  }
  return descriptor;
}

function readDocument(descriptor: number): Buffer {
  const chunks: Buffer[] = [];
  let total = 0;
  const buffer = Buffer.alloc(16 * 1024);
  try {
    for (;;) {
      const read = readSync(descriptor, buffer, 0, buffer.length, null);
      if (read === 0) {
        break;
      }
      total += read;
      if (total > MAX_DOCUMENT_BYTES) {
        throw new Rejected();
      }
      chunks.push(Buffer.from(buffer.subarray(0, read)));
    }
  } finally {
    closeSync(descriptor);
  }
  return Buffer.concat(chunks);
}

function main(): number {
  const descriptor = handoffDescriptor();
  if (descriptor === undefined) {
    console.log("refused credential_lease_handoff_fd_invalid");
    return 2;
  }
  let bytes: Buffer;
  try {
    bytes = readDocument(descriptor);
  } catch (error) {
    // A document over the contract bound is a document refusal, not a
    // channel failure: it must print `invalid` and exit 1 like the Rust and
    // Go samples. Only the descriptor read itself is a channel refusal.
    if (error instanceof Rejected) {
      console.log("invalid");
      return 1;
    }
    console.log("refused credential_lease_handoff_fd_unavailable");
    return 2;
  }
  let document: Json;
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    document = new StrictParser(text).parse();
  } catch {
    console.log("invalid");
    return 1;
  }
  let kinds: number;
  try {
    kinds = validate(document);
  } catch {
    console.log("invalid");
    return 1;
  }
  console.log(`valid kinds=${kinds}`);
  return 0;
}

process.exitCode = main();

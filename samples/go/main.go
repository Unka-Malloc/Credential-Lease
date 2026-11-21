// Language sample: receive a handoff over FAIRLINY_HANDOFF_FD, validate the
// closed document contract, and report only non-secret shape.
//
// This is the Go half of the Rust/Go/TypeScript interface-signature samples.
// It intentionally uses only the standard library, so it can be built and
// run offline:
//
//	go build -o validate .
//	FAIRLINY_HANDOFF_FD=3 ./validate 3< document.json
//
// It agrees with the Rust reference implementation and the TypeScript sample
// on every shared conformance vector, including duplicate object member names.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	handoffFDEnv     = "FAIRLINY_HANDOFF_FD"
	maxDocumentBytes = 2229554
	maxLeaseSeconds  = 31622400
	maxSecretBytes   = 8192
	maxKeys          = 64
	maxSchemaBytes   = 128
	maxKindBytes     = 64
	maxDepth         = 64
	// The egress scope axes and their per-axis bounds.
	maxEgressMatchers      = 32
	maxEgressHostBytes     = 253
	maxEgressPrefixBytes   = 512
	maxEgressTokenBytes    = 64
	maxEgressTemplateBytes = 512
	// A descriptor is the platform's signed raw descriptor value; a decimal
	// number outside that range is a malformed channel, not an unavailable one.
	maxHandoffDescriptor = 1<<31 - 1
	// The contract test family schema pinned by the reference vectors.
	sampleSchema = "test.credential-lease.handoff.v1"
	// The only kind in this sample's host-supplied kind table.
	sampleKind = "api"
)

var (
	errInvalid     = errors.New("invalid document")
	canonicalUUID  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	osExit         = os.Exit
	standardOutput = os.Stdout
)

func main() {
	osExit(run())
}

func run() int {
	fd, refusal := handoffDescriptor()
	if refusal != "" {
		fmt.Fprintln(standardOutput, "refused "+refusal)
		return 2
	}
	document, err := readDocument(fd)
	if err != nil {
		if errors.Is(err, errInvalid) {
			fmt.Fprintln(standardOutput, "invalid")
			return 1
		}
		fmt.Fprintln(standardOutput, "refused credential_lease_handoff_fd_unavailable")
		return 2
	}
	parsed, err := parseDocument(document)
	if err != nil {
		fmt.Fprintln(standardOutput, "invalid")
		return 1
	}
	kinds, err := validate(parsed)
	if err != nil {
		fmt.Fprintln(standardOutput, "invalid")
		return 1
	}
	fmt.Fprintf(standardOutput, "valid kinds=%d\n", kinds)
	return 0
}

// handoffDescriptor accepts a plain decimal descriptor number at or above 3;
// standard streams are never a valid handoff channel. An absent variable is
// its own refusal — credential_lease_handoff_fd_missing — distinct from a
// present but malformed value.
func handoffDescriptor() (descriptor int, refusal string) {
	raw, present := os.LookupEnv(handoffFDEnv)
	if !present {
		return 0, "credential_lease_handoff_fd_missing"
	}
	if raw == "" || len(raw) > 10 {
		return 0, "credential_lease_handoff_fd_invalid"
	}
	for _, character := range raw {
		if character < '0' || character > '9' {
			return 0, "credential_lease_handoff_fd_invalid"
		}
	}
	descriptor, err := strconv.Atoi(raw)
	if err != nil || descriptor < 3 || descriptor > maxHandoffDescriptor {
		return 0, "credential_lease_handoff_fd_invalid"
	}
	return descriptor, ""
}

func readDocument(descriptor int) ([]byte, error) {
	file := os.NewFile(uintptr(descriptor), handoffFDEnv)
	if file == nil {
		return nil, errors.New("descriptor unavailable")
	}
	defer file.Close()
	var document []byte
	buffer := make([]byte, 16*1024)
	for {
		read, err := file.Read(buffer)
		if read > 0 {
			if len(document)+read > maxDocumentBytes {
				return nil, errInvalid
			}
			document = append(document, buffer[:read]...)
		}
		if errors.Is(err, io.EOF) {
			return document, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func validate(document any) (int, error) {
	top, err := closedFields(document,
		[]string{"schemaVersion", "leaseDurationSeconds", "leaseExpiresAtEpochSeconds", "epoch", "credentials"},
		[]string{"egress"})
	if err != nil {
		return 0, err
	}
	schema, ok := top["schemaVersion"].(string)
	if !ok || len(schema) > maxSchemaBytes || schema != sampleSchema {
		return 0, errInvalid
	}
	duration, ok := unsigned(top["leaseDurationSeconds"])
	if !ok || duration < 1 || duration > maxLeaseSeconds {
		return 0, errInvalid
	}
	deadline, ok := unsigned(top["leaseExpiresAtEpochSeconds"])
	if !ok || deadline == 0 {
		return 0, errInvalid
	}
	if rawEgress, present := top["egress"]; present {
		if err := validateEgress(rawEgress); err != nil {
			return 0, err
		}
	}
	epoch, ok := top["epoch"].(string)
	if !ok || !canonicalUUID.MatchString(epoch) {
		return 0, errInvalid
	}
	entries, ok := top["credentials"].([]any)
	if !ok {
		return 0, errInvalid
	}
	kinds := 0
	totalKeys := 0
	seenKinds := map[string]bool{}
	seenIDs := map[string]bool{}
	for _, rawEntry := range entries {
		entry, err := exactFields(rawEntry, "kind", "keys")
		if err != nil {
			return 0, err
		}
		kind, ok := entry["kind"].(string)
		if !ok || len(kind) > maxKindBytes || kind != sampleKind || seenKinds[kind] {
			return 0, errInvalid
		}
		seenKinds[kind] = true
		keys, ok := entry["keys"].([]any)
		if !ok || len(keys) == 0 {
			return 0, errInvalid
		}
		for _, rawKey := range keys {
			key, err := exactFields(rawKey, "credentialId", "expiresAtEpochSeconds", "secret")
			if err != nil {
				return 0, err
			}
			credentialID, ok := key["credentialId"].(string)
			if !ok || !canonicalUUID.MatchString(credentialID) || seenIDs[credentialID] {
				return 0, errInvalid
			}
			seenIDs[credentialID] = true
			if expires, present := key["expiresAtEpochSeconds"]; present && expires != nil {
				seconds, ok := unsigned(expires)
				if !ok || seconds == 0 {
					return 0, errInvalid
				}
			}
			secret, ok := key["secret"].([]any)
			if !ok || len(secret) == 0 || len(secret) > maxSecretBytes {
				return 0, errInvalid
			}
			for _, rawByte := range secret {
				value, ok := unsigned(rawByte)
				if !ok || value > 255 {
					return 0, errInvalid
				}
			}
			totalKeys++
		}
		kinds++
	}
	if totalKeys > maxKeys {
		return 0, errInvalid
	}
	return kinds, nil
}

// exactFields enforces the contract's closed field sets: every member must be
// named, no member may be missing, and no extra member may appear.
func exactFields(value any, names ...string) (map[string]any, error) {
	return closedFields(value, names, nil)
}

// closedFields enforces a closed object shape: every required member must be
// present, no member outside the required and optional names may appear, and
// the value must be an object at all.
func closedFields(value any, required, optional []string) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errInvalid
	}
	allowed := make(map[string]bool, len(required)+len(optional))
	for _, name := range required {
		allowed[name] = true
		if _, present := object[name]; !present {
			return nil, errInvalid
		}
	}
	for _, name := range optional {
		allowed[name] = true
	}
	for name := range object {
		if !allowed[name] {
			return nil, errInvalid
		}
	}
	return object, nil
}

// validateEgress applies the closed `egress` member rules: a bounded object
// whose optional matcher axes each carry their own type, count and content
// limits. An absent axis constrains nothing; an absent `egress` member is
// handled by the caller.
func validateEgress(value any) error {
	top, err := closedFields(value, nil,
		[]string{"hosts", "ports", "pathPrefixes", "methods", "headerTemplates", "allowRedirects"})
	if err != nil {
		return err
	}
	if raw, present := top["hosts"]; present {
		hosts, ok := raw.([]any)
		if !ok || len(hosts) > maxEgressMatchers {
			return errInvalid
		}
		for _, item := range hosts {
			host, ok := item.(string)
			if !ok || !isHostPattern(host) {
				return errInvalid
			}
		}
	}
	if raw, present := top["ports"]; present {
		ports, ok := raw.([]any)
		if !ok || len(ports) > maxEgressMatchers {
			return errInvalid
		}
		for _, item := range ports {
			port, ok := unsigned(item)
			if !ok || port == 0 || port > 65535 {
				return errInvalid
			}
		}
	}
	if raw, present := top["pathPrefixes"]; present {
		prefixes, ok := raw.([]any)
		if !ok || len(prefixes) > maxEgressMatchers {
			return errInvalid
		}
		for _, item := range prefixes {
			prefix, ok := item.(string)
			if !ok || len(prefix) > maxEgressPrefixBytes || !strings.HasPrefix(prefix, "/") ||
				!isHeaderValue(prefix) {
				return errInvalid
			}
		}
	}
	if raw, present := top["methods"]; present {
		methods, ok := raw.([]any)
		if !ok || len(methods) > maxEgressMatchers {
			return errInvalid
		}
		for _, item := range methods {
			method, ok := item.(string)
			if !ok || len(method) > maxEgressTokenBytes || !isHTTPToken(method) {
				return errInvalid
			}
		}
	}
	if raw, present := top["headerTemplates"]; present {
		templates, ok := raw.([]any)
		if !ok || len(templates) > maxEgressMatchers {
			return errInvalid
		}
		for _, item := range templates {
			template, err := exactFields(item, "name", "value")
			if err != nil {
				return err
			}
			name, ok := template["name"].(string)
			if !ok || len(name) > maxEgressTokenBytes || !isHTTPToken(name) {
				return errInvalid
			}
			templateValue, ok := template["value"].(string)
			if !ok || len(templateValue) > maxEgressTemplateBytes || !isHeaderValue(templateValue) {
				return errInvalid
			}
		}
	}
	if raw, present := top["allowRedirects"]; present {
		if _, ok := raw.(bool); !ok {
			return errInvalid
		}
	}
	return nil
}

// isHostPattern reports whether value is an exact host name or a single
// `*.` suffix wildcard with DNS labels, matching the Rust egress contract:
// lowercased, at most 253 bytes, and never a bare `*` or a partial wildcard.
func isHostPattern(value string) bool {
	if value == "" || len(value) > maxEgressHostBytes {
		return false
	}
	// The label rules are ASCII: non-ASCII input must be refused on the
	// original bytes — a Unicode-aware lowercase can fold some characters
	// (for example U+212A KELVIN SIGN) into ASCII and carry them past the
	// label check the Rust contract applies.
	for i := 0; i < len(value); i++ {
		if value[i] > 0x7f {
			return false
		}
	}
	normalized := strings.ToLower(value)
	name := strings.TrimPrefix(normalized, "*.")
	if name == "" || strings.Contains(name, "*") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for i := 0; i < len(label); i++ {
			character := label[i]
			if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
				return false
			}
		}
	}
	return true
}

// isHTTPToken reports whether value is an RFC 9110 `token` — the shape HTTP
// methods and header names must have.
func isHTTPToken(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		character := value[i]
		switch {
		case character >= '0' && character <= '9',
			character >= 'A' && character <= 'Z',
			character >= 'a' && character <= 'z':
		default:
			switch character {
			case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			default:
				return false
			}
		}
	}
	return true
}

// isHeaderValue reports whether value can safely occupy an HTTP field value:
// no control characters and no DEL, so a template or rendered value can never
// split into a second header line.
func isHeaderValue(value string) bool {
	for _, character := range value {
		if character < ' ' || character == 0x7f {
			return false
		}
	}
	return true
}

func unsigned(value any) (uint64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.ParseUint(number.String(), 10, 64)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

// parseDocument builds a strict JSON tree. Duplicate object member names are
// refused at every level, matching the reference implementation's closed
// contract rather than JSON's usual last-wins behaviour.
func parseDocument(data []byte) (any, error) {
	// Go's decoder silently repairs malformed Unicode: invalid UTF-8 and an
	// unpaired \u surrogate escape both decode as U+FFFD. The contract refuses
	// both, so the raw bytes are validated before the decoder can replace
	// them — matching the Rust and TypeScript implementations.
	if !validJSONText(data) {
		return nil, errInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := parseValue(decoder, 0)
	if err != nil {
		return nil, errInvalid
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errInvalid
	}
	return value, nil
}

func parseValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > maxDepth {
		return nil, errInvalid
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return token, nil
	}
	switch delimiter {
	case '{':
		return parseObject(decoder, depth+1)
	case '[':
		return parseArray(decoder, depth+1)
	default:
		return nil, errInvalid
	}
}

func parseObject(decoder *json.Decoder, depth int) (map[string]any, error) {
	object := map[string]any{}
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, errInvalid
		}
		if _, duplicate := object[key]; duplicate {
			return nil, errInvalid
		}
		value, err := parseValue(decoder, depth)
		if err != nil {
			return nil, err
		}
		object[key] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	return object, nil
}

func parseArray(decoder *json.Decoder, depth int) ([]any, error) {
	array := []any{}
	for decoder.More() {
		value, err := parseValue(decoder, depth)
		if err != nil {
			return nil, err
		}
		array = append(array, value)
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	return array, nil
}

// validJSONText enforces the two Unicode rules Go's decoder relaxes: the
// document must be valid UTF-8, and a \u escape inside a string must not
// carry an unpaired surrogate — both of which the decoder would otherwise
// replace with U+FFFD. Escapes the scanner skips over (a truncated or
// non-hex \u, a stray backslash) are left for the decoder itself to refuse.
func validJSONText(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	inString := false
	for index := 0; index < len(data); index++ {
		if !inString {
			if data[index] == '"' {
				inString = true
			}
			continue
		}
		if data[index] == '"' {
			inString = false
			continue
		}
		if data[index] != '\\' {
			continue
		}
		if index+1 >= len(data) {
			return true
		}
		if data[index+1] != 'u' {
			index++
			continue
		}
		if index+6 > len(data) {
			return true
		}
		code, ok := hex4(data[index+2 : index+6])
		if !ok {
			index += 5
			continue
		}
		index += 5
		switch {
		case code >= 0xd800 && code <= 0xdbff:
			// A high surrogate is valid only immediately paired with a low
			// surrogate escape. The full second escape must be present
			// before any of it is read — a truncated tail must refuse, not
			// slice past the input's end.
			if index+7 > len(data) || data[index+1] != '\\' || data[index+2] != 'u' {
				return false
			}
			low, ok := hex4(data[index+3 : index+7])
			if !ok || low < 0xdc00 || low > 0xdfff {
				return false
			}
			index += 6
		case code >= 0xdc00 && code <= 0xdfff:
			return false
		}
	}
	return true
}

// hex4 reads exactly four hexadecimal digits as a UTF-16 code unit.
func hex4(digits []byte) (uint32, bool) {
	var value uint32
	for _, digit := range digits {
		value <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			value += uint32(digit - '0')
		case digit >= 'a' && digit <= 'f':
			value += uint32(digit-'a') + 10
		case digit >= 'A' && digit <= 'F':
			value += uint32(digit-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

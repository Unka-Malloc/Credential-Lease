//! The egress scope descriptor a handoff carries for outbound channels.
//!
//! A runtime that forwards traffic — an HTTP proxy injecting leased
//! credentials or a TCP dialer gating connect calls — may move credential
//! material only to targets the custody owner declared at mint time. The
//! scope is fail-closed by construction:
//!
//! - A handoff that declares no `egress` member carries the deny-all
//!   scope: no host pattern exists, so [`EgressScope::permits`] refuses
//!   every target.
//! - A matcher list left undeclared constrains nothing on its own axis —
//!   hosts are always required, while ports, methods and path prefixes
//!   are opt-in precision the caller adds only as needed.
//! - `allow_redirects` is `false` unless the owner explicitly enabled it,
//!   so a redirect can never carry credentials somewhere the scope did
//!   not name.
//!
//! Nothing in the descriptor names a particular provider or transport:
//! hosts, ports, path prefixes, methods and header templates are all
//! caller-declared match shapes.

use crate::handoff::{decimal_digits, escaped_len, push_json_string};
use crate::SecretBytes;
use anyhow::{anyhow, ensure, Result};
use serde::de::{Error as DeError, MapAccess, SeqAccess, Visitor};
use std::collections::BTreeSet;
use std::fmt;

/// The largest matcher list one axis may declare.
pub const MAX_EGRESS_MATCHERS: usize = 32;

/// The largest host pattern, covering a full DNS name.
pub const MAX_EGRESS_HOST_BYTES: usize = 253;

/// The largest path prefix a scope may carry.
pub const MAX_EGRESS_PREFIX_BYTES: usize = 512;

/// The largest wire token: an HTTP method or header name.
pub const MAX_EGRESS_TOKEN_BYTES: usize = 64;

/// The largest header value template.
pub const MAX_EGRESS_TEMPLATE_BYTES: usize = 512;

/// The marker a header template substitutes with the resolved secret at
/// injection time.
pub const SECRET_PLACEHOLDER: &str = "{secret}";

/// Worst-case serialized size of the `egress` member, counted into
/// [`crate::handoff::MAX_HANDOFF_DOC_BYTES`]. Escapable strings are priced
/// at twice their byte length.
pub(crate) const MAX_EGRESS_DOC_BYTES: usize = 128
    + MAX_EGRESS_MATCHERS * (MAX_EGRESS_HOST_BYTES + 3)
    + MAX_EGRESS_MATCHERS * 7
    + MAX_EGRESS_MATCHERS * (2 * MAX_EGRESS_PREFIX_BYTES + 3)
    + MAX_EGRESS_MATCHERS * (MAX_EGRESS_TOKEN_BYTES + 3)
    + MAX_EGRESS_MATCHERS * (MAX_EGRESS_TOKEN_BYTES + 2 * MAX_EGRESS_TEMPLATE_BYTES + 24)
    + 18;

/// Whether `value` is an HTTP field-name or method token — the RFC 9110
/// `token` production, used for declared methods and header names.
fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            matches!(byte,
                b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
                | b'^' | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z')
        })
}

/// Whether `value` can safely occupy an HTTP field value: no control
/// characters and no DEL, so a template or rendered value can never split
/// into a second header line.
fn is_header_value(value: &str) -> bool {
    value.chars().all(|c| c >= ' ' && c != '\u{7f}')
}

/// Lowercase `value` and confirm it is an exact host name or a single
/// `*.` suffix wildcard. Anything else — a bare `*`, a port, a path, an
/// empty label — is refused so the matcher set stays precise.
fn normalize_host_pattern(value: &str) -> Result<String> {
    ensure!(
        !value.is_empty() && value.len() <= MAX_EGRESS_HOST_BYTES,
        "credential_lease_egress_invalid"
    );
    let normalized = value.to_ascii_lowercase();
    let name = normalized.strip_prefix("*.").unwrap_or(&normalized);
    ensure!(
        !name.is_empty() && !name.contains('*'),
        "credential_lease_egress_invalid"
    );
    for label in name.split('.') {
        ensure!(
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-'),
            "credential_lease_egress_invalid"
        );
    }
    Ok(normalized)
}

/// Whether a normalized pattern admits `host`, which the caller has
/// already lowercased and stripped of any trailing root dot. A `*.`
/// pattern matches subdomains of its suffix — never the suffix itself.
fn host_matches(pattern: &str, host: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(suffix) => host
            .strip_suffix(suffix)
            .is_some_and(|head| head.ends_with('.')),
        None => host == pattern,
    }
}

/// One header a runtime injects on in-scope requests. The value template
/// carries the [`SECRET_PLACEHOLDER`] marker wherever the resolved secret
/// belongs; surrounding text is literal.
#[derive(Clone, Eq, PartialEq)]
pub struct HeaderTemplate {
    name: String,
    value_template: String,
}

impl HeaderTemplate {
    /// Declare a header. The name must be an HTTP token; the template is
    /// bounded and must be header-safe (no control characters), whether or
    /// not it contains the secret marker.
    pub fn new(name: String, value_template: String) -> Result<Self> {
        ensure!(
            name.len() <= MAX_EGRESS_TOKEN_BYTES && is_http_token(&name),
            "credential_lease_egress_invalid"
        );
        ensure!(
            value_template.len() <= MAX_EGRESS_TEMPLATE_BYTES && is_header_value(&value_template),
            "credential_lease_egress_invalid"
        );
        Ok(Self {
            name,
            value_template,
        })
    }

    /// The header name the runtime sets.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The value template as declared, markers unreplaced.
    pub fn value_template(&self) -> &str {
        &self.value_template
    }

    /// Render the template with a resolved secret: every marker is
    /// replaced and the result is re-checked as header-safe, so a secret
    /// containing CR/LF fails closed instead of injecting extra headers.
    /// A non-UTF-8 secret is refused with its own stable code.
    pub fn render(&self, secret: &SecretBytes) -> Result<String> {
        let rendered = self.value_template.replace(
            SECRET_PLACEHOLDER,
            secret.expose_utf8().map_err(|error| anyhow!("{error}"))?,
        );
        ensure!(
            is_header_value(&rendered),
            "credential_lease_egress_invalid"
        );
        Ok(rendered)
    }
}

impl fmt::Debug for HeaderTemplate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeaderTemplate")
            .field("name", &self.name)
            .field("value", &"[redacted]")
            .finish()
    }
}

/// A target an outbound channel intends to reach.
pub struct EgressTarget<'a> {
    host: &'a str,
    port: u16,
    method: Option<&'a str>,
    path: Option<&'a str>,
}

impl<'a> EgressTarget<'a> {
    /// A raw connect target — a TCP dial carries no method or path, so a
    /// scope that declares either matcher can never admit it.
    pub fn connect(host: &'a str, port: u16) -> Self {
        Self {
            host,
            port,
            method: None,
            path: None,
        }
    }

    /// An HTTP request target.
    pub fn http(host: &'a str, port: u16, method: &'a str, path: &'a str) -> Self {
        Self {
            host,
            port,
            method: Some(method),
            path: Some(path),
        }
    }
}

/// The egress scope the custody owner granted with a handoff.
///
/// Matching is conjunctive: a target is admitted only when its host fits
/// one declared pattern, its port is in the declared set, its method is in
/// the declared set, and its path starts with one declared prefix — each
/// axis enforced only when the owner declared it. No host patterns means
/// no target is ever admitted.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct EgressScope {
    hosts: BTreeSet<String>,
    ports: BTreeSet<u16>,
    path_prefixes: Vec<String>,
    methods: BTreeSet<String>,
    header_templates: Vec<HeaderTemplate>,
    allow_redirects: bool,
}

impl EgressScope {
    /// The scope a handoff carries when it declares no `egress` member:
    /// no host pattern exists, so every target is refused and redirects
    /// are off.
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Declare a scope. Every axis is caller-supplied and validated;
    /// malformed patterns are refused with `credential_lease_egress_invalid`
    /// rather than coerced.
    pub fn new(
        hosts: Vec<String>,
        ports: Vec<u16>,
        path_prefixes: Vec<String>,
        methods: Vec<String>,
        header_templates: Vec<HeaderTemplate>,
        allow_redirects: bool,
    ) -> Result<Self> {
        ensure!(
            hosts.len() <= MAX_EGRESS_MATCHERS
                && ports.len() <= MAX_EGRESS_MATCHERS
                && path_prefixes.len() <= MAX_EGRESS_MATCHERS
                && methods.len() <= MAX_EGRESS_MATCHERS
                && header_templates.len() <= MAX_EGRESS_MATCHERS,
            "credential_lease_egress_invalid"
        );
        let hosts = hosts
            .iter()
            .map(|host| normalize_host_pattern(host))
            .collect::<Result<BTreeSet<_>>>()?;
        ensure!(
            ports.iter().all(|port| *port > 0),
            "credential_lease_egress_invalid"
        );
        let ports: BTreeSet<u16> = ports.into_iter().collect();
        for prefix in &path_prefixes {
            ensure!(
                prefix.len() <= MAX_EGRESS_PREFIX_BYTES
                    && prefix.starts_with('/')
                    && is_header_value(prefix),
                "credential_lease_egress_invalid"
            );
        }
        let methods = methods
            .into_iter()
            .map(|method| {
                ensure!(
                    method.len() <= MAX_EGRESS_TOKEN_BYTES && is_http_token(&method),
                    "credential_lease_egress_invalid"
                );
                Ok(method)
            })
            .collect::<Result<BTreeSet<_>>>()?;
        Ok(Self {
            hosts,
            ports,
            path_prefixes,
            methods,
            header_templates,
            allow_redirects,
        })
    }

    /// Whether the scope admits `target`. All declared axes must match;
    /// an undeclared axis constrains nothing, but a scope with no host
    /// patterns refuses every target.
    pub fn permits(&self, target: &EgressTarget<'_>) -> bool {
        if self.hosts.is_empty() {
            return false;
        }
        let host = target.host.to_ascii_lowercase();
        let host = host.strip_suffix('.').unwrap_or(&host);
        self.hosts.iter().any(|pattern| host_matches(pattern, host))
            && (self.ports.is_empty() || self.ports.contains(&target.port))
            && (self.methods.is_empty()
                || target
                    .method
                    .is_some_and(|method| self.methods.contains(method)))
            && (self.path_prefixes.is_empty()
                || target.path.is_some_and(|path| {
                    self.path_prefixes
                        .iter()
                        .any(|prefix| path.starts_with(prefix.as_str()))
                }))
    }

    /// Whether the owner allowed credential-bearing redirects. `false`
    /// unless `allow_redirects` was explicitly enabled — an admitted
    /// target is the only place the credential may land.
    pub fn allow_redirects(&self) -> bool {
        self.allow_redirects
    }

    /// Whether the scope admits no target at all — no host pattern was
    /// declared, so `permits` is false for everything.
    pub fn is_deny_all(&self) -> bool {
        self.hosts.is_empty()
    }

    /// The declared host patterns, normalized lowercase, in sorted order.
    pub fn hosts(&self) -> impl Iterator<Item = &str> + '_ {
        self.hosts.iter().map(String::as_str)
    }

    /// The declared port set.
    pub fn ports(&self) -> impl Iterator<Item = u16> + '_ {
        self.ports.iter().copied()
    }

    /// The declared path prefixes, in declaration order.
    pub fn path_prefixes(&self) -> &[String] {
        &self.path_prefixes
    }

    /// The declared HTTP methods, in sorted order.
    pub fn methods(&self) -> impl Iterator<Item = &str> + '_ {
        self.methods.iter().map(String::as_str)
    }

    /// The declared header injection templates, in declaration order.
    pub fn header_templates(&self) -> &[HeaderTemplate] {
        &self.header_templates
    }

    /// Emit the `egress` member's object body — `{...}` including braces —
    /// using the handoff document's shared JSON writer.
    pub(crate) fn write_json(&self, buffer: &mut String) {
        buffer.push_str("{\"hosts\":[");
        for (index, host) in self.hosts.iter().enumerate() {
            if index > 0 {
                buffer.push(',');
            }
            push_json_string(buffer, host);
        }
        buffer.push_str("],\"ports\":[");
        for (index, port) in self.ports.iter().enumerate() {
            if index > 0 {
                buffer.push(',');
            }
            buffer.push_str(&port.to_string());
        }
        buffer.push_str("],\"pathPrefixes\":[");
        for (index, prefix) in self.path_prefixes.iter().enumerate() {
            if index > 0 {
                buffer.push(',');
            }
            push_json_string(buffer, prefix);
        }
        buffer.push_str("],\"methods\":[");
        for (index, method) in self.methods.iter().enumerate() {
            if index > 0 {
                buffer.push(',');
            }
            push_json_string(buffer, method);
        }
        buffer.push_str("],\"headerTemplates\":[");
        for (index, template) in self.header_templates.iter().enumerate() {
            if index > 0 {
                buffer.push(',');
            }
            buffer.push_str("{\"name\":");
            push_json_string(buffer, template.name());
            buffer.push_str(",\"value\":");
            push_json_string(buffer, template.value_template());
            buffer.push('}');
        }
        buffer.push_str("],\"allowRedirects\":");
        buffer.push_str(if self.allow_redirects {
            "true"
        } else {
            "false"
        });
        buffer.push('}');
    }

    /// An upper bound on the member's serialized length, counted into the
    /// handoff document's pre-allocation so the buffer never grows while
    /// secrets are being written.
    pub(crate) fn serialized_len_upper_bound(&self) -> usize {
        let mut length = 128 + 5;
        for host in &self.hosts {
            length += escaped_len(host) + 1;
        }
        for port in &self.ports {
            length += decimal_digits(u64::from(*port)) + 1;
        }
        for prefix in &self.path_prefixes {
            length += escaped_len(prefix) + 1;
        }
        for method in &self.methods {
            length += escaped_len(method) + 1;
        }
        for template in &self.header_templates {
            length += 25 + escaped_len(template.name()) + escaped_len(template.value_template());
        }
        length
    }
}

/// The `egress` member read under the document's closed-field rules:
/// typed and bounded while it is read, with no intermediate value tree.
/// Every member is optional; absent matcher lists constrain nothing and
/// an absent `allowRedirects` is `false`. The scope carries no secret
/// material; the bounded-visitor discipline still applies so an over-long
/// matcher list can never materialize the allocation it claims.
pub(crate) struct WireEgress(pub EgressScope);

impl<'de> serde::Deserialize<'de> for WireEgress {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(EgressVisitor)
    }
}

fn duplicate_member<E: DeError>() -> E {
    DeError::custom("duplicate member name")
}

fn missing_member<E: DeError>() -> E {
    DeError::custom("missing required member")
}

struct EgressVisitor;

impl<'de> Visitor<'de> for EgressVisitor {
    type Value = WireEgress;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a closed egress scope object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut hosts: Option<Vec<String>> = None;
        let mut ports: Option<Vec<u16>> = None;
        let mut path_prefixes: Option<Vec<String>> = None;
        let mut methods: Option<Vec<String>> = None;
        let mut header_templates: Option<Vec<HeaderTemplate>> = None;
        let mut allow_redirects: Option<bool> = None;
        while let Some(field) = access.next_key::<String>()? {
            match field.as_str() {
                "hosts" => {
                    if hosts.is_some() {
                        return Err(duplicate_member());
                    }
                    hosts = Some(access.next_value::<BoundedStrings>()?.0);
                }
                "ports" => {
                    if ports.is_some() {
                        return Err(duplicate_member());
                    }
                    ports = Some(access.next_value::<BoundedPorts>()?.0);
                }
                "pathPrefixes" => {
                    if path_prefixes.is_some() {
                        return Err(duplicate_member());
                    }
                    path_prefixes = Some(access.next_value::<BoundedStrings>()?.0);
                }
                "methods" => {
                    if methods.is_some() {
                        return Err(duplicate_member());
                    }
                    methods = Some(access.next_value::<BoundedStrings>()?.0);
                }
                "headerTemplates" => {
                    if header_templates.is_some() {
                        return Err(duplicate_member());
                    }
                    header_templates = Some(
                        access
                            .next_value::<BoundedTemplates>()?
                            .0
                            .into_iter()
                            .map(|template| template.0)
                            .collect(),
                    );
                }
                "allowRedirects" => {
                    if allow_redirects.is_some() {
                        return Err(duplicate_member());
                    }
                    allow_redirects = Some(access.next_value::<bool>()?);
                }
                _ => return Err(DeError::custom("unknown member name")),
            }
        }
        EgressScope::new(
            hosts.unwrap_or_default(),
            ports.unwrap_or_default(),
            path_prefixes.unwrap_or_default(),
            methods.unwrap_or_default(),
            header_templates.unwrap_or_default(),
            allow_redirects.unwrap_or(false),
        )
        .map(WireEgress)
        .map_err(|_| DeError::custom("invalid egress scope"))
    }
}

/// A string matcher list read straight into a bounded vector: the count
/// limit is enforced while reading, so an over-long declared list never
/// materializes its claimed allocation.
struct BoundedStrings(Vec<String>);

impl<'de> serde::Deserialize<'de> for BoundedStrings {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_seq(BoundedStringsVisitor)
    }
}

struct BoundedStringsVisitor;

impl<'de> Visitor<'de> for BoundedStringsVisitor {
    type Value = BoundedStrings;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded matcher string list")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = access.next_element::<String>()? {
            if items.len() >= MAX_EGRESS_MATCHERS {
                return Err(DeError::custom("too many egress matchers"));
            }
            items.push(item);
        }
        Ok(BoundedStrings(items))
    }
}

/// The port list, bounded like every other matcher axis.
struct BoundedPorts(Vec<u16>);

impl<'de> serde::Deserialize<'de> for BoundedPorts {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_seq(BoundedPortsVisitor)
    }
}

struct BoundedPortsVisitor;

impl<'de> Visitor<'de> for BoundedPortsVisitor {
    type Value = BoundedPorts;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded port list")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = access.next_element::<u16>()? {
            if items.len() >= MAX_EGRESS_MATCHERS {
                return Err(DeError::custom("too many egress matchers"));
            }
            items.push(item);
        }
        Ok(BoundedPorts(items))
    }
}

/// The header template list, bounded like every other matcher axis.
struct BoundedTemplates(Vec<WireHeaderTemplate>);

impl<'de> serde::Deserialize<'de> for BoundedTemplates {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_seq(BoundedTemplatesVisitor)
    }
}

struct BoundedTemplatesVisitor;

impl<'de> Visitor<'de> for BoundedTemplatesVisitor {
    type Value = BoundedTemplates;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded header template list")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = access.next_element::<WireHeaderTemplate>()? {
            if items.len() >= MAX_EGRESS_MATCHERS {
                return Err(DeError::custom("too many egress matchers"));
            }
            items.push(item);
        }
        Ok(BoundedTemplates(items))
    }
}

/// One header template: the closed `name`/`value` object, both members
/// required exactly once.
struct WireHeaderTemplate(HeaderTemplate);

impl<'de> serde::Deserialize<'de> for WireHeaderTemplate {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(WireHeaderTemplateVisitor)
    }
}

struct WireHeaderTemplateVisitor;

impl<'de> Visitor<'de> for WireHeaderTemplateVisitor {
    type Value = WireHeaderTemplate;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a closed header template object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut name: Option<String> = None;
        let mut value: Option<String> = None;
        while let Some(field) = access.next_key::<String>()? {
            match field.as_str() {
                "name" => {
                    if name.is_some() {
                        return Err(duplicate_member());
                    }
                    name = Some(access.next_value::<String>()?);
                }
                "value" => {
                    if value.is_some() {
                        return Err(duplicate_member());
                    }
                    value = Some(access.next_value::<String>()?);
                }
                _ => return Err(DeError::custom("unknown member name")),
            }
        }
        HeaderTemplate::new(
            name.ok_or_else(missing_member)?,
            value.ok_or_else(missing_member)?,
        )
        .map(WireHeaderTemplate)
        .map_err(|_| DeError::custom("invalid header template"))
    }
}

impl fmt::Debug for EgressScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Matcher counts only: templates could embed caller literals, so
        // the scope's Debug never echoes declared strings.
        formatter
            .debug_struct("EgressScope")
            .field("hosts", &self.hosts.len())
            .field("ports", &self.ports.len())
            .field("path_prefixes", &self.path_prefixes.len())
            .field("methods", &self.methods.len())
            .field("header_templates", &self.header_templates.len())
            .field("allow_redirects", &self.allow_redirects)
            .finish()
    }
}

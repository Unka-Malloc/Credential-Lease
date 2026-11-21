//! Consumer-facing behavior: a handoff carries the custody-declared egress
//! scope. An undeclared scope fails closed on every outbound target and
//! `allow_redirects` stays off; a declared scope admits only targets that
//! satisfy every axis the owner declared, for HTTP and raw TCP alike.

use anyhow::Result;
use credential_lease::credential::LeasedCredential;
use credential_lease::egress::{EgressScope, EgressTarget, HeaderTemplate, MAX_EGRESS_MATCHERS};
use credential_lease::epoch::LeaseEpochSource;
use credential_lease::handoff::CredentialHandoff;
use credential_lease::kind::CredentialKind;
use credential_lease::lease::CredentialLease;
use credential_lease::SecretBytes;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Kind {
    Api,
}

impl CredentialKind for Kind {
    const HANDOFF_SCHEMA: &'static str = "test.credential-lease.handoff.v1";

    fn as_str(self) -> &'static str {
        "api"
    }

    fn from_str(value: &str) -> Option<Self> {
        (value == "api").then_some(Self::Api)
    }
}

struct FixedEpoch(String);

impl LeaseEpochSource for FixedEpoch {
    fn active_epoch(&self) -> Result<Option<String>> {
        Ok(Some(self.0.clone()))
    }
}

fn epoch() -> String {
    "00000000-0000-4000-8000-0000000000e4".to_owned()
}

fn credentials() -> BTreeMap<Kind, Vec<LeasedCredential>> {
    BTreeMap::from([(
        Kind::Api,
        vec![LeasedCredential::new(
            "00000000-0000-4000-8000-0000000000e5".to_owned(),
            SecretBytes::try_from_bytes(vec![0xE4; 24]).unwrap(),
            None,
        )
        .unwrap()],
    )])
}

fn scoped_lease(egress: EgressScope) -> CredentialLease<Kind> {
    CredentialLease::new(
        credentials(),
        Duration::from_secs(60),
        epoch(),
        Arc::new(FixedEpoch(epoch())),
        egress,
    )
    .unwrap()
}

fn proxy_scope() -> EgressScope {
    EgressScope::new(
        vec!["api.example.com".to_owned(), "*.example.org".to_owned()],
        vec![443],
        vec!["/v1/".to_owned()],
        vec!["GET".to_owned(), "POST".to_owned()],
        vec![
            HeaderTemplate::new("Authorization".to_owned(), "Bearer {secret}".to_owned()).unwrap(),
        ],
        false,
    )
    .unwrap()
}

fn handoff_document(egress: serde_json::Value) -> Vec<u8> {
    let mut document = serde_json::json!({
        "schemaVersion": Kind::HANDOFF_SCHEMA,
        "leaseDurationSeconds": 60,
        "leaseExpiresAtEpochSeconds": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60,
        "epoch": epoch(),
        "credentials": [{
            "kind": "api",
            "keys": [{
                "credentialId": "00000000-0000-4000-8000-0000000000e5",
                "expiresAtEpochSeconds": null,
                "secret": vec![0xE4u8; 24],
            }],
        }],
    });
    if !egress.is_null() {
        document["egress"] = egress;
    }
    serde_json::to_vec(&document).unwrap()
}

fn assert_handoff_invalid(payload: &[u8]) {
    let error = CredentialHandoff::<Kind>::from_json(payload).unwrap_err();
    assert_eq!(error.to_string(), "credential_lease_handoff_invalid");
}

#[test]
fn undeclared_egress_scope_fails_closed_on_every_target() {
    // given a handoff document carrying no egress member, when the runtime
    // reads the scope, then every outbound shape is refused and redirects
    // are off — the default is fail-closed, never implicitly open
    let handoff =
        CredentialHandoff::<Kind>::from_json(&handoff_document(serde_json::Value::Null)).unwrap();
    let scope = handoff.egress();
    assert!(scope.is_deny_all());
    assert!(!scope.allow_redirects());
    assert!(!scope.permits(&EgressTarget::http(
        "api.example.com",
        443,
        "GET",
        "/v1/keys"
    )));
    assert!(!scope.permits(&EgressTarget::connect("api.example.com", 443)));
}

#[test]
fn declared_scope_admits_only_targets_satisfying_every_declared_axis() {
    // given a scope declaring hosts, ports, path prefixes and methods,
    // when targets are checked, then each axis must match and an
    // undeclared-mismatch on any axis fails closed
    let scope = proxy_scope();
    // Every declared axis matches.
    assert!(scope.permits(&EgressTarget::http(
        "api.example.com",
        443,
        "GET",
        "/v1/keys"
    )));
    assert!(scope.permits(&EgressTarget::http(
        "cdn.edge.example.org",
        443,
        "POST",
        "/v1/"
    )));
    // Host outside every pattern.
    assert!(!scope.permits(&EgressTarget::http(
        "api.evil.example.net",
        443,
        "GET",
        "/v1/keys"
    )));
    // Exact pattern does not widen to subdomains.
    assert!(!scope.permits(&EgressTarget::http(
        "deep.api.example.com",
        443,
        "GET",
        "/v1/keys"
    )));
    // `*.` pattern covers subdomains but never the apex.
    assert!(!scope.permits(&EgressTarget::http("example.org", 443, "GET", "/v1/keys")));
    // Port outside the declared set.
    assert!(!scope.permits(&EgressTarget::http(
        "api.example.com",
        8443,
        "GET",
        "/v1/keys"
    )));
    // Method outside the declared set.
    assert!(!scope.permits(&EgressTarget::http(
        "api.example.com",
        443,
        "DELETE",
        "/v1/keys"
    )));
    // Path outside every declared prefix.
    assert!(!scope.permits(&EgressTarget::http(
        "api.example.com",
        443,
        "GET",
        "/v2/keys"
    )));
    // A raw TCP dial carries no method or path, so a scope declaring
    // either matcher can never admit it.
    assert!(!scope.permits(&EgressTarget::connect("api.example.com", 443)));
    // Case-insensitive hosts: DNS names compare case-folded.
    assert!(scope.permits(&EgressTarget::http(
        "API.EXAMPLE.COM",
        443,
        "GET",
        "/v1/keys"
    )));
}

#[test]
fn tcp_connect_scope_admits_a_dial_on_host_and_port_alone() {
    // given a scope declaring only hosts and ports, when a bare TCP dial
    // is checked, then it is admitted — methods and path prefixes are
    // opt-in precision, not mandatory axes
    let scope = EgressScope::new(
        vec!["db.internal".to_owned()],
        vec![5432],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        false,
    )
    .unwrap();
    assert!(scope.permits(&EgressTarget::connect("db.internal", 5432)));
    assert!(!scope.permits(&EgressTarget::connect("db.internal", 5433)));
    assert!(!scope.permits(&EgressTarget::connect("other.internal", 5432)));
}

#[test]
fn allow_redirects_stays_off_unless_the_owner_explicitly_enables_it() {
    // given documents differing only in allowRedirects, when parsed, then
    // absent reads as false, false reads as false, and only an explicit
    // true enables redirects
    let egress = serde_json::json!({"hosts": ["api.example.com"]});
    let handoff = CredentialHandoff::<Kind>::from_json(&handoff_document(egress)).unwrap();
    assert!(!handoff.egress().allow_redirects());
    assert!(handoff
        .egress()
        .permits(&EgressTarget::http("api.example.com", 443, "GET", "/")));

    let egress = serde_json::json!({"hosts": ["api.example.com"], "allowRedirects": false});
    let handoff = CredentialHandoff::<Kind>::from_json(&handoff_document(egress)).unwrap();
    assert!(!handoff.egress().allow_redirects());

    let egress = serde_json::json!({"hosts": ["api.example.com"], "allowRedirects": true});
    let handoff = CredentialHandoff::<Kind>::from_json(&handoff_document(egress)).unwrap();
    assert!(handoff.egress().allow_redirects());

    // A non-boolean flag is malformed, not coerced.
    let egress = serde_json::json!({"hosts": ["api.example.com"], "allowRedirects": "yes"});
    assert_handoff_invalid(&handoff_document(egress));
}

#[test]
fn closed_egress_schema_rejects_unknown_and_malformed_members() {
    // The egress object obeys the document's closed-field rule: unknown
    // members, wrong types and malformed matchers all reject the document.
    let base = serde_json::json!({"hosts": ["api.example.com"]});
    let mut unknown = base.clone();
    unknown["egressPolicy"] = serde_json::json!(true);
    assert_handoff_invalid(&handoff_document(unknown));

    for malformed in [
        serde_json::json!({"hosts": "api.example.com"}),
        serde_json::json!({"hosts": ["*"]}),
        serde_json::json!({"hosts": ["bad host!.com"]}),
        serde_json::json!({"hosts": ["api.example.com:443"]}),
        serde_json::json!({"hosts": ["api.example.com", "api.example.com", 42]}),
        serde_json::json!({"ports": [0]}),
        serde_json::json!({"ports": [65536]}),
        serde_json::json!({"ports": ["443"]}),
        serde_json::json!({"methods": ["not a method"]}),
        serde_json::json!({"pathPrefixes": ["relative/path"]}),
        serde_json::json!({"pathPrefixes": ["/with\r\ninjection"]}),
        serde_json::json!({"headerTemplates": [{"name": "X-H"}]}),
        serde_json::json!({"headerTemplates": [{"name": "Bad Name", "value": "v"}]}),
        serde_json::json!({"headerTemplates": [{"name": "X-H", "value": "a\r\nb"}]}),
        serde_json::json!({"headerTemplates": [{"name": "X-H", "value": "v", "extra": 1}]}),
        serde_json::json!([]),
    ] {
        assert_handoff_invalid(&handoff_document(malformed));
    }
    // Matcher lists above the bound reject the document too.
    let too_many_hosts = serde_json::json!({
        "hosts": (0..=MAX_EGRESS_MATCHERS).map(|i| format!("h{i}.example.com")).collect::<Vec<_>>(),
    });
    assert_handoff_invalid(&handoff_document(too_many_hosts));
    // A duplicate member name inside egress rejects the whole document.
    let dup = format!(
        r#"{{"schemaVersion":"{}","leaseDurationSeconds":60,"leaseExpiresAtEpochSeconds":{},"epoch":"{}","egress":{{"hosts":["api.example.com"],"hosts":["evil.example.com"]}},"credentials":[]}}"#,
        Kind::HANDOFF_SCHEMA,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60,
        epoch(),
    );
    assert_handoff_invalid(dup.as_bytes());
}

#[test]
fn egress_scope_survives_the_handoff_round_trip_and_projection() {
    // given a lease minted with a declared scope, when it projects to a
    // document and the receiver rebuilds, then the scope arrives verbatim
    // — forwarding can never silently widen the granted boundary
    let scope = proxy_scope();
    let lease = scoped_lease(scope.clone());
    assert_eq!(lease.egress(), &scope);
    let document = lease.handoff_projection().unwrap().to_json().unwrap();
    let text = String::from_utf8_lossy(document.expose_bytes());
    assert!(text.contains("\"egress\":{\"hosts\":[\"*.example.org\",\"api.example.com\"]"));
    assert!(text.contains("\"allowRedirects\":false"));

    let parsed = CredentialHandoff::<Kind>::from_json(document.expose_bytes()).unwrap();
    assert_eq!(parsed.egress(), &scope);
    let rebuilt = CredentialLease::from_handoff(parsed, Arc::new(FixedEpoch(epoch()))).unwrap();
    assert_eq!(rebuilt.egress(), &scope);
    // Re-projecting keeps the same scope — no silent widening downstream.
    assert_eq!(rebuilt.handoff_projection().unwrap().egress(), &scope);
}

#[test]
fn header_template_substitutes_the_secret_and_refuses_header_injection() {
    // given a Bearer template, when a resolved secret is rendered, then
    // the marker is replaced — and a secret carrying CR/LF or non-UTF-8
    // bytes fails closed instead of splitting the header line
    let template =
        HeaderTemplate::new("Authorization".to_owned(), "Bearer {secret}".to_owned()).unwrap();
    let secret = SecretBytes::try_from_string("syntok".to_owned()).unwrap();
    assert_eq!(template.render(&secret).unwrap(), "Bearer syntok");

    let hostile = SecretBytes::try_from_bytes(b"a\r\nInjected: x".to_vec()).unwrap();
    assert_eq!(
        template.render(&hostile).unwrap_err().to_string(),
        "credential_lease_egress_invalid"
    );
    let non_utf8 = SecretBytes::try_from_bytes(vec![0xff, 0xfe]).unwrap();
    assert_eq!(
        template.render(&non_utf8).unwrap_err().to_string(),
        "credential_lease_secret_not_utf8"
    );
    // Templates without the marker stay literal.
    let plain = HeaderTemplate::new("X-Route".to_owned(), "internal".to_owned()).unwrap();
    assert_eq!(plain.render(&secret).unwrap(), "internal");
}

#[test]
fn scoped_handoff_document_still_zeroizes_on_drop() {
    // given a scope declared alongside secrets, when the serialized
    // document is zeroized, then both the policy and the secret material
    // are scrubbed — egress carries no exemption from erasure
    let lease = scoped_lease(proxy_scope());
    let mut document = lease.handoff_projection().unwrap().to_json().unwrap();
    assert!(String::from_utf8_lossy(document.expose_bytes()).contains("\"allowRedirects\""));
    use zeroize::Zeroize;
    document.zeroize();
    assert!(document.expose_bytes().is_empty());
}

#[test]
fn disconnected_slot_reports_the_deny_all_scope() {
    let slot = credential_lease::CredentialSlot::<Kind>::disconnected();
    let scope = slot.egress();
    assert!(scope.is_deny_all());
    assert!(!scope.allow_redirects());
}

#[test]
fn resolve_scoped_returns_the_secret_with_its_own_grants_scope() {
    // A forwarding runtime reads the secret and the scope from the same
    // lease snapshot — a concurrent handoff install can never pair the
    // credential with another grant's boundary.
    let scope = proxy_scope();
    let slot = credential_lease::CredentialSlot::new(scoped_lease(scope.clone()));
    let (secret, resolved_scope) = slot.resolve_scoped(Kind::Api).unwrap();
    assert_eq!(secret.expose_bytes(), &[0xE4u8; 24]);
    assert_eq!(resolved_scope, scope);
}

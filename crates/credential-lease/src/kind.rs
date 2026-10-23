//! Credential kind parameter.
//!
//! A kind family names the sort of credential a lease carries — provider API
//! keys, peer identity assertions, or anything else a custody owner leases
//! to a runtime. The kind parameter is closed: implementors enumerate their
//! variants through [`CredentialKind::from_str`], and every family pins the
//! handoff schema it accepts so documents cannot cross families.

/// A closed family of credential kinds.
///
/// `Ord` keeps handoff serialization deterministic; `Copy` suits the
/// enum-shaped implementations this trait is designed for.
pub trait CredentialKind: Copy + Ord + Send + Sync + 'static {
    /// The only `schemaVersion` a handoff document of this family may carry.
    const HANDOFF_SCHEMA: &'static str;

    /// The wire name of this kind inside a handoff credentials entry.
    fn as_str(self) -> &'static str;

    /// Resolve a wire name back into a kind. Unknown names return `None`
    /// so parsing fails closed instead of guessing.
    fn from_str(value: &str) -> Option<Self>;
}

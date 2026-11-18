use credential_lease::{SecretBytes, SecretBytesError, MAX_SECRET_BYTES};
use zeroize::Zeroize;
#[test]
fn neutral_secret_contract_is_redacted_and_explicitly_copied() {
    let mut original = SecretBytes::try_from_string("x".repeat(24)).unwrap();
    assert_eq!(format!("{original:?}"), "SecretBytes([redacted])");
    let copy = original.copy_for_persistent_read();
    original.zeroize();
    assert!(original.expose_bytes().is_empty());
    assert_eq!(copy.expose_utf8().unwrap(), "x".repeat(24));
}
#[test]
fn invalid_secret_material_has_value_free_errors() {
    assert_eq!(
        SecretBytes::try_from_bytes(Vec::new()).unwrap_err(),
        SecretBytesError::Empty
    );
    assert_eq!(
        SecretBytes::try_from_bytes(vec![1; MAX_SECRET_BYTES + 1]).unwrap_err(),
        SecretBytesError::Oversize
    );
    assert_eq!(
        SecretBytes::try_from_bytes(vec![255])
            .unwrap()
            .expose_utf8()
            .unwrap_err(),
        SecretBytesError::NotUtf8
    );
    assert_eq!(
        SecretBytesError::Empty.to_string(),
        "credential_lease_secret_empty"
    );
}

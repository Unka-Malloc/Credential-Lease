//! The macOS Keychain backend.
//!
//! One module owns every SecItem call: query construction, the Data
//! Protection versus classic routing flag, the classic process-wide UI
//! policy, and the silent backend-selection probe. Owner authorization
//! arrives as a [`KeychainAuthContext`] and becomes
//! `kSecUseAuthenticationContext`; this module never evaluates a policy.
//!
//! # Plaintext copies
//!
//! Value bytes cross into Core Foundation only inside a `CFData` whose
//! backing store comes from this module's zeroizing allocator, so the buffer
//! is overwritten before it is freed — whenever Core Foundation releases its
//! last reference. Read results are copied once into [`SecretBytes`] and the
//! raw result dictionary never leaves this module.
//!
//! What remains outside this crate's control: the copies Security.framework
//! and `securityd` make while serializing a request or a result, and the
//! immutable `CFData` a read returns, which the framework allocates and
//! frees without zeroing. Writing into that buffer would violate its
//! immutability contract, so the module only bounds its lifetime: it is
//! released as soon as the bytes are copied out.

use std::alloc::{alloc, dealloc, Layout};
use std::ffi::c_void;
use std::ptr;
use std::sync::{Mutex, OnceLock};

use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use core_foundation_sys::base::{
    CFAllocatorAllocate, CFAllocatorContext, CFAllocatorCreate, CFAllocatorDeallocate,
    CFAllocatorRef, CFEqual, CFGetTypeID, CFIndex, CFOptionFlags, CFRelease, CFTypeRef,
};
use core_foundation_sys::data::{CFDataCreateWithBytesNoCopy, CFDataRef};
use core_foundation_sys::dictionary::CFDictionaryGetValueIfPresent;
use core_foundation_sys::string::CFStringRef;
use credential_lease::SecretBytes;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework_sys::access_control::kSecAccessControlUserPresence;
use security_framework_sys::base::{
    errSecAuthFailed, errSecDuplicateItem, errSecItemNotFound, errSecSuccess,
};
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrAccessGroup, kSecAttrAccount, kSecAttrService,
    kSecAttrSynchronizable, kSecClass, kSecClassGenericPassword, kSecReturnAttributes,
    kSecReturnData, kSecReturnPersistentRef, kSecUseAuthenticationContext,
    kSecUseDataProtectionKeychain, kSecValueData,
};
use security_framework_sys::keychain::{
    SecKeychainGetUserInteractionAllowed, SecKeychainSetUserInteractionAllowed,
};
use security_framework_sys::keychain_item::{
    SecItemAdd, SecItemCopyMatching, SecItemDelete, SecItemUpdate,
};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::context::KeychainAuthContext;
use crate::error::{KeychainError, KeychainErrorKind};
use crate::item::{AddItemOutcome, KeychainItem, KeychainItemProvenance, KeychainItemQuery};
use crate::{Keychain, KeychainBackend};

macro_rules! security_framework_static {
    ($value:expr, $wrapper:ident) => {{
        // SAFETY: every invocation passes a Security.framework SDK-exported static CFString.
        unsafe { $wrapper($value) }
    }};
}

const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

#[link(name = "Security", kind = "framework")]
extern "C" {
    static kSecValuePersistentRef: CFStringRef;
    static kSecAttrAccessible: CFStringRef;
}

// The classic Keychain has a process-wide UI switch, independent of the
// authorization context. Serialize temporary changes so one batch cannot
// restore UI in the middle of another batch's effect. This never changes an
// ACL.
static CLASSIC_KEYCHAIN_INTERACTION: Mutex<()> = Mutex::new(());

trait ClassicKeychainInteraction {
    fn allowed(&self) -> Result<bool, KeychainError>;
    fn set_allowed(&self, allowed: bool) -> Result<(), KeychainError>;
}

struct SystemClassicKeychainInteraction;

fn interaction_control_failed() -> KeychainError {
    KeychainError::new(
        "credential_lease_keychain_interaction_control_failed",
        KeychainErrorKind::InteractionControlFailed,
        None,
    )
}

impl ClassicKeychainInteraction for SystemClassicKeychainInteraction {
    fn allowed(&self) -> Result<bool, KeychainError> {
        let mut allowed = 0;
        // SAFETY: allowed is a valid initialized Boolean out-pointer.
        let status = unsafe { SecKeychainGetUserInteractionAllowed(&mut allowed) };
        if status != errSecSuccess {
            return Err(interaction_control_failed());
        }
        Ok(allowed != 0)
    }

    fn set_allowed(&self, allowed: bool) -> Result<(), KeychainError> {
        // SAFETY: this changes only the process's legacy Keychain UI policy.
        let status = unsafe { SecKeychainSetUserInteractionAllowed(u8::from(allowed)) };
        if status != errSecSuccess {
            return Err(interaction_control_failed());
        }
        Ok(())
    }
}

struct ClassicInteractionRestore<'a> {
    port: &'a dyn ClassicKeychainInteraction,
    was_allowed: Option<bool>,
}

impl Drop for ClassicInteractionRestore<'_> {
    fn drop(&mut self) {
        // Restore the exact previous state, including a caller's pre-existing
        // UI prohibition. The normal path reports a failed restore.
        if let Some(was_allowed) = self.was_allowed.take() {
            let _ = self.port.set_allowed(was_allowed);
        }
    }
}

fn without_classic_keychain_interaction<T>(
    port: &dyn ClassicKeychainInteraction,
    effect: impl FnOnce() -> Result<T, KeychainError>,
) -> Result<T, KeychainError> {
    with_classic_keychain_interaction(port, false, effect)
}

fn with_classic_keychain_interaction<T>(
    port: &dyn ClassicKeychainInteraction,
    allowed: bool,
    effect: impl FnOnce() -> Result<T, KeychainError>,
) -> Result<T, KeychainError> {
    let _lock = CLASSIC_KEYCHAIN_INTERACTION
        .lock()
        .map_err(|_| interaction_control_failed())?;
    let was_allowed = port.allowed()?;
    port.set_allowed(allowed)?;
    let mut restore = ClassicInteractionRestore {
        port,
        was_allowed: Some(was_allowed),
    };
    let result = effect();
    let restored = port.set_allowed(was_allowed);
    // The explicit restore reports failure on the normal path; Drop also
    // restores during unwinding, before releasing the serialization lock.
    restore.was_allowed = None;
    restored?;
    result
}

fn with_keychain_backend<T>(
    backend: KeychainBackend,
    effect: impl FnOnce() -> Result<T, KeychainError>,
) -> Result<T, KeychainError> {
    match backend {
        KeychainBackend::DataProtection => effect(),
        KeychainBackend::Classic => {
            without_classic_keychain_interaction(&SystemClassicKeychainInteraction, effect)
        }
    }
}

fn keychain_effect(
    backend: KeychainBackend,
    effect: impl FnOnce() -> i32,
) -> Result<i32, KeychainError> {
    with_keychain_backend(backend, || keychain_effect_status(backend, effect()))
}

fn keychain_effect_status(backend: KeychainBackend, status: i32) -> Result<i32, KeychainError> {
    if backend == KeychainBackend::Classic
        && (status == errSecAuthFailed || status == ERR_SEC_INTERACTION_NOT_ALLOWED)
    {
        return Err(KeychainError::new(
            "credential_lease_keychain_classic_access_requires_user_action",
            KeychainErrorKind::ClassicAccessRequiresUserAction,
            Some(status),
        ));
    }
    Ok(status)
}

/// Map a SecItem status to the boundary's refusal shape. An authorization
/// failure reports `AuthorizationRequired` — the host revokes its cached
/// native context so the next explicit operation authenticates again
/// instead of silently falling back to a password prompt.
fn status_result(operation: &'static str, status: i32) -> Result<(), KeychainError> {
    if status == errSecSuccess {
        return Ok(());
    }
    if status == errSecAuthFailed || status == ERR_SEC_INTERACTION_NOT_ALLOWED {
        return Err(KeychainError::new(
            "credential_lease_keychain_authorization_required",
            KeychainErrorKind::AuthorizationRequired,
            Some(status),
        ));
    }
    Err(KeychainError::new(
        match operation {
            "write" => "credential_lease_keychain_write_failed",
            "read" => "credential_lease_keychain_read_failed",
            "delete" => "credential_lease_keychain_delete_failed",
            "add" => "credential_lease_keychain_add_failed",
            _ => "credential_lease_keychain_operation_failed",
        },
        KeychainErrorKind::Failed,
        Some(status),
    ))
}

fn data_invalid() -> KeychainError {
    KeychainError::new(
        "credential_lease_keychain_data_invalid",
        KeychainErrorKind::Failed,
        None,
    )
}

static SELECTED_KEYCHAIN_BACKEND: OnceLock<Option<KeychainBackend>> = OnceLock::new();

pub(crate) fn selected_backend() -> Option<KeychainBackend> {
    *SELECTED_KEYCHAIN_BACKEND.get_or_init(|| {
        if keychain_roundtrip_probe(KeychainBackend::DataProtection) {
            Some(KeychainBackend::DataProtection)
        } else if keychain_roundtrip_probe(KeychainBackend::Classic) {
            Some(KeychainBackend::Classic)
        } else {
            None
        }
    })
}

impl Keychain {
    /// Write one protected item: update the existing record when present,
    /// otherwise add it. The add path retries a lost update race exactly
    /// once so a duplicate that appears between the two calls is still
    /// written.
    pub fn set_item(
        &self,
        context: &KeychainAuthContext,
        query: &KeychainItemQuery<'_>,
        secret: &SecretBytes,
    ) -> Result<(), KeychainError> {
        let query_dict = CFDictionary::from_CFType_pairs(&base_pairs(query, context, self.backend));
        // Data Protection applies SecAccessControl. The classic Keychain has
        // separate application ACLs; this update cannot convert those ACLs.
        let update =
            CFDictionary::from_CFType_pairs(&protected_secret_pairs(secret.expose_bytes())?);
        // SAFETY: query and update own their CF values for the synchronous call.
        let update_status = keychain_effect(self.backend, || unsafe {
            SecItemUpdate(
                query_dict.as_concrete_TypeRef(),
                update.as_concrete_TypeRef(),
            )
        })?;
        match keychain_update_transition(update_status) {
            KeychainUpdateTransition::Complete => return Ok(()),
            KeychainUpdateTransition::AddNew => {}
            KeychainUpdateTransition::Fail(status) => {
                return status_result("write", status);
            }
        }

        let mut pairs = base_pairs(query, context, self.backend);
        pairs.extend(protected_secret_pairs(secret.expose_bytes())?);
        let add_query = CFDictionary::from_CFType_pairs(&pairs);
        // SAFETY: add_query owns all referenced values for the synchronous call.
        let add_status = keychain_effect(self.backend, || unsafe {
            SecItemAdd(add_query.as_concrete_TypeRef(), ptr::null_mut())
        })?;
        if add_status == errSecSuccess {
            return Ok(());
        }
        if add_status == errSecDuplicateItem {
            // SAFETY: query and update remain valid for the synchronous retry.
            let retry_status = keychain_effect(self.backend, || unsafe {
                SecItemUpdate(
                    query_dict.as_concrete_TypeRef(),
                    update.as_concrete_TypeRef(),
                )
            })?;
            return status_result("write", retry_status);
        }
        status_result("write", add_status)
    }

    /// Append-only add: the item is created or `Duplicate` is reported —
    /// nothing is ever overwritten through this operation. Item contracts
    /// that are append-only resolve `Duplicate` by comparing the existing
    /// record.
    pub fn add_item(
        &self,
        context: &KeychainAuthContext,
        query: &KeychainItemQuery<'_>,
        secret: &SecretBytes,
    ) -> Result<AddItemOutcome, KeychainError> {
        let mut pairs = base_pairs(query, context, self.backend);
        pairs.extend(protected_secret_pairs(secret.expose_bytes())?);
        let add_query = CFDictionary::from_CFType_pairs(&pairs);
        // SAFETY: add_query owns all referenced values for the synchronous call.
        let add_status = keychain_effect(self.backend, || unsafe {
            SecItemAdd(add_query.as_concrete_TypeRef(), ptr::null_mut())
        })?;
        if add_status == errSecSuccess {
            return Ok(AddItemOutcome::Added);
        }
        if add_status == errSecDuplicateItem {
            return Ok(AddItemOutcome::Duplicate);
        }
        status_result("add", add_status)?;
        Ok(AddItemOutcome::Added)
    }

    /// Copy one item's value bytes only.
    pub fn copy_secret(
        &self,
        context: &KeychainAuthContext,
        query: &KeychainItemQuery<'_>,
    ) -> Result<Option<SecretBytes>, KeychainError> {
        let mut pairs = base_pairs(query, context, self.backend);
        pairs.push((
            security_framework_static!(kSecReturnData, sec_key),
            CFBoolean::from(true).into_CFType(),
        ));
        with_keychain_backend(self.backend, || {
            copy_secret_from_query_effect(&pairs, self.backend)
        })
    }

    /// Copy one item with its value bytes, its persistent reference, and
    /// its provenance attributes.
    pub fn copy_item(
        &self,
        context: &KeychainAuthContext,
        query: &KeychainItemQuery<'_>,
    ) -> Result<Option<KeychainItem>, KeychainError> {
        let mut pairs = base_pairs(query, context, self.backend);
        pairs.push((
            security_framework_static!(kSecReturnAttributes, sec_key),
            CFBoolean::from(true).into_CFType(),
        ));
        pairs.push((
            security_framework_static!(kSecReturnData, sec_key),
            CFBoolean::from(true).into_CFType(),
        ));
        pairs.push((
            security_framework_static!(kSecReturnPersistentRef, sec_key),
            CFBoolean::from(true).into_CFType(),
        ));
        with_keychain_backend(self.backend, || {
            copy_item_from_query_effect(&pairs, self.backend)
        })
    }

    /// Delete one item; an absent item is not an error.
    pub fn delete_item(
        &self,
        context: &KeychainAuthContext,
        query: &KeychainItemQuery<'_>,
    ) -> Result<(), KeychainError> {
        let query_dict = CFDictionary::from_CFType_pairs(&base_pairs(query, context, self.backend));
        // SAFETY: query owns valid CF values for the synchronous call.
        let status = keychain_effect(self.backend, || unsafe {
            SecItemDelete(query_dict.as_concrete_TypeRef())
        })?;
        if status == errSecItemNotFound {
            Ok(())
        } else {
            status_result("delete", status)
        }
    }

    /// Read one item from the classic Keychain — the legacy migration's
    /// source. `allow_interaction` is the host's decision: during the
    /// explicit, user-consented migration the legacy item's application ACL
    /// may display its consent dialog; otherwise the classic UI is
    /// suppressed for the duration of the read.
    ///
    /// The operation answers `Ok(None)` when this store is not the Data
    /// Protection Keychain — a same-store copy is not a migration.
    pub fn copy_legacy_classic_secret(
        &self,
        context: &KeychainAuthContext,
        query: &KeychainItemQuery<'_>,
        allow_interaction: bool,
    ) -> Result<Option<SecretBytes>, KeychainError> {
        let Some(mut pairs) = classic_migration_pairs(query, context, self.backend) else {
            return Ok(None);
        };
        pairs.push((
            security_framework_static!(kSecReturnData, sec_key),
            CFBoolean::from(true).into_CFType(),
        ));
        with_classic_keychain_interaction(
            &SystemClassicKeychainInteraction,
            allow_interaction,
            || copy_secret_from_query_effect(&pairs, KeychainBackend::Classic),
        )
    }

    /// Delete one item from the classic Keychain — the legacy migration's
    /// cleanup. Refused outright when this store is not the Data Protection
    /// Keychain: deleting the only copy is never a migration.
    pub fn delete_legacy_classic_item(
        &self,
        context: &KeychainAuthContext,
        query: &KeychainItemQuery<'_>,
        allow_interaction: bool,
    ) -> Result<(), KeychainError> {
        let pairs = classic_migration_pairs(query, context, self.backend).ok_or_else(|| {
            KeychainError::new(
                "credential_lease_keychain_migration_target_invalid",
                KeychainErrorKind::Failed,
                None,
            )
        })?;
        let query_dict = CFDictionary::from_CFType_pairs(&pairs);
        let status = with_classic_keychain_interaction(
            &SystemClassicKeychainInteraction,
            allow_interaction,
            || {
                // SAFETY: query owns valid CF values for the synchronous call.
                keychain_effect_status(KeychainBackend::Classic, unsafe {
                    SecItemDelete(query_dict.as_concrete_TypeRef())
                })
            },
        )?;
        if status == errSecItemNotFound {
            Ok(())
        } else {
            status_result("delete", status)
        }
    }
}

/// The ordinary item query: class, service, account, the optional storage
/// attributes the host asked for, and the authorized context. The routing
/// flag follows `use_data_protection` when set, otherwise the selected
/// backend — explicit on Data Protection, absent on Classic so a classic
/// add does not get routed into a store that would discard the protection
/// attribute it carries.
fn base_pairs(
    query: &KeychainItemQuery<'_>,
    context: &KeychainAuthContext,
    backend: KeychainBackend,
) -> Vec<(CFString, CFType)> {
    let mut pairs = vec![
        (
            security_framework_static!(kSecClass, sec_key),
            security_framework_static!(kSecClassGenericPassword, sec_string_value),
        ),
        (
            security_framework_static!(kSecAttrService, sec_key),
            CFString::from(query.service).into_CFType(),
        ),
        (
            security_framework_static!(kSecAttrAccount, sec_key),
            CFString::from(query.account).into_CFType(),
        ),
    ];
    if let Some(access_group) = query.access_group {
        pairs.push((
            security_framework_static!(kSecAttrAccessGroup, sec_key),
            CFString::from(access_group).into_CFType(),
        ));
    }
    if let Some(synchronizable) = query.synchronizable {
        pairs.push((
            security_framework_static!(kSecAttrSynchronizable, sec_key),
            CFBoolean::from(synchronizable).into_CFType(),
        ));
    }
    pairs.push((
        security_framework_static!(kSecUseAuthenticationContext, sec_key),
        context.as_cf_type(),
    ));
    match query.use_data_protection {
        Some(use_data_protection) => pairs.push((
            security_framework_static!(kSecUseDataProtectionKeychain, sec_key),
            CFBoolean::from(use_data_protection).into_CFType(),
        )),
        None if backend == KeychainBackend::DataProtection => pairs.push((
            security_framework_static!(kSecUseDataProtectionKeychain, sec_key),
            CFBoolean::from(true).into_CFType(),
        )),
        None => {}
    }
    pairs
}

/// Legacy migration source pairs: an explicit classic-only query. Valid
/// only when the selected destination is the Data Protection Keychain —
/// copying and deleting inside the classic store itself is not a
/// migration, so the pairs exist only for a distinct destination.
fn classic_migration_pairs(
    query: &KeychainItemQuery<'_>,
    context: &KeychainAuthContext,
    destination: KeychainBackend,
) -> Option<Vec<(CFString, CFType)>> {
    (destination == KeychainBackend::DataProtection).then(|| {
        vec![
            (
                security_framework_static!(kSecClass, sec_key),
                security_framework_static!(kSecClassGenericPassword, sec_string_value),
            ),
            (
                security_framework_static!(kSecAttrService, sec_key),
                CFString::from(query.service).into_CFType(),
            ),
            (
                security_framework_static!(kSecAttrAccount, sec_key),
                CFString::from(query.account).into_CFType(),
            ),
            (
                security_framework_static!(kSecUseAuthenticationContext, sec_key),
                context.as_cf_type(),
            ),
            (
                security_framework_static!(kSecUseDataProtectionKeychain, sec_key),
                CFBoolean::from(false).into_CFType(),
            ),
        ]
    })
}

/// The write payload: a `SecAccessControl` requiring user presence plus
/// the value bytes.
fn protected_secret_pairs(secret: &[u8]) -> Result<Vec<(CFString, CFType)>, KeychainError> {
    Ok(vec![
        (
            security_framework_static!(kSecAttrAccessControl, sec_key),
            backend_access_control()?.into_CFType(),
        ),
        (
            security_framework_static!(kSecValueData, sec_key),
            zeroizing_cf_data(secret)?.into_CFType(),
        ),
    ])
}

/// The access control every protected write carries — and the one
/// [`KeychainItemProvenance::has_backend_access_control`] compares against.
fn backend_access_control() -> Result<SecAccessControl, KeychainError> {
    SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        kSecAccessControlUserPresence,
    )
    .map_err(|_| {
        KeychainError::new(
            "credential_lease_keychain_access_control_unavailable",
            KeychainErrorKind::Failed,
            None,
        )
    })
}

/// Every zeroizing buffer is preceded by a header holding the allocation's
/// total size, because a Core Foundation deallocator receives only the
/// pointer. The header width keeps the payload 16-byte aligned.
const ZEROIZING_HEADER: usize = 16;

fn zeroizing_layout(total: usize) -> Option<Layout> {
    Layout::from_size_align(total, ZEROIZING_HEADER).ok()
}

extern "C" fn zeroizing_allocate(
    size: CFIndex,
    _hint: CFOptionFlags,
    _info: *mut c_void,
) -> *mut c_void {
    let Some(total) = usize::try_from(size)
        .ok()
        .and_then(|size| size.checked_add(ZEROIZING_HEADER))
    else {
        return ptr::null_mut();
    };
    let Some(layout) = zeroizing_layout(total) else {
        return ptr::null_mut();
    };
    // SAFETY: the layout is valid and non-zero-sized (it includes the header).
    let base = unsafe { alloc(layout) };
    if base.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: base is a fresh, suitably aligned allocation of `total` bytes,
    // so the header write and the payload offset stay in bounds.
    unsafe {
        base.cast::<usize>().write(total);
        base.add(ZEROIZING_HEADER).cast()
    }
}

/// Overwrite one zeroizing allocation, header included, and return its base
/// and layout for release.
///
/// # Safety
///
/// `payload` must come from [`zeroizing_allocate`] and not yet be freed.
unsafe fn scrub_zeroizing_buffer(payload: *mut c_void) -> (*mut u8, Layout) {
    // SAFETY: the caller guarantees payload sits ZEROIZING_HEADER bytes past
    // a live allocation whose first word records its total size.
    unsafe {
        let base = payload.cast::<u8>().sub(ZEROIZING_HEADER);
        let total = base.cast::<usize>().read();
        std::slice::from_raw_parts_mut(base, total).zeroize();
        let layout = Layout::from_size_align_unchecked(total, ZEROIZING_HEADER);
        (base, layout)
    }
}

extern "C" fn zeroizing_deallocate(payload: *mut c_void, _info: *mut c_void) {
    if payload.is_null() {
        return;
    }
    // SAFETY: Core Foundation hands back only pointers this allocator
    // produced, exactly once.
    unsafe {
        let (base, layout) = scrub_zeroizing_buffer(payload);
        dealloc(base, layout);
    }
    #[cfg(test)]
    tests::SCRUBBED_RELEASES.with(|count| count.set(count.get() + 1));
}

struct ZeroizingAllocator(CFAllocatorRef);

// SAFETY: a CFAllocator is an immutable, thread-safe Core Foundation object;
// the wrapped reference is created once and never released.
unsafe impl Send for ZeroizingAllocator {}
// SAFETY: as above — shared use only passes the reference to CF calls.
unsafe impl Sync for ZeroizingAllocator {}

static ZEROIZING_ALLOCATOR: OnceLock<ZeroizingAllocator> = OnceLock::new();

fn zeroizing_allocator() -> Option<CFAllocatorRef> {
    let allocator = ZEROIZING_ALLOCATOR.get_or_init(|| {
        let mut context = CFAllocatorContext {
            version: 0,
            info: ptr::null_mut(),
            retain: None,
            release: None,
            copyDescription: None,
            allocate: Some(zeroizing_allocate),
            reallocate: None,
            deallocate: Some(zeroizing_deallocate),
            preferredSize: None,
        };
        // SAFETY: the context is fully initialized; CFAllocatorCreate copies
        // it, and the allocator object itself uses the default allocator.
        ZeroizingAllocator(unsafe { CFAllocatorCreate(ptr::null(), &mut context) })
    });
    (!allocator.0.is_null()).then_some(allocator.0)
}

fn secret_buffer_unavailable() -> KeychainError {
    KeychainError::new(
        "credential_lease_keychain_secret_buffer_unavailable",
        KeychainErrorKind::Failed,
        None,
    )
}

/// A `CFData` over a copy of `secret` whose backing store is overwritten
/// before Core Foundation frees it, however long the framework retains it.
fn zeroizing_cf_data(secret: &[u8]) -> Result<CFData, KeychainError> {
    let allocator = zeroizing_allocator().ok_or_else(secret_buffer_unavailable)?;
    let length = CFIndex::try_from(secret.len()).map_err(|_| secret_buffer_unavailable())?;
    // SAFETY: the allocator is live for the process lifetime.
    let buffer = unsafe { CFAllocatorAllocate(allocator, length, 0) }.cast::<u8>();
    if buffer.is_null() {
        return Err(secret_buffer_unavailable());
    }
    // SAFETY: buffer holds `secret.len()` writable bytes that do not overlap
    // the borrowed secret.
    unsafe { ptr::copy_nonoverlapping(secret.as_ptr(), buffer, secret.len()) };
    // SAFETY: on success the CFData owns buffer and releases it through the
    // same allocator; the default allocator creates the CFData object.
    let data = unsafe { CFDataCreateWithBytesNoCopy(ptr::null(), buffer, length, allocator) };
    if data.is_null() {
        // SAFETY: creation failed, so buffer is still exclusively ours.
        unsafe { CFAllocatorDeallocate(allocator, buffer.cast()) };
        return Err(secret_buffer_unavailable());
    }
    // SAFETY: CFDataCreateWithBytesNoCopy returned a +1 reference.
    Ok(unsafe { CFData::wrap_under_create_rule(data) })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeychainUpdateTransition {
    Complete,
    AddNew,
    Fail(i32),
}

fn keychain_update_transition(status: i32) -> KeychainUpdateTransition {
    if status == errSecSuccess {
        KeychainUpdateTransition::Complete
    } else if status == errSecItemNotFound {
        KeychainUpdateTransition::AddNew
    } else {
        KeychainUpdateTransition::Fail(status)
    }
}

/// Data-only copy — the legacy classic read and any path that does not
/// need attributes.
fn copy_secret_from_query_effect(
    pairs: &[(CFString, CFType)],
    backend: KeychainBackend,
) -> Result<Option<SecretBytes>, KeychainError> {
    let query = CFDictionary::from_CFType_pairs(pairs);
    let mut copied: CFTypeRef = ptr::null();
    // SAFETY: query is valid and copied is an initialized out-pointer.
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut copied) };
    // Own any result before resolving status or restoring classic UI. In
    // particular, a restore failure must drop the returned secret object.
    let value = if copied.is_null() {
        None
    } else {
        // SAFETY: SecItemCopyMatching returns its object at +1 ownership.
        Some(unsafe { CFType::wrap_under_create_rule(copied) })
    };
    let status = keychain_effect_status(backend, status)?;
    if status == errSecItemNotFound {
        return Ok(None);
    }
    status_result("read", status)?;
    let Some(value) = value else {
        return Ok(None);
    };
    let data = value.downcast::<CFData>().ok_or_else(data_invalid)?;
    secret_from_cf_data(&data).map(Some)
}

/// Copy a returned value into its zeroizing container. The single
/// exact-capacity copy moves into [`SecretBytes`] before any check, so a
/// refused buffer is scrubbed too; the platform's immutable `CFData` is
/// released by the caller right after.
fn secret_from_cf_data(data: &CFData) -> Result<SecretBytes, KeychainError> {
    SecretBytes::try_from_bytes(data.bytes().to_vec()).map_err(|_| data_invalid())
}

/// Full copy — value bytes, persistent reference, and the typed provenance
/// projection the host's checks consume. The raw result dictionary, which
/// holds the value data, is released here and never handed out.
fn copy_item_from_query_effect(
    pairs: &[(CFString, CFType)],
    backend: KeychainBackend,
) -> Result<Option<KeychainItem>, KeychainError> {
    let query = CFDictionary::from_CFType_pairs(pairs);
    let mut copied: CFTypeRef = ptr::null();
    // SAFETY: query is valid and copied is an initialized out-pointer.
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut copied) };
    let value = if copied.is_null() {
        None
    } else {
        // SAFETY: SecItemCopyMatching returns its object at +1 ownership.
        Some(unsafe { CFType::wrap_under_create_rule(copied) })
    };
    let status = keychain_effect_status(backend, status)?;
    if status == errSecItemNotFound {
        return Ok(None);
    }
    status_result("read", status)?;
    let Some(value) = value else {
        return Ok(None);
    };
    let attributes = value.downcast::<CFDictionary>().ok_or_else(data_invalid)?;
    let secret = dictionary_data(&attributes, unsafe { kSecValueData })
        .ok_or_else(data_invalid)
        .and_then(|data| secret_from_cf_data(&data))?;
    let persistent_reference = dictionary_data(&attributes, unsafe { kSecValuePersistentRef })
        .map(|reference| reference.bytes().to_vec());
    let provenance = item_provenance(&attributes)?;
    Ok(Some(KeychainItem::new(
        secret,
        persistent_reference,
        provenance,
    )))
}

/// The provenance projection: only the named storage attributes, never the
/// value data.
fn item_provenance(attributes: &CFDictionary) -> Result<KeychainItemProvenance, KeychainError> {
    let expected_access_control = backend_access_control()?;
    // SAFETY: the keys are SDK-exported static CFStrings.
    let (service, account, access_group, accessible, synchronizable, access_control) = unsafe {
        (
            kSecAttrService,
            kSecAttrAccount,
            kSecAttrAccessGroup,
            kSecAttrAccessible,
            kSecAttrSynchronizable,
            kSecAttrAccessControl,
        )
    };
    Ok(KeychainItemProvenance {
        service: dictionary_string(attributes, service),
        account: dictionary_string(attributes, account),
        access_group: dictionary_string(attributes, access_group),
        accessible: dictionary_string(attributes, accessible),
        synchronizable: dictionary_value(attributes, synchronizable)
            .and_then(|value| value.downcast::<CFBoolean>())
            .map(bool::from),
        backend_access_control: dictionary_value(attributes, access_control).is_some_and(
            // SAFETY: both references are live CF objects for the call.
            |value| unsafe {
                CFEqual(value.as_CFTypeRef(), expected_access_control.as_CFTypeRef()) != 0
            },
        ),
    })
}

fn dictionary_value(dictionary: &CFDictionary, key: CFStringRef) -> Option<CFType> {
    let mut value: *const c_void = ptr::null();
    // SAFETY: dictionary is a live CFDictionary and value an initialized
    // out-pointer; the key is an SDK-exported CFString.
    let found = unsafe {
        CFDictionaryGetValueIfPresent(dictionary.as_concrete_TypeRef(), key.cast(), &mut value)
    };
    if found == 0 || value.is_null() {
        return None;
    }
    // SAFETY: value is a live CF object owned by the dictionary; get-rule
    // wrapping retains it.
    Some(unsafe { CFType::wrap_under_get_rule(value.cast()) })
}

fn dictionary_data(dictionary: &CFDictionary, key: CFStringRef) -> Option<CFData> {
    dictionary_value(dictionary, key).and_then(|value| value.downcast::<CFData>())
}

fn dictionary_string(dictionary: &CFDictionary, key: CFStringRef) -> Option<String> {
    dictionary_value(dictionary, key)
        .and_then(|value| value.downcast::<CFString>())
        .map(|value| value.to_string())
}

fn keychain_roundtrip_probe(backend: KeychainBackend) -> bool {
    with_keychain_backend(backend, || Ok(silent_keychain_roundtrip_probe(backend))).unwrap_or(false)
}

fn silent_keychain_roundtrip_probe(backend: KeychainBackend) -> bool {
    const PROBE_SERVICE: &str = "dev.credential-lease.keychain-probe";
    const PROBE_MATERIAL: &[u8] = b"credential-lease-keychain-probe";
    let account = format!("probe-{}", Uuid::new_v4());

    let mut pairs = vec![
        (
            security_framework_static!(kSecClass, sec_key),
            security_framework_static!(kSecClassGenericPassword, sec_string_value),
        ),
        (
            security_framework_static!(kSecAttrService, sec_key),
            CFString::from(PROBE_SERVICE).into_CFType(),
        ),
        (
            security_framework_static!(kSecAttrAccount, sec_key),
            CFString::from(account.as_str()).into_CFType(),
        ),
    ];
    pairs.push((
        security_framework_static!(kSecUseDataProtectionKeychain, sec_key),
        CFBoolean::from(backend == KeychainBackend::DataProtection).into_CFType(),
    ));
    // A production write always carries a SecAccessControl; probing without
    // one would pass on ad hoc builds that cannot actually persist a
    // protected item (errSecMissingEntitlement) and misreport the store as
    // available. A plain ACL exercises the same boundary without any
    // interactive readback.
    let Ok(probe_access) =
        SecAccessControl::create_with_protection(Some(ProtectionMode::AccessibleWhenUnlocked), 0)
    else {
        return false;
    };
    pairs.push((
        security_framework_static!(kSecAttrAccessControl, sec_key),
        probe_access.into_CFType(),
    ));
    let query_pair_count = pairs.len() - 1;
    pairs.push((
        security_framework_static!(kSecValueData, sec_key),
        CFData::from_buffer(PROBE_MATERIAL).into_CFType(),
    ));
    let add_query = CFDictionary::from_CFType_pairs(&pairs);
    // SAFETY: add_query owns all referenced values for the synchronous call.
    let add_status = unsafe { SecItemAdd(add_query.as_concrete_TypeRef(), ptr::null_mut()) };
    if add_status != errSecSuccess {
        return false;
    }

    let mut query_pairs = pairs
        .iter()
        .take(query_pair_count)
        .cloned()
        .collect::<Vec<(CFString, CFType)>>();
    query_pairs.push((
        security_framework_static!(kSecReturnData, sec_key),
        CFBoolean::from(true).into_CFType(),
    ));
    let read_query = CFDictionary::from_CFType_pairs(&query_pairs);
    let mut copied: CFTypeRef = ptr::null();
    // SAFETY: read_query is valid and copied is an initialized out-pointer.
    let read_status = unsafe { SecItemCopyMatching(read_query.as_concrete_TypeRef(), &mut copied) };
    let read_ok = if read_status == errSecSuccess && !copied.is_null() {
        // SAFETY: copied is a live CF object returned at +1 ownership.
        let type_id = unsafe { CFGetTypeID(copied) };
        if type_id == CFData::type_id() {
            // SAFETY: type identity is CFData and +1 ownership transfers to the wrapper.
            let data = unsafe { CFData::wrap_under_create_rule(copied as CFDataRef) };
            data.bytes() == PROBE_MATERIAL
        } else {
            // SAFETY: copied has not yet been released.
            unsafe { CFRelease(copied) };
            false
        }
    } else {
        false
    };

    let delete_pairs = pairs
        .iter()
        .take(query_pair_count)
        .cloned()
        .collect::<Vec<(CFString, CFType)>>();
    let delete_query = CFDictionary::from_CFType_pairs(&delete_pairs);
    // SAFETY: delete_query owns valid CF values for the synchronous call.
    let delete_status = unsafe { SecItemDelete(delete_query.as_concrete_TypeRef()) };
    read_ok && delete_status == errSecSuccess
}

fn sec_key(value: CFStringRef) -> CFString {
    // SAFETY: callers supply SDK-exported static CFString constants.
    unsafe { CFString::wrap_under_get_rule(value) }
}

fn sec_string_value(value: CFStringRef) -> CFType {
    sec_key(value).into_CFType()
}

#[cfg(test)]
mod tests {
    use super::*;
    use security_framework_sys::access_control::kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
    use std::cell::{Cell, RefCell};
    use std::sync::atomic::{AtomicBool, Ordering};

    thread_local! {
        /// Zeroizing releases observed on the current thread.
        pub(super) static SCRUBBED_RELEASES: Cell<usize> = const { Cell::new(0) };
    }

    struct SyntheticInteraction {
        allowed: Cell<bool>,
        changes: RefCell<Vec<bool>>,
        fail_disable: bool,
        fail_restore: bool,
    }

    impl ClassicKeychainInteraction for SyntheticInteraction {
        fn allowed(&self) -> Result<bool, KeychainError> {
            Ok(self.allowed.get())
        }

        fn set_allowed(&self, allowed: bool) -> Result<(), KeychainError> {
            self.changes.borrow_mut().push(allowed);
            if (self.fail_disable && !allowed) || (self.fail_restore && allowed) {
                return Err(KeychainError::new(
                    "credential_lease_keychain_interaction_control_failed",
                    KeychainErrorKind::InteractionControlFailed,
                    None,
                ));
            }
            self.allowed.set(allowed);
            Ok(())
        }
    }

    fn synthetic_context() -> KeychainAuthContext {
        KeychainAuthContext::from_cf_type(CFBoolean::true_value().into_CFType())
    }

    fn dict_value(dictionary: &CFDictionary<CFString, CFType>, key: CFStringRef) -> Option<CFType> {
        let mut value: *const core::ffi::c_void = ptr::null();
        // SAFETY: dictionary is a live CFDictionary and value an initialized
        // out-pointer; the key is an SDK-exported CFString.
        let found = unsafe {
            CFDictionaryGetValueIfPresent(dictionary.as_concrete_TypeRef(), key.cast(), &mut value)
        };
        if found == 0 || value.is_null() {
            return None;
        }
        // SAFETY: the dictionary owns a live CF object; get-rule wrapping
        // retains it for inspection.
        Some(unsafe { CFType::wrap_under_get_rule(value.cast()) })
    }

    #[test]
    fn classic_batch_suppresses_per_item_ui_and_restores_exact_policy() {
        for was_allowed in [false, true] {
            let port = SyntheticInteraction {
                allowed: Cell::new(was_allowed),
                changes: RefCell::default(),
                fail_disable: false,
                fail_restore: false,
            };
            let reads = Cell::new(0);
            let result: Result<(), KeychainError> =
                without_classic_keychain_interaction(&port, || {
                    for _ in 0..2 {
                        assert!(!port.allowed.get());
                        reads.set(reads.get() + 1);
                    }
                    Err(KeychainError::new(
                        "credential_lease_keychain_read_failed",
                        KeychainErrorKind::Failed,
                        None,
                    ))
                });
            assert_eq!(
                result.unwrap_err().code(),
                "credential_lease_keychain_read_failed"
            );
            assert_eq!(reads.get(), 2);
            assert_eq!(port.allowed.get(), was_allowed);
            assert_eq!(*port.changes.borrow(), [false, was_allowed]);
        }
    }

    #[test]
    fn legacy_migration_ui_restores_both_previous_policies_after_cancel() {
        for was_allowed in [false, true] {
            let port = SyntheticInteraction {
                allowed: Cell::new(was_allowed),
                changes: RefCell::default(),
                fail_disable: false,
                fail_restore: false,
            };
            let result: Result<(), KeychainError> =
                with_classic_keychain_interaction(&port, true, || {
                    assert!(port.allowed.get());
                    Err(KeychainError::new(
                        "credential_lease_keychain_read_failed",
                        KeychainErrorKind::Failed,
                        None,
                    ))
                });
            assert!(result.is_err());
            assert_eq!(port.allowed.get(), was_allowed);
            assert_eq!(*port.changes.borrow(), [true, was_allowed]);
        }
    }

    #[test]
    fn classic_ui_control_failure_prevents_any_keychain_effect() {
        let port = SyntheticInteraction {
            allowed: Cell::new(true),
            changes: RefCell::default(),
            fail_disable: true,
            fail_restore: false,
        };
        let reads = Cell::new(0);
        let result: Result<(), KeychainError> = without_classic_keychain_interaction(&port, || {
            reads.set(reads.get() + 1);
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(reads.get(), 0);
        assert!(port.allowed.get());
    }

    #[test]
    fn classic_restore_failure_drops_successful_read_result() {
        struct ReadResult<'a>(&'a Cell<usize>);
        impl Drop for ReadResult<'_> {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        let port = SyntheticInteraction {
            allowed: Cell::new(true),
            changes: RefCell::default(),
            fail_disable: false,
            fail_restore: true,
        };
        let drops = Cell::new(0);
        let result: Result<ReadResult<'_>, KeychainError> =
            without_classic_keychain_interaction(&port, || Ok(ReadResult(&drops)));
        assert!(result.is_err());
        assert_eq!(drops.get(), 1);
        assert!(!port.allowed.get());
    }

    #[test]
    fn concurrent_classic_batches_never_restore_ui_during_another_effect() {
        use std::sync::{atomic::AtomicUsize, Barrier};

        struct Interaction(AtomicBool);
        impl ClassicKeychainInteraction for Interaction {
            fn allowed(&self) -> Result<bool, KeychainError> {
                Ok(self.0.load(Ordering::SeqCst))
            }

            fn set_allowed(&self, allowed: bool) -> Result<(), KeychainError> {
                self.0.store(allowed, Ordering::SeqCst);
                Ok(())
            }
        }
        let port = Interaction(AtomicBool::new(true));
        let start = Barrier::new(2);
        let active = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            let port = &port;
            let start = &start;
            let active = &active;
            for allow_migration_ui in [false, true] {
                scope.spawn(move || {
                    start.wait();
                    for _ in 0..16 {
                        with_classic_keychain_interaction(port, allow_migration_ui, || {
                            assert_eq!(active.fetch_add(1, Ordering::SeqCst), 0);
                            assert_eq!(port.allowed()?, allow_migration_ui);
                            std::thread::yield_now();
                            assert_eq!(port.allowed()?, allow_migration_ui);
                            assert_eq!(active.fetch_sub(1, Ordering::SeqCst), 1);
                            Ok(())
                        })
                        .unwrap();
                    }
                });
            }
        });
        assert!(port.allowed().unwrap());
    }

    #[test]
    fn query_targets_selected_store_and_retains_one_authorization_context() {
        let context = synthetic_context();
        for backend in [KeychainBackend::Classic, KeychainBackend::DataProtection] {
            for account in ["synthetic-key-one", "synthetic-key-two"] {
                let query = KeychainItemQuery::new("synthetic-service", account).unwrap();
                let pairs = base_pairs(&query, &context, backend);
                let dict = CFDictionary::from_CFType_pairs(&pairs);
                assert_eq!(
                    dict_value(&dict, unsafe { kSecAttrService })
                        .and_then(|value| value.downcast::<CFString>())
                        .map(|value| value.to_string())
                        .as_deref(),
                    Some("synthetic-service")
                );
                assert_eq!(
                    dict_value(&dict, unsafe { kSecAttrAccount })
                        .and_then(|value| value.downcast::<CFString>())
                        .map(|value| value.to_string())
                        .as_deref(),
                    Some(account)
                );
                if backend == KeychainBackend::DataProtection {
                    assert_eq!(
                        dict_value(&dict, unsafe { kSecUseDataProtectionKeychain })
                            .map(|value| value.as_CFTypeRef()),
                        Some(CFBoolean::from(true).as_CFTypeRef())
                    );
                }
                assert_eq!(
                    dict_value(&dict, unsafe { kSecUseAuthenticationContext })
                        .map(|value| value.as_CFTypeRef()),
                    Some(context.as_cf_type().as_CFTypeRef())
                );
            }
        }
        // A classic-routed query leaves the data-protection flag unset, and a
        // query may pin the flag explicitly in either direction.
        let query = KeychainItemQuery::new("synthetic-service", "synthetic-account").unwrap();
        let classic_pairs = base_pairs(&query, &context, KeychainBackend::Classic);
        let classic_dict = CFDictionary::from_CFType_pairs(&classic_pairs);
        assert!(dict_value(&classic_dict, unsafe { kSecUseDataProtectionKeychain }).is_none());
        for forced in [false, true] {
            let forced_query = query.clone().with_data_protection(forced);
            let forced_pairs = base_pairs(&forced_query, &context, KeychainBackend::Classic);
            let forced_dict = CFDictionary::from_CFType_pairs(&forced_pairs);
            assert_eq!(
                dict_value(&forced_dict, unsafe { kSecUseDataProtectionKeychain })
                    .map(|value| value.as_CFTypeRef()),
                Some(CFBoolean::from(forced).as_CFTypeRef())
            );
        }
        // Optional storage attributes appear only when declared.
        let grouped = query
            .clone()
            .with_access_group("synthetic-access-group")
            .with_synchronizable(false);
        let grouped_dict = CFDictionary::from_CFType_pairs(&base_pairs(
            &grouped,
            &context,
            KeychainBackend::DataProtection,
        ));
        assert_eq!(
            dict_value(&grouped_dict, unsafe { kSecAttrAccessGroup })
                .and_then(|value| value.downcast::<CFString>())
                .map(|value| value.to_string())
                .as_deref(),
            Some("synthetic-access-group")
        );
        assert_eq!(
            dict_value(&grouped_dict, unsafe { kSecAttrSynchronizable })
                .map(|value| value.as_CFTypeRef()),
            Some(CFBoolean::from(false).as_CFTypeRef())
        );
    }

    #[test]
    fn classic_migration_requires_a_distinct_data_protection_destination() {
        let context = synthetic_context();
        let query = KeychainItemQuery::new("synthetic-service", "same-item").unwrap();
        assert!(classic_migration_pairs(&query, &context, KeychainBackend::Classic).is_none());
        let pairs =
            classic_migration_pairs(&query, &context, KeychainBackend::DataProtection).unwrap();
        let dict = CFDictionary::from_CFType_pairs(&pairs);
        assert_eq!(
            *dict.get(security_framework_static!(
                kSecUseDataProtectionKeychain,
                sec_key
            )),
            CFBoolean::false_value().into_CFType()
        );
    }

    #[test]
    fn classic_access_denial_is_actionable_without_exposing_platform_errors() {
        for status in [errSecAuthFailed, ERR_SEC_INTERACTION_NOT_ALLOWED] {
            let error = keychain_effect_status(KeychainBackend::Classic, status).unwrap_err();
            assert_eq!(
                error.kind(),
                KeychainErrorKind::ClassicAccessRequiresUserAction
            );
            assert_eq!(
                error.code(),
                "credential_lease_keychain_classic_access_requires_user_action"
            );
            assert_eq!(error.os_status(), Some(status));
        }
        for status in [errSecAuthFailed, ERR_SEC_INTERACTION_NOT_ALLOWED] {
            let error = status_result("read", status).unwrap_err();
            assert_eq!(error.kind(), KeychainErrorKind::AuthorizationRequired);
            assert_eq!(error.os_status(), Some(status));
        }
    }

    #[test]
    fn update_failure_never_falls_through_to_add() {
        assert_eq!(
            keychain_update_transition(errSecAuthFailed),
            KeychainUpdateTransition::Fail(errSecAuthFailed)
        );
        assert_eq!(
            keychain_update_transition(ERR_SEC_INTERACTION_NOT_ALLOWED),
            KeychainUpdateTransition::Fail(ERR_SEC_INTERACTION_NOT_ALLOWED)
        );
    }

    #[test]
    fn add_is_reached_only_after_verified_not_found() {
        assert_eq!(
            keychain_update_transition(errSecSuccess),
            KeychainUpdateTransition::Complete
        );
        assert_eq!(
            keychain_update_transition(errSecItemNotFound),
            KeychainUpdateTransition::AddNew
        );
    }

    #[test]
    fn existing_item_updates_include_user_presence_access_control() {
        let pairs = protected_secret_pairs(b"synthetic-secret").unwrap();
        assert_eq!(pairs.len(), 2);
        assert_eq!(
            pairs[0].0,
            security_framework_static!(kSecAttrAccessControl, sec_key)
        );
        assert_eq!(
            pairs[1].0,
            security_framework_static!(kSecValueData, sec_key)
        );
    }

    #[test]
    fn provenance_projects_storage_attributes_without_value_data() {
        let secret = b"prov-x";
        let attributes = |access_control: CFType| {
            CFDictionary::from_CFType_pairs(&[
                (
                    security_framework_static!(kSecAttrService, sec_key),
                    CFString::from("synthetic-service").into_CFType(),
                ),
                (
                    security_framework_static!(kSecAttrAccount, sec_key),
                    CFString::from("synthetic-account").into_CFType(),
                ),
                (
                    security_framework_static!(kSecAttrAccessGroup, sec_key),
                    CFString::from("synthetic-access-group").into_CFType(),
                ),
                (
                    security_framework_static!(kSecAttrAccessible, sec_key),
                    security_framework_static!(
                        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                        sec_string_value
                    ),
                ),
                (
                    security_framework_static!(kSecAttrSynchronizable, sec_key),
                    CFBoolean::false_value().into_CFType(),
                ),
                (
                    security_framework_static!(kSecAttrAccessControl, sec_key),
                    access_control,
                ),
                (
                    security_framework_static!(kSecValueData, sec_key),
                    CFData::from_buffer(secret).into_CFType(),
                ),
            ])
            .to_untyped()
        };

        let backend =
            item_provenance(&attributes(backend_access_control().unwrap().into_CFType())).unwrap();
        assert_eq!(backend.service(), Some("synthetic-service"));
        assert_eq!(backend.account(), Some("synthetic-account"));
        assert_eq!(backend.access_group(), Some("synthetic-access-group"));
        assert_eq!(
            backend.accessible(),
            Some(
                security_framework_static!(kSecAttrAccessibleWhenUnlockedThisDeviceOnly, sec_key)
                    .to_string()
                    .as_str()
            )
        );
        assert_eq!(backend.synchronizable(), Some(false));
        assert!(backend.has_backend_access_control());
        let projection = format!("{backend:?}");
        assert!(!projection.contains("synthetic-provenance-secret"));

        let weaker = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlocked),
            0,
        )
        .unwrap();
        let foreign = item_provenance(&attributes(weaker.into_CFType())).unwrap();
        assert!(!foreign.has_backend_access_control());

        // Absent or mistyped attributes are reported as absent, never guessed.
        let sparse = CFDictionary::from_CFType_pairs(&[(
            security_framework_static!(kSecAttrService, sec_key),
            CFBoolean::true_value().into_CFType(),
        )])
        .to_untyped();
        let sparse = item_provenance(&sparse).unwrap();
        assert_eq!(sparse.service(), None);
        assert_eq!(sparse.account(), None);
        assert_eq!(sparse.synchronizable(), None);
        assert!(!sparse.has_backend_access_control());
    }

    #[test]
    fn write_side_value_data_is_scrubbed_before_release() {
        for length in [1usize, 15, 16, 17, 64] {
            let secret = vec![0xAA; length];
            let data = zeroizing_cf_data(&secret).unwrap();
            assert_eq!(data.bytes(), secret);
            let released = SCRUBBED_RELEASES.with(Cell::get);
            drop(data);
            assert_eq!(SCRUBBED_RELEASES.with(Cell::get), released + 1);
        }

        let secret = b"writ-x";
        let payload = zeroizing_allocate(secret.len() as CFIndex, 0, ptr::null_mut());
        assert!(!payload.is_null());
        // SAFETY: payload holds secret.len() writable bytes from the allocator.
        unsafe {
            ptr::copy_nonoverlapping(secret.as_ptr(), payload.cast::<u8>(), secret.len());
            let (base, layout) = scrub_zeroizing_buffer(payload);
            let scrubbed = std::slice::from_raw_parts(base, layout.size());
            assert!(scrubbed.iter().all(|byte| *byte == 0));
            dealloc(base, layout);
        }
    }

    #[test]
    fn read_side_copy_is_zeroized_and_refuses_invalid_lengths() {
        let data = CFData::from_buffer(b"synthetic-read-secret");
        let mut secret = secret_from_cf_data(&data).unwrap();
        assert_eq!(secret.expose_bytes(), b"synthetic-read-secret");
        secret.zeroize();
        assert!(secret.expose_bytes().is_empty());

        // Empty and oversize values are refused with a value-free code; the
        // copied buffer is zeroized before the refusal drops it.
        for payload in [
            Vec::new(),
            vec![0xAA; credential_lease::MAX_SECRET_BYTES + 1],
        ] {
            let data = CFData::from_buffer(&payload);
            let error = secret_from_cf_data(&data).unwrap_err();
            assert_eq!(error.code(), "credential_lease_keychain_data_invalid");
            assert_eq!(
                format!("{error:?}"),
                "credential_lease_keychain_data_invalid"
            );
        }
    }

    #[test]
    fn item_query_refuses_an_empty_name() {
        for (service, account) in [("", "a"), ("s", ""), ("  ", "a"), ("s", "  ")] {
            let error = KeychainItemQuery::new(service, account).unwrap_err();
            assert_eq!(error.code(), "credential_lease_keychain_item_invalid");
        }
    }
}

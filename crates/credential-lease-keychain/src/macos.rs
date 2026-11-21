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

use core_foundation::array::CFArray;
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
    errSecAuthFailed, errSecDuplicateItem, errSecItemNotFound, errSecSuccess, errSecUnimplemented,
};
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrAccessGroup, kSecAttrAccount, kSecAttrService,
    kSecAttrSynchronizable, kSecClass, kSecClassGenericPassword, kSecMatchLimit, kSecMatchLimitAll,
    kSecReturnAttributes, kSecReturnData, kSecReturnPersistentRef, kSecUseAuthenticationContext,
    kSecUseAuthenticationUI, kSecUseDataProtectionKeychain, kSecValueData,
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
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;
const ERR_SEC_NO_SUCH_KEYCHAIN: i32 = -25294;
const ERR_SEC_INVALID_KEYCHAIN: i32 = -25295;

#[link(name = "Security", kind = "framework")]
extern "C" {
    static kSecValuePersistentRef: CFStringRef;
    static kSecAttrAccessible: CFStringRef;
    static kSecAttrGeneric: CFStringRef;
    static kSecUseAuthenticationUIFail: CFStringRef;
    // SecAccessControlPriv.h — exported by Security.framework though not
    // declared in the public header. Both return references the control
    // owns: the protection class and the ACL constraint dictionary — the
    // two policy fields insertion-time binding does not touch.
    fn SecAccessControlGetProtection(access_control: CFTypeRef) -> CFTypeRef;
    fn SecAccessControlGetConstraints(access_control: CFTypeRef) -> CFTypeRef;
    #[cfg(test)]
    fn SecAccessControlSetBound(access_control: CFTypeRef, bound: u8);
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

/// What one store probe concluded — and therefore what the process may
/// cache.
enum ProbeVerdict {
    /// The round trip proved a usable protected store.
    Supported,
    /// The store can never serve this process: an entitlement or
    /// store-level refusal that outlives any later unlock. Only this
    /// verdict lets selection fall through to the classic backend.
    Unsupported,
    /// The probe could not decide: a locked store, denied interaction, or
    /// any undiagnosed refusal that may clear before the next explicit
    /// call. It answers `None` for this call and is never cached, so the
    /// next call re-probes.
    Unavailable,
}

/// What the probe's failure means for caching: the platform status when a
/// SecItem call refused, or an undiagnosable probe outcome (a failed
/// access-control construction, a malformed result, a failed delete).
enum ProbeFailure {
    Status(i32),
    Undetermined,
}

/// The selection the process may remember: a proven store, or a proven
/// "no usable backend". A temporarily-unavailable verdict is deliberately
/// not representable — it must never be cached.
enum BackendSelection {
    Store(KeychainBackend),
    NoStore,
}

static SELECTED_KEYCHAIN_BACKEND: OnceLock<BackendSelection> = OnceLock::new();

/// Platform refusals that mean "this store will never serve this process"
/// — the binary lacks the entitlement the store requires, or the store
/// itself is absent or invalid. Everything else is treated as transient:
/// a locked keychain or a denied interaction may clear on the next
/// explicit call, so it is reported but never cached.
fn is_permanent_probe_refusal(status: i32) -> bool {
    status == errSecUnimplemented
        || status == ERR_SEC_MISSING_ENTITLEMENT
        || status == ERR_SEC_NO_SUCH_KEYCHAIN
        || status == ERR_SEC_INVALID_KEYCHAIN
}

pub(crate) fn selected_backend() -> Option<KeychainBackend> {
    if let Some(selection) = SELECTED_KEYCHAIN_BACKEND.get() {
        return match selection {
            BackendSelection::Store(backend) => Some(*backend),
            BackendSelection::NoStore => None,
        };
    }
    let selection = match keychain_probe_verdict(KeychainBackend::DataProtection) {
        ProbeVerdict::Supported => BackendSelection::Store(KeychainBackend::DataProtection),
        // The classic fallback is chosen only when Data Protection is
        // verifiably unsupported — a temporarily locked store answers
        // `None` uncached and is re-probed on the next explicit call, so
        // the process is not pinned to a fallback the unlock could undo.
        ProbeVerdict::Unavailable => return None,
        ProbeVerdict::Unsupported => match keychain_probe_verdict(KeychainBackend::Classic) {
            ProbeVerdict::Supported => BackendSelection::Store(KeychainBackend::Classic),
            ProbeVerdict::Unavailable => return None,
            ProbeVerdict::Unsupported => BackendSelection::NoStore,
        },
    };
    match SELECTED_KEYCHAIN_BACKEND.get_or_init(|| selection) {
        BackendSelection::Store(backend) => Some(*backend),
        BackendSelection::NoStore => None,
    }
}

impl Keychain {
    /// Write one protected item: update the existing record when present,
    /// otherwise add it.
    ///
    /// `SecItemUpdate` cannot attach or change an item's `SecAccessControl`
    /// on the Data Protection Keychain: an update carrying one reports
    /// success while the item keeps the protection it was created with.
    /// The write therefore enumerates the records the query matches first.
    /// More than one match refuses before any mutation — an unscoped query
    /// can select records sharing a service and account in several access
    /// groups, and a `SecItemUpdate` or `SecItemDelete` acts on *every*
    /// match, not on the one record a limit-one read returned. The single
    /// selected record is pinned by its persistent reference for every
    /// mutation and verification that follows: an item already carrying
    /// this backend's access control takes a value-only update on the
    /// pinned record; one under any other protection is replaced through
    /// `replace_item`'s recoverable swap — the only
    /// way protection changes; an absent item is added directly. Before
    /// any of that, `resolve_replace_swap` completes or repairs whatever
    /// an earlier swap's recorded state left behind, so an interrupted or
    /// failed replacement can never strand the record it parked. A
    /// duplicate that appears between the check and the add re-runs the
    /// verification once before the last write, and every completed write
    /// re-reads the pinned record's attributes to prove the required
    /// protection landed.
    ///
    /// A query declaring `synchronizable` is refused before any SecItem
    /// call: the platform cannot attach the device-only access control
    /// every write carries to a synchronizable item. A write routed to the
    /// classic store is refused the same way: explicit classic routing
    /// strips that access control — the only protection this backend
    /// writes — so the item could never carry the required protection.
    /// Reads and deletes of existing synchronizable or classic items stay
    /// supported — only writes are refused.
    pub fn set_item(
        &self,
        context: &KeychainAuthContext,
        query: &KeychainItemQuery<'_>,
        secret: &SecretBytes,
    ) -> Result<(), KeychainError> {
        let store = effective_store(query, self.backend)?;
        ensure_write_supported(query, store)?;
        let query_pairs = base_pairs(query, context, self.backend)?;
        let mut retry_on_duplicate = true;
        loop {
            let (found, ambiguous) = match with_keychain_backend(store, || {
                find_matching_item(&query_pairs, store, query.synchronizable != Some(true))
            })? {
                ItemMatch::Absent => (None, false),
                // An ambiguous identity still goes through swap
                // resolution first: a recorded swap's parked original is
                // repaired back to its identity before the refusal, so an
                // interrupted replacement is never left stranded by the
                // verdict.
                ItemMatch::Ambiguous => (None, true),
                ItemMatch::One(item) => (Some(item), false),
            };
            let matched = match resolve_replace_swap(context, query, found.as_ref(), store)? {
                SwapRecovery::Clean if ambiguous => return Err(item_ambiguous()),
                SwapRecovery::Clean => found,
                // The recorded swap was repaired — re-enumerate the
                // identity and dispatch on the records the repair left.
                SwapRecovery::Repaired => continue,
                // A record that is not this swap's claimed the identity
                // while the original is parked — a racing writer, handled
                // like a racing writer at the add.
                SwapRecovery::Duplicate if retry_on_duplicate => {
                    retry_on_duplicate = false;
                    continue;
                }
                SwapRecovery::Duplicate => {
                    return status_result("write", errSecDuplicateItem);
                }
            };
            // A record the platform cannot pin — a synchronizable item —
            // can never carry the required access control, so the write
            // refuses rather than mutating it unpinned.
            if let Some(item) = matched.as_ref() {
                if item.reference.is_none() {
                    return Err(synchronizable_write_invalid());
                }
            }
            match protection_action(matched.as_ref().map(|item| item.protected)) {
                ProtectionAction::UpdateValue => {
                    let item = matched.as_ref().expect("a protected match exists");
                    let pinned = pinned_pairs(
                        item.reference.as_ref().expect("a pinnable match"),
                        context,
                        store,
                    );
                    let pinned_dict = CFDictionary::from_CFType_pairs(&pinned);
                    let update = CFDictionary::from_CFType_pairs(&secret_value_pairs(
                        secret.expose_bytes(),
                    )?);
                    // SAFETY: pinned_dict and update own their CF values
                    // for the synchronous call.
                    let update_status = keychain_effect(store, || unsafe {
                        SecItemUpdate(
                            pinned_dict.as_concrete_TypeRef(),
                            update.as_concrete_TypeRef(),
                        )
                    })?;
                    match keychain_update_transition(update_status) {
                        KeychainUpdateTransition::Complete => {
                            return ensure_write_protected(&pinned, store);
                        }
                        // The item vanished between the protection check
                        // and the update: fall through to the add.
                        KeychainUpdateTransition::AddNew => {}
                        KeychainUpdateTransition::Fail(status) => {
                            return status_result("write", status);
                        }
                    }
                }
                ProtectionAction::ReplaceItem => {
                    let item = matched.as_ref().expect("an unprotected match exists");
                    match self.replace_item(context, query, secret, item, &query_pairs, store)? {
                        ReplaceTransition::Done => return Ok(()),
                        ReplaceTransition::Duplicate if retry_on_duplicate => {
                            retry_on_duplicate = false;
                            continue;
                        }
                        ReplaceTransition::Duplicate => {
                            return status_result("write", errSecDuplicateItem);
                        }
                    }
                }
                ProtectionAction::AddItem => {}
            }
            let mut pairs = query_pairs.clone();
            // The matched record's access group is preserved: a query that
            // declared no group places the write in the record's group,
            // never silently in the default group.
            if query.access_group.is_none() {
                if let Some(group) = matched
                    .as_ref()
                    .and_then(|item| item.access_group.as_deref())
                {
                    pairs.push((
                        security_framework_static!(kSecAttrAccessGroup, sec_key),
                        CFString::from(group).into_CFType(),
                    ));
                }
            }
            pairs.extend(protected_secret_pairs(secret.expose_bytes())?);
            // The add answers the new record's persistent reference so the
            // closing protection proof reads exactly the record written.
            pairs.push((
                security_framework_static!(kSecReturnPersistentRef, sec_key),
                CFBoolean::from(true).into_CFType(),
            ));
            let add_query = CFDictionary::from_CFType_pairs(&pairs);
            let mut added_reference: CFTypeRef = ptr::null();
            // SAFETY: add_query owns all referenced values for the synchronous call.
            let add_status = keychain_effect(store, || unsafe {
                SecItemAdd(add_query.as_concrete_TypeRef(), &mut added_reference)
            })?;
            if add_status == errSecSuccess {
                return ensure_write_protected(
                    &pinned_result_reference(added_reference, context, store)?,
                    store,
                );
            }
            // A duplicate appeared between the check and the add: a
            // racing writer placed the item, and its own protection is
            // unknown — the check runs once more before the last write.
            if add_status == errSecDuplicateItem && retry_on_duplicate {
                retry_on_duplicate = false;
                continue;
            }
            return status_result("write", add_status);
        }
    }

    /// The recoverable replacement of one existing record whose protection
    /// `SecItemUpdate` can never change.
    ///
    /// The swap first records its own durable state — a non-secret record
    /// under the reserved [`REPLACE_STATE_SERVICE`] service naming the
    /// item's identity, the access group the original is parked in, and
    /// this swap's fresh identifier — before the existing record is
    /// touched. Only then is the selected record renamed aside to the
    /// per-swap parked account [`replace_parked_account`] derives — a
    /// mutation pinned to the record's persistent reference that leaves
    /// the record, its access group, and its access control intact — and
    /// only then is the protected item added under the original identity,
    /// carrying this swap's marker in its `kSecAttrGeneric`. An
    /// interrupted swap is therefore always provable: the state record
    /// resolves the parked record and the swap's own replacement without
    /// ever mistaking an unrelated item for either, so
    /// [`resolve_replace_swap`] can restore, roll back, or complete the
    /// swap on any later call or process. A claimed state record or a
    /// failed rename refuses the write with the record untouched; a
    /// failed add or proof renames the record back before the refusal is
    /// reported, and a failed restore is itself reported: the original
    /// stays parked under the name the recorded swap resolves, never
    /// erased.
    ///
    /// The added record's protection is verified *before* the parked
    /// original is removed: a failed proof removes the record the add
    /// placed and restores the original to its identity, so the write
    /// never reports an unproven record as written and never destroys the
    /// existing credential first. Only after the proof lands is the
    /// parked original deleted — pinned, so no other record the identity
    /// matches can be taken with it — and the state record is removed
    /// last, so a failure anywhere still leaves the recorded swap the
    /// next call's recovery resolves. The replacement add preserves the
    /// record's access group when the query declared none.
    fn replace_item(
        &self,
        context: &KeychainAuthContext,
        query: &KeychainItemQuery<'_>,
        secret: &SecretBytes,
        item: &MatchedItem,
        query_pairs: &[(CFString, CFType)],
        store: KeychainBackend,
    ) -> Result<ReplaceTransition, KeychainError> {
        // The swap's durable state and the full add payload are prepared
        // before the existing record is touched: a preparation failure
        // leaves the record intact.
        let swap_id = Uuid::new_v4();
        let state_pairs = swap_state_pairs(query, item, &swap_id, context, store);
        let state_query = CFDictionary::from_CFType_pairs(&state_pairs);
        let mut add_pairs = query_pairs.to_vec();
        if query.access_group.is_none() {
            if let Some(group) = item.access_group.as_deref() {
                add_pairs.push((
                    security_framework_static!(kSecAttrAccessGroup, sec_key),
                    CFString::from(group).into_CFType(),
                ));
            }
        }
        add_pairs.extend(protected_secret_pairs(secret.expose_bytes())?);
        // The replacement is marked with this swap's identifier, so a
        // later call can prove a record at the identity is the swap's
        // own add — and roll it back — without touching an unrelated
        // record.
        add_pairs.push((
            security_framework_static!(kSecAttrGeneric, sec_key),
            CFData::from_buffer(&swap_marker(&swap_id)).into_CFType(),
        ));
        add_pairs.push((
            security_framework_static!(kSecReturnPersistentRef, sec_key),
            CFBoolean::from(true).into_CFType(),
        ));
        let add_query = CFDictionary::from_CFType_pairs(&add_pairs);
        // SAFETY: state_query owns all referenced values for the
        // synchronous call.
        let mut state_reference: CFTypeRef = ptr::null();
        let state_status = keychain_effect(store, || unsafe {
            SecItemAdd(state_query.as_concrete_TypeRef(), &mut state_reference)
        })?;
        if state_status == errSecDuplicateItem {
            // A swap for this identity is already recorded — a racing
            // writer, handled like the add's duplicate.
            return Ok(ReplaceTransition::Duplicate);
        }
        if state_status != errSecSuccess {
            return status_result("write", state_status).map(|_| ReplaceTransition::Done);
        }
        let state_pinned = pinned_result_reference(state_reference, context, store)?;
        let state_dict = CFDictionary::from_CFType_pairs(&state_pinned);
        let reference = item.reference.as_ref().expect("a pinnable match");
        let pinned = pinned_pairs(reference, context, store);
        let pinned_dict = CFDictionary::from_CFType_pairs(&pinned);
        let parked = replace_parked_account(&swap_id);
        let rename = CFDictionary::from_CFType_pairs(&[(
            security_framework_static!(kSecAttrAccount, sec_key),
            CFString::from(parked.as_str()).into_CFType(),
        )]);
        // SAFETY: pinned_dict and rename own their CF values for the
        // synchronous call.
        let rename_status = keychain_effect(store, || unsafe {
            SecItemUpdate(
                pinned_dict.as_concrete_TypeRef(),
                rename.as_concrete_TypeRef(),
            )
        })?;
        if rename_status != errSecSuccess {
            // The original is untouched — the recorded state resolves to
            // no parked record, so a leftover cleans itself on the next
            // call either way.
            let _ = delete_pinned(&state_dict, store);
            if rename_status == errSecDuplicateItem {
                // The per-swap name was claimed between the recovery
                // pass and the rename — a racing writer, handled like a
                // racing writer at the add.
                return Ok(ReplaceTransition::Duplicate);
            }
            return status_result("write", rename_status).map(|_| ReplaceTransition::Done);
        }
        let mut added_reference: CFTypeRef = ptr::null();
        // SAFETY: add_query owns all referenced values for the synchronous call.
        let add_status = keychain_effect(store, || unsafe {
            SecItemAdd(add_query.as_concrete_TypeRef(), &mut added_reference)
        })?;
        // The restore payload puts the parked record back under its
        // original identity — still pinned to the same persistent
        // reference — on every path that cannot keep the swap.
        let restore = CFDictionary::from_CFType_pairs(&[(
            security_framework_static!(kSecAttrAccount, sec_key),
            CFString::from(query.account).into_CFType(),
        )]);
        if add_status != errSecSuccess {
            // The restore is itself reported: when it fails the original
            // stays parked under the name the recorded swap resolves,
            // never erased.
            let restore_status = keychain_effect(store, || unsafe {
                SecItemUpdate(
                    pinned_dict.as_concrete_TypeRef(),
                    restore.as_concrete_TypeRef(),
                )
            })?;
            if restore_status != errSecSuccess {
                return status_result("write", restore_status).map(|_| ReplaceTransition::Done);
            }
            let _ = delete_pinned(&state_dict, store);
            if add_status == errSecDuplicateItem {
                // A racing writer claimed the identity between the rename
                // and the add: the caller re-runs the protection check on
                // whatever the identity now holds.
                return Ok(ReplaceTransition::Duplicate);
            }
            return status_result("write", add_status).map(|_| ReplaceTransition::Done);
        }
        let added = pinned_result_reference(added_reference, context, store)?;
        if let Err(verify) = ensure_write_protected(&added, store) {
            // The new record's protection cannot be proven: the record
            // the add placed is removed and the original returns to its
            // identity — the original is never destroyed before its
            // replacement is verified, and a failed cleanup leaves the
            // recorded swap for the next call's recovery.
            let added_dict = CFDictionary::from_CFType_pairs(&added);
            // SAFETY: added_dict and pinned_dict own their CF values for
            // the synchronous calls.
            let _ = keychain_effect(store, || unsafe {
                SecItemDelete(added_dict.as_concrete_TypeRef())
            });
            let restore_status = keychain_effect(store, || unsafe {
                SecItemUpdate(
                    pinned_dict.as_concrete_TypeRef(),
                    restore.as_concrete_TypeRef(),
                )
            })?;
            if restore_status != errSecSuccess {
                return status_result("write", restore_status).map(|_| ReplaceTransition::Done);
            }
            let _ = delete_pinned(&state_dict, store);
            return Err(verify);
        }
        // SAFETY: pinned_dict owns its CF values for the synchronous call.
        let delete_status = keychain_effect(store, || unsafe {
            SecItemDelete(pinned_dict.as_concrete_TypeRef())
        })?;
        if delete_status != errSecSuccess && delete_status != errSecItemNotFound {
            return status_result("delete", delete_status).map(|_| ReplaceTransition::Done);
        }
        // The state record is spent last: a failure anywhere above still
        // leaves the recorded swap the next call's recovery resolves.
        delete_pinned(&state_dict, store)?;
        Ok(ReplaceTransition::Done)
    }

    /// Append-only add: the item is created or `Duplicate` is reported —
    /// nothing is ever overwritten through this operation. Item contracts
    /// that are append-only resolve `Duplicate` by comparing the existing
    /// record.
    ///
    /// A query declaring `synchronizable` or routing to the classic store
    /// is refused before any SecItem call, for the same reason
    /// [`Keychain::set_item`] refuses them.
    pub fn add_item(
        &self,
        context: &KeychainAuthContext,
        query: &KeychainItemQuery<'_>,
        secret: &SecretBytes,
    ) -> Result<AddItemOutcome, KeychainError> {
        let store = effective_store(query, self.backend)?;
        ensure_write_supported(query, store)?;
        let mut pairs = base_pairs(query, context, self.backend)?;
        pairs.extend(protected_secret_pairs(secret.expose_bytes())?);
        let add_query = CFDictionary::from_CFType_pairs(&pairs);
        // SAFETY: add_query owns all referenced values for the synchronous call.
        let add_status = keychain_effect(store, || unsafe {
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
        let store = effective_store(query, self.backend)?;
        let mut pairs = base_pairs(query, context, self.backend)?;
        pairs.push((
            security_framework_static!(kSecReturnData, sec_key),
            CFBoolean::from(true).into_CFType(),
        ));
        with_keychain_backend(store, || copy_secret_from_query_effect(&pairs, store))
    }

    /// Copy one item with its value bytes, its persistent reference, and
    /// its provenance attributes. A synchronizable item answers with its
    /// persistent reference absent — the platform serves such items only
    /// as attributes and data, so the read does not request one.
    pub fn copy_item(
        &self,
        context: &KeychainAuthContext,
        query: &KeychainItemQuery<'_>,
    ) -> Result<Option<KeychainItem>, KeychainError> {
        let store = effective_store(query, self.backend)?;
        let pairs = copy_item_pairs(query, context, self.backend)?;
        with_keychain_backend(store, || copy_item_from_query_effect(&pairs, store))
    }

    /// Delete one item; an absent item is not an error.
    ///
    /// The delete is pinned to one record's persistent reference for the
    /// same reason [`Keychain::set_item`] pins its mutations: an unscoped
    /// query can match records sharing a service and account in several
    /// access groups, and `SecItemDelete` removes every match. More than
    /// one match refuses `credential_lease_keychain_item_ambiguous`
    /// instead of deleting records the lookup did not select.
    ///
    /// A record the platform cannot name — a synchronizable item, which
    /// Apple documents as served through attribute- and data-only queries
    /// — takes the attribute-scoped path `attribute_scoped_delete_pairs`
    /// builds: the unique match the enumeration verified is narrowed by
    /// the record's own access group and synchronizable flag, and that
    /// scoped query carries the delete.
    ///
    /// An interrupted replacement leaves the original parked under a
    /// per-swap name no identity query reaches: an absent match cannot
    /// report success while a recorded swap still holds the item.
    /// `resolve_swap_for_delete` resolves the recorded state first — the
    /// parked original and the state record itself are removed before
    /// the identity record — so the delete never reports the identity
    /// gone while the swap still owns part of it, and never touches a
    /// record the recorded swap does not prove.
    pub fn delete_item(
        &self,
        context: &KeychainAuthContext,
        query: &KeychainItemQuery<'_>,
    ) -> Result<(), KeychainError> {
        let store = effective_store(query, self.backend)?;
        let query_pairs = base_pairs(query, context, self.backend)?;
        let item = match with_keychain_backend(store, || {
            find_matching_item(&query_pairs, store, query.synchronizable != Some(true))
        })? {
            ItemMatch::Absent => None,
            ItemMatch::Ambiguous => return Err(item_ambiguous()),
            ItemMatch::One(item) => Some(item),
        };
        resolve_swap_for_delete(query, item.as_ref(), context, store)?;
        let Some(item) = item else {
            return Ok(());
        };
        let delete_pairs = match item.reference.as_ref() {
            Some(reference) => pinned_pairs(reference, context, store),
            None => attribute_scoped_delete_pairs(query, &query_pairs, &item),
        };
        let delete_dict = CFDictionary::from_CFType_pairs(&delete_pairs);
        // SAFETY: delete_dict owns valid CF values for the synchronous call.
        let status = keychain_effect(store, || unsafe {
            SecItemDelete(delete_dict.as_concrete_TypeRef())
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
    /// The migration destination is always the Data Protection Keychain:
    /// on any other store the operation refuses
    /// `credential_lease_keychain_migration_target_invalid`, so `Ok(None)`
    /// unambiguously means the source item is absent — a classic handle
    /// cannot masquerade a same-store copy as a migration. A grouped,
    /// synchronizable, or Data-Protection-routed query refuses
    /// `credential_lease_keychain_routing_invalid` instead: the classic
    /// source path cannot honor any of those selectors, so the call
    /// could never address the item it declared.
    pub fn copy_legacy_classic_secret(
        &self,
        context: &KeychainAuthContext,
        query: &KeychainItemQuery<'_>,
        allow_interaction: bool,
    ) -> Result<Option<SecretBytes>, KeychainError> {
        let mut pairs = classic_migration_pairs(query, context, self.backend)?;
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
    /// Keychain: deleting the only copy is never a migration. A grouped,
    /// synchronizable, or Data-Protection-routed query refuses
    /// `credential_lease_keychain_routing_invalid` for the same reason
    /// [`Self::copy_legacy_classic_secret`] does.
    pub fn delete_legacy_classic_item(
        &self,
        context: &KeychainAuthContext,
        query: &KeychainItemQuery<'_>,
        allow_interaction: bool,
    ) -> Result<(), KeychainError> {
        let pairs = classic_migration_pairs(query, context, self.backend)?;
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

/// The store a query actually lands on: the host's explicit routing flag
/// when set, otherwise this handle's probed backend — except a
/// synchronizable item, which the platform serves only from the Data
/// Protection Keychain regardless of the handle's store (TN3137), and an
/// access-group-scoped query, whose `kSecAttrAccessGroup` the classic
/// path strips outright (Security.framework honors the attribute only on
/// the Data Protection store — a grouped query there would match on
/// service and account alone). Both the routing flag and the interaction
/// policy are derived from this store, so a classic-routed query can
/// never escape the backend's classic interaction suppression — the
/// bypass a forced `use_data_protection = false` would otherwise open on
/// a Data Protection handle — and a synchronizable or grouped query
/// always gets the Data Protection no-UI policy and error handling.
fn effective_store(
    query: &KeychainItemQuery<'_>,
    backend: KeychainBackend,
) -> Result<KeychainBackend, KeychainError> {
    match query.use_data_protection {
        Some(true) => Ok(KeychainBackend::DataProtection),
        // A synchronizable or access-group-scoped item cannot live in
        // the classic store — the platform would serve the first from
        // Data Protection anyway, and it would strip the second's
        // scoping attribute, so routing flags that claim classic
        // contradict the declared attributes and are refused rather than
        // silently re-routed or silently de-scoped.
        Some(false) if query.synchronizable == Some(true) || query.access_group.is_some() => {
            Err(routing_invalid())
        }
        Some(false) => Ok(KeychainBackend::Classic),
        None if query.synchronizable == Some(true) => Ok(KeychainBackend::DataProtection),
        // A grouped query keeps its scoping only on the Data Protection
        // store, so implicit routing must not let a fallback-classic
        // handle serve it unscoped.
        None if query.access_group.is_some() => Ok(KeychainBackend::DataProtection),
        None => Ok(backend),
    }
}

/// The refusal for a routing flag that contradicts the query's declared
/// attributes — explicit classic routing on an item only the Data
/// Protection store can scope or host.
fn routing_invalid() -> KeychainError {
    KeychainError::new(
        "credential_lease_keychain_routing_invalid",
        KeychainErrorKind::Failed,
        None,
    )
}

/// The refusal a write issues for an item the platform can never give
/// the required protection: a synchronizable item, which Security.framework
/// serves only as attributes and data — no persistent reference to pin a
/// mutation to and no `SecAccessControl` an add could attach.
fn synchronizable_write_invalid() -> KeychainError {
    KeychainError::new(
        "credential_lease_keychain_synchronizable_write_invalid",
        KeychainErrorKind::Failed,
        None,
    )
}

/// Synchronizable items are readable and deletable through this backend
/// but never writable: Security.framework refuses a `SecAccessControl`
/// on a synchronizable item (`errSecParam`), and dropping the control to
/// satisfy the write would silently store the item without the
/// device-only protection this backend exists to enforce.
///
/// The classic store cannot take the required protection at all: explicit
/// classic routing strips the `SecAccessControl` the write carries — the
/// classic store's separate application ACLs are outside this backend's
/// protection contract — so a classic-routed write is refused before any
/// SecItem call rather than persisted unprotected.
fn ensure_write_supported(
    query: &KeychainItemQuery<'_>,
    store: KeychainBackend,
) -> Result<(), KeychainError> {
    if query.synchronizable == Some(true) {
        return Err(synchronizable_write_invalid());
    }
    if store == KeychainBackend::Classic {
        return Err(KeychainError::new(
            "credential_lease_keychain_classic_write_unsupported",
            KeychainErrorKind::Failed,
            None,
        ));
    }
    Ok(())
}

/// The explicit store routing the probe and every production operation
/// pin alike. An add that leaves the flag unset while carrying
/// `kSecAttrAccessControl` is routed to the Data Protection Keychain by
/// SecItem itself — off the store the operation was built for. The flag
/// is therefore never omitted: `true` on the Data Protection store,
/// `false` on the classic store.
fn data_protection_routing(store: KeychainBackend) -> (CFString, CFType) {
    (
        security_framework_static!(kSecUseDataProtectionKeychain, sec_key),
        CFBoolean::from(store == KeychainBackend::DataProtection).into_CFType(),
    )
}

/// The ordinary item query: class, service, account, the optional storage
/// attributes the host asked for, and the authorized context. The routing
/// flag is always the effective store's explicit pin — the same one the
/// probe uses — so no operation can drift onto a store it was not built
/// for.
fn base_pairs(
    query: &KeychainItemQuery<'_>,
    context: &KeychainAuthContext,
    backend: KeychainBackend,
) -> Result<Vec<(CFString, CFType)>, KeychainError> {
    let store = effective_store(query, backend)?;
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
    if store == KeychainBackend::DataProtection {
        // Ordinary operations on the Data Protection store must never raise
        // authentication UI outside the host's authorization workflow: when
        // the authorized context does not satisfy the item's access
        // control, the call fails `errSecInteractionNotAllowed` — which the
        // caller sees as `AuthorizationRequired` — instead of prompting.
        // Interactive classic operations exist only on the explicit
        // migration entry points, which build their own query.
        pairs.push((
            security_framework_static!(kSecUseAuthenticationUI, sec_key),
            security_framework_static!(kSecUseAuthenticationUIFail, sec_string_value),
        ));
    }
    pairs.push(data_protection_routing(store));
    Ok(pairs)
}

/// The full-copy query pairs: attributes and value data, plus the
/// persistent reference — except for a synchronizable item, which the
/// platform serves only as attributes and data. Requesting a persistent
/// reference there is not a supported return type, so synchronizable
/// reads omit it and the copied item's reference stays `None`.
fn copy_item_pairs(
    query: &KeychainItemQuery<'_>,
    context: &KeychainAuthContext,
    backend: KeychainBackend,
) -> Result<Vec<(CFString, CFType)>, KeychainError> {
    let mut pairs = base_pairs(query, context, backend)?;
    pairs.push((
        security_framework_static!(kSecReturnAttributes, sec_key),
        CFBoolean::from(true).into_CFType(),
    ));
    pairs.push((
        security_framework_static!(kSecReturnData, sec_key),
        CFBoolean::from(true).into_CFType(),
    ));
    if query.synchronizable != Some(true) {
        pairs.push((
            security_framework_static!(kSecReturnPersistentRef, sec_key),
            CFBoolean::from(true).into_CFType(),
        ));
    }
    Ok(pairs)
}

/// The refusal every migration entry point returns when the selected
/// destination is not the Data Protection Keychain.
fn migration_target_invalid() -> KeychainError {
    KeychainError::new(
        "credential_lease_keychain_migration_target_invalid",
        KeychainErrorKind::Failed,
        None,
    )
}

/// Legacy migration source pairs: an explicit classic-only query. Valid
/// only when the selected destination is the Data Protection Keychain —
/// copying and deleting inside the classic store itself is not a
/// migration, so the pairs exist only for a distinct destination. A
/// query whose declared selectors the classic source cannot honor is
/// refused the same way explicit classic routing is: an access group,
/// which the classic path strips outright; a synchronizable item, which
/// the platform serves only from the Data Protection Keychain (TN3137);
/// and an explicit Data Protection routing flag. Dropping any of them
/// would issue a query on service and account alone — silently
/// re-targeting a different item that shares the identifiers, so the
/// read or the delete never reaches SecItem.
fn classic_migration_pairs(
    query: &KeychainItemQuery<'_>,
    context: &KeychainAuthContext,
    destination: KeychainBackend,
) -> Result<Vec<(CFString, CFType)>, KeychainError> {
    if query.access_group.is_some()
        || query.synchronizable == Some(true)
        || query.use_data_protection == Some(true)
    {
        return Err(routing_invalid());
    }
    if destination != KeychainBackend::DataProtection {
        return Err(migration_target_invalid());
    }
    Ok(vec![
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
        data_protection_routing(KeychainBackend::Classic),
    ])
}

/// The add payload: a `SecAccessControl` requiring user presence plus
/// the value bytes. Only `SecItemAdd` can attach the access control;
/// [`Keychain::set_item`]'s update path uses [`secret_value_pairs`]
/// after verifying the existing item already carries it.
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

/// The update payload: the value bytes alone. `SecItemUpdate` cannot
/// attach or change an item's `SecAccessControl`, so the update runs
/// only on an item whose protection [`existing_item_protection`] just
/// verified — carrying the control in the update dictionary would
/// report success while the item kept whatever it was created with.
fn secret_value_pairs(secret: &[u8]) -> Result<Vec<(CFString, CFType)>, KeychainError> {
    Ok(vec![(
        security_framework_static!(kSecValueData, sec_key),
        zeroizing_cf_data(secret)?.into_CFType(),
    )])
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
        // The tail of the allocation may never have been initialized, so the
        // wipe goes through `MaybeUninit<u8>` — a `u8` slice over
        // uninitialized bytes would be undefined behavior regardless of the
        // values written through it.
        std::slice::from_raw_parts_mut(base.cast::<std::mem::MaybeUninit<u8>>(), total).zeroize();
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

/// Run `SecItemCopyMatching` over `pairs`. Any returned object is owned
/// before the status resolves or classic UI restores — in particular, a
/// restore failure must drop the returned object. An absent item and an
/// empty success both answer `None`.
fn copy_matching(
    pairs: &[(CFString, CFType)],
    backend: KeychainBackend,
) -> Result<Option<CFType>, KeychainError> {
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
    Ok(value)
}

/// Data-only copy — the legacy classic read and any path that does not
/// need attributes.
fn copy_secret_from_query_effect(
    pairs: &[(CFString, CFType)],
    backend: KeychainBackend,
) -> Result<Option<SecretBytes>, KeychainError> {
    let Some(value) = copy_matching(pairs, backend)? else {
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
    let Some(value) = copy_matching(pairs, backend)? else {
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
        backend_access_control: dictionary_value(attributes, access_control)
            .is_some_and(|value| access_control_policy_matches(&value, &expected_access_control)),
    })
}

/// Whether a stored `kSecAttrAccessControl` carries this backend's
/// protection policy. `SecItemAdd` re-evaluates the control on insertion
/// and serializes it back with its binding state set, so `CFEqual` on the
/// whole control counts a correctly-protected stored item as different —
/// `SecAccessControlCompare` compares the binding metadata too. The
/// policy comparison covers only the parts that are not binding: the
/// protection class and the ACL constraint dictionary.
fn access_control_policy_matches(value: &CFType, expected: &SecAccessControl) -> bool {
    if value.type_of() != SecAccessControl::type_id() {
        return false;
    }
    // SAFETY: both arguments are live SecAccessControl objects for the
    // calls; the getters return references the controls own, valid for
    // the comparisons below.
    let stored_protection = unsafe { SecAccessControlGetProtection(value.as_CFTypeRef()) };
    let stored_constraints = unsafe { SecAccessControlGetConstraints(value.as_CFTypeRef()) };
    let expected_protection = unsafe { SecAccessControlGetProtection(expected.as_CFTypeRef()) };
    let expected_constraints = unsafe { SecAccessControlGetConstraints(expected.as_CFTypeRef()) };
    cf_equal_or_both_absent(stored_protection, expected_protection)
        && cf_equal_or_both_absent(stored_constraints, expected_constraints)
}

/// `CFEqual` over two possibly-absent references: absent matches absent
/// and never matches present.
fn cf_equal_or_both_absent(left: CFTypeRef, right: CFTypeRef) -> bool {
    match (left.is_null(), right.is_null()) {
        (true, true) => true,
        // SAFETY: both references name live Core Foundation objects.
        (false, false) => unsafe { CFEqual(left, right) != 0 },
        _ => false,
    }
}

/// What a mutation query matched — and therefore what the mutation may
/// act on. `Ambiguous` refuses: an unscoped query can match records
/// sharing a service and account in several access groups, and a
/// `SecItemUpdate` or `SecItemDelete` acts on *every* match, not on the
/// one record a limit-one read returned, so a mutation may only proceed
/// when the lookup selected exactly one record.
enum ItemMatch {
    Absent,
    One(MatchedItem),
    Ambiguous,
}

/// The one record the lookup selected: the persistent reference every
/// pinned mutation and verification addresses — `None` only for a record
/// the platform cannot name, a synchronizable item — the record's
/// verified protection, its `kSecAttrGeneric` marker, and the access
/// group and synchronizable flag an attribute-scoped operation
/// preserves.
struct MatchedItem {
    reference: Option<CFData>,
    protected: bool,
    access_group: Option<String>,
    synchronizable: Option<bool>,
    generic: Option<Vec<u8>>,
}

/// The outcome of a tombstone-swap replacement: completed, or the
/// replacement add met a racing writer and the protection check runs
/// again.
enum ReplaceTransition {
    Done,
    Duplicate,
}

/// The refusal a mutation issues when the lookup selected more than one
/// record: acting on one picked match could still update or delete every
/// match, so the write refuses before any SecItem mutation runs.
fn item_ambiguous() -> KeychainError {
    KeychainError::new(
        "credential_lease_keychain_item_ambiguous",
        KeychainErrorKind::Failed,
        None,
    )
}

/// The enumeration query [`find_matching_item`] issues: every record's
/// attributes over every match, never value data. The persistent
/// reference is requested only where the caller's query can address a
/// record the platform can name — a synchronizable-scoped query omits
/// it, since the platform serves those records as attributes and data
/// alone.
fn enumeration_pairs(
    query_pairs: &[(CFString, CFType)],
    request_reference: bool,
) -> Vec<(CFString, CFType)> {
    let mut pairs = query_pairs.to_vec();
    pairs.push((
        security_framework_static!(kSecReturnAttributes, sec_key),
        CFBoolean::from(true).into_CFType(),
    ));
    if request_reference {
        pairs.push((
            security_framework_static!(kSecReturnPersistentRef, sec_key),
            CFBoolean::from(true).into_CFType(),
        ));
    }
    pairs.push((
        security_framework_static!(kSecMatchLimit, sec_key),
        security_framework_static!(kSecMatchLimitAll, sec_string_value),
    ));
    pairs
}

/// Enumerate every record the query addresses. The attribute query rides
/// the caller's `query_pairs` — the same pinned store the operation
/// targets — through [`enumeration_pairs`]. A lone match may arrive
/// unboxed as a bare attribute dictionary rather than a one-element
/// array; both shapes are accepted.
fn find_matching_item(
    query_pairs: &[(CFString, CFType)],
    store: KeychainBackend,
    request_reference: bool,
) -> Result<ItemMatch, KeychainError> {
    let pairs = enumeration_pairs(query_pairs, request_reference);
    let Some(value) = copy_matching(&pairs, store)? else {
        return Ok(ItemMatch::Absent);
    };
    match value.downcast::<CFArray>() {
        Some(array) => match array.len() {
            0 => Ok(ItemMatch::Absent),
            // SAFETY: get_unchecked is in bounds, and the array owns live
            // CF objects wrapped under the get rule for inspection.
            1 => unsafe {
                matched_item(&CFType::wrap_under_get_rule(
                    *array.get_unchecked(0) as CFTypeRef
                ))
            },
            _ => Ok(ItemMatch::Ambiguous),
        },
        None => matched_item(&value),
    }
}

/// The one matched record projected for mutation decisions: its pinned
/// reference where the platform can name one, its proven protection, and
/// the access group and synchronizable flag an attribute-scoped
/// operation preserves. A synchronizable record arrives without a
/// persistent reference — the platform serves it only as attributes and
/// data — so the projection keeps `None` and the caller decides which
/// operations may address it.
fn matched_item(value: &CFType) -> Result<ItemMatch, KeychainError> {
    let attributes = value.downcast::<CFDictionary>().ok_or_else(data_invalid)?;
    let reference = dictionary_data(&attributes, unsafe { kSecValuePersistentRef });
    let generic = dictionary_data(&attributes, unsafe { kSecAttrGeneric })
        .map(|generic| generic.bytes().to_vec());
    let provenance = item_provenance(&attributes)?;
    Ok(ItemMatch::One(MatchedItem {
        reference,
        protected: provenance.has_backend_access_control(),
        access_group: provenance.access_group().map(str::to_owned),
        synchronizable: provenance.synchronizable(),
        generic,
    }))
}

/// The delete query for a record the platform cannot name with a
/// persistent reference — a synchronizable item. The unique match the
/// enumeration already verified is narrowed by the record's own
/// attributes: its access group and synchronizable flag ride the
/// caller's query pairs when the query did not declare them, so the
/// scoped query still names exactly that record. Everything else —
/// service, account, authorization context, the pinned store — is the
/// same query the enumeration ran.
fn attribute_scoped_delete_pairs(
    query: &KeychainItemQuery<'_>,
    query_pairs: &[(CFString, CFType)],
    item: &MatchedItem,
) -> Vec<(CFString, CFType)> {
    let mut pairs = query_pairs.to_vec();
    if query.access_group.is_none() {
        if let Some(group) = item.access_group.as_deref() {
            pairs.push((
                security_framework_static!(kSecAttrAccessGroup, sec_key),
                CFString::from(group).into_CFType(),
            ));
        }
    }
    if query.synchronizable.is_none() {
        if let Some(synchronizable) = item.synchronizable {
            pairs.push((
                security_framework_static!(kSecAttrSynchronizable, sec_key),
                CFBoolean::from(synchronizable).into_CFType(),
            ));
        }
    }
    pairs
}

/// The service every swap-state record lives under: a reserved namespace
/// outside the caller's own items, so a state record can never collide
/// with an item the backend serves.
const REPLACE_STATE_SERVICE: &str = "credential-lease.replace.tombstone";

/// The none sentinel in a swap-state value's group field: an ungrouped
/// parked record records no access group.
const REPLACE_STATE_NONE: u32 = u32::MAX;

/// The account a replacement parks the original record under while the
/// swap runs: it carries the swap's own random identifier, so no account
/// a caller could supply is ever a parked record — the only durable
/// proof a parked record belongs to a swap is the state record that
/// names it.
fn replace_parked_account(swap_id: &Uuid) -> String {
    format!("credential-lease.replace.tombstone.{swap_id}")
}

/// The swap-state record's account — deterministic per item identity so
/// a second swap for the same item reports a duplicate instead of
/// writing a competing record. The name itself is never parsed back:
/// the record's value carries the identity it proves.
fn swap_state_account(service: &str, account: &str) -> String {
    format!("state.{service}\u{1f}{account}")
}

/// The durable marker the replacement record carries in its
/// `kSecAttrGeneric` attribute: bound to the swap's identifier, it lets
/// a later call prove a record at the identity is this swap's own
/// replacement — and roll it back or clean up around it — without
/// touching an unrelated record it could never tell apart.
fn swap_marker(swap_id: &Uuid) -> Vec<u8> {
    let mut marker = b"clrt".to_vec();
    marker.extend_from_slice(swap_id.as_bytes());
    marker
}

/// The durable state one replacement records before it touches the
/// item. The value is not a secret — only the identifiers the swap
/// needs to be found and proven again.
struct SwapStateValue {
    /// The service the swapped item lives under.
    service: String,
    /// The account the swapped item lives under.
    account: String,
    /// The access group the parked original was parked in — `None` for
    /// an ungrouped record. Recorded at swap time so a later call
    /// resolves the interruption by the swap's own scope, never by
    /// whatever record the identity happens to hold then.
    parked_group: Option<String>,
    /// This swap's identifier — the parked record's name and the
    /// replacement's `kSecAttrGeneric` marker both derive from it.
    swap_id: Uuid,
}

/// Serialize the swap state: `clrs`, a version byte, the length-prefixed
/// service, account, and parked access group (or the none sentinel),
/// and the swap identifier.
fn encode_swap_state(
    service: &str,
    account: &str,
    parked_group: Option<&str>,
    swap_id: &Uuid,
) -> Vec<u8> {
    fn field(value: &mut Vec<u8>, bytes: Option<&[u8]>) {
        match bytes {
            Some(bytes) => {
                value.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                value.extend_from_slice(bytes);
            }
            None => value.extend_from_slice(&REPLACE_STATE_NONE.to_be_bytes()),
        }
    }
    let mut value = Vec::new();
    value.extend_from_slice(b"clrs");
    value.push(1);
    field(&mut value, Some(service.as_bytes()));
    field(&mut value, Some(account.as_bytes()));
    field(&mut value, parked_group.map(str::as_bytes));
    value.extend_from_slice(swap_id.as_bytes());
    value
}

/// Parse a swap-state value. Anything that does not decode exactly —
/// foreign data, a truncated record, trailing bytes — is not this
/// backend's state and is never acted on.
fn decode_swap_state(value: &[u8]) -> Option<SwapStateValue> {
    fn take<'a>(rest: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
        let (head, tail) = rest.split_at_checked(len)?;
        *rest = tail;
        Some(head)
    }
    fn field(rest: &mut &[u8]) -> Option<Option<String>> {
        let length = u32::from_be_bytes(take(rest, 4)?.try_into().ok()?);
        if length == REPLACE_STATE_NONE {
            return Some(None);
        }
        let bytes = take(rest, usize::try_from(length).ok()?)?;
        Some(Some(String::from_utf8(bytes.to_vec()).ok()?))
    }
    let mut rest = value;
    if take(&mut rest, 4)? != b"clrs".as_slice() || take(&mut rest, 1)? != [1].as_slice() {
        return None;
    }
    let (Some(service), Some(account)) = (field(&mut rest)?, field(&mut rest)?) else {
        return None;
    };
    let parked_group = field(&mut rest)?;
    let swap_id = Uuid::from_bytes(take(&mut rest, 16)?.try_into().ok()?);
    rest.is_empty().then_some(SwapStateValue {
        service,
        account,
        parked_group,
        swap_id,
    })
}

/// One recorded replacement: the state record's own persistent
/// reference, the swap's identifier, the access group the state record
/// itself was stored under — the caller's intended group — and the
/// access group the swap recorded for the parked original.
#[derive(Debug)]
struct SwapState {
    reference: CFData,
    swap_id: Uuid,
    caller_group: Option<String>,
    parked_group: Option<String>,
}

/// The add payload for one swap's state record: non-secret metadata —
/// the identity the swap serves, the access group the original is
/// parked in, and the swap's identifier — under the reserved service,
/// in the caller's intended group when one applies. The record is never
/// synchronizable and is pinned for the swap's own cleanup through
/// `kSecReturnPersistentRef`.
fn swap_state_pairs(
    query: &KeychainItemQuery<'_>,
    item: &MatchedItem,
    swap_id: &Uuid,
    context: &KeychainAuthContext,
    store: KeychainBackend,
) -> Vec<(CFString, CFType)> {
    let mut pairs = vec![
        (
            security_framework_static!(kSecClass, sec_key),
            security_framework_static!(kSecClassGenericPassword, sec_string_value),
        ),
        (
            security_framework_static!(kSecAttrService, sec_key),
            CFString::from(REPLACE_STATE_SERVICE).into_CFType(),
        ),
        (
            security_framework_static!(kSecAttrAccount, sec_key),
            CFString::from(swap_state_account(query.service, query.account).as_str()).into_CFType(),
        ),
        (
            security_framework_static!(kSecAttrSynchronizable, sec_key),
            CFBoolean::from(false).into_CFType(),
        ),
        (
            security_framework_static!(kSecUseAuthenticationContext, sec_key),
            context.as_cf_type(),
        ),
    ];
    if let Some(group) = query.access_group.or(item.access_group.as_deref()) {
        pairs.push((
            security_framework_static!(kSecAttrAccessGroup, sec_key),
            CFString::from(group).into_CFType(),
        ));
    }
    if store == KeychainBackend::DataProtection {
        pairs.push((
            security_framework_static!(kSecUseAuthenticationUI, sec_key),
            security_framework_static!(kSecUseAuthenticationUIFail, sec_string_value),
        ));
    }
    pairs.push(data_protection_routing(store));
    pairs.push((
        security_framework_static!(kSecValueData, sec_key),
        CFData::from_buffer(&encode_swap_state(
            query.service,
            query.account,
            item.access_group.as_deref(),
            swap_id,
        ))
        .into_CFType(),
    ));
    pairs.push((
        security_framework_static!(kSecReturnPersistentRef, sec_key),
        CFBoolean::from(true).into_CFType(),
    ));
    pairs
}

/// The enumeration query for recorded swaps: every record under the
/// reserved service, with the attributes, value data, and persistent
/// reference recovery parses.
fn swap_state_query_pairs(
    context: &KeychainAuthContext,
    store: KeychainBackend,
) -> Vec<(CFString, CFType)> {
    let mut pairs = vec![
        (
            security_framework_static!(kSecClass, sec_key),
            security_framework_static!(kSecClassGenericPassword, sec_string_value),
        ),
        (
            security_framework_static!(kSecAttrService, sec_key),
            CFString::from(REPLACE_STATE_SERVICE).into_CFType(),
        ),
        (
            security_framework_static!(kSecAttrSynchronizable, sec_key),
            CFBoolean::from(false).into_CFType(),
        ),
        (
            security_framework_static!(kSecUseAuthenticationContext, sec_key),
            context.as_cf_type(),
        ),
    ];
    if store == KeychainBackend::DataProtection {
        pairs.push((
            security_framework_static!(kSecUseAuthenticationUI, sec_key),
            security_framework_static!(kSecUseAuthenticationUIFail, sec_string_value),
        ));
    }
    pairs.push(data_protection_routing(store));
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
    pairs.push((
        security_framework_static!(kSecMatchLimit, sec_key),
        security_framework_static!(kSecMatchLimitAll, sec_string_value),
    ));
    pairs
}

/// Every recorded swap for the query's identity. A record under the
/// reserved service proves a swap only when its value decodes and names
/// exactly this service and account — a foreign or unparseable record
/// is ignored, and a matching record that cannot be pinned can never be
/// cleaned, so it refuses rather than wedge every later call.
fn find_swap_states(
    query: &KeychainItemQuery<'_>,
    context: &KeychainAuthContext,
    store: KeychainBackend,
) -> Result<Vec<SwapState>, KeychainError> {
    let pairs = swap_state_query_pairs(context, store);
    let Some(value) = copy_matching(&pairs, store)? else {
        return Ok(Vec::new());
    };
    let mut states = Vec::new();
    let mut collect = |value: &CFType| -> Result<(), KeychainError> {
        let attributes = value.downcast::<CFDictionary>().ok_or_else(data_invalid)?;
        let Some(state_value) = dictionary_data(&attributes, unsafe { kSecValueData }) else {
            return Ok(());
        };
        let Some(decoded) = decode_swap_state(state_value.bytes()) else {
            return Ok(());
        };
        if decoded.service != query.service || decoded.account != query.account {
            return Ok(());
        }
        let Some(reference) = dictionary_data(&attributes, unsafe { kSecValuePersistentRef })
        else {
            return Err(data_invalid());
        };
        states.push(SwapState {
            reference,
            swap_id: decoded.swap_id,
            caller_group: dictionary_string(&attributes, unsafe { kSecAttrAccessGroup }),
            parked_group: decoded.parked_group,
        });
        Ok(())
    };
    match value.downcast::<CFArray>() {
        Some(array) => {
            for index in 0..array.len() {
                // SAFETY: index is in bounds, and the array owns live CF
                // objects wrapped under the get rule for inspection.
                collect(unsafe {
                    &CFType::wrap_under_get_rule(*array.get_unchecked(index) as CFTypeRef)
                })?;
            }
        }
        None => collect(&value)?,
    }
    Ok(states)
}

/// The recorded swap this call resolves, if any. A declared access
/// group selects only the swap recorded under it — a swap for the same
/// identity in another group is a different item and is left alone.
/// With no declared group, a single recorded swap resolves the caller's
/// intended group by its own; several recorded swaps leave the intended
/// group ambiguous, and resolution refuses rather than act on the wrong
/// group's records.
fn select_swap_state(
    states: Vec<SwapState>,
    declared_group: Option<&str>,
) -> Result<Option<SwapState>, KeychainError> {
    let mut states: Vec<SwapState> = states
        .into_iter()
        .filter(|state| match declared_group {
            Some(group) => state.caller_group.as_deref() == Some(group),
            None => true,
        })
        .collect();
    match states.len() {
        0 => Ok(None),
        1 => Ok(states.pop()),
        _ => Err(item_ambiguous()),
    }
}

/// The parked-record lookup a recorded swap resolves: the per-swap
/// parked account under the caller's service, narrowed to the access
/// group the swap recorded — so an unscoped retry always finds the
/// parked original in the group the swap put it in, not whichever group
/// the identity happens to hold a record in — never synchronizable,
/// because a swap only ever parks a pinnable record.
fn find_parked_record(
    query: &KeychainItemQuery<'_>,
    state: &SwapState,
    context: &KeychainAuthContext,
    store: KeychainBackend,
) -> Result<ItemMatch, KeychainError> {
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
            CFString::from(replace_parked_account(&state.swap_id).as_str()).into_CFType(),
        ),
    ];
    if let Some(group) = state.parked_group.as_deref() {
        pairs.push((
            security_framework_static!(kSecAttrAccessGroup, sec_key),
            CFString::from(group).into_CFType(),
        ));
    }
    pairs.push((
        security_framework_static!(kSecAttrSynchronizable, sec_key),
        CFBoolean::from(false).into_CFType(),
    ));
    pairs.push((
        security_framework_static!(kSecUseAuthenticationContext, sec_key),
        context.as_cf_type(),
    ));
    if store == KeychainBackend::DataProtection {
        pairs.push((
            security_framework_static!(kSecUseAuthenticationUI, sec_key),
            security_framework_static!(kSecUseAuthenticationUIFail, sec_string_value),
        ));
    }
    pairs.push(data_protection_routing(store));
    find_matching_item(&pairs, store, true)
}

/// What the state a recorded swap left behind tells the write to do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SwapVerdict {
    /// The parked original is gone — the state record's proof is spent
    /// and only its own removal remains.
    StaleClean,
    /// The original is parked and the swap's identity is free: rename
    /// the parked record back — the restore direction, never away from
    /// it — and dispatch on it.
    Restore,
    /// The identity holds this swap's own verified replacement: only
    /// the parked original's and the state record's pinned deletions
    /// remain.
    Cleanup,
    /// The identity holds this swap's own unproven replacement — an add
    /// the interruption left before its verification or rollback:
    /// remove that record, restore the parked original, and re-run.
    Rollback,
    /// A record that is not this swap's holds the identity while the
    /// original is parked: a racing writer claimed it mid-swap — the
    /// same verdict the add's duplicate carries.
    Duplicate,
}

/// The verdict a recorded swap yields, before any SecItem mutation
/// runs. Only an unprotected, pinnable record can be a parked original
/// — the swap parks exactly that — so a protected or unnameable record
/// at the parked name is foreign and is refused rather than touched.
/// The identity record counts only when it sits in the swap's own
/// group: an unscoped caller can match a record in a different group,
/// and that record is not this swap's identity. A marked identity
/// record is the swap's own replacement — protected means the swap's
/// add proved out, unprotected means the interruption left it before
/// verification — and anything else holding the swap's identity is a
/// competing writer.
fn swap_verdict(
    state: &SwapState,
    parked: &ItemMatch,
    identity: Option<&MatchedItem>,
) -> Result<SwapVerdict, KeychainError> {
    let parked = match parked {
        ItemMatch::Absent => return Ok(SwapVerdict::StaleClean),
        ItemMatch::Ambiguous => return Err(item_ambiguous()),
        ItemMatch::One(parked) => parked,
    };
    if parked.protected || parked.reference.is_none() {
        return Err(data_invalid());
    }
    let marker = swap_marker(&state.swap_id);
    Ok(match identity {
        Some(item) if item.access_group.as_deref() != state.parked_group.as_deref() => {
            SwapVerdict::Restore
        }
        Some(item) if item.generic.as_deref() == Some(marker.as_slice()) => {
            if item.protected {
                SwapVerdict::Cleanup
            } else {
                SwapVerdict::Rollback
            }
        }
        Some(_) => SwapVerdict::Duplicate,
        None => SwapVerdict::Restore,
    })
}

/// What the swap-resolution pass hands back to the write.
enum SwapRecovery {
    /// No recorded swap applies: dispatch on the caller's match.
    Clean,
    /// A recorded swap was resolved — the store changed, so the write
    /// re-enumerates and dispatches on the records the resolution left.
    Repaired,
    /// A record that is not this swap's holds the identity while the
    /// original is parked — the same verdict a racing writer gets.
    Duplicate,
}

/// Delete the record a pinned query names. An already-absent record is
/// not an error; any other failure is the caller's to report.
fn delete_pinned(
    pinned_dict: &CFDictionary<CFString, CFType>,
    store: KeychainBackend,
) -> Result<(), KeychainError> {
    // SAFETY: pinned_dict owns valid CF values for the synchronous call.
    let status = keychain_effect(store, || unsafe {
        SecItemDelete(pinned_dict.as_concrete_TypeRef())
    })?;
    if status != errSecSuccess && status != errSecItemNotFound {
        status_result("delete", status)?;
    }
    Ok(())
}

/// The pinned update that returns a parked record to its identity —
/// the restore direction, never away from it.
fn restore_parked(
    pinned_dict: &CFDictionary<CFString, CFType>,
    account: &str,
    store: KeychainBackend,
) -> Result<i32, KeychainError> {
    let restore = CFDictionary::from_CFType_pairs(&[(
        security_framework_static!(kSecAttrAccount, sec_key),
        CFString::from(account).into_CFType(),
    )]);
    // SAFETY: pinned_dict and restore own their CF values for the
    // synchronous call.
    keychain_effect(store, || unsafe {
        SecItemUpdate(
            pinned_dict.as_concrete_TypeRef(),
            restore.as_concrete_TypeRef(),
        )
    })
}

/// Resolve the state an interrupted or failed replacement recorded.
/// The state record — never a derivable name — proves what belongs to
/// the swap: a parked original under a free identity is renamed back
/// before the swap re-runs, a leftover beside the swap's verified
/// replacement is deleted pinned, the swap's own unproven replacement
/// is rolled back and restored around, and an unrelated record holding
/// the identity is a racing writer's verdict — never touched.
fn resolve_replace_swap(
    context: &KeychainAuthContext,
    query: &KeychainItemQuery<'_>,
    matched: Option<&MatchedItem>,
    store: KeychainBackend,
) -> Result<SwapRecovery, KeychainError> {
    let states = with_keychain_backend(store, || find_swap_states(query, context, store))?;
    let Some(state) = select_swap_state(states, query.access_group)? else {
        return Ok(SwapRecovery::Clean);
    };
    let parked_match =
        with_keychain_backend(store, || find_parked_record(query, &state, context, store))?;
    let state_pinned =
        CFDictionary::from_CFType_pairs(&pinned_pairs(&state.reference, context, store));
    match swap_verdict(&state, &parked_match, matched)? {
        SwapVerdict::StaleClean => {
            delete_pinned(&state_pinned, store)?;
            Ok(SwapRecovery::Repaired)
        }
        SwapVerdict::Restore => {
            let ItemMatch::One(parked) = parked_match else {
                unreachable!("a restore verdict requires a parked match")
            };
            let pinned = CFDictionary::from_CFType_pairs(&pinned_pairs(
                parked.reference.as_ref().expect("a pinnable parked record"),
                context,
                store,
            ));
            let restore_status = restore_parked(&pinned, query.account, store)?;
            if restore_status == errSecDuplicateItem {
                // A record claimed the identity between the enumeration
                // and the restore — a racing writer.
                return Ok(SwapRecovery::Duplicate);
            }
            if restore_status != errSecSuccess {
                status_result("write", restore_status)?;
            }
            delete_pinned(&state_pinned, store)?;
            Ok(SwapRecovery::Repaired)
        }
        SwapVerdict::Cleanup => {
            let ItemMatch::One(parked) = parked_match else {
                unreachable!("a cleanup verdict requires a parked match")
            };
            // The swap's verified add holds the identity: only the
            // parked original's pinned deletion and the state record's
            // removal remain — the state is spent last so a failure
            // still leaves the swap resolvable.
            let pinned = CFDictionary::from_CFType_pairs(&pinned_pairs(
                parked.reference.as_ref().expect("a pinnable parked record"),
                context,
                store,
            ));
            delete_pinned(&pinned, store)?;
            delete_pinned(&state_pinned, store)?;
            Ok(SwapRecovery::Repaired)
        }
        SwapVerdict::Rollback => {
            let ItemMatch::One(parked) = parked_match else {
                unreachable!("a rollback verdict requires a parked match")
            };
            // The swap's own unproven replacement goes first — pinned,
            // so no other record is taken with it — then the parked
            // original returns to its identity, and the state record is
            // spent last.
            let Some(identity) = matched.and_then(|item| item.reference.as_ref()) else {
                // A marked identity record that cannot be pinned can
                // never be proven the swap's own — refuse rather than
                // touch it unpinned.
                return Err(data_invalid());
            };
            let identity_pinned =
                CFDictionary::from_CFType_pairs(&pinned_pairs(identity, context, store));
            delete_pinned(&identity_pinned, store)?;
            let pinned = CFDictionary::from_CFType_pairs(&pinned_pairs(
                parked.reference.as_ref().expect("a pinnable parked record"),
                context,
                store,
            ));
            let restore_status = restore_parked(&pinned, query.account, store)?;
            if restore_status == errSecDuplicateItem {
                return Ok(SwapRecovery::Duplicate);
            }
            if restore_status != errSecSuccess {
                status_result("write", restore_status)?;
            }
            delete_pinned(&state_pinned, store)?;
            Ok(SwapRecovery::Repaired)
        }
        SwapVerdict::Duplicate => Ok(SwapRecovery::Duplicate),
    }
}

/// Resolve a recorded swap for a delete: the parked original and the
/// state record are removed before the identity record, so the delete
/// never reports the item gone while the swap still owns part of it.
/// A record at the recorded parked name that cannot be this swap's —
/// protected, or unnameable — is refused untouched. An unscoped delete
/// that matched a record in a different group than the recorded swap
/// cannot tell which item the caller meant and refuses instead of
/// deleting across groups.
fn resolve_swap_for_delete(
    query: &KeychainItemQuery<'_>,
    matched: Option<&MatchedItem>,
    context: &KeychainAuthContext,
    store: KeychainBackend,
) -> Result<(), KeychainError> {
    let states = with_keychain_backend(store, || find_swap_states(query, context, store))?;
    let Some(state) = select_swap_state(states, query.access_group)? else {
        return Ok(());
    };
    if let Some(item) = matched {
        if item.access_group.as_deref() != state.parked_group.as_deref() {
            return Err(item_ambiguous());
        }
    }
    match with_keychain_backend(store, || find_parked_record(query, &state, context, store))? {
        ItemMatch::Absent => {}
        ItemMatch::Ambiguous => return Err(item_ambiguous()),
        ItemMatch::One(parked) => {
            if parked.protected || parked.reference.is_none() {
                return Err(data_invalid());
            }
            let pinned = CFDictionary::from_CFType_pairs(&pinned_pairs(
                parked.reference.as_ref().expect("a pinnable parked record"),
                context,
                store,
            ));
            delete_pinned(&pinned, store)?;
        }
    }
    let state_pinned =
        CFDictionary::from_CFType_pairs(&pinned_pairs(&state.reference, context, store));
    delete_pinned(&state_pinned, store)
}

/// A mutation or verification query pinned to one record's persistent
/// reference: the platform addresses the exact record the reference
/// names, so an update, a delete, or an attributes read lands on the
/// record the lookup selected — never on every record an unscoped query
/// happens to match. The routing pin and authorization context are the
/// same ones the ordinary query carries.
fn pinned_pairs(
    reference: &CFData,
    context: &KeychainAuthContext,
    store: KeychainBackend,
) -> Vec<(CFString, CFType)> {
    let mut pairs = vec![
        (
            security_framework_static!(kSecClass, sec_key),
            security_framework_static!(kSecClassGenericPassword, sec_string_value),
        ),
        (
            security_framework_static!(kSecValuePersistentRef, sec_key),
            reference.clone().into_CFType(),
        ),
        (
            security_framework_static!(kSecUseAuthenticationContext, sec_key),
            context.as_cf_type(),
        ),
    ];
    if store == KeychainBackend::DataProtection {
        pairs.push((
            security_framework_static!(kSecUseAuthenticationUI, sec_key),
            security_framework_static!(kSecUseAuthenticationUIFail, sec_string_value),
        ));
    }
    pairs.push(data_protection_routing(store));
    pairs
}

/// The pinned verification query for a record a `SecItemAdd` just
/// created. The add requested `kSecReturnPersistentRef`, so the closing
/// protection proof reads exactly the record written, not whatever else
/// the identity could match at verification time.
fn pinned_result_reference(
    added_reference: CFTypeRef,
    context: &KeychainAuthContext,
    store: KeychainBackend,
) -> Result<Vec<(CFString, CFType)>, KeychainError> {
    if added_reference.is_null() {
        return Err(data_invalid());
    }
    // SAFETY: SecItemAdd returned its result object at +1 ownership.
    let reference = unsafe { CFType::wrap_under_create_rule(added_reference) };
    let reference = reference.downcast::<CFData>().ok_or_else(data_invalid)?;
    Ok(pinned_pairs(&reference, context, store))
}

/// The stored protection of the record a pinned query names: `None` when
/// the record is absent, `Some(true)` only when it carries this backend's
/// protection policy, `Some(false)` under any other protection.
fn pinned_item_protection(
    pinned_pairs: &[(CFString, CFType)],
    store: KeychainBackend,
) -> Result<Option<bool>, KeychainError> {
    let mut pairs = pinned_pairs.to_vec();
    pairs.push((
        security_framework_static!(kSecReturnAttributes, sec_key),
        CFBoolean::from(true).into_CFType(),
    ));
    let Some(value) = copy_matching(&pairs, store)? else {
        return Ok(None);
    };
    let attributes = value.downcast::<CFDictionary>().ok_or_else(data_invalid)?;
    item_provenance(&attributes).map(|provenance| Some(provenance.has_backend_access_control()))
}

/// The closing check of every protected write: re-read the pinned
/// record's attributes on the same store and require the access control
/// this backend writes. A write the store reported successful but cannot
/// prove its protection on — a racing writer's replacement, or a store
/// that silently dropped the control — refuses rather than reporting an
/// unprotected item as written.
fn ensure_write_protected(
    pinned_pairs: &[(CFString, CFType)],
    store: KeychainBackend,
) -> Result<(), KeychainError> {
    match pinned_item_protection(pinned_pairs, store)? {
        Some(true) => Ok(()),
        _ => Err(KeychainError::new(
            "credential_lease_keychain_protection_unenforced",
            KeychainErrorKind::Failed,
            None,
        )),
    }
}

/// What the existing item's verified protection allows [`Keychain::set_item`]
/// to do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProtectionAction {
    /// The item already carries this backend's access control: update
    /// its value only — the protection stays whatever it was created
    /// with, and it was just proven correct.
    UpdateValue,
    /// The item exists under different protection `SecItemUpdate` can
    /// never change: delete it so the add re-stores it protected.
    ReplaceItem,
    /// No item exists: add one carrying the required access control.
    AddItem,
}

fn protection_action(existing_protection: Option<bool>) -> ProtectionAction {
    match existing_protection {
        Some(true) => ProtectionAction::UpdateValue,
        Some(false) => ProtectionAction::ReplaceItem,
        None => ProtectionAction::AddItem,
    }
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

fn keychain_probe_verdict(backend: KeychainBackend) -> ProbeVerdict {
    match keychain_roundtrip_probe(backend) {
        Ok(()) => ProbeVerdict::Supported,
        Err(ProbeFailure::Status(status)) if is_permanent_probe_refusal(status) => {
            ProbeVerdict::Unsupported
        }
        Err(_) => ProbeVerdict::Unavailable,
    }
}

fn keychain_roundtrip_probe(backend: KeychainBackend) -> Result<(), ProbeFailure> {
    with_keychain_backend(backend, || Ok(silent_keychain_roundtrip_probe(backend)))
        .map_err(|_| ProbeFailure::Undetermined)?
}

fn silent_keychain_roundtrip_probe(backend: KeychainBackend) -> Result<(), ProbeFailure> {
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
    pairs.push(data_protection_routing(backend));
    // A production write always carries a SecAccessControl; probing without
    // one would pass on ad hoc builds that cannot actually persist a
    // protected item (errSecMissingEntitlement) and misreport the store as
    // available. A plain ACL exercises the same boundary without any
    // interactive readback.
    let Ok(probe_access) =
        SecAccessControl::create_with_protection(Some(ProtectionMode::AccessibleWhenUnlocked), 0)
    else {
        return Err(ProbeFailure::Undetermined);
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
        return Err(ProbeFailure::Status(add_status));
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
    let read_result = if read_status != errSecSuccess {
        Err(ProbeFailure::Status(read_status))
    } else if copied.is_null() {
        Err(ProbeFailure::Undetermined)
    } else {
        // SAFETY: copied is a live CF object returned at +1 ownership.
        let type_id = unsafe { CFGetTypeID(copied) };
        if type_id == CFData::type_id() {
            // SAFETY: type identity is CFData and +1 ownership transfers to the wrapper.
            let data = unsafe { CFData::wrap_under_create_rule(copied as CFDataRef) };
            if data.bytes() == PROBE_MATERIAL {
                Ok(())
            } else {
                Err(ProbeFailure::Undetermined)
            }
        } else {
            // SAFETY: copied has not yet been released.
            unsafe { CFRelease(copied) };
            Err(ProbeFailure::Undetermined)
        }
    };

    let delete_pairs = pairs
        .iter()
        .take(query_pair_count)
        .cloned()
        .collect::<Vec<(CFString, CFType)>>();
    let delete_query = CFDictionary::from_CFType_pairs(&delete_pairs);
    // The created probe item is cleaned up on every outcome — success,
    // read refusal, and undiagnosed result alike.
    // SAFETY: delete_query owns valid CF values for the synchronous call.
    let delete_status = unsafe { SecItemDelete(delete_query.as_concrete_TypeRef()) };
    read_result?;
    if delete_status != errSecSuccess {
        return Err(ProbeFailure::Status(delete_status));
    }
    Ok(())
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
            for account in ["synthetic-account-one", "synthetic-account-two"] {
                let query = KeychainItemQuery::new("synthetic-service", account).unwrap();
                let pairs = base_pairs(&query, &context, backend).unwrap();
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
        // The routing flag is always explicit — the same pin the probe
        // uses — so no operation can drift onto a store it was not built
        // for. A query may pin the store explicitly in either direction.
        let query = KeychainItemQuery::new("synthetic-service", "synthetic-account").unwrap();
        let classic_pairs = base_pairs(&query, &context, KeychainBackend::Classic).unwrap();
        let classic_dict = CFDictionary::from_CFType_pairs(&classic_pairs);
        assert_eq!(
            dict_value(&classic_dict, unsafe { kSecUseDataProtectionKeychain })
                .map(|value| value.as_CFTypeRef()),
            Some(CFBoolean::from(false).as_CFTypeRef())
        );
        for forced in [false, true] {
            let forced_query = query.clone().with_data_protection(forced);
            let forced_pairs =
                base_pairs(&forced_query, &context, KeychainBackend::Classic).unwrap();
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
        let grouped_dict = CFDictionary::from_CFType_pairs(
            &base_pairs(&grouped, &context, KeychainBackend::DataProtection).unwrap(),
        );
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
        assert_eq!(
            classic_migration_pairs(&query, &context, KeychainBackend::Classic)
                .unwrap_err()
                .code(),
            "credential_lease_keychain_migration_target_invalid"
        );
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
    fn the_add_payload_carries_user_presence_access_control() {
        let pairs = protected_secret_pairs(&[0xA5u8; 24]).unwrap();
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
    fn the_update_payload_carries_only_the_value_bytes() {
        // SecItemUpdate cannot attach a SecAccessControl to an item that
        // already exists: the update dictionary must carry the value
        // alone, so a mismatched item can never report success while
        // keeping weaker protection.
        let pairs = secret_value_pairs(&[0xA5u8; 24]).unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(
            pairs[0].0,
            security_framework_static!(kSecValueData, sec_key)
        );
    }

    #[test]
    fn only_a_verified_matching_item_takes_a_value_update() {
        assert_eq!(protection_action(Some(true)), ProtectionAction::UpdateValue);
        // Any other protection — weaker, different, or absent access
        // control — is re-stored through delete-then-add, never updated.
        assert_eq!(
            protection_action(Some(false)),
            ProtectionAction::ReplaceItem
        );
        assert_eq!(protection_action(None), ProtectionAction::AddItem);
    }

    #[test]
    fn provenance_projects_storage_attributes_without_value_data() {
        let secret = [0x5Au8; 24];
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
                    CFData::from_buffer(&secret).into_CFType(),
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
        assert!(!projection.contains(&format!("{secret:?}")));

        let weaker = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlocked),
            0,
        )
        .unwrap();
        let foreign = item_provenance(&attributes(weaker.into_CFType())).unwrap();
        assert!(!foreign.has_backend_access_control());

        // The control SecItem stores is the same policy plus its
        // insertion-time binding: it still proves the item is protected —
        // the binding is metadata, not a policy difference.
        let bound = backend_access_control().unwrap();
        // SAFETY: bound is a live SecAccessControl this test owns.
        unsafe { SecAccessControlSetBound(bound.as_CFTypeRef(), 1) };
        let bound_item = item_provenance(&attributes(bound.into_CFType())).unwrap();
        assert!(bound_item.has_backend_access_control());

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
    fn the_stored_binding_is_not_a_policy_difference() {
        let expected = backend_access_control().unwrap();
        // Insertion binds the control it stores: same protection class,
        // same ACL constraints, binding metadata added. The policy
        // comparison still matches.
        let bound = backend_access_control().unwrap();
        // SAFETY: bound is a live SecAccessControl this test owns.
        unsafe { SecAccessControlSetBound(bound.as_CFTypeRef(), 1) };
        assert!(access_control_policy_matches(
            &bound.clone().into_CFType(),
            &expected
        ));
        // A different policy still fails: a weaker protection class, the
        // same class without the user-presence constraint, and a value
        // that is not an access control at all.
        let weaker_protection = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlocked),
            kSecAccessControlUserPresence,
        )
        .unwrap();
        assert!(!access_control_policy_matches(
            &weaker_protection.into_CFType(),
            &expected
        ));
        let unconstrained = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            0,
        )
        .unwrap();
        assert!(!access_control_policy_matches(
            &unconstrained.into_CFType(),
            &expected
        ));
        assert!(!access_control_policy_matches(
            &CFBoolean::true_value().into_CFType(),
            &expected
        ));
    }

    #[test]
    fn a_pinned_mutation_addresses_one_record_alone() {
        let context = synthetic_context();
        let reference = CFData::from_buffer(&[0xABu8; 16]);
        let dict = CFDictionary::from_CFType_pairs(&pinned_pairs(
            &reference,
            &context,
            KeychainBackend::DataProtection,
        ));
        assert_eq!(
            dict_value(&dict, unsafe { kSecValuePersistentRef }).map(|value| value.as_CFTypeRef()),
            Some(reference.as_CFTypeRef())
        );
        // The persistent reference selects the record: no identity or
        // scope attribute travels in a pinned mutation, so it can never
        // act on every record an unscoped query would match.
        // SAFETY: the keys are SDK-exported static CFStrings.
        for key in unsafe { [kSecAttrService, kSecAttrAccount, kSecAttrAccessGroup] } {
            assert!(dict_value(&dict, key).is_none());
        }
        assert_eq!(
            dict_value(&dict, unsafe { kSecUseAuthenticationContext })
                .map(|value| value.as_CFTypeRef()),
            Some(context.as_cf_type().as_CFTypeRef())
        );
        assert_eq!(
            dict_value(&dict, unsafe { kSecUseDataProtectionKeychain })
                .map(|value| value.as_CFTypeRef()),
            Some(CFBoolean::from(true).as_CFTypeRef())
        );
        // The classic routing carries the flag the other way and no UI
        // policy — its interaction policy is the process-wide switch.
        let classic = CFDictionary::from_CFType_pairs(&pinned_pairs(
            &reference,
            &context,
            KeychainBackend::Classic,
        ));
        assert_eq!(
            dict_value(&classic, unsafe { kSecUseDataProtectionKeychain })
                .map(|value| value.as_CFTypeRef()),
            Some(CFBoolean::from(false).as_CFTypeRef())
        );
        assert!(dict_value(&classic, unsafe { kSecUseAuthenticationUI }).is_none());
    }

    #[test]
    fn ambiguous_matches_refuse_before_any_mutation() {
        assert_eq!(
            item_ambiguous().code(),
            "credential_lease_keychain_item_ambiguous"
        );
        // The protection lookup adds the enumeration keys to the write's
        // own query pairs: every record the mutation could reach is
        // counted before any SecItem mutation runs.
        let context = synthetic_context();
        let query = KeychainItemQuery::new("synthetic-service", "synthetic-account").unwrap();
        let query_pairs = base_pairs(&query, &context, KeychainBackend::DataProtection).unwrap();
        let mut pairs = query_pairs.clone();
        pairs.push((
            security_framework_static!(kSecMatchLimit, sec_key),
            security_framework_static!(kSecMatchLimitAll, sec_string_value),
        ));
        let dict = CFDictionary::from_CFType_pairs(&pairs);
        assert_eq!(
            dict_value(&dict, unsafe { kSecMatchLimit }).map(|value| value.as_CFTypeRef()),
            Some(security_framework_static!(kSecMatchLimitAll, sec_string_value).as_CFTypeRef())
        );
        assert_eq!(
            dict_value(&dict, unsafe { kSecAttrService })
                .and_then(|value| value.downcast::<CFString>())
                .map(|value| value.to_string())
                .as_deref(),
            Some("synthetic-service")
        );
    }

    #[test]
    fn the_enumeration_requests_a_reference_only_where_the_store_serves_it() {
        // Apple documents attributes and data as the supported return
        // types for synchronizable items: a synchronizable-scoped
        // enumeration omits the persistent-reference request, while every
        // query that can address a pinnable record keeps it.
        let context = synthetic_context();
        let query = KeychainItemQuery::new("synthetic-service", "synthetic-account").unwrap();
        let query_pairs = base_pairs(&query, &context, KeychainBackend::DataProtection).unwrap();
        for (request, expected) in [(true, Some(true)), (false, None)] {
            let dict = CFDictionary::from_CFType_pairs(&enumeration_pairs(&query_pairs, request));
            assert_eq!(
                dict_value(&dict, unsafe { kSecReturnPersistentRef })
                    .map(|value| value.as_CFTypeRef()),
                expected.map(|flag| CFBoolean::from(flag).as_CFTypeRef())
            );
            assert_eq!(
                dict_value(&dict, unsafe { kSecReturnAttributes })
                    .map(|value| value.as_CFTypeRef()),
                Some(CFBoolean::from(true).as_CFTypeRef())
            );
            assert_eq!(
                dict_value(&dict, unsafe { kSecMatchLimit }).map(|value| value.as_CFTypeRef()),
                Some(
                    security_framework_static!(kSecMatchLimitAll, sec_string_value).as_CFTypeRef()
                )
            );
        }
    }

    #[test]
    fn a_synchronizable_delete_scopes_the_attribute_path_to_the_record() {
        // The platform cannot name a synchronizable record with a
        // persistent reference, so the delete narrows the caller's query
        // by the record's own attributes instead: its access group and
        // synchronizable flag when the query declared neither. No
        // persistent reference ever travels in the scoped query.
        let context = synthetic_context();
        let item = MatchedItem {
            reference: None,
            protected: false,
            access_group: Some("record-group".to_owned()),
            synchronizable: Some(true),
            generic: None,
        };
        let query = KeychainItemQuery::new("synthetic-service", "synthetic-account")
            .unwrap()
            .with_synchronizable(true);
        let query_pairs = base_pairs(&query, &context, KeychainBackend::DataProtection).unwrap();
        let dict = CFDictionary::from_CFType_pairs(&attribute_scoped_delete_pairs(
            &query,
            &query_pairs,
            &item,
        ));
        assert!(dict_value(&dict, unsafe { kSecValuePersistentRef }).is_none());
        assert_eq!(
            dict_value(&dict, unsafe { kSecAttrAccessGroup })
                .and_then(|value| value.downcast::<CFString>())
                .map(|value| value.to_string())
                .as_deref(),
            Some("record-group")
        );
        assert_eq!(
            dict_value(&dict, unsafe { kSecAttrSynchronizable }).map(|value| value.as_CFTypeRef()),
            Some(CFBoolean::from(true).as_CFTypeRef())
        );
        // A query that declares the attributes keeps its own scope: the
        // record's group is never substituted for the declared one.
        let declared = KeychainItemQuery::new("synthetic-service", "synthetic-account")
            .unwrap()
            .with_access_group("declared-group")
            .with_synchronizable(true);
        let query_pairs = base_pairs(&declared, &context, KeychainBackend::DataProtection).unwrap();
        let dict = CFDictionary::from_CFType_pairs(&attribute_scoped_delete_pairs(
            &declared,
            &query_pairs,
            &item,
        ));
        assert_eq!(
            dict_value(&dict, unsafe { kSecAttrAccessGroup })
                .and_then(|value| value.downcast::<CFString>())
                .map(|value| value.to_string())
                .as_deref(),
            Some("declared-group")
        );
    }

    #[test]
    fn an_unpinnable_record_refuses_the_write_path() {
        // A matched record without a persistent reference — a
        // synchronizable item — can never carry the required access
        // control, so the write refuses it before any pinned mutation.
        let unpinnable = MatchedItem {
            reference: None,
            protected: false,
            access_group: None,
            synchronizable: Some(true),
            generic: None,
        };
        assert!(unpinnable.reference.is_none());
        assert_eq!(
            synchronizable_write_invalid().code(),
            "credential_lease_keychain_synchronizable_write_invalid"
        );
    }

    #[test]
    fn the_parked_name_and_marker_belong_to_one_swap_alone() {
        // Every swap draws its own identifier: the parked account and
        // the replacement's marker derive from it, so no account a
        // caller could supply is ever a parked record — an ordinary
        // credential named like a leftover is never found, renamed, or
        // deleted, because the only lookup runs through a recorded
        // swap's own name.
        let one = Uuid::new_v4();
        let two = Uuid::new_v4();
        assert_ne!(one, two);
        let parked = replace_parked_account(&one);
        assert!(parked.starts_with("credential-lease.replace.tombstone."));
        assert_ne!(parked, replace_parked_account(&two));
        assert_ne!(
            parked,
            "credential-lease.replace.tombstone.synthetic-account"
        );
        assert_ne!(parked, "synthetic-account");
        assert_ne!(swap_marker(&one), swap_marker(&two));
        assert!(swap_marker(&one).starts_with(b"clrt"));
        // The state record's account is deterministic per identity, so a
        // second swap for the same item is a duplicate, never a
        // competing record.
        assert_eq!(
            swap_state_account("synthetic-service", "synthetic-account"),
            swap_state_account("synthetic-service", "synthetic-account")
        );
        assert_ne!(
            swap_state_account("synthetic-service", "synthetic-account"),
            swap_state_account("synthetic-service", "other-account")
        );
    }

    #[test]
    fn swap_state_encoding_round_trips_and_refuses_foreign_values() {
        let swap_id = Uuid::new_v4();
        for group in [None, Some("recorded-group")] {
            let value =
                encode_swap_state("synthetic-service", "synthetic-account", group, &swap_id);
            let decoded = decode_swap_state(&value).unwrap();
            assert_eq!(decoded.service, "synthetic-service");
            assert_eq!(decoded.account, "synthetic-account");
            assert_eq!(decoded.parked_group.as_deref(), group);
            assert_eq!(decoded.swap_id, swap_id);
        }
        // Foreign, truncated, mistyped, and trailing-byte values are not
        // this backend's state and are never acted on.
        let mut trailing = encode_swap_state("s", "a", None, &swap_id);
        trailing.push(0);
        for bad in [
            Vec::new(),
            b"foreign-value".to_vec(),
            encode_swap_state("s", "a", None, &swap_id)[..8].to_vec(),
            trailing,
        ] {
            assert!(decode_swap_state(&bad).is_none());
        }
    }

    #[test]
    fn a_recorded_swap_resolves_by_its_recorded_access_group() {
        // The caller's declared group selects the swap recorded under
        // it; an unscoped caller resolves a single recorded swap by its
        // own group, and recorded swaps in several groups refuse the
        // ambiguous intent rather than act on the wrong records.
        let state = |group: Option<&str>| SwapState {
            reference: CFData::from_buffer(&[0xB0u8; 16]),
            swap_id: Uuid::new_v4(),
            caller_group: group.map(str::to_owned),
            parked_group: group.map(str::to_owned),
        };
        assert!(select_swap_state(Vec::new(), None).unwrap().is_none());
        assert_eq!(
            select_swap_state(vec![state(Some("group-a"))], None)
                .unwrap()
                .unwrap()
                .caller_group
                .as_deref(),
            Some("group-a")
        );
        assert_eq!(
            select_swap_state(
                vec![state(Some("group-a")), state(Some("group-b"))],
                Some("group-b")
            )
            .unwrap()
            .unwrap()
            .caller_group
            .as_deref(),
            Some("group-b")
        );
        assert_eq!(
            select_swap_state(vec![state(Some("group-a")), state(Some("group-b"))], None)
                .unwrap_err()
                .code(),
            "credential_lease_keychain_item_ambiguous"
        );
    }

    #[test]
    fn swap_verdict_decides_from_the_state_the_interruption_left() {
        let swap_id = Uuid::new_v4();
        let state = SwapState {
            reference: CFData::from_buffer(&[0xA0u8; 16]),
            swap_id,
            caller_group: Some("group-a".to_owned()),
            parked_group: Some("group-a".to_owned()),
        };
        let parked = || {
            ItemMatch::One(MatchedItem {
                reference: Some(CFData::from_buffer(&[0xB0u8; 16])),
                protected: false,
                access_group: Some("group-a".to_owned()),
                synchronizable: Some(false),
                generic: None,
            })
        };
        let identity = |protected: bool, marker: Option<Vec<u8>>, group: Option<&str>| {
            Some(MatchedItem {
                reference: Some(CFData::from_buffer(&[0xC1u8; 16])),
                protected,
                access_group: group.map(str::to_owned),
                synchronizable: Some(false),
                generic: marker,
            })
        };
        // The parked original is gone: only the spent state record's own
        // removal remains — whether the swap completed, restored, or the
        // record was otherwise removed.
        assert_eq!(
            swap_verdict(&state, &ItemMatch::Absent, None).unwrap(),
            SwapVerdict::StaleClean
        );
        assert_eq!(
            swap_verdict(&state, &ItemMatch::Ambiguous, None)
                .unwrap_err()
                .code(),
            "credential_lease_keychain_item_ambiguous"
        );
        // The identity is free: the parked original is restored.
        assert_eq!(
            swap_verdict(&state, &parked(), None).unwrap(),
            SwapVerdict::Restore
        );
        // The identity record is this swap's own replacement — its
        // marker names the swap — protected means the add proved out
        // and only cleanup remains, unprotected means the interruption
        // left it unverified and it rolls back instead of wedging every
        // retry on a duplicate.
        assert_eq!(
            swap_verdict(
                &state,
                &parked(),
                identity(true, Some(swap_marker(&swap_id)), Some("group-a")).as_ref()
            )
            .unwrap(),
            SwapVerdict::Cleanup
        );
        assert_eq!(
            swap_verdict(
                &state,
                &parked(),
                identity(false, Some(swap_marker(&swap_id)), Some("group-a")).as_ref()
            )
            .unwrap(),
            SwapVerdict::Rollback
        );
        // A record that is not this swap's — no marker, or another
        // swap's — holds the identity: a competing writer, never
        // touched.
        for foreign in [
            identity(true, None, Some("group-a")),
            identity(false, None, Some("group-a")),
            identity(true, Some(swap_marker(&Uuid::new_v4())), Some("group-a")),
        ] {
            assert_eq!(
                swap_verdict(&state, &parked(), foreign.as_ref()).unwrap(),
                SwapVerdict::Duplicate
            );
        }
        // The record an unscoped retry matched sits in a different
        // group than the swap recorded: it is not this swap's identity,
        // so the parked original restores by its recorded group instead
        // of being abandoned to a wrong-group verdict.
        assert_eq!(
            swap_verdict(
                &state,
                &parked(),
                identity(true, None, Some("group-b")).as_ref()
            )
            .unwrap(),
            SwapVerdict::Restore
        );
        // A protected or unnameable record at the parked name is not a
        // parked original — the swap only parks unprotected pinnable
        // records — so it is foreign and refused untouched.
        for foreign_parked in [
            ItemMatch::One(MatchedItem {
                reference: Some(CFData::from_buffer(&[0xE3u8; 16])),
                protected: true,
                access_group: None,
                synchronizable: Some(false),
                generic: None,
            }),
            ItemMatch::One(MatchedItem {
                reference: None,
                protected: false,
                access_group: None,
                synchronizable: Some(true),
                generic: None,
            }),
        ] {
            assert_eq!(
                swap_verdict(&state, &foreign_parked, None)
                    .unwrap_err()
                    .code(),
                "credential_lease_keychain_data_invalid"
            );
        }
    }

    #[test]
    fn the_swap_state_add_records_the_swap_under_the_reserved_service() {
        // The durable state is written before the original is touched:
        // the reserved service, the deterministic per-identity account,
        // the caller's intended group, and the value naming the
        // identity, the parked record's group, and the swap identifier.
        let context = synthetic_context();
        let swap_id = Uuid::new_v4();
        let query = KeychainItemQuery::new("synthetic-service", "synthetic-account")
            .unwrap()
            .with_access_group("declared-group");
        let item = MatchedItem {
            reference: Some(CFData::from_buffer(&[0xB0u8; 16])),
            protected: false,
            access_group: Some("record-group".to_owned()),
            synchronizable: Some(false),
            generic: None,
        };
        let dict = CFDictionary::from_CFType_pairs(&swap_state_pairs(
            &query,
            &item,
            &swap_id,
            &context,
            KeychainBackend::DataProtection,
        ));
        assert_eq!(
            dict_value(&dict, unsafe { kSecAttrService })
                .and_then(|value| value.downcast::<CFString>())
                .map(|value| value.to_string())
                .as_deref(),
            Some(REPLACE_STATE_SERVICE)
        );
        assert_eq!(
            dict_value(&dict, unsafe { kSecAttrAccount })
                .and_then(|value| value.downcast::<CFString>())
                .map(|value| value.to_string())
                .as_deref(),
            Some(swap_state_account("synthetic-service", "synthetic-account").as_str())
        );
        assert_eq!(
            dict_value(&dict, unsafe { kSecAttrAccessGroup })
                .and_then(|value| value.downcast::<CFString>())
                .map(|value| value.to_string())
                .as_deref(),
            Some("declared-group")
        );
        assert_eq!(
            dict_value(&dict, unsafe { kSecAttrSynchronizable }).map(|value| value.as_CFTypeRef()),
            Some(CFBoolean::from(false).as_CFTypeRef())
        );
        // The state records the parked original's own group — the
        // matched record's — not only the declared one.
        let state_value = dict_value(&dict, unsafe { kSecValueData })
            .and_then(|value| value.downcast::<CFData>())
            .unwrap();
        let decoded = decode_swap_state(state_value.bytes()).unwrap();
        assert_eq!(decoded.parked_group.as_deref(), Some("record-group"));
        assert_eq!(decoded.swap_id, swap_id);
        // The state record itself is pinnable for cleanup.
        assert_eq!(
            dict_value(&dict, unsafe { kSecReturnPersistentRef }).map(|value| value.as_CFTypeRef()),
            Some(CFBoolean::from(true).as_CFTypeRef())
        );
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

        let secret = [0xA5u8; 24];
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
        let data = CFData::from_buffer(&[0x3Cu8; 24]);
        let mut secret = secret_from_cf_data(&data).unwrap();
        assert_eq!(secret.expose_bytes(), &[0x3Cu8; 24]);
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

    #[test]
    fn effective_store_follows_explicit_routing_over_the_selected_backend() {
        let query = KeychainItemQuery::new("synthetic-service", "synthetic-account").unwrap();
        for backend in [KeychainBackend::Classic, KeychainBackend::DataProtection] {
            assert_eq!(effective_store(&query, backend).unwrap(), backend);
            assert_eq!(
                effective_store(&query.clone().with_data_protection(true), backend).unwrap(),
                KeychainBackend::DataProtection
            );
            assert_eq!(
                effective_store(&query.clone().with_data_protection(false), backend).unwrap(),
                KeychainBackend::Classic
            );
        }
    }

    #[test]
    fn synchronizable_queries_route_to_data_protection() {
        let context = synthetic_context();
        let query = KeychainItemQuery::new("synthetic-service", "synthetic-account").unwrap();
        // A synchronizable item is served only by the Data Protection
        // Keychain (TN3137): an unflagged query on a Classic handle still
        // lands there, so it takes the Data Protection no-UI policy and
        // error handling rather than Classic's.
        let sync = query.clone().with_synchronizable(true);
        assert_eq!(
            effective_store(&sync, KeychainBackend::Classic).unwrap(),
            KeychainBackend::DataProtection
        );
        let dict = CFDictionary::from_CFType_pairs(
            &base_pairs(&sync, &context, KeychainBackend::Classic).unwrap(),
        );
        assert_eq!(
            dict_value(&dict, unsafe { kSecUseDataProtectionKeychain })
                .map(|value| value.as_CFTypeRef()),
            Some(CFBoolean::from(true).as_CFTypeRef())
        );
        assert_eq!(
            dict_value(&dict, unsafe { kSecUseAuthenticationUI }).map(|value| value.as_CFTypeRef()),
            Some(
                security_framework_static!(kSecUseAuthenticationUIFail, sec_string_value)
                    .as_CFTypeRef()
            )
        );
        // Forcing classic routing on a synchronizable item contradicts the
        // declared attributes: refused, never silently re-routed.
        let contradictory = query
            .clone()
            .with_synchronizable(true)
            .with_data_protection(false);
        for backend in [KeychainBackend::Classic, KeychainBackend::DataProtection] {
            assert_eq!(
                effective_store(&contradictory, backend).unwrap_err().code(),
                "credential_lease_keychain_routing_invalid"
            );
            assert!(base_pairs(&contradictory, &context, backend).is_err());
        }
        // An explicitly non-synchronizable item may still route classic.
        let classic_only = query.with_synchronizable(false).with_data_protection(false);
        assert_eq!(
            effective_store(&classic_only, KeychainBackend::DataProtection).unwrap(),
            KeychainBackend::Classic
        );
    }

    #[test]
    fn grouped_queries_keep_their_scope_on_data_protection() {
        let context = synthetic_context();
        let query = KeychainItemQuery::new("synthetic-service", "synthetic-account").unwrap();
        // Security.framework strips kSecAttrAccessGroup on the classic
        // path, so an implicitly routed grouped query must land on the
        // Data Protection store even on a fallback-classic handle —
        // otherwise the scope is silently dropped and the operation
        // matches on service and account alone.
        let grouped = query.clone().with_access_group("synthetic-access-group");
        assert_eq!(
            effective_store(&grouped, KeychainBackend::Classic).unwrap(),
            KeychainBackend::DataProtection
        );
        let dict = CFDictionary::from_CFType_pairs(
            &base_pairs(&grouped, &context, KeychainBackend::Classic).unwrap(),
        );
        assert_eq!(
            dict_value(&dict, unsafe { kSecUseDataProtectionKeychain })
                .map(|value| value.as_CFTypeRef()),
            Some(CFBoolean::from(true).as_CFTypeRef())
        );
        assert_eq!(
            dict_value(&dict, unsafe { kSecAttrAccessGroup })
                .and_then(|value| value.downcast::<CFString>())
                .map(|value| value.to_string())
                .as_deref(),
            Some("synthetic-access-group")
        );
        assert_eq!(
            dict_value(&dict, unsafe { kSecUseAuthenticationUI }).map(|value| value.as_CFTypeRef()),
            Some(
                security_framework_static!(kSecUseAuthenticationUIFail, sec_string_value)
                    .as_CFTypeRef()
            )
        );
        // Forcing classic routing on a grouped query contradicts the
        // declared scope: refused, never silently de-scoped.
        let contradictory = query
            .clone()
            .with_access_group("synthetic-access-group")
            .with_data_protection(false);
        for backend in [KeychainBackend::Classic, KeychainBackend::DataProtection] {
            assert_eq!(
                effective_store(&contradictory, backend).unwrap_err().code(),
                "credential_lease_keychain_routing_invalid"
            );
            assert!(base_pairs(&contradictory, &context, backend).is_err());
        }
        // The legacy migration entry points force a classic source query,
        // so a grouped query refuses there the same way — before any
        // SecItem call, on either handle.
        for backend in [KeychainBackend::Classic, KeychainBackend::DataProtection] {
            assert_eq!(
                classic_migration_pairs(&grouped, &context, backend)
                    .unwrap_err()
                    .code(),
                "credential_lease_keychain_routing_invalid"
            );
            let keychain = Keychain { backend };
            assert_eq!(
                keychain
                    .copy_legacy_classic_secret(&context, &grouped, false)
                    .unwrap_err()
                    .code(),
                "credential_lease_keychain_routing_invalid"
            );
            assert_eq!(
                keychain
                    .delete_legacy_classic_item(&context, &grouped, false)
                    .unwrap_err()
                    .code(),
                "credential_lease_keychain_routing_invalid"
            );
        }
        // An explicitly unscoped query may still route classic.
        let unscoped = query.with_synchronizable(false).with_data_protection(false);
        assert_eq!(
            effective_store(&unscoped, KeychainBackend::DataProtection).unwrap(),
            KeychainBackend::Classic
        );
    }

    #[test]
    fn synchronizable_queries_refuse_on_the_classic_migration_source() {
        // A synchronizable item is served only by the Data Protection
        // Keychain (TN3137): it can never be the classic item a migration
        // reads or deletes. The shared source helper drops the
        // `kSecAttrSynchronizable` selector, so honoring the call would
        // issue a query on service and account alone and could copy or
        // delete a different classic item with the same identifiers —
        // the query refuses before either legacy entry point reaches
        // SecItem, on either handle.
        let context = synthetic_context();
        let synchronizable = KeychainItemQuery::new("synthetic-service", "synthetic-account")
            .unwrap()
            .with_synchronizable(true);
        for backend in [KeychainBackend::Classic, KeychainBackend::DataProtection] {
            assert_eq!(
                classic_migration_pairs(&synchronizable, &context, backend)
                    .unwrap_err()
                    .code(),
                "credential_lease_keychain_routing_invalid"
            );
            let keychain = Keychain { backend };
            assert_eq!(
                keychain
                    .copy_legacy_classic_secret(&context, &synchronizable, false)
                    .unwrap_err()
                    .code(),
                "credential_lease_keychain_routing_invalid"
            );
            assert_eq!(
                keychain
                    .delete_legacy_classic_item(&context, &synchronizable, false)
                    .unwrap_err()
                    .code(),
                "credential_lease_keychain_routing_invalid"
            );
        }
        // An explicit Data Protection routing flag declares an item the
        // forced-classic source cannot reach either — refused for the
        // same reason.
        let routed = KeychainItemQuery::new("synthetic-service", "synthetic-account")
            .unwrap()
            .with_data_protection(true);
        for backend in [KeychainBackend::Classic, KeychainBackend::DataProtection] {
            assert_eq!(
                classic_migration_pairs(&routed, &context, backend)
                    .unwrap_err()
                    .code(),
                "credential_lease_keychain_routing_invalid"
            );
            let keychain = Keychain { backend };
            assert_eq!(
                keychain
                    .copy_legacy_classic_secret(&context, &routed, false)
                    .unwrap_err()
                    .code(),
                "credential_lease_keychain_routing_invalid"
            );
            assert_eq!(
                keychain
                    .delete_legacy_classic_item(&context, &routed, false)
                    .unwrap_err()
                    .code(),
                "credential_lease_keychain_routing_invalid"
            );
        }
    }

    #[test]
    fn synchronizable_writes_refuse_before_any_secitem_call() {
        // Security.framework answers errSecParam when a SecAccessControl
        // rides a synchronizable item, so the backend refuses the write
        // itself — the refusal lands before store selection, and no
        // SecItem call ever runs. An unset or explicit-false flag keeps
        // the write path open.
        let context = synthetic_context();
        let secret = SecretBytes::try_from_bytes(vec![0xA5u8; 24]).unwrap();
        for backend in [KeychainBackend::Classic, KeychainBackend::DataProtection] {
            let keychain = Keychain { backend };
            let synchronizable = KeychainItemQuery::new("synthetic-service", "synthetic-account")
                .unwrap()
                .with_synchronizable(true);
            assert_eq!(
                keychain
                    .add_item(&context, &synchronizable, &secret)
                    .unwrap_err()
                    .code(),
                "credential_lease_keychain_synchronizable_write_invalid"
            );
            assert_eq!(
                keychain
                    .set_item(&context, &synchronizable, &secret)
                    .unwrap_err()
                    .code(),
                "credential_lease_keychain_synchronizable_write_invalid"
            );
            for flag in [None, Some(false)] {
                let writable =
                    KeychainItemQuery::new("synthetic-service", "synthetic-account").unwrap();
                let writable = match flag {
                    Some(flag) => writable.with_synchronizable(flag),
                    None => writable,
                };
                // An unset or explicit-false flag keeps the write path
                // open on the store that can take the access control.
                assert!(ensure_write_supported(&writable, KeychainBackend::DataProtection).is_ok());
            }
        }
    }

    #[test]
    fn classic_writes_refuse_before_any_secitem_call() {
        // Explicit classic routing strips `kSecAttrAccessControl` — the
        // only protection this backend writes — so a classic-routed write
        // is refused before any SecItem call rather than persisted
        // unprotected. The effective store is what decides, not the
        // handle: a forced-classic query refuses on a Data Protection
        // handle too.
        let context = synthetic_context();
        let secret = SecretBytes::try_from_bytes(vec![0xA5u8; 24]).unwrap();
        let query = KeychainItemQuery::new("synthetic-service", "synthetic-account").unwrap();
        let classic = Keychain {
            backend: KeychainBackend::Classic,
        };
        assert_eq!(
            classic
                .add_item(&context, &query, &secret)
                .unwrap_err()
                .code(),
            "credential_lease_keychain_classic_write_unsupported"
        );
        assert_eq!(
            classic
                .set_item(&context, &query, &secret)
                .unwrap_err()
                .code(),
            "credential_lease_keychain_classic_write_unsupported"
        );
        let protection = Keychain {
            backend: KeychainBackend::DataProtection,
        };
        let forced = query.clone().with_data_protection(false);
        assert_eq!(
            protection
                .add_item(&context, &forced, &secret)
                .unwrap_err()
                .code(),
            "credential_lease_keychain_classic_write_unsupported"
        );
        assert_eq!(
            protection
                .set_item(&context, &forced, &secret)
                .unwrap_err()
                .code(),
            "credential_lease_keychain_classic_write_unsupported"
        );
    }

    #[test]
    fn synchronizable_reads_omit_the_persistent_reference_request() {
        // Apple documents attributes and data as the supported return
        // types for synchronizable items: the persistent-reference flag is
        // left out of the read, and the copied item's reference stays
        // `None`. Ordinary and explicitly non-synchronizable reads keep
        // requesting it.
        let context = synthetic_context();
        let synchronizable = KeychainItemQuery::new("synthetic-service", "synthetic-account")
            .unwrap()
            .with_synchronizable(true);
        for backend in [KeychainBackend::Classic, KeychainBackend::DataProtection] {
            let pairs = copy_item_pairs(&synchronizable, &context, backend).unwrap();
            let dict = CFDictionary::from_CFType_pairs(&pairs);
            assert!(dict_value(&dict, unsafe { kSecReturnPersistentRef }).is_none());
        }
        for synchronizable in [None, Some(false)] {
            let query = KeychainItemQuery::new("synthetic-service", "synthetic-account").unwrap();
            let query = match synchronizable {
                Some(flag) => query.with_synchronizable(flag),
                None => query,
            };
            let pairs = copy_item_pairs(&query, &context, KeychainBackend::DataProtection).unwrap();
            let dict = CFDictionary::from_CFType_pairs(&pairs);
            assert_eq!(
                dict_value(&dict, unsafe { kSecReturnPersistentRef })
                    .map(|value| value.as_CFTypeRef()),
                Some(CFBoolean::from(true).as_CFTypeRef())
            );
        }
    }

    #[test]
    fn data_protection_queries_forbid_authentication_ui() {
        let context = synthetic_context();
        let query = KeychainItemQuery::new("synthetic-service", "synthetic-account").unwrap();
        // The effective Data Protection store carries the fail-on-UI policy.
        let dict = CFDictionary::from_CFType_pairs(
            &base_pairs(&query, &context, KeychainBackend::DataProtection).unwrap(),
        );
        assert_eq!(
            dict_value(&dict, unsafe { kSecUseAuthenticationUI }).map(|value| value.as_CFTypeRef()),
            Some(
                security_framework_static!(kSecUseAuthenticationUIFail, sec_string_value)
                    .as_CFTypeRef()
            )
        );
        // A classic-routed query carries none — its interaction policy is
        // the classic process-wide switch, applied by the operation itself.
        for query in [query.clone(), query.clone().with_data_protection(false)] {
            let dict = CFDictionary::from_CFType_pairs(
                &base_pairs(&query, &context, KeychainBackend::Classic).unwrap(),
            );
            assert!(dict_value(&dict, unsafe { kSecUseAuthenticationUI }).is_none());
        }
        let forced = query.with_data_protection(false);
        let dict = CFDictionary::from_CFType_pairs(
            &base_pairs(&forced, &context, KeychainBackend::DataProtection).unwrap(),
        );
        assert!(dict_value(&dict, unsafe { kSecUseAuthenticationUI }).is_none());
    }

    #[test]
    fn probe_refusal_classification_separates_permanent_from_transient() {
        for status in [
            errSecUnimplemented,
            ERR_SEC_MISSING_ENTITLEMENT,
            ERR_SEC_NO_SUCH_KEYCHAIN,
            ERR_SEC_INVALID_KEYCHAIN,
        ] {
            assert!(is_permanent_probe_refusal(status));
        }
        for status in [
            errSecAuthFailed,
            ERR_SEC_INTERACTION_NOT_ALLOWED,
            errSecItemNotFound,
            errSecDuplicateItem,
        ] {
            assert!(!is_permanent_probe_refusal(status));
        }
    }

    #[test]
    fn classic_fallback_reports_availability_without_protected_write_readiness() {
        // When the probe falls back to the classic store the handle is a
        // real, usable backend — but only for reads and deletes. The
        // availability reports keep that split: write readiness is `false`
        // exactly on the store whose `add_item`/`set_item` calls always
        // refuse.
        let classic = Keychain {
            backend: KeychainBackend::Classic,
        };
        assert!(!classic.supports_protected_writes());
        let protection = Keychain {
            backend: KeychainBackend::DataProtection,
        };
        assert!(protection.supports_protected_writes());
        // The public item APIs agree with the report: the same classic
        // handle refuses both write paths before any SecItem call.
        let context = synthetic_context();
        let secret = SecretBytes::try_from_bytes(vec![0xA5u8; 24]).unwrap();
        let query = KeychainItemQuery::new("synthetic-service", "synthetic-account").unwrap();
        for result in [
            classic.add_item(&context, &query, &secret).map(|_| ()),
            classic.set_item(&context, &query, &secret),
        ] {
            assert_eq!(
                result.unwrap_err().code(),
                "credential_lease_keychain_classic_write_unsupported"
            );
        }
        // The legacy migration entry points refuse outright on the classic
        // handle — the destination is always the Data Protection store —
        // so a host can distinguish a missing source item (`Ok(None)` on a
        // Data Protection handle) from an unavailable destination.
        for result in [
            classic
                .copy_legacy_classic_secret(&context, &query, false)
                .map(|_| ()),
            classic.delete_legacy_classic_item(&context, &query, false),
        ] {
            assert_eq!(
                result.unwrap_err().code(),
                "credential_lease_keychain_migration_target_invalid"
            );
        }
    }
}

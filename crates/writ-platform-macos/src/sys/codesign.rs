//! A running process's code signature, through Security.framework: the guest code for a pid
//! (`SecCodeCopyGuestWithAttributes`), checked valid (`SecCodeCheckValidity`: the kernel's
//! view of the running code and the signature of its file on disk), then its signing
//! identifier and team (`SecCodeCopySigningInformation`). No identity for unsigned code, an
//! invalid signature, or code the daemon can't read.

use core_foundation_sys::base::{CFGetTypeID, CFIndex, CFRelease, CFTypeRef, OSStatus};
use core_foundation_sys::dictionary::{
    CFDictionaryCreate, CFDictionaryGetValue, CFDictionaryRef, kCFTypeDictionaryKeyCallBacks,
    kCFTypeDictionaryValueCallBacks,
};
use core_foundation_sys::number::{CFNumberCreate, kCFNumberSInt32Type};
use core_foundation_sys::string::{
    CFStringGetCString, CFStringGetLength, CFStringGetMaximumSizeForEncoding, CFStringGetTypeID,
    CFStringRef, kCFStringEncodingUTF8,
};

/// `SecCodeRef`.
type SecCodeRef = *mut libc::c_void;

/// `kSecCSSigningInformation` (`<Security/SecCode.h>`).
const SIGNING_INFORMATION: u32 = 1 << 1;
/// `kSecCSDefaultFlags`.
const DEFAULT_FLAGS: u32 = 0;
/// `errSecSuccess`.
const SUCCESS: OSStatus = 0;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecGuestAttributePid: CFStringRef;
    static kSecCodeInfoIdentifier: CFStringRef;
    static kSecCodeInfoTeamIdentifier: CFStringRef;
    fn SecCodeCopyGuestWithAttributes(
        host: SecCodeRef,
        attributes: CFDictionaryRef,
        flags: u32,
        guest: *mut SecCodeRef,
    ) -> OSStatus;
    fn SecCodeCheckValidity(
        code: SecCodeRef,
        flags: u32,
        requirement: *const libc::c_void,
    ) -> OSStatus;
    fn SecCodeCopySigningInformation(
        code: SecCodeRef,
        flags: u32,
        information: *mut CFDictionaryRef,
    ) -> OSStatus;
}

/// A Core Foundation object this code owns (a "Copy" or "Create"), released when dropped.
struct Owned(CFTypeRef);

impl Owned {
    /// Takes `object`, or `None` when it is null.
    fn new(object: CFTypeRef) -> Option<Self> {
        (!object.is_null()).then_some(Self(object))
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a non-null object this code got from a Copy or Create call and
        // releases once, here.
        unsafe { CFRelease(self.0) }
    }
}

/// A valid signature's identifier and team.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    pub identifier: String,
    pub team: Option<String>,
}

/// The longest identifier or team read, in UTF-16 units (longer ones aren't identities any
/// check would take: they are left out).
const MAX_UNITS: CFIndex = 255;

/// The code signature of the running process `pid`, when it has a valid one.
pub fn signature(pid: u32) -> Option<Signed> {
    let pid = i32::try_from(pid).ok()?;
    // SAFETY: `pid` is a valid i32 that `CFNumberCreate` copies; the result is owned.
    let number = Owned::new(unsafe {
        CFNumberCreate(
            std::ptr::null(),
            kCFNumberSInt32Type,
            std::ptr::addr_of!(pid).cast::<libc::c_void>(),
        )
        .cast::<libc::c_void>()
    })?;
    // SAFETY: the Security framework's constant key, valid for the process's life.
    let key: CFTypeRef = unsafe { kSecGuestAttributePid }.cast::<libc::c_void>();
    let value: CFTypeRef = number.0;
    // SAFETY: one key and one value, both valid objects that outlive the call (the
    // dictionary retains them with the CFType callbacks); the result is owned.
    let attributes = Owned::new(unsafe {
        CFDictionaryCreate(
            std::ptr::null(),
            &raw const key,
            &raw const value,
            1,
            &raw const kCFTypeDictionaryKeyCallBacks,
            &raw const kCFTypeDictionaryValueCallBacks,
        )
        .cast::<libc::c_void>()
    })?;
    let mut guest: SecCodeRef = std::ptr::null_mut();
    // SAFETY: a null host (the system's), a valid attributes dictionary, and a valid place
    // for the guest, which is owned on success.
    let status = unsafe {
        SecCodeCopyGuestWithAttributes(
            std::ptr::null_mut(),
            attributes.0.cast(),
            DEFAULT_FLAGS,
            &raw mut guest,
        )
    };
    if status != SUCCESS {
        return None;
    }
    let guest = Owned::new(guest.cast_const())?;
    // SAFETY: a valid code object, no requirement (null): only the signature's validity.
    let valid =
        unsafe { SecCodeCheckValidity(guest.0.cast_mut(), DEFAULT_FLAGS, std::ptr::null()) };
    if valid != SUCCESS {
        return None;
    }
    let mut information: CFDictionaryRef = std::ptr::null();
    // SAFETY: a valid code object and a valid place for the dictionary, owned on success.
    let status = unsafe {
        SecCodeCopySigningInformation(
            guest.0.cast_mut(),
            SIGNING_INFORMATION,
            &raw mut information,
        )
    };
    if status != SUCCESS {
        return None;
    }
    let information = Owned::new(information.cast::<libc::c_void>())?;
    // SAFETY: the Security framework's constant keys, valid for the process's life.
    let (identifier_key, team_key) =
        unsafe { (kSecCodeInfoIdentifier, kSecCodeInfoTeamIdentifier) };
    let identifier = string(&information, identifier_key)?;
    let team = string(&information, team_key);
    Some(Signed { identifier, team })
}

/// The string `key` maps to in `dictionary`: `None` when absent, not a string, longer than
/// [`MAX_UNITS`] or not convertible.
fn string(dictionary: &Owned, key: CFStringRef) -> Option<String> {
    // SAFETY: a valid dictionary and key; the value is borrowed (Get), not owned, and lives
    // as long as the dictionary, which outlives this function's use of it.
    let value = unsafe { CFDictionaryGetValue(dictionary.0.cast(), key.cast::<libc::c_void>()) };
    if value.is_null() {
        return None;
    }
    // SAFETY: `value` is a valid object; these only read its type.
    if unsafe { CFGetTypeID(value) != CFStringGetTypeID() } {
        return None;
    }
    let text: CFStringRef = value.cast();
    // SAFETY: `text` is a valid string (its type checked above).
    let units = unsafe { CFStringGetLength(text) };
    if !(1..=MAX_UNITS).contains(&units) {
        return None;
    }
    // SAFETY: a plain size computation.
    let most = unsafe { CFStringGetMaximumSizeForEncoding(units, kCFStringEncodingUTF8) };
    let capacity = usize::try_from(most).ok()?.checked_add(1)?;
    let mut buffer = vec![0u8; capacity];
    let size = CFIndex::try_from(buffer.len()).ok()?;
    // SAFETY: the buffer is valid and writable for `size` bytes, enough for the string in
    // UTF-8 and its terminator.
    let converted = unsafe {
        CFStringGetCString(
            text,
            buffer.as_mut_ptr().cast::<libc::c_char>(),
            size,
            kCFStringEncodingUTF8,
        )
    };
    if converted == 0 {
        return None;
    }
    let end = buffer.iter().position(|&b| b == 0)?;
    buffer.truncate(end);
    String::from_utf8(buffer).ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn a_system_binary_is_apple_signed() {
        // launchd: signed by Apple, platform binaries have no team.
        let launchd = signature(1).unwrap();
        assert_eq!(launchd.identifier, "com.apple.xpc.launchd");
        assert_eq!(launchd.team, None);
    }
}

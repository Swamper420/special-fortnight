//! Original procedure `0x0040e414` (245 bytes, `0x40e414–0x40e508`).
//! Evidence: `evidence/0040e414_fn_0040e414.md`.

unsafe extern "C" fn default_mkwork(_d: *mut u32) {}
unsafe extern "C" fn default_hunt(_f: u8, _s: *mut u8, _e: *mut u8, _o: *mut u32) {}
unsafe extern "C" fn default_convert(_p: *mut u8) -> *mut u16 {
    core::ptr::null_mut()
}
unsafe extern "C" fn default_mkdir(_p: *mut u16) -> i32 {
    1
}
unsafe extern "C" fn default_lasterror() -> u32 {
    0
}
unsafe extern "C" fn default_msg(_id: u32, _v: u32, _o: *mut u8) {}
unsafe extern "C" fn default_fmt(_e: u32) {}
unsafe extern "C" fn default_fmt2(_e: u32, _o: *mut u32) {}
unsafe extern "C" fn default_def0(_id: u32, _v: u32, _n: i32, _o: *mut u8) {}
unsafe extern "C" fn default_mkmsg(_e: *mut u32, _f: u8, _s: u32) -> *mut u32 {
    core::ptr::null_mut()
}
unsafe extern "C" fn default_fatal(_m: *mut u32) {}
unsafe extern "C" fn default_store(_d: *mut u32, _s: u32) {}
unsafe extern "C" fn default_free(_s: *mut u32, _n: u32) {}

/// ponytail: hook for `fn_0040b9fc`.
pub static mut HOOK_0040B9FC: unsafe extern "C" fn(*mut u32) = default_mkwork;
/// Target `0x40e2f8` name hunt.
///
/// ponytail: hook standing in for same-batch `fn_0040e2f8`.
pub static mut HOOK_0040E2F8: unsafe extern "C" fn(u8, *mut u8, *mut u8, *mut u32) = default_hunt;
/// ponytail: hook for `fn_00404d24`.
pub static mut HOOK_00404D24: unsafe extern "C" fn(*mut u8) -> *mut u16 = default_convert;
/// `KERNEL32.DLL::CreateDirectoryW`.
///
/// ponytail: hook standing in for the raw import call at the original site.
pub static mut HOOK_CreateDirectoryW: unsafe extern "C" fn(*mut u16) -> i32 = default_mkdir;
/// `KERNEL32.DLL::GetLastError`.
///
/// ponytail: hook standing in for the raw import call at the original site.
pub static mut HOOK_GetLastError: unsafe extern "C" fn() -> u32 = default_lasterror;
/// Target `0x40df20` message.
///
/// ponytail: hook standing in for same-batch `fn_0040df20`.
pub static mut HOOK_0040DF20: unsafe extern "C" fn(u32, u32, *mut u8) = default_msg;
/// ponytail: hook for `fn_00407ee8`.
pub static mut HOOK_00407EE8: unsafe extern "C" fn(u32) = default_fmt;
/// ponytail: hook for `fn_0040bf84`.
pub static mut HOOK_0040BF84: unsafe extern "C" fn(u32, *mut u32) = default_fmt2;
/// Target `0x40def0` message.
///
/// ponytail: hook standing in for same-batch `fn_0040def0`.
pub static mut HOOK_0040DEF0: unsafe extern "C" fn(u32, u32, i32, *mut u8) = default_def0;
/// ponytail: hook for `fn_00409824`.
pub static mut HOOK_00409824: unsafe extern "C" fn(*mut u32, u8, u32) -> *mut u32 = default_mkmsg;
/// ponytail: hook for `fn_00403f88`.
pub static mut HOOK_00403F88: unsafe extern "C" fn(*mut u32) = default_fatal;
/// ponytail: hook for `fn_00404c98`.
pub static mut HOOK_00404C98: unsafe extern "C" fn(*mut u32, u32) = default_store;
/// ponytail: hook for `thunk 0x404c90`.
pub static mut HOOK_004046E8: unsafe extern "C" fn(*mut u32, u32) = default_free;

/// Temp-dir creation loop; stores dir token to `*param_1`.
/// `param_1` EAX per `__register` observation.
pub unsafe fn fn_0040e414(param_1: *mut u32) {
    // ponytail: SEH frame not modeled — test-platform init detail.
    loop {
        let mut work: u32 = 0;
        HOOK_0040B9FC(&mut work);
        let mut tok: u32 = 0;
        HOOK_0040E2F8(0, (&mut work as *mut u32) as *mut u8, DOT_TMP.as_ptr() as *mut u8, &mut tok);
        let w = HOOK_00404D24((&mut work as *mut u32) as *mut u8);
        if HOOK_CreateDirectoryW(w) != 0 {
            break;
        }
        let err = HOOK_GetLastError();
        if err == 0xb7 {
            continue;
        }
        let mut m1 = [0u8; 8];
        HOOK_0040DF20(0x36, work, m1.as_mut_ptr());
        HOOK_00407EE8(err);
        let mut m2: u32 = 0;
        HOOK_0040BF84(err, &mut m2);
        let mut m3 = [0u8; 8];
        HOOK_0040DEF0(0x68, (&mut m1 as *mut u8) as u32, 2, m3.as_mut_ptr());
        let m = HOOK_00409824(&mut 0u32, 1, m2);
        HOOK_00403F88(m);
    }
    HOOK_00404C98(param_1, 0);
    let mut a: u32 = 0;
    let mut b: u32 = 0;
    HOOK_004046E8(&mut a, 3);
    HOOK_004046E8(&mut b, 3);
}

/// `".tmp"` suffix at `0x40e524` (observed UTF-16 bytes `.`, `t`, `m`, `p`, NUL).
pub static DOT_TMP: &[u8] = b".\0t\0m\0p\0\0\0";

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static MKDIRS: AtomicUsize = AtomicUsize::new(0);
    static FATALS: AtomicUsize = AtomicUsize::new(0);
    static ERR: AtomicUsize = AtomicUsize::new(0);
    static STORES: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn mkdir(_p: *mut u16) -> i32 {
        MKDIRS.fetch_add(1, Ordering::SeqCst);
        if MKDIRS.load(Ordering::SeqCst) >= 2 { 1 } else { 0 }
    }
    unsafe extern "C" fn lasterror() -> u32 {
        ERR.load(Ordering::SeqCst) as u32
    }
    unsafe extern "C" fn fatal(_m: *mut u32) {
        FATALS.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn store(_d: *mut u32, _s: u32) {
        STORES.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn retry_paths() {
        unsafe {
            HOOK_CreateDirectoryW = mkdir;
            HOOK_GetLastError = lasterror;
            HOOK_00403F88 = fatal;
            HOOK_00404C98 = store;
        }
        // 0xb7 → silent retry then success.
        MKDIRS.store(0, Ordering::SeqCst);
        FATALS.store(0, Ordering::SeqCst);
        STORES.store(0, Ordering::SeqCst);
        ERR.store(0xb7, Ordering::SeqCst);
        let mut out = 0u32;
        unsafe { fn_0040e414(&mut out) };
        assert_eq!(MKDIRS.load(Ordering::SeqCst), 2);
        assert_eq!(FATALS.load(Ordering::SeqCst), 0);
        assert_eq!(STORES.load(Ordering::SeqCst), 1);
        // Other error → fatal then retry then success.
        MKDIRS.store(0, Ordering::SeqCst);
        FATALS.store(0, Ordering::SeqCst);
        STORES.store(0, Ordering::SeqCst);
        ERR.store(5, Ordering::SeqCst);
        unsafe { fn_0040e414(&mut out) };
        assert_eq!(MKDIRS.load(Ordering::SeqCst), 2);
        assert_eq!(FATALS.load(Ordering::SeqCst), 1);
        assert_eq!(STORES.load(Ordering::SeqCst), 1);
    }
}

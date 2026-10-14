//! Original procedure `0x0040e770` (167 bytes, `0x0040e770–0x0040e816`).
//! Evidence: `evidence/0040e770_fn_0040e770.md`.

unsafe extern "C" fn default_u32() -> u32 {
    0
}
unsafe extern "C" fn default_e88(_a: u32, _b: u32) {}
unsafe extern "C" fn default_b84(_a: u32, _b: *mut u32) {}
unsafe extern "C" fn default_d(_a: u32, _b: *const u8, _c: u32, _d: *mut u8) {}
unsafe extern "C" fn default_n824(_a: *const u8, _b: u8, _c: *mut u8) -> u32 {
    0
}
unsafe extern "C" fn default_u32_arg(_a: u32) {}
unsafe extern "C" fn default_void(_p: *mut u8) {}
unsafe extern "C" fn default_rel(_p: *mut u8, _n: u32) {}

/// Message-pointer table base `DAT_00412c08` (indexed `(param_1 & 0xff)`).
pub static mut DAT_00412C08: *const *const u8 = core::ptr::null();
/// Target `0x00406700 GetLastError`.
pub static mut HOOK_GETLASTERROR: unsafe extern "C" fn() -> u32 = default_u32;
/// Target `0x00407ee8 (lasterr, 0)`.
pub static mut HOOK_00407EE8: unsafe extern "C" fn(u32, u32) = default_e88;
/// Target `0x0040bf84 (lasterr, &local)`.
pub static mut HOOK_0040BF84: unsafe extern "C" fn(u32, *mut u32) = default_b84;
/// Target `0x0040def0 (packed, &entry, 2, &obj)`.
pub static mut HOOK_0040DEF0: unsafe extern "C" fn(u32, *const u8, u32, *mut u8) = default_d;
/// Target `0x00409824 (table, 1, obj)`.
pub static mut HOOK_00409824: unsafe extern "C" fn(*const u8, u8, *mut u8) -> u32 = default_n824;
/// Target `0x00403f88 (show/fail)`.
pub static mut HOOK_00403F88: unsafe extern "C" fn(u32) = default_u32_arg;
/// Target `0x00404c90` thunk (release local, 2).
pub static mut HOOK_00404C90: unsafe extern "C" fn(*mut u8, u32) = default_rel;
/// Target `0x00404c88` thunk (release obj).
pub static mut HOOK_00404C88: unsafe extern "C" fn(*mut u8) = default_void;

/// Fatal-error reporter (`param_1` EAX lane; caller passes `0x6a`).
pub unsafe fn fn_0040e770(param_1: u32) {
    let err = HOOK_GETLASTERROR();
    // ponytail: `MOVZX BL` mask exact.
    let entry: *const u8 = if DAT_00412C08.is_null() {
        core::ptr::null()
    } else {
        core::ptr::read_unaligned(DAT_00412C08.wrapping_add((param_1 & 0xff) as usize))
    };
    let mut obj: *mut u8 = core::ptr::null_mut();
    HOOK_00407EE8(err, 0);
    let mut detail: u32 = 0;
    HOOK_0040BF84(err, &mut detail);
    // ponytail: CONCAT31(detail>>8, 0x68) pack observed.
    let packed: u32 = (detail & 0xff00) | 0x68;
    HOOK_0040DEF0(packed, entry, 2, &mut obj as *mut *mut u8 as *mut u8);
    let shown = HOOK_00409824(core::ptr::null(), 1, obj);
    HOOK_00403F88(shown);
    HOOK_00404C90(&mut detail as *mut u32 as *mut u8, 2);
    HOOK_00404C88(&mut obj as *mut *mut u8 as *mut u8);
    let _ = default_void;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

    static ORDER: AtomicUsize = AtomicUsize::new(0);
    static GOT_IDX: AtomicU32 = AtomicU32::new(0);
    static ROW: [usize; 4] = [1, 2, 3, 4];

    unsafe extern "C" fn e88(_a: u32, _b: u32) {
        assert_eq!(ORDER.fetch_add(1, Ordering::SeqCst), 0);
    }
    unsafe extern "C" fn b84(_a: u32, _b: *mut u32) {
        assert_eq!(ORDER.fetch_add(1, Ordering::SeqCst), 1);
    }
    unsafe extern "C" fn d(_a: u32, _b: *const u8, _c: u32, _d: *mut u8) {
        assert_eq!(ORDER.fetch_add(1, Ordering::SeqCst), 2);
    }
    unsafe extern "C" fn n824(_a: *const u8, _b: u8, _c: *mut u8) -> u32 {
        assert_eq!(ORDER.fetch_add(1, Ordering::SeqCst), 3);
        7
    }
    unsafe extern "C" fn f88(a: u32) {
        assert_eq!(ORDER.fetch_add(1, Ordering::SeqCst), 4);
        assert_eq!(a, 7);
    }

    #[test]
    fn order_and_table_mask() {
        unsafe {
            DAT_00412C08 = ROW.as_ptr() as *const *const u8;
            HOOK_00407EE8 = e88;
            HOOK_0040BF84 = b84;
            HOOK_0040DEF0 = d;
            HOOK_00409824 = n824;
            HOOK_00403F88 = f88;
            ORDER.store(0, Ordering::SeqCst);
            fn_0040e770(0x101);
            assert_eq!(ORDER.load(Ordering::SeqCst), 5);
            let _ = GOT_IDX.load(Ordering::SeqCst);
        }
    }
}

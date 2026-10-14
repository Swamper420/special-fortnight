//! Original procedure `0x00402ec8` (49 bytes, `0x00402ec8–0x00402ef8`).
//! Evidence: `evidence/00402ec8_fn_00402ec8.md`.

/// Target `0x00406588`, queried once, result dereferenced for inner pointer:
/// direct intra-reconstruction call (rewired; signatures verified
/// `fn() -> *const u8`).
use crate::fn_00406588::fn_00406588;

/// Test-only serialization for tests driving the real `fn_00406588`
/// chain (also held by cross-module tests that call `fn_00402ec8`
/// directly).
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Indirect slot observed as `dword ptr [0x00413020]`, called with taken
/// value when nonzero.
///
/// ponytail: absolute-address cell as nullable hook, upgrade to real
/// image-relative import once data layout proven.
pub static mut HOOK_00413020: Option<unsafe extern "C" fn(u32)> = None;

/// `p=query(); i=*p; if !i {0} else {v=*[i+8]; *[i+8]=0; cb?(v); v}`.
/// Take-then-clear kept (callback observes cleared slot). Pointer link
/// read pointer-sized; field/return stay `u32` per observed widths.
pub unsafe fn fn_00402ec8() -> u32 {
    let p = fn_00406588();
    let inner = core::ptr::read_unaligned(p as *const *const u8);
    if inner.is_null() {
        return 0;
    }
    let v = core::ptr::read_unaligned(inner.wrapping_byte_add(8) as *const u32);
    core::ptr::write_unaligned(inner.wrapping_byte_add(8) as *mut u32, 0);
    if let Some(cb) = HOOK_00413020 {
        cb(v);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00413020, TEST_LOCK, fn_00402ec8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static CB_HITS: AtomicUsize = AtomicUsize::new(0);
    static CB_ARG: AtomicUsize = AtomicUsize::new(0);
    static mut CTX_WORD: *const u8 = core::ptr::null();
    static mut STRUCT_WORDS: [u32; 3] = [0; 3];

    /// TLS slot behind real `fn_00406588`: returns the ctx word.
    unsafe extern "C" fn tls_get_value(_index: u32) -> *const u8 {
        core::ptr::addr_of!(CTX_WORD) as *const u8
    }

    unsafe extern "C" fn callback(arg: u32) {
        CB_HITS.fetch_add(1, Ordering::SeqCst);
        CB_ARG.store(arg as usize, Ordering::SeqCst);
    }

    #[test]
    fn null_take_and_callback_lanes() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _tls = crate::fn_00406588::TEST_LOCK.lock().unwrap();
        // Real `fn_00406588` slow path straight to the ctx word.
        let (old_flag, old_hook, old_index);
        unsafe {
            old_flag = crate::fn_00406588::FLAG_00415b44;
            old_hook = crate::fn_00406588::TLS_GET_VALUE_00406520;
            old_index = crate::fn_00406588::TLS_INDEX_004127ac;
            crate::fn_00406588::FLAG_00415b44 = 1;
            crate::fn_00406588::TLS_GET_VALUE_00406520 = tls_get_value;
            crate::fn_00406588::TLS_INDEX_004127ac = 0;
            HOOK_00413020 = None;
            CTX_WORD = core::ptr::null();
        }
        CALLS.store(0, Ordering::SeqCst);
        // Null-inner lane: returns 0, no callback.
        assert_eq!(unsafe { fn_00402ec8() }, 0);
        // Take without callback: returns value, clears slot.
        unsafe {
            STRUCT_WORDS = [0, 0, 0xA5A5_5A5A];
            CTX_WORD = STRUCT_WORDS.as_ptr() as *const u8;
        }
        assert_eq!(unsafe { fn_00402ec8() }, 0xA5A5_5A5A);
        assert_eq!(unsafe { STRUCT_WORDS[2] }, 0);
        // Take with callback: calls once with value, clears.
        unsafe {
            STRUCT_WORDS = [0, 0, 0x1234_5678];
            CTX_WORD = STRUCT_WORDS.as_ptr() as *const u8;
            HOOK_00413020 = Some(callback);
        }
        CB_HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00402ec8() }, 0x1234_5678);
        assert_eq!(unsafe { STRUCT_WORDS[2] }, 0);
        assert_eq!(CB_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CB_ARG.load(Ordering::SeqCst), 0x1234_5678);
        unsafe {
            HOOK_00413020 = None;
            CTX_WORD = core::ptr::null();
            STRUCT_WORDS = [0; 3];
            crate::fn_00406588::FLAG_00415b44 = old_flag;
            crate::fn_00406588::TLS_GET_VALUE_00406520 = old_hook;
            crate::fn_00406588::TLS_INDEX_004127ac = old_index;
        }
    }
}

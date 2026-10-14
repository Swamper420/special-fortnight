//! Original procedure `0x00402ec8` (49 bytes, `0x402ec8–0x402ef8`).
//! Evidence: `evidence/00402ec8_fn_00402ec8.md`.

unsafe extern "C" fn default_resolver() -> *const u8 {
    core::ptr::null()
}

/// Target `0x406588`, queried once, result dereferenced for inner pointer.
///
/// ponytail: hook standing in for reconstructed `fn_00406588`, rewire to
/// real call once cross-module linkage proven.
pub static mut HOOK_00406588: unsafe extern "C" fn() -> *const u8 = default_resolver;

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
    let p = HOOK_00406588();
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
    use super::{HOOK_00406588, HOOK_00413020, fn_00402ec8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test-only serialization for tests sharing HOOK globals.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static CB_HITS: AtomicUsize = AtomicUsize::new(0);
    static CB_ARG: AtomicUsize = AtomicUsize::new(0);
    static mut CTX_WORD: *const u8 = core::ptr::null();
    static mut STRUCT_WORDS: [u32; 3] = [0; 3];

    unsafe extern "C" fn resolver() -> *const u8 {
        core::ptr::addr_of!(CTX_WORD) as *const u8
    }

    unsafe extern "C" fn callback(arg: u32) {
        CB_HITS.fetch_add(1, Ordering::SeqCst);
        CB_ARG.store(arg as usize, Ordering::SeqCst);
    }

    #[test]
    fn null_take_and_callback_lanes() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_00406588 = resolver;
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
        }
    }
}

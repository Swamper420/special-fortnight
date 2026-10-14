//! Original procedure `0x004081e8` (46 bytes, `0x004081e8–0x00408215`).
//! Evidence: `evidence/004081e8_fn_004081e8.md`.

unsafe extern "C" fn default_end(s: *mut u16) -> *mut u16 {
    s
}

/// End callee `0x004080fc` (`FUN_004080fc`), observed `(short *) -> short *`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_004080fc` once it exists.
pub static mut HOOK_004080FC: unsafe extern "C" fn(*mut u16) -> *mut u16 = default_end;

/// Last-occurrence u16 search: needle 0 → terminator address via hook;
/// else last lane equal to `param_2`, or null.
/// `param_1` arrives in EAX, `param_2` in DX per Ghidra `__register`
/// observation.
pub unsafe fn fn_004081e8(mut param_1: *mut u16, param_2: u16) -> *mut u16 {
    if param_2 == 0 {
        return HOOK_004080FC(param_1);
    }
    let mut last: *mut u16 = core::ptr::null_mut();
    loop {
        let c: u16 = core::ptr::read_unaligned(param_1);
        if param_2 == c {
            last = param_1;
            param_1 = param_1.wrapping_add(1);
        } else if c == 0 {
            break;
        } else {
            param_1 = param_1.wrapping_add(1);
        }
    }
    last
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004080FC, fn_004081e8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static END_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn scan_end(mut s: *mut u16) -> *mut u16 {
        END_CALLS.fetch_add(1, Ordering::SeqCst);
        while core::ptr::read_unaligned(s) != 0 {
            s = s.wrapping_add(1);
        }
        s
    }

    #[test]
    fn zero_needle_last_hit_miss_lanes() {
        unsafe {
            HOOK_004080FC = scan_end;
        }
        END_CALLS.store(0, Ordering::SeqCst);
        // Zero needle: hook DATA pointer passed through untouched.
        let mut s = [0x41u16, 0x42, 0x41, 0];
        let end = unsafe { fn_004081e8(s.as_mut_ptr(), 0) };
        assert_eq!(end, unsafe { s.as_mut_ptr().wrapping_add(3) });
        assert_eq!(END_CALLS.load(Ordering::SeqCst), 1);
        // Last occurrence recorded.
        assert_eq!(
            unsafe { fn_004081e8(s.as_mut_ptr(), 0x41) },
            unsafe { s.as_mut_ptr().wrapping_add(2) }
        );
        // Single hit.
        assert_eq!(
            unsafe { fn_004081e8(s.as_mut_ptr(), 0x42) },
            unsafe { s.as_mut_ptr().wrapping_add(1) }
        );
        // Miss: null.
        assert!(unsafe { fn_004081e8(s.as_mut_ptr(), 0x43) }.is_null());
        // Empty string, nonzero needle: null.
        let mut e = [0u16];
        assert!(unsafe { fn_004081e8(e.as_mut_ptr(), 0x41) }.is_null());
    }
}

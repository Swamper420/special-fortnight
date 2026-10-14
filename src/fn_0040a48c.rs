//! Original procedure `0x0040a48c` (6 bytes, `0x0040a48c–0x0040a491`).
//! Evidence: `evidence/0040a48c_fn_0040a48c.md`.

use crate::fn_004081e8::fn_004081e8;

/// Tail-forward to done `fn_004081e8`; callee result discarded,
/// void return respected. `param_1` in EAX, `param_2` in DX per
/// Ghidra `__register` observation.
///
/// ponytail: direct call to the done callee (no hook); single thin
/// wrapper.
pub unsafe fn fn_0040a48c(param_1: *mut u16, param_2: u16) {
    fn_004081e8(param_1, param_2);
}

#[cfg(test)]
mod tests {
    use super::fn_0040a48c;
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
    fn forward_lanes() {
        // Zero-needle lane reaches the foreign end hook (owner has
        // no lock): hold the common one first.
        let _common = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        let saved = unsafe { crate::fn_004081e8::HOOK_004080FC };
        unsafe { crate::fn_004081e8::HOOK_004080FC = scan_end };
        // Zero needle: forwarded, hook finds the terminator.
        let mut s = [0x41u16, 0x42, 0x41, 0];
        END_CALLS.store(0, Ordering::SeqCst);
        unsafe { fn_0040a48c(s.as_mut_ptr(), 0) };
        assert_eq!(END_CALLS.load(Ordering::SeqCst), 1);
        // Nonzero needles: no hook, last-hit / miss purely local.
        let mut t = [0x41u16, 0x42, 0x41, 0];
        END_CALLS.store(0, Ordering::SeqCst);
        unsafe { fn_0040a48c(t.as_mut_ptr(), 0x43) };
        assert_eq!(END_CALLS.load(Ordering::SeqCst), 0);
        unsafe { fn_0040a48c(t.as_mut_ptr(), 0x41) };
        assert_eq!(END_CALLS.load(Ordering::SeqCst), 0);
        unsafe { crate::fn_004081e8::HOOK_004080FC = saved };
    }
}

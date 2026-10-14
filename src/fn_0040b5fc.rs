//! Original procedure `0x0040b5fc` (34 bytes, `0x0040b5fc–0x0040b61d`).
//! Evidence: `evidence/0040b5fc_fn_0040b5fc.md`.

unsafe extern "C" fn default_end(_obj: usize, end: usize) -> usize {
    end
}

/// Callee `0x0040b620` (`FUN_0040b620`), called with `(obj, obj+len*2)`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_0040b620` once it exists.
pub static mut HOOK_0040B620: unsafe extern "C" fn(usize, usize) -> usize = default_end;

/// Test-only serialization for tests sharing this module's globals.
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `if p==0 { 0 } else { b620(p, p + *(p-4)*2) }`. Length word is
/// the dword at byte `p-4`, consumed signed (`LEA` stride), so the
/// offset is sign-extended; address math wraps. The second assembly
/// null test is dead (early return dominates) and folded.
pub unsafe fn fn_0040b5fc(param_1: usize) -> usize {
    if param_1 == 0 {
        return 0;
    }
    let len: u32 = core::ptr::read_unaligned((param_1.wrapping_sub(4)) as *const u32);
    let end = param_1.wrapping_add((len as i32).wrapping_mul(2) as usize);
    HOOK_0040B620(param_1, end)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040B620, TEST_LOCK, fn_0040b5fc};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG0: AtomicUsize = AtomicUsize::new(0);
    static ARG1: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn end(_obj: usize, end: usize) -> usize {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG0.store(_obj, Ordering::SeqCst);
        ARG1.store(end, Ordering::SeqCst);
        0xde_ad
    }

    #[test]
    fn null_and_tagged_lanes() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe { HOOK_0040B620 = end };
        // Null lane: no hook fire, returns 0.
        HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_0040b5fc(0) }, 0);
        assert_eq!(HITS.load(Ordering::SeqCst), 0);
        // Live lane: length word adjacent to object under test.
        let mut arena = [0u32; 8];
        arena[0] = 5;
        let obj = arena.as_mut_ptr().wrapping_add(1) as usize;
        HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_0040b5fc(obj) }, 0xde_ad);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG0.load(Ordering::SeqCst), obj);
        assert_eq!(ARG1.load(Ordering::SeqCst), obj.wrapping_add(10));
    }
}

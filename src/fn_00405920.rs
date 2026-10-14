//! Original procedure `0x00405920` (15 bytes, `0x00405920–0x0040592e`).
//! Evidence: `evidence/00405920_fn_00405920.md`.

/// Tail-forward `(dst, src, chars, count)` to `0x004057bc`; params
/// arrive in EAX/EDX/ECX (+stack count) per Ghidra `__register`
/// observation. `RET 0x4` modeled as by-value `u32`.
///
/// Target `0x004057bc` (`FUN_004057bc`): direct intra-reconstruction
/// call (rewired; signatures verified
/// `fn(usize, usize, *mut u8, u32)`).
pub unsafe fn fn_00405920(
    param_1: *mut u8,
    param_2: *mut u8,
    param_3: *mut u8,
    param_4: u32,
) {
    crate::fn_004057bc::fn_004057bc(param_1 as usize, param_2 as usize, param_3, param_4);
}

/// Test-only serialization for tests driving the real `fn_004057bc`
/// chain (also held by the `fn_00405940` test that forwards through
/// this module).
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::{TEST_LOCK, fn_00405920};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_A: AtomicUsize = AtomicUsize::new(0);
    static GOT_B: AtomicUsize = AtomicUsize::new(0);

    /// Tag-`0x0a` lane behind the real `fn_004057bc`.
    unsafe extern "C" fn lane(a: usize, b: usize) {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_A.store(a, Ordering::SeqCst);
        GOT_B.store(b, Ordering::SeqCst);
    }

    #[test]
    fn forwards_all_four_lanes() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _callee = crate::fn_004057bc::TEST_LOCK.lock().unwrap();
        // Real `fn_004057bc` behind the forward: tag 0x0a, count 1
        // runs the `(dst, *src)` lane once.
        let old_lane;
        unsafe {
            old_lane = crate::fn_004057bc::HOOK_00404718;
            crate::fn_004057bc::HOOK_00404718 = lane;
        }
        let mut dst = [0usize; 2];
        let mut src = [0x11223344usize, 0x55667788usize];
        let mut desc = [0x0au8];
        HITS.store(0, Ordering::SeqCst);
        unsafe {
            fn_00405920(
                dst.as_mut_ptr() as *mut u8,
                src.as_mut_ptr() as *mut u8,
                desc.as_mut_ptr(),
                1,
            )
        };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_A.load(Ordering::SeqCst), dst.as_mut_ptr() as usize);
        assert_eq!(GOT_B.load(Ordering::SeqCst), 0x11223344usize);
        unsafe {
            crate::fn_004057bc::HOOK_00404718 = old_lane;
        }
    }
}

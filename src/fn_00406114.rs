//! Original procedure `0x00406114` (31 bytes, `0x406114–0x406132`).
//! Evidence: `evidence/00406114_fn_00406114.md`.

unsafe extern "C" fn default_alloc(_size: u32) -> usize {
    0
}

/// Allocator `FUN_00402e04` (`CALL 0x402e04` with `EAX=8`).
///
/// ponytail: hook standing in for done `fn_00402e04`, rewire to the real
/// call once cross-module linkage exists.
pub static mut HOOK_FN_00402e04: unsafe extern "C" fn(u32) -> usize = default_alloc;

/// List head at `0x412030` (`DAT_00412030`); null means empty.
///
/// ponytail: absolute-address cell as hook global shared with
/// `fn_00406134`/`fn_00406198`, upgrade to real image-relative data
/// once data layout proven.
pub static mut DAT_00412030: *mut u8 = core::ptr::null_mut();

/// Test-only serialization for tests sharing `DAT_00412030` (also held
/// by `fn_00406134`/`fn_00406198` tests).
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Push: `node=alloc(8); node[0]=head; node[1]=param; head=node`.
/// `param_1` arrives in EAX (callee-saved via EBX) per observation.
/// Node slots are pointer-sized on host (16 B); value slot at +8.
pub unsafe fn fn_00406114(param_1: u32) {
    unsafe {
        let node = HOOK_FN_00402e04(8) as *mut u8;
        let head: *mut u8 = DAT_00412030;
        core::ptr::write_unaligned(node as *mut *mut u8, head);
        core::ptr::write_unaligned(node.wrapping_byte_add(8) as *mut usize, param_1 as usize);
        DAT_00412030 = node;
    }
}

#[cfg(test)]
mod tests {
    use super::{DAT_00412030, HOOK_FN_00402e04, TEST_LOCK, fn_00406114};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn alloc(size: u32) -> usize {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_ARG.store(size as usize, Ordering::SeqCst);
        Box::into_raw(Box::new([0usize; 2])) as usize
    }

    #[test]
    fn push_links_head_and_stores_param() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe { HOOK_FN_00402e04 = alloc };
        ALLOC_HITS.store(0, Ordering::SeqCst);
        // Push onto empty list.
        unsafe {
            DAT_00412030 = core::ptr::null_mut();
            fn_00406114(0x77);
        }
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 8);
        let n1 = unsafe { DAT_00412030 } as usize;
        assert_ne!(n1, 0);
        unsafe {
            assert_eq!(core::ptr::read_unaligned(n1 as *const usize), 0);
            assert_eq!(
                core::ptr::read_unaligned((n1 as *const u8).wrapping_byte_add(8) as *const usize),
                0x77
            );
            // Push again; new head links to old.
            fn_00406114(0x99);
        }
        let n2 = unsafe { DAT_00412030 } as usize;
        assert_ne!(n2, n1);
        unsafe {
            assert_eq!(core::ptr::read_unaligned(n2 as *const usize), n1);
            assert_eq!(
                core::ptr::read_unaligned((n2 as *const u8).wrapping_byte_add(8) as *const usize),
                0x99
            );
            let _ = Box::from_raw(n1 as *mut [usize; 2]);
            let _ = Box::from_raw(n2 as *mut [usize; 2]);
        }
    }
}

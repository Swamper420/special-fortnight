//! Original procedure `0x00402e20` (23 bytes, `0x00402e20–0x00402e36`).
//! Evidence: `evidence/00402e20_fn_00402e20.md`.

unsafe extern "C" fn default_indirect() -> u32 {
    1
}

unsafe extern "C" fn default_tail(_arg: u32) {}

/// Indirect slot observed as `dword ptr [0x00412740]` (`PTR_FUN_00412740`,
/// resolved target `0x00401c7c`, unreconstructed).
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade to real
/// image-relative import once data layout proven.
pub static mut PTR_00412740: unsafe extern "C" fn() -> u32 = default_indirect;

/// Tail target `0x00402f60` (`FUN_00402f60`), reached by `JMP` with
/// `AL=2` over nonzero indirect result (upper bytes preserved).
///
/// ponytail: hook standing in for done `fn_00402f60`, rewire to real
/// two-lane call once cross-module test serialization exists.
pub static mut TAIL_00402F60: unsafe extern "C" fn(u32) = default_tail;

/// Test-only serialization for tests sharing PTR/TAIL globals (also
/// held by cross-module tests that call `fn_00402e20` directly).
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `if param!=0 { if [0x00412740]() != 0 { tail((r & ~0xff) | 2) } }`.
/// `param_1` arrives in EAX per Ghidra `__register` observation.
pub unsafe fn fn_00402e20(param_1: u32) {
    if param_1 == 0 {
        return;
    }
    let r = PTR_00412740();
    if r == 0 {
        return;
    }
    TAIL_00402F60((r & 0xffffff00) | 2);
}

#[cfg(test)]
mod tests {
    use super::{PTR_00412740, TAIL_00402F60, TEST_LOCK, fn_00402e20};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static INDIRECT_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_ARG: AtomicUsize = AtomicUsize::new(0);
    static INDIRECT_RET: AtomicUsize = AtomicUsize::new(1);

    unsafe extern "C" fn indirect() -> u32 {
        INDIRECT_HITS.fetch_add(1, Ordering::SeqCst);
        INDIRECT_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn tail(arg: u32) {
        TAIL_HITS.fetch_add(1, Ordering::SeqCst);
        TAIL_ARG.store(arg as usize, Ordering::SeqCst);
    }

    #[test]
    fn branches() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe {
            PTR_00412740 = indirect;
            TAIL_00402F60 = tail;
        }
        INDIRECT_HITS.store(0, Ordering::SeqCst);
        TAIL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00402e20(0) };
        assert_eq!(INDIRECT_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);

        INDIRECT_RET.store(0, Ordering::SeqCst);
        unsafe { fn_00402e20(1) };
        assert_eq!(INDIRECT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);

        INDIRECT_RET.store(7, Ordering::SeqCst);
        unsafe { fn_00402e20(9) };
        assert_eq!(INDIRECT_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 2);

        INDIRECT_RET.store(0x12345678, Ordering::SeqCst);
        unsafe { fn_00402e20(9) };
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 0x12345602);
    }
}

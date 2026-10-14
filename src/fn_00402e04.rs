//! Original procedure `0x00402e04` (27 bytes, `0x00402e04–0x00402e1e`).
//! Evidence: `evidence/00402e04_fn_00402e04.md`.

unsafe extern "C" fn default_indirect() -> i32 {
    1
}

unsafe extern "C" fn default_tail(_arg: u32) {}

/// Indirect slot observed as `dword ptr [0x0041273c]` (`PTR_FUN_0041273c`,
/// resolved target `0x004018f8`, unreconstructed).
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade to real
/// image-relative import once data layout proven.
pub static mut PTR_0041273C: unsafe extern "C" fn() -> i32 = default_indirect;

/// Tail target `0x00402f60` (`FUN_00402f60`), reached by `JMP` with `AL=1`.
///
/// ponytail: hook standing in for done `fn_00402f60`, rewire to real
/// two-lane call once cross-module test serialization exists.
pub static mut TAIL_00402F60: unsafe extern "C" fn(u32) = default_tail;

/// Test-only serialization for tests sharing PTR/TAIL globals (also
/// held by cross-module tests that call `fn_00402e04`'s cell directly).
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `if param<1 {0} else { r=[0x0041273c](); if r!=0 {r} else { tail(1); 1 } }`.
/// `param_1` arrives in EAX, signed (`JLE`); returns EAX.
pub unsafe fn fn_00402e04(param_1: i32) -> i32 {
    if param_1 < 1 {
        return 0;
    }
    let r = PTR_0041273C();
    if r != 0 {
        return r;
    }
    TAIL_00402F60(1);
    1
}

#[cfg(test)]
mod tests {
    use super::{PTR_0041273C, TAIL_00402F60, TEST_LOCK, fn_00402e04};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static INDIRECT_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_ARG: AtomicUsize = AtomicUsize::new(0);
    static INDIRECT_RET: AtomicUsize = AtomicUsize::new(1);

    unsafe extern "C" fn indirect() -> i32 {
        INDIRECT_HITS.fetch_add(1, Ordering::SeqCst);
        INDIRECT_RET.load(Ordering::SeqCst) as i32
    }

    unsafe extern "C" fn tail(arg: u32) {
        TAIL_HITS.fetch_add(1, Ordering::SeqCst);
        TAIL_ARG.store(arg as usize, Ordering::SeqCst);
    }

    #[test]
    fn branches() {
        let _guard = TEST_LOCK.lock().unwrap();
        unsafe {
            PTR_0041273C = indirect;
            TAIL_00402F60 = tail;
        }
        INDIRECT_HITS.store(0, Ordering::SeqCst);
        TAIL_HITS.store(0, Ordering::SeqCst);
        unsafe { assert_eq!(fn_00402e04(0), 0) };
        assert_eq!(INDIRECT_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);
        unsafe { assert_eq!(fn_00402e04(-5), 0) };
        assert_eq!(INDIRECT_HITS.load(Ordering::SeqCst), 0);

        INDIRECT_RET.store(7, Ordering::SeqCst);
        unsafe { assert_eq!(fn_00402e04(1), 7) };
        assert_eq!(INDIRECT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);

        INDIRECT_RET.store(0, Ordering::SeqCst);
        unsafe { assert_eq!(fn_00402e04(9), 1) };
        assert_eq!(INDIRECT_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 1);
    }
}

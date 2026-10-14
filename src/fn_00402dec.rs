//! Original procedure `0x00402dec` (23 bytes, `0x402dec–0x402e02`).
//! Evidence: `evidence/00402dec_fn_00402dec.md`.

unsafe extern "C" fn default_indirect() -> u32 {
    1
}

unsafe extern "C" fn default_tail(_arg: u32) {}

/// Indirect slot observed as `dword ptr [0x412748]` (`PTR_FUN_00412748`).
///
/// ponytail: absolute-address cell modeled as mutable hook, upgrade to real
/// image-relative import once data layout proven.
pub static mut PTR_00412748: unsafe extern "C" fn() -> u32 = default_indirect;

/// Tail target `0x402f60` (`FUN_00402f60`), reached by `JMP` with `AL=1`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00402f60` once it exists.
pub static mut TAIL_00402f60: unsafe extern "C" fn(u32) = default_tail;

/// `if param!=0 { if [0x412748]() == 0 { tail(1) } }`.
/// `param_1` arrives in EAX per Ghidra `__register` observation.
pub unsafe fn fn_00402dec(param_1: u32) {
    if param_1 == 0 {
        return;
    }
    let r = PTR_00412748();
    if r != 0 {
        return;
    }
    TAIL_00402f60(1);
}

#[cfg(test)]
mod tests {
    use super::{PTR_00412748, TAIL_00402f60, fn_00402dec};
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
        unsafe {
            PTR_00412748 = indirect;
            TAIL_00402f60 = tail;
        }
        INDIRECT_HITS.store(0, Ordering::SeqCst);
        TAIL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00402dec(0) };
        assert_eq!(INDIRECT_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);

        INDIRECT_RET.store(7, Ordering::SeqCst);
        unsafe { fn_00402dec(1) };
        assert_eq!(INDIRECT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);

        INDIRECT_RET.store(0, Ordering::SeqCst);
        unsafe { fn_00402dec(9) };
        assert_eq!(INDIRECT_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 1);
    }
}

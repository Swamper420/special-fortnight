//! Original procedure `0x00402dec` (23 bytes, `0x00402dec–0x00402e02`).
//! Evidence: `evidence/00402dec_fn_00402dec.md`.

unsafe extern "C" fn default_indirect() -> u32 {
    1
}

unsafe extern "C" fn default_tail(_arg: u32) {}

/// Indirect slot observed as `dword ptr [0x00412748]` (`PTR_FUN_00412748`,
/// static bytes `0x0040218c`): rewired to the real `fn_0040218c` via a
/// minimal ABI adapter (EAX size in, EAX base out; the call site keeps
/// `param_1` in EAX across the setup, so the hook takes it explicitly).
// ponytail: adapter, exact parity on i686 only.
use crate::fn_0040218c::fn_0040218c;
unsafe extern "C" fn adapt_0040218c(size: u32) -> u32 {
    fn_0040218c(size) as u32
}
pub static mut PTR_00412748: unsafe extern "C" fn(u32) -> u32 = adapt_0040218c;

/// Tail target `0x00402f60` (`FUN_00402f60`), reached by `JMP` with `AL=1`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00402f60` once it exists.
pub static mut TAIL_00402f60: unsafe extern "C" fn(u32) = default_tail;

/// `if param!=0 { if [0x00412748](param) == 0 { tail(1) } }`, EAX out.
/// `param_1` arrives in EAX per Ghidra `__register` observation; EAX
/// still holds the indirect's result at `RET` (verified against
/// `0x402dec–0x402e02`), so the entry's table alloc observes the base.
pub unsafe fn fn_00402dec(param_1: u32) -> u32 {
    if param_1 == 0 {
        return 0;
    }
    let r = PTR_00412748(param_1);
    if r != 0 {
        return r;
    }
    TAIL_00402f60(1);
    1
}

#[cfg(test)]
mod tests {
    use super::{PTR_00412748, TAIL_00402f60, fn_00402dec};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static INDIRECT_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_ARG: AtomicUsize = AtomicUsize::new(0);
    static INDIRECT_RET: AtomicUsize = AtomicUsize::new(1);

    static INDIRECT_ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn indirect(size: u32) -> u32 {
        INDIRECT_HITS.fetch_add(1, Ordering::SeqCst);
        INDIRECT_ARG.store(size as usize, Ordering::SeqCst);
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
        unsafe { assert_eq!(fn_00402dec(0), 0) };
        assert_eq!(INDIRECT_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);

        INDIRECT_RET.store(7, Ordering::SeqCst);
        unsafe { assert_eq!(fn_00402dec(1), 7) };
        assert_eq!(INDIRECT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(INDIRECT_ARG.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);

        INDIRECT_RET.store(0, Ordering::SeqCst);
        unsafe { assert_eq!(fn_00402dec(9), 1) };
        assert_eq!(INDIRECT_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 1);
    }
}

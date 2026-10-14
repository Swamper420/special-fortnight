//! Original procedure `0x00402f60` (11 bytes, `0x402f60–0x402f6a`).
//! Evidence: `evidence/00402f60_fn_00402f60.md`.

unsafe extern "C" fn default_target(_masked: u32, _stack_top: u32) {}

/// Tail target `0x402f14` (`FUN_00402f14`), reached by `JMP` with
/// `EAX = param & 0x7f`, `EDX = dword ptr [ESP]`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00402f14` once it exists.
pub static mut NEXT_00402f14: unsafe extern "C" fn(u32, u32) = default_target;

/// `tail_14((param & 0x7f), stack_top)`; `param_1` arrives in EAX,
/// stack lane is dword at ESP on entry (explicit param: Rust has no ESP).
pub unsafe fn fn_00402f60(param_1: u32, stack_top: u32) {
    NEXT_00402f14(param_1 & 0x7f, stack_top);
}

#[cfg(test)]
mod tests {
    use super::{NEXT_00402f14, fn_00402f60};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static GOT_A: AtomicUsize = AtomicUsize::new(0);
    static GOT_B: AtomicUsize = AtomicUsize::new(0);
    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a: u32, b: u32) {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_A.store(a as usize, Ordering::SeqCst);
        GOT_B.store(b as usize, Ordering::SeqCst);
    }

    #[test]
    fn masks_and_forwards() {
        unsafe { NEXT_00402f14 = hook };
        unsafe { fn_00402f60(0x1ff, 0xdead) };
        assert_eq!(GOT_A.load(Ordering::SeqCst), 0x7f);
        assert_eq!(GOT_B.load(Ordering::SeqCst), 0xdead);
        unsafe { fn_00402f60(1, 0x1234) };
        assert_eq!(GOT_A.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_B.load(Ordering::SeqCst), 0x1234);
        assert_eq!(HITS.load(Ordering::SeqCst), 2);
    }
}

//! Original procedure `0x0040380c` (7 bytes, `0x0040380c–0x00403812`).
//! Evidence: `evidence/0040380c_fn_0040380c.md`.

unsafe extern "C" fn default_target(_param_1: u32, _stack_top: u32) {}

/// Tail target `0x00402f60` (`FUN_00402f60`), reached by direct `JMP`
/// after `MOV AL, 0x5`.
///
/// ponytail: hook standing in for reconstructed `fn_00402f60`, rewire to
/// `crate::fn_00402f60::fn_00402f60` once cross-module linkage proven.
pub static mut HOOK_0040380C: unsafe extern "C" fn(u32, u32) = default_target;

/// `MOV AL, 0x5; JMP 0x00402f60` — low byte forced to 5, upper
/// bytes and the entry-ESP lane pass through.
pub unsafe fn fn_0040380c(param_1: u32, stack_top: u32) {
    HOOK_0040380C(param_1 & 0xffffff00 | 5, stack_top);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040380C, fn_0040380c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static MASKED: AtomicUsize = AtomicUsize::new(0);
    static STACK: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(masked: u32, stack_top: u32) {
        HITS.fetch_add(1, Ordering::SeqCst);
        MASKED.store(masked as usize, Ordering::SeqCst);
        STACK.store(stack_top as usize, Ordering::SeqCst);
    }

    #[test]
    fn forces_low_byte_and_forwards() {
        unsafe { HOOK_0040380C = target };
        unsafe { fn_0040380c(0xabcdef12, 0x77aa) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(MASKED.load(Ordering::SeqCst), 0xabcdef05);
        assert_eq!(STACK.load(Ordering::SeqCst), 0x77aa);
    }
}

//! Original procedure `0x00409810` (6 bytes, `0x409810–0x409815`).
//! Evidence: `evidence/00409810_fn_00409810.md`.

unsafe extern "C" fn default_tail(_entry_eax: usize) {}

/// Target `0x4097f0` (`FUN_004097f0`), entered by `JMP` with the popped
/// `EAX` as its entry lane.
///
/// ponytail: hook standing in for done `fn_004097f0`, rewire to the real
/// call once cross-module linkage proven.
pub static mut HOOK_004097F0: unsafe extern "C" fn(usize) = default_tail;

/// `POP EAX; JMP 004097f0`: pops the guest return address into `EAX`
/// and enters `097f0` with it. No guest stack exists on host, so the
/// lane is a feasible `0`; `() -> void` per `__register` observation.
pub unsafe fn fn_00409810() {
    HOOK_004097F0(0);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004097F0, fn_00409810};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn tail(entry_eax: usize) {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(entry_eax, Ordering::SeqCst);
    }

    #[test]
    fn hands_off_to_097f0() {
        unsafe { HOOK_004097F0 = tail };
        unsafe { fn_00409810() };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 0);
    }
}

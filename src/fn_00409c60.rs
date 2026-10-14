//! Original procedure `0x00409c60` (13 bytes, `0x00409c60–0x00409c6c`).
//! Evidence: `evidence/00409c60_fn_00409c60.md`.

unsafe extern "C" fn default_tail(_arg: u32) {}

/// Tail target `0x00403f88` (`FUN_00403f88`), reached by `JMP` with
/// `param_1` still in EAX.
///
/// ponytail: hook standing in for reconstructed `fn_00403f88`,
/// rewire to the real call once cross-module linkage proven.
pub static mut HOOK_00403F88: unsafe extern "C" fn(u32) = default_tail;

/// `*param_3 = param_2; tail(param_1)`. `param_1` EAX / `param_2` EDX /
/// `param_3` ECX per Ghidra `__register` observation. `MOV ESP,ECX`
/// is the store-address setup; `MOV EBP,[EBP]` frame restore has no
/// host equivalent.
pub unsafe fn fn_00409c60(param_1: u32, param_2: u32, param_3: *mut u32) {
    core::ptr::write_unaligned(param_3, param_2);
    HOOK_00403F88(param_1);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00403F88, fn_00409c60};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn tail(arg: u32) {
        TAIL_HITS.fetch_add(1, Ordering::SeqCst);
        TAIL_ARG.store(arg as usize, Ordering::SeqCst);
    }

    #[test]
    fn store_then_tail() {
        unsafe { HOOK_00403F88 = tail };
        let mut cell: u32 = 0;
        TAIL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00409c60(0x5A, 0xDEAD_BEEF, &mut cell as *mut u32) };
        assert_eq!(cell, 0xDEAD_BEEF);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 0x5A);
    }
}

//! Original procedure `0x004049bc` (5 bytes, `0x004049bc–0x004049c0`).
//! Evidence: `evidence/004049bc_fn_004049bc.md`.

unsafe extern "C" fn default_target(_slot: *mut u32) -> i32 {
    0
}

/// Target `0x00404964` (`FUN_00404964`), reached by terminal `JMP`.
///
/// ponytail: hook standing in for unreconstructed target, rewire to
/// real `fn_00404964` once cross-module linkage proven.
pub static mut HOOK_00404964: unsafe extern "C" fn(*mut u32) -> i32 = default_target;

/// `JMP 0x00404964` with `param_1` in EAX per Ghidra `__register`
/// observation. Tail jump modeled as call+return.
pub unsafe fn fn_004049bc(param_1: *mut u32) -> i32 {
    HOOK_00404964(param_1)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00404964, fn_004049bc};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(slot: *mut u32) -> i32 {
        ARG.store(slot as usize, Ordering::SeqCst);
        0x51
    }

    #[test]
    fn forwards_slot_and_return() {
        unsafe { HOOK_00404964 = target };
        let mut slot = 0u32;
        let p = &mut slot as *mut u32;
        assert_eq!(unsafe { fn_004049bc(p) }, 0x51);
        assert_eq!(ARG.load(Ordering::SeqCst), p as usize);
    }
}

//! Original procedure `0x004054ac` (5 bytes, `0x4054ac–0x4054b0`).
//! Evidence: `evidence/004054ac_fn_004054ac.md`.

unsafe extern "C" fn default_target(_slot: *mut u32) -> i32 {
    0
}

/// Target `0x405458` (`FUN_00405458`), reached by terminal `JMP`.
///
/// ponytail: hook standing in for unreconstructed target, rewire to
/// real `fn_00405458` once cross-module linkage proven.
pub static mut HOOK_00405458: unsafe extern "C" fn(*mut u32) -> i32 = default_target;

/// `JMP 0x00405458` with `param_1` in EAX per Ghidra `__register`
/// observation. Tail jump modeled as call+return.
pub unsafe fn fn_004054ac(param_1: *mut u32) -> i32 {
    HOOK_00405458(param_1)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00405458, fn_004054ac};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(slot: *mut u32) -> i32 {
        ARG.store(slot as usize, Ordering::SeqCst);
        -9
    }

    #[test]
    fn forwards_slot_and_return() {
        unsafe { HOOK_00405458 = target };
        let mut slot = 0u32;
        let p = &mut slot as *mut u32;
        assert_eq!(unsafe { fn_004054ac(p) }, -9);
        assert_eq!(ARG.load(Ordering::SeqCst), p as usize);
    }
}

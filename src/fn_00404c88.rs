//! Original procedure `0x00404c88` (5 bytes, `0x00404c88–0x00404c8c`).
//! Evidence: `evidence/00404c88_fn_00404c88.md`.

unsafe extern "C" fn default_target(_slot: *mut u32) -> *mut u32 {
    core::ptr::null_mut()
}

/// Target `0x004046c4` (`FUN_004046c4`), reached by terminal `JMP`.
///
/// ponytail: hook standing in for done `fn_004046c4`, rewire to the
/// real call once cross-module linkage proven.
pub static mut HOOK_004046C4: unsafe extern "C" fn(*mut u32) -> *mut u32 = default_target;

/// `JMP 0x004046c4` with `param_1` in EAX per Ghidra `__register`
/// observation. Tail jump modeled as call+return of the slot pointer.
pub unsafe fn fn_00404c88(param_1: *mut u32) -> *mut u32 {
    HOOK_004046C4(param_1)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004046C4, fn_00404c88};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(slot: *mut u32) -> *mut u32 {
        ARG.store(slot as usize, Ordering::SeqCst);
        slot
    }

    #[test]
    fn forwards_slot_and_echoes() {
        unsafe { HOOK_004046C4 = target };
        let mut slot = 0u32;
        let p = &mut slot as *mut u32;
        assert_eq!(unsafe { fn_00404c88(p) }, p);
        assert_eq!(ARG.load(Ordering::SeqCst), p as usize);
    }
}

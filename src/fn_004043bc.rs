//! Original procedure `0x004043bc` (18 bytes, `0x4043bc–0x4043ce`).
//! Evidence: `evidence/004043bc_fn_004043bc.md`.

unsafe extern "C" fn default_target(_a: u32, _b: *mut u32) {}

/// Target `0x4063e4` (`FUN_004063e4`), both lanes forwarded.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_004063e4` once it exists.
pub static mut HOOK_004063e4: unsafe extern "C" fn(u32, *mut u32) = default_target;

/// `FUN_004063e4(param_1, param_2)`.
/// `param_1` arrives in EAX, `param_2` in EDX per Ghidra `__register`
/// observation. Entry PUSH/POP of EBX/ESI is callee-save only.
pub unsafe fn fn_004043bc(param_1: u32, param_2: *mut u32) {
    HOOK_004063e4(param_1, param_2);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004063e4, fn_004043bc};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG0: AtomicUsize = AtomicUsize::new(0);
    static ARG1: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn target(a: u32, b: *mut u32) {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG0.store(a as usize, Ordering::SeqCst);
        ARG1.store(b as usize, Ordering::SeqCst);
    }

    #[test]
    fn forwards_both_lanes() {
        static mut SLOT: u32 = 0x77;
        unsafe {
            HOOK_004063e4 = target;
            fn_004043bc(0x11, core::ptr::addr_of_mut!(SLOT));
        }
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG0.load(Ordering::SeqCst), 0x11);
        assert_eq!(
            ARG1.load(Ordering::SeqCst),
            unsafe { core::ptr::addr_of_mut!(SLOT) } as usize
        );
    }
}

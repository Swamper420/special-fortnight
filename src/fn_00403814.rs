//! Original procedure `0x00403814` (21 bytes, `0x403814–0x403828`).
//! Evidence: `evidence/00403814_fn_00403814.md`.

unsafe extern "C" fn default_callee(_a: *mut u8, _b: *mut u8) {}

/// Target `0x4063d0` (`FUN_004063d0`), called with the derefed
/// link and the `param_2` passthrough.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_004063d0` once it exists.
pub static mut HOOK_004063d0: unsafe extern "C" fn(*mut u8, *mut u8) = default_callee;

/// `callee(*[param_1-0x38], param_2)`. `param_1` EAX / `param_2`
/// EDX per Ghidra `__register` observation; `PUSH/POP` spills have
/// no host-visible effect.
pub unsafe fn fn_00403814(param_1: *mut u8, param_2: *mut u8) {
    unsafe {
        let link: *mut u8 =
            core::ptr::read_unaligned(param_1.wrapping_byte_sub(0x38) as *const *mut u8);
        HOOK_004063d0(link, param_2);
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004063d0, fn_00403814};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_A: AtomicUsize = AtomicUsize::new(0);
    static GOT_B: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn callee(a: *mut u8, b: *mut u8) {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_A.store(a as usize, Ordering::SeqCst);
        GOT_B.store(b as usize, Ordering::SeqCst);
    }

    #[test]
    fn link_and_passthrough() {
        unsafe {
            HOOK_004063d0 = callee;
        }
        let mut arena = [0u8; 0x40];
        let base = arena.as_mut_ptr();
        let marker = unsafe { base.add(0x10) };
        let param_2 = unsafe { base.add(0x20) };
        let obj = unsafe { base.add(0x38) };
        unsafe {
            core::ptr::write_unaligned(base as *mut *mut u8, marker);
            HITS.store(0, Ordering::SeqCst);
            fn_00403814(obj, param_2);
        }
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_A.load(Ordering::SeqCst), marker as usize);
        assert_eq!(GOT_B.load(Ordering::SeqCst), param_2 as usize);
    }
}

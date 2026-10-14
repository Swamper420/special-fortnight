//! Original procedure `0x0040c1f8` (40 bytes, `0x40c1f8–0x40c21f`).
//! Evidence: `evidence/0040c1f8_fn_0040c1f8.md`.

unsafe extern "C" fn default_target(_p1: *const u8, _p2: u32) {}

/// Target `0x40c130` (`FUN_0040c130`), called as `(*param_1, 0x26)`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_0040c130` once it exists.
pub static mut HOOK_0040c130: unsafe extern "C" fn(*const u8, u32) = default_target;

/// `r = (*param_1)[+8](param_1, param_2, param_3); if r != param_3 { hook(*param_1, 0x26) }`.
/// Register lanes observed: `param_1` in EAX, `param_2` in EDX, `param_3` in ECX.
///
/// ponytail: callee ABIs are `extern "C"` placeholders, upgrade to real
/// Borland register convention once call sites prove register layout.
pub unsafe fn fn_0040c1f8(param_1: *mut *const u8, param_2: u32, param_3: i32) {
    let vtbl = core::ptr::read_unaligned(param_1 as *const *const u8);
    let slot = vtbl.wrapping_byte_add(8) as *const *const core::ffi::c_void;
    let target = core::ptr::read_unaligned(slot);
    let f: unsafe extern "C" fn(*mut *const u8, u32, i32) -> i32 =
        core::mem::transmute(target);
    let r = f(param_1, param_2, param_3);
    if param_3 != r {
        let first = core::ptr::read_unaligned(param_1 as *const *const u8);
        HOOK_0040c130(first, 0x26);
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040c130, fn_0040c1f8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static RET: AtomicUsize = AtomicUsize::new(0);
    static HOOK_HITS: AtomicUsize = AtomicUsize::new(0);
    static HOOK_ARG2: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn indirect(
        _o: *mut *const u8,
        _p2: u32,
        _p3: i32,
    ) -> i32 {
        RET.load(Ordering::SeqCst) as i32
    }

    unsafe extern "C" fn hook(_p1: *const u8, p2: u32) {
        HOOK_HITS.fetch_add(1, Ordering::SeqCst);
        HOOK_ARG2.store(p2 as usize, Ordering::SeqCst);
    }

    #[test]
    fn mismatch_reports_once_with_0x26() {
        let target = indirect as *const core::ffi::c_void;
        let mut vtbl = [0u8; 16];
        unsafe {
            core::ptr::copy_nonoverlapping(
                &target as *const _ as *const u8,
                vtbl.as_mut_ptr().add(8),
                core::mem::size_of::<*const core::ffi::c_void>(),
            );
        }
        let vtbl_ptr = vtbl.as_ptr();
        let mut obj = vtbl_ptr;
        let obj_ptr: *mut *const u8 = &mut obj;
        unsafe { HOOK_0040c130 = hook };
        HOOK_HITS.store(0, Ordering::SeqCst);
        RET.store(7, Ordering::SeqCst);
        unsafe { fn_0040c1f8(obj_ptr, 0x1234, 7) };
        assert_eq!(HOOK_HITS.load(Ordering::SeqCst), 0);
        RET.store(9, Ordering::SeqCst);
        unsafe { fn_0040c1f8(obj_ptr, 0x1234, 7) };
        assert_eq!(HOOK_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(HOOK_ARG2.load(Ordering::SeqCst), 0x26);
    }
}

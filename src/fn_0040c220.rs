//! Original procedure `0x0040c220` (22 bytes, `0x0040c220–0x0040c235`).
//! Evidence: `evidence/0040c220_fn_0040c220.md`.

/// `(param_1, &{param_2, 0})` through vtable slot `+0xc`.
/// Register lanes observed: `param_1` in EAX, `param_2` in EDX.
///
/// ponytail: callee ABI is `extern "C"` placeholder, upgrade to real
/// Borland register convention once call sites prove register layout.
pub unsafe fn fn_0040c220(param_1: *mut *const u8, param_2: u32) {
    let vtbl = core::ptr::read_unaligned(param_1 as *const *const u8);
    let slot = vtbl.wrapping_byte_add(0xc) as *const *const core::ffi::c_void;
    let target = core::ptr::read_unaligned(slot);
    let f: unsafe extern "C" fn(*mut *const u8, *const [u32; 2]) =
        core::mem::transmute(target);
    let args = [param_2, 0u32];
    f(param_1, &args);
}

#[cfg(test)]
mod tests {
    use super::fn_0040c220;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_OBJ: AtomicUsize = AtomicUsize::new(0);
    static GOT_A0: AtomicUsize = AtomicUsize::new(0);
    static GOT_A1: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn indirect(obj: *mut *const u8, args: *const [u32; 2]) {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_OBJ.store(obj as usize, Ordering::SeqCst);
        let a = unsafe { core::ptr::read_unaligned(args) };
        GOT_A0.store(a[0] as usize, Ordering::SeqCst);
        GOT_A1.store(a[1] as usize, Ordering::SeqCst);
    }

    #[test]
    fn forwards_obj_and_zero_padded_buffer() {
        let target = indirect as *const core::ffi::c_void;
        let mut vtbl = [0u8; 20];
        unsafe {
            core::ptr::copy_nonoverlapping(
                &target as *const _ as *const u8,
                vtbl.as_mut_ptr().add(0xc),
                core::mem::size_of::<*const core::ffi::c_void>(),
            );
        }
        let vtbl_ptr = vtbl.as_ptr();
        let mut obj = vtbl_ptr;
        let obj_ptr: *mut *const u8 = &mut obj;
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040c220(obj_ptr, 0x12345678) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_OBJ.load(Ordering::SeqCst), obj_ptr as usize);
        assert_eq!(GOT_A0.load(Ordering::SeqCst), 0x12345678);
        assert_eq!(GOT_A1.load(Ordering::SeqCst), 0);
    }
}

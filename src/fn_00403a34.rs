//! Original procedure `0x00403a34` (6 bytes, `0x403a34–0x403a39`).
//! Evidence: `evidence/00403a34_fn_00403a34.md`.

/// Unchecked indirect dispatch: `call *(vtable-8)(param)`.
/// `param_1` arrives in EAX per Ghidra `__register` observation; EAX
/// still holds it at the indirect call (only EDX clobbered).
///
/// ponytail: callee ABI placeholder (`extern "C"`), upgrade to real
/// Borland register convention once call sites prove register layout.
pub unsafe fn fn_00403a34(param_1: *mut *const u8) {
    let vtbl = core::ptr::read_unaligned(param_1 as *const *const u8);
    let slot = vtbl.wrapping_byte_sub(8) as *const *const core::ffi::c_void;
    let target = core::ptr::read_unaligned(slot);
    let f: unsafe extern "C" fn(*mut *const u8) = core::mem::transmute(target);
    f(param_1);
}

#[cfg(test)]
mod tests {
    use super::fn_00403a34;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_OBJ: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn mock(obj: *mut *const u8) {
        HITS.fetch_add(1, Ordering::SeqCst);
        GOT_OBJ.store(obj as usize, Ordering::SeqCst);
    }

    #[test]
    fn dispatches_through_vtable_minus_8() {
        // Byte layout mirroring 32-bit original: func ptr lives 8 bytes
        // below vtbl, read back with read_unaligned. Works on 64-bit host.
        let mock_ptr = mock as *const core::ffi::c_void;
        let mut buf = [0u8; 16];
        unsafe {
            core::ptr::copy_nonoverlapping(
                &mock_ptr as *const _ as *const u8,
                buf.as_mut_ptr(),
                core::mem::size_of::<*const core::ffi::c_void>(),
            );
        }
        let vtbl = unsafe { buf.as_ptr().add(8) };
        let mut obj = vtbl;
        let obj_ptr: *mut *const u8 = &mut obj;
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00403a34(obj_ptr) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_OBJ.load(Ordering::SeqCst), obj_ptr as usize);
    }
}

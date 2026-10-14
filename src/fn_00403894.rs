//! Original procedure `0x00403894` (12 bytes, `0x00403894–0x0040389f`).
//! Evidence: `evidence/00403894_fn_00403894.md`.

/// Null-checked indirect dispatch: `call *(vtable-4)(param, 1)`.
/// `param_1` arrives in EAX per Ghidra `__register` observation.
///
/// ponytail: callee ABI placeholder (`extern "C"`), upgrade to real
/// Borland register convention once call sites prove register layout.
pub unsafe fn fn_00403894(param_1: *mut *const u8) {
    if param_1.is_null() {
        return;
    }
    let vtbl = core::ptr::read_unaligned(param_1 as *const *const u8);
    let slot = vtbl.wrapping_byte_sub(4) as *const *const core::ffi::c_void;
    let target = core::ptr::read_unaligned(slot);
    let f: unsafe extern "C" fn(*mut *const u8, u8) = core::mem::transmute(target);
    f(param_1, 1);
}

#[cfg(test)]
mod tests {
    use super::fn_00403894;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn mock(_p: *mut *const u8, b: u8) {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(b as usize, Ordering::SeqCst);
    }

    #[test]
    fn null_returns_silently() {
        unsafe { fn_00403894(core::ptr::null_mut()) };
    }

    #[test]
    fn dispatches_through_vtable_minus_4() {
        // Byte layout mirroring 32-bit original: func ptr lives 4 bytes
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
        let vtbl = unsafe { buf.as_ptr().add(4) };
        let mut obj = vtbl;
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00403894(&mut obj as *mut *const u8) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 1);
    }
}

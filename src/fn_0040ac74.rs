//! Original procedure `0x0040ac74` (14 bytes, `0x0040ac74–0x0040ac81`).
//! Evidence: `evidence/0040ac74_fn_0040ac74.md`.

use crate::fn_00403894::fn_00403894;

/// Take-and-clear: `old=*param_1; *param_1=0; 3894(old)`.
/// `param_1` arrives in EAX per Ghidra `__register` observation.
/// Direct call to done `fn_00403894` (stateless, no hooks); its
/// internal null check covers the null-old lane.
pub unsafe fn fn_0040ac74(param_1: *mut *mut u8) {
    let old: *mut u8 = core::ptr::read_unaligned(param_1 as *const *mut u8);
    core::ptr::write_unaligned(param_1, core::ptr::null_mut());
    fn_00403894(old as *mut *const u8);
}

#[cfg(test)]
mod tests {
    use super::fn_0040ac74;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn mock(_p: *mut *const u8, b: u8) {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(b as usize, Ordering::SeqCst);
    }

    /// Fake object under test: func ptr 4 bytes below vtbl, as in
    /// `fn_00403894`'s own dispatch test. Locals declared in the
    /// caller scope (a helper would dangle obj).
    macro_rules! setup {
        ($buf:ident, $obj:ident, $slot:ident) => {
            let mock_ptr = mock as *const core::ffi::c_void;
            let mut $buf = [0u8; 16];
            unsafe {
                core::ptr::copy_nonoverlapping(
                    &mock_ptr as *const _ as *const u8,
                    $buf.as_mut_ptr(),
                    core::mem::size_of::<*const core::ffi::c_void>(),
                );
            }
            let vtbl = unsafe { $buf.as_ptr().add(4) };
            let mut $obj = vtbl;
            let mut $slot: *mut u8 =
                &mut $obj as *mut *const u8 as *mut u8;
        };
    }

    #[test]
    fn take_clear_dispatch_lanes() {
        // Null-old lane: slot stays null, no dispatch.
        let mut null_slot: *mut u8 = core::ptr::null_mut();
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040ac74(&mut null_slot as *mut *mut u8) };
        assert!(null_slot.is_null());
        assert_eq!(HITS.load(Ordering::SeqCst), 0);
        // Live-old lane: slot cleared, dispatch fires once with flag 1.
        setup!(buf, _obj, slot);
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040ac74(&mut slot as *mut *mut u8) };
        assert!(slot.is_null());
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), 1);
        let _ = buf;
    }
}

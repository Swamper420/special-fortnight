//! Original procedure `0x00403884` (15 bytes, `0x00403884–0x00403892`).
//! Evidence: `evidence/00403884_fn_00403884.md`.

use crate::fn_00403a34::fn_00403a34;
use crate::fn_00403a8c::fn_00403a8c;

/// `r = 3a8c(obj, flag); if flag > 0 { 3a34(r) }`. DL tested after the
/// first call is the incoming flag (callee preserves EDX both lanes);
/// EAX after the call is obj on both lanes.
///
/// ponytail: direct calls to done callees (no hooks); ABI placeholder
/// (`extern "C"`) inherited from callees.
pub unsafe fn fn_00403884(param_1: *mut u8, param_2: u8) {
    let r = fn_00403a8c(param_1, param_2);
    if (param_2 as i8) <= 0 {
        return;
    }
    fn_00403a34(r as *mut *const u8);
}

#[cfg(test)]
mod tests {
    use super::fn_00403884;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS_A: AtomicUsize = AtomicUsize::new(0);
    static HITS_B: AtomicUsize = AtomicUsize::new(0);
    static GOT_A: AtomicUsize = AtomicUsize::new(0);
    static GOT_B: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn mock_a(p: *mut u8) {
        HITS_A.fetch_add(1, Ordering::SeqCst);
        GOT_A.store(p as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn mock_b(o: *mut *const u8) {
        HITS_B.fetch_add(1, Ordering::SeqCst);
        GOT_B.store(o as usize, Ordering::SeqCst);
    }

    /// One fake vtable serving both dispatches: `[vtbl-0x18]=mock_a`
    /// (`fn_00403a8c` slot), `[vtbl-8]=mock_b` (`fn_00403a34` slot).
    /// Locals declared in caller scope (a helper would dangle obj).
    macro_rules! setup {
        ($buf:ident, $obj:ident, $param:ident) => {
            let mock_a_ptr = mock_a as *const core::ffi::c_void;
            let mock_b_ptr = mock_b as *const core::ffi::c_void;
            let mut $buf = [0u8; 32];
            unsafe {
                core::ptr::copy_nonoverlapping(
                    &mock_a_ptr as *const _ as *const u8,
                    $buf.as_mut_ptr(),
                    core::mem::size_of::<*const core::ffi::c_void>(),
                );
                core::ptr::copy_nonoverlapping(
                    &mock_b_ptr as *const _ as *const u8,
                    $buf.as_mut_ptr().add(0x10),
                    core::mem::size_of::<*const core::ffi::c_void>(),
                );
            }
            let vtbl = unsafe { $buf.as_ptr().add(0x18) };
            let mut $obj = vtbl;
            let $param = &mut $obj as *mut *const u8 as *mut u8;
        };
    }

    #[test]
    fn branches() {
        setup!(buf, _obj, param);
        let obj = param as usize;
        HITS_A.store(0, Ordering::SeqCst);
        HITS_B.store(0, Ordering::SeqCst);
        unsafe { fn_00403884(param, 0) };
        assert_eq!(HITS_A.load(Ordering::SeqCst), 0);
        assert_eq!(HITS_B.load(Ordering::SeqCst), 0);

        setup!(_buf2, _obj2, param2);
        let obj2 = param2 as usize;
        unsafe { fn_00403884(param2, 1) };
        assert_eq!(HITS_A.load(Ordering::SeqCst), 1);
        assert_eq!(HITS_B.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_A.load(Ordering::SeqCst), obj2);
        assert_eq!(GOT_B.load(Ordering::SeqCst), obj2);
        let _ = (buf, obj);
    }
}

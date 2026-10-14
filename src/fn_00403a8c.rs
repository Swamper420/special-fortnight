//! Original procedure `0x00403a8c` (15 bytes, `0x00403a8c–0x00403a9a`).
//! Evidence: `evidence/00403a8c_fn_00403a8c.md`.

/// Signed-`DL > 0` guard gates vtable dispatch: `call [vtbl-0x18](obj)`,
/// returns obj on both lanes. Incoming DL clobbered by vtbl load.
/// Caller regs (PUSH/POP EAX,EDX) meaningless on host; EAX-return
/// modeled as returning `param_1`.
///
/// ponytail: callee ABI placeholder (`extern "C"`), upgrade to real
/// Borland register convention once call sites prove register layout.
pub unsafe fn fn_00403a8c(param_1: *mut u8, param_2: u8) -> *mut u8 {
    if (param_2 as i8) <= 0 {
        return param_1;
    }
    let vtbl = core::ptr::read_unaligned(param_1 as *const *const u8);
    let slot = vtbl.wrapping_byte_sub(0x18) as *const *const core::ffi::c_void;
    let target = core::ptr::read_unaligned(slot);
    let f: unsafe extern "C" fn(*mut u8) = core::mem::transmute(target);
    f(param_1);
    param_1
}

#[cfg(test)]
mod tests {
    use super::fn_00403a8c;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    /// Test-only serialization for tests sharing HITS/ARG globals.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    unsafe extern "C" fn mock(p: *mut u8) {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(p as usize, Ordering::SeqCst);
    }

    /// Byte layout mirroring 32-bit original: func ptr lives 0x18 bytes
    /// below vtbl, read back with read_unaligned. Works on 64-bit host.
    /// Declares locals in the caller scope (a wrapping helper would
    /// leave the obj pointer dangling).
    macro_rules! lane {
        ($buf:ident, $obj:ident, $param:ident) => {
            let mock_ptr = mock as *const core::ffi::c_void;
            let mut $buf = [0u8; 48];
            unsafe {
                core::ptr::copy_nonoverlapping(
                    &mock_ptr as *const _ as *const u8,
                    $buf.as_mut_ptr(),
                    core::mem::size_of::<*const core::ffi::c_void>(),
                );
            }
            let vtbl = unsafe { $buf.as_ptr().add(0x18) };
            let mut $obj = vtbl;
            let $param = &mut $obj as *mut *const u8 as *mut u8;
        };
    }

    #[test]
    fn skip_lane_returns_without_call() {
        let _guard = TEST_LOCK.lock().unwrap();
        lane!(buf, _obj, param);
        HITS.store(0, Ordering::SeqCst);
        let ret = unsafe { fn_00403a8c(param, 0) };
        assert_eq!(ret, param);
        assert_eq!(HITS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn dispatch_lane_calls_and_returns_obj() {
        let _guard = TEST_LOCK.lock().unwrap();
        lane!(_buf, obj_hold, param);
        HITS.store(0, Ordering::SeqCst);
        let ret = unsafe { fn_00403a8c(param, 1) };
        assert_eq!(ret, param);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG.load(Ordering::SeqCst), param as usize);
        let _ = &mut obj_hold;
    }
}

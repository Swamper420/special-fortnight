//! Original procedure `0x00403ab4` (43 bytes, `0x403ab4–0x403ade`).
//! Evidence: `evidence/00403ab4_fn_00403ab4.md`.

use crate::fn_00402e20::fn_00402e20;

/// Global dword at `0x4138c4` (`DAT_004138c4`): indirect table base.
/// Null (0) skips the indirect lane; else target is read at `+4`.
///
/// ponytail: absolute-address cell as pointer-sized hook global, upgrade
/// to real image-relative import once data layout proven.
pub static mut DAT_004138c4: *mut u8 = core::ptr::null_mut();

/// `if DAT!=0 && [p+0xc]!=0 { DAT[1]([p+0xc]) }; 02e20(p)` with
/// `EDX=0`. DAT checked first (short-circuit isomorphic: DAT-null lane
/// never reads `[p+0xc]`).
///
/// ponytail: direct call to done `fn_00402e20` (no hook); ABI placeholder
/// (`unsafe fn`) inherited from callee.
pub unsafe fn fn_00403ab4(param_1: *mut u8) {
    let dat = DAT_004138c4;
    if !dat.is_null() {
        let field =
            core::ptr::read_unaligned(param_1.wrapping_byte_add(0xc) as *const u32);
        if field != 0 {
            let slot = dat.wrapping_byte_add(4) as *const *const core::ffi::c_void;
            let target = core::ptr::read_unaligned(slot);
            let f: unsafe extern "C" fn(u32) = core::mem::transmute(target);
            f(field);
        }
    }
    fn_00402e20(param_1 as u32);
}

#[cfg(test)]
mod tests {
    use super::{DAT_004138c4, fn_00403ab4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test-only serialization for tests sharing DAT_004138c4.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn indirect(arg: u32) {
        HITS.fetch_add(1, Ordering::SeqCst);
        ARG.store(arg as usize, Ordering::SeqCst);
    }

    #[test]
    fn guard_and_dispatch_lanes() {
        let _own = TEST_LOCK.lock().unwrap();
        // fn_00403ab4 calls done fn_00402e20, which reads its PTR/TAIL
        // globals: hold the owner lock so its writer test can't race us.
        let _callee = crate::fn_00402e20::TEST_LOCK.lock().unwrap();
        unsafe {
            let saved = DAT_004138c4;
            HITS.store(0, Ordering::SeqCst);

            // DAT null: no indirect call, direct lane reached.
            DAT_004138c4 = core::ptr::null_mut();
            let mut obj = [0u8; 16];
            let p = obj.as_mut_ptr();
            core::ptr::write_unaligned(p.wrapping_byte_add(0xc) as *mut u32, 9);
            fn_00403ab4(p);
            assert_eq!(HITS.load(Ordering::SeqCst), 0);

            // DAT set, field zero: no indirect call.
            let ip = indirect as *const core::ffi::c_void;
            let mut tbl = [0u8; 16];
            core::ptr::copy_nonoverlapping(
                &ip as *const _ as *const u8,
                tbl.as_mut_ptr().add(4),
                core::mem::size_of::<*const core::ffi::c_void>(),
            );
            DAT_004138c4 = tbl.as_mut_ptr();
            core::ptr::write_unaligned(p.wrapping_byte_add(0xc) as *mut u32, 0);
            fn_00403ab4(p);
            assert_eq!(HITS.load(Ordering::SeqCst), 0);

            // Both nonzero: one indirect call carrying the field.
            core::ptr::write_unaligned(p.wrapping_byte_add(0xc) as *mut u32, 0x1122_3344);
            fn_00403ab4(p);
            assert_eq!(HITS.load(Ordering::SeqCst), 1);
            assert_eq!(ARG.load(Ordering::SeqCst), 0x1122_3344);

            DAT_004138c4 = saved;
        }
    }
}

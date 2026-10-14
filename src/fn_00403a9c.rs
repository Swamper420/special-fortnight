//! Original procedure `0x00403a9c` (23 bytes, `0x00403a9c–0x00403ab2`).
//! Evidence: `evidence/00403a9c_fn_00403a9c.md`.

use crate::fn_00403ab4::fn_00403ab4;
use crate::fn_00403ae0::fn_00403ae0;

/// `slot=ae0(param); v=[slot]; if v!=0 { [slot]=0; ab4(v) }`.
/// `param_1` arrives in EAX per Ghidra `__register` observation;
/// both callees reconstructed, called directly (no hooks).
pub unsafe fn fn_00403a9c(param_1: *mut u8) {
    unsafe {
        let slot = fn_00403ae0(param_1);
        let v: u32 = core::ptr::read_unaligned(slot as *const u32);
        if v == 0 {
            return;
        }
        core::ptr::write_unaligned(slot as *mut u32, 0);
        fn_00403ab4(v as *mut u8);
    }
}

#[cfg(test)]
mod tests {
    use super::fn_00403a9c;
    use crate::fn_00402e20::TEST_LOCK as E20_LOCK;
    use crate::fn_00403ab4::DAT_004138c4;

    unsafe extern "C" fn sink0() -> u32 {
        0
    }

    #[test]
    fn null_skips_nonzero_clears_and_dispatches() {
        // Downstream `fn_00402e20` hooks pinned under its lock so the
        // nonzero lane stays side-effect free on host.
        let _guard = E20_LOCK.lock().unwrap();
        unsafe {
            let saved_dat = DAT_004138c4;
            let saved_ptr = crate::fn_00402e20::PTR_00412740;
            DAT_004138c4 = core::ptr::null_mut();
            crate::fn_00402e20::PTR_00412740 = sink0;

            // Arena: vtbl-0x34 field cell, obj slot holding vtbl,
            // and the routed u32 cell ae0 computes (obj+field-4).
            let mut arena = [0u8; 128];
            let base = arena.as_mut_ptr();
            let vtbl = base.add(0x40);
            let obj = base.add(0x60);
            let cell = base.add(0x70);
            core::ptr::write_unaligned(vtbl.wrapping_byte_sub(0x34) as *mut u32, 0x14);
            core::ptr::write_unaligned(obj as *mut *mut u8, vtbl);

            // Null lane: no clear, no dispatch.
            core::ptr::write_unaligned(cell as *mut u32, 0);
            fn_00403a9c(obj);
            assert_eq!(core::ptr::read_unaligned(cell as *const u32), 0);

            // Nonzero lane: cell zeroed, value dispatched.
            core::ptr::write_unaligned(cell as *mut u32, 0x12345678);
            fn_00403a9c(obj);
            assert_eq!(core::ptr::read_unaligned(cell as *const u32), 0);

            crate::fn_00402e20::PTR_00412740 = saved_ptr;
            DAT_004138c4 = saved_dat;
        }
    }
}

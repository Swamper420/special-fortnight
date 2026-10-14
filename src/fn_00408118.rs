//! Original procedure `0x00408118` (15 bytes, `0x408118–0x408126`).
//! Evidence: `evidence/00408118_fn_00408118.md`.

use crate::fn_00402fbc::fn_00402fbc;

/// Wide fill: `402fbc(src=param_2, dst=param_1, n=param_3*2)`, returning
/// `param_1` (the destination). `param_1` arrives in EAX (saved across
/// the call), `param_2` in EDX, `param_3` in ECX per `__register`; the
/// `XCHG EAX,EDX` swap puts source in EAX and destination in EDX for
/// the callee, and `ADD ECX,ECX` wraps. The `PUSH/POP ESI` spill is
/// callee-saved preservation with no observable effect; unmodeled.
///
/// ponytail: direct call to done, pure `fn_00402fbc` (no hook) — single
/// thin wrapper.
pub unsafe fn fn_00408118(param_1: *mut u8, param_2: *mut u8, param_3: i32) -> *mut u8 {
    fn_00402fbc(param_2, param_1, param_3.wrapping_mul(2) as u32);
    param_1
}

#[cfg(test)]
mod tests {
    use super::fn_00408118;

    #[test]
    fn copy_double_len_lanes() {
        // Pure callee, no hooks/globals: locals only, no TEST_LOCK.
        let src = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x99, 0xAA];
        let mut dst = [0u8; 8];
        let ret = unsafe { fn_00408118(dst.as_mut_ptr(), src.as_ptr() as *mut u8, 3) };
        assert_eq!(ret, dst.as_mut_ptr());
        assert_eq!(dst, [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0, 0]);

        // Zero-count lane: destination untouched.
        let mut dst0 = [0xBBu8; 4];
        let ret0 = unsafe { fn_00408118(dst0.as_mut_ptr(), src.as_ptr() as *mut u8, 0) };
        assert_eq!(ret0, dst0.as_mut_ptr());
        assert_eq!(dst0, [0xBBu8; 4]);
    }
}

//! Original procedure `0x00402f08` (12 bytes, `0x00402f08–0x00402f13`).
//! Evidence: `evidence/00402f08_fn_00402f08.md`.

/// Cell observed as `dword ptr [0x00412004]`, written from EDX on entry.
///
/// ponytail: absolute-address cell modeled as mutable static, upgrade to real
/// image-relative import once data layout proven.
pub static mut CELL_00412004: u32 = 0;

/// Target `0x004046ac` (`FUN_004046ac`), called with EAX lane (`param_1`):
/// direct intra-reconstruction call (rewired; signatures verified
/// `fn(u32)`).

/// `DAT_00412004 = param_2; FUN_004046ac(param_1)`.
/// `param_1` arrives in EAX, `param_2` in EDX per Ghidra `__register`
/// observation.
pub unsafe fn fn_00402f08(param_1: u32, param_2: u32) {
    CELL_00412004 = param_2;
    crate::fn_004046ac::fn_004046ac(param_1);
}

#[cfg(test)]
mod tests {
    use super::{CELL_00412004, fn_00402f08};

    #[test]
    fn store_then_forward() {
        // Real `fn_004046ac` stores to its cell, then the real main
        // loop takes the zeroed quick-exit lane.
        let _guard = crate::fn_004046ac::TEST_LOCK.lock().unwrap();
        let _loop = crate::fn_00404580::TEST_LOCK.lock().unwrap();
        let (old_c4, old_b18, old_struct, old_s48, old_s2c);
        unsafe {
            old_c4 = crate::fn_00404580::CELL_00412004;
            old_b18 = crate::fn_00404580::CELL_00415B18;
            old_struct = crate::fn_00404580::STRUCT_00415AE4;
            old_s48 = crate::fn_00404580::SLOT_00413048;
            old_s2c = crate::fn_00404580::SLOT_0041302C;
            crate::fn_00404580::CELL_00412004 = 0;
            crate::fn_00404580::CELL_00415B18 = 0;
            crate::fn_00404580::STRUCT_00415AE4 = [0; 12];
            crate::fn_00404580::SLOT_00413048 = None;
            crate::fn_00404580::SLOT_0041302C = None;
            fn_00402f08(0xAB, 0x12345678);
        }
        assert_eq!(unsafe { CELL_00412004 }, 0x12345678);
        assert_eq!(unsafe { crate::fn_004046ac::CELL_00412000 }, 0xAB);
        unsafe {
            crate::fn_00404580::CELL_00412004 = old_c4;
            crate::fn_00404580::CELL_00415B18 = old_b18;
            crate::fn_00404580::STRUCT_00415AE4 = old_struct;
            crate::fn_00404580::SLOT_00413048 = old_s48;
            crate::fn_00404580::SLOT_0041302C = old_s2c;
        }
    }
}

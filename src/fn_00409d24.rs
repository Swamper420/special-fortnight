//! Original procedure `0x00409d24` (22 bytes, `0x00409d24–0x00409d39`).
//! Evidence: `evidence/00409d24_fn_00409d24.md`.

/// Callee `0x00409ca4` (`FUN_00409ca4`), `(param_1)`; low byte of
/// its return selects the table entry: direct intra-reconstruction
/// call (rewired; signatures verified `fn(*const u32) -> u32`).

/// Table observed as `dword ptr [EAX*0x8 + 0x004128ec]`
/// (`DAT_004128ec`): 256 entries × 8 bytes, first dword read.
///
/// ponytail: absolute-address table as mutable static, upgrade to
/// real image-relative import once data layout proven.
pub static mut TBL_004128EC: [[u32; 2]; 256] = [[0; 2]; 256];

/// `return TBL[(call(param_1) & 0xff)][0]`. `param_1` arrives in
/// EAX per Ghidra `__register` observation. `PUSH/POP EBX`
/// omitted (callee-saved, no observable effect).
pub unsafe fn fn_00409d24(param_1: *const u32) -> u32 {
    let r = crate::fn_00409ca4::fn_00409ca4(param_1);
    let idx = (r & 0xff) as usize;
    TBL_004128EC[idx][0]
}

#[cfg(test)]
mod tests {
    use super::{TBL_004128EC, fn_00409d24};

    #[test]
    fn mask_and_stride_lanes() {
        // Own table only, real `fn_00409ca4` status map, no TEST_LOCK.
        // 0xC0000092→low 0x06, 0xC0000005→low 0x0B, 0→low 0x16.
        unsafe {
            TBL_004128EC[0x06][0] = 0xdead;
            TBL_004128EC[0x06][1] = 0xbeef;
            TBL_004128EC[0x0b][0] = 0x1234;
            TBL_004128EC[0x16][0] = 0x77;
        }
        let cell = 0xC0000092u32;
        assert_eq!(unsafe { fn_00409d24(&cell as *const u32) }, 0xdead);
        let cell = 0xC0000005u32;
        assert_eq!(unsafe { fn_00409d24(&cell as *const u32) }, 0x1234);
        // Upper bits discarded by the `& 0xff` mask; sibling stride
        // dword ignored.
        let cell = 0u32;
        assert_eq!(unsafe { fn_00409d24(&cell as *const u32) }, 0x77);
    }
}

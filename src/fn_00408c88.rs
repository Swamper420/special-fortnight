//! Original procedure `0x00408c88` (45 bytes, `0x00408c88–0x00408cb4`).
//! Evidence: `evidence/00408c88_fn_00408c88.md`.

use crate::fn_00408cb5::fn_00408cb5;
use crate::fn_00408dd7::fn_00408dd7;
use crate::fn_00408eab::fn_00408eab;

/// Dispatcher over the flag byte: `param_3 != 0` runs the integer
/// lane (`dd7(out, in, p4)`), else the float lane (`cb5(out, in,
/// p4, p5)`); both tails call the shared epilogue `eab`.
/// `EBX=EAX` / `ESI=EDX` redistribution and the `[EBP-4]=0` local
/// are implicit in the explicit args; `[EBP+8]`/`[EBP+0xC]` thread
/// through as `param_4`/`param_5`. Direct calls to reconstructed
/// siblings (no hooks).
pub unsafe fn fn_00408c88(
    param_1: *mut u8,
    param_2: *mut u8,
    param_3: u8,
    param_4: u32,
    param_5: u32,
) {
    if param_3 != 0 {
        fn_00408dd7(param_1, param_2, param_4);
        fn_00408eab();
        return;
    }
    fn_00408cb5(param_1, param_2, param_4, param_5);
    fn_00408eab();
}

#[cfg(test)]
mod tests {
    use super::fn_00408c88;

    unsafe fn word_at(p: *mut u8, off: usize) -> u16 {
        core::ptr::read_unaligned(p.wrapping_byte_add(off) as *const u16)
    }

    unsafe fn byte_at(p: *mut u8, off: usize) -> u8 {
        core::ptr::read_unaligned(p.wrapping_byte_add(off) as *const u8)
    }

    unsafe fn digits_eq(p: *mut u8, want: &[u8]) -> bool {
        for (i, b) in want.iter().enumerate() {
            if byte_at(p, 3 + i) != *b {
                return false;
            }
        }
        byte_at(p, 3 + want.len()) == 0
    }

    #[test]
    fn dispatch_lanes() {
        // Integer lane (flag != 0): dd7(1, scale 4) → "1", len -3.
        let mut out = [0u8; 32];
        let mut one = 1u64.to_le_bytes();
        unsafe { fn_00408c88(out.as_mut_ptr(), one.as_mut_ptr(), 1, 4, 9) };
        assert_eq!(unsafe { word_at(out.as_mut_ptr(), 0) }, 0xFFFD);
        assert_eq!(unsafe { byte_at(out.as_mut_ptr(), 2) }, 0);
        assert!(unsafe { digits_eq(out.as_mut_ptr(), b"1") });

        // Float lane (flag == 0): cb5(8.0, decimals 0) → "8", exp 1.
        let mut out = [0u8; 32];
        let mut eight = [0u8; 10];
        eight[..8].copy_from_slice(&0x8000_0000_0000_0000u64.to_le_bytes());
        eight[8..].copy_from_slice(&0x4002u16.to_le_bytes());
        unsafe { fn_00408c88(out.as_mut_ptr(), eight.as_mut_ptr(), 0, 0, 9) };
        assert_eq!(unsafe { word_at(out.as_mut_ptr(), 0) }, 1);
        assert_eq!(unsafe { byte_at(out.as_mut_ptr(), 2) }, 0);
        assert!(unsafe { digits_eq(out.as_mut_ptr(), b"8") });
    }
}

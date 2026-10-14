//! Original procedure `0x0040b2b4` (31 bytes, `0x0040b2b4–0x0040b2d2`).
//! Evidence: `evidence/0040b2b4_fn_0040b2b4.md`.

/// Unsigned 64-bit compare over two `[lo, hi]` u32 pairs: high
/// words first (`JA`→1, `JC`→-1), then low words, else 0.
/// `param_1` arrives in EAX, `param_2` in EDX per Ghidra
/// `__register` observation; the `0xffffffff` lane reads as
/// signed `-1`. No calls, no globals.
pub unsafe fn fn_0040b2b4(param_1: *const u32, param_2: *const u32) -> u32 {
    let a_hi: u32 = core::ptr::read_unaligned(param_1.wrapping_add(1));
    let b_hi: u32 = core::ptr::read_unaligned(param_2.wrapping_add(1));
    if a_hi > b_hi {
        return 1;
    }
    if a_hi < b_hi {
        return 0xffff_ffff;
    }
    let a_lo: u32 = core::ptr::read_unaligned(param_1);
    let b_lo: u32 = core::ptr::read_unaligned(param_2);
    if a_lo > b_lo {
        return 1;
    }
    if a_lo < b_lo {
        return 0xffff_ffff;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::fn_0040b2b4;

    #[test]
    fn hi_lo_compare_lanes() {
        // No globals: no TEST_LOCK.
        unsafe {
            // Hi greater decides regardless of lo.
            assert_eq!(fn_0040b2b4([0, 9].as_ptr(), [0xffff_ffff, 8].as_ptr()), 1);
            // Hi less decides regardless of lo.
            assert_eq!(
                fn_0040b2b4([0xffff_ffff, 1].as_ptr(), [0, 2].as_ptr()),
                0xffff_ffff
            );
            // Hi equal, lo greater.
            assert_eq!(fn_0040b2b4([2, 4].as_ptr(), [1, 4].as_ptr()), 1);
            // Hi equal, lo less.
            assert_eq!(
                fn_0040b2b4([1, 4].as_ptr(), [2, 4].as_ptr()),
                0xffff_ffff
            );
            // Fully equal.
            assert_eq!(fn_0040b2b4([3, 7].as_ptr(), [3, 7].as_ptr()), 0);
        }
    }
}

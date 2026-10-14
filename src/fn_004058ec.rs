//! Original procedure `0x004058ec` (35 bytes, `0x004058ec–0x0040590e`).
//! Evidence: `evidence/004058ec_fn_004058ec.md`.

/// Wrapping 64-bit multiply of `(hi_a:lo_a)` (EDX:EAX) by the two
/// stack dwords `(lo_b, hi_b)`; result `EDX:EAX` modeled as `u64`.
///
/// Observed order: `EAX=[ESP+0x10]*[ESP]` (low `lo_a*hi_b`, kept in
/// ECX), `EAX=[ESP+4]*[ESP+0xC]` (low `hi_a*lo_b`, accumulated),
/// `EAX=[ESP]*[ESP+0xC]` (`lo_a*lo_b`) with the mids folded into
/// EDX, `RET 0x8`. Incoming ECX is never read (only clobbered by the
/// `POP`s), so it is not a parameter. All `MUL`s wrap; Rust uses
/// `wrapping_mul` on the assembled `u64` operands (same low 64
/// bits).
pub unsafe fn fn_004058ec(lo_a: u32, hi_a: u32, lo_b: u32, hi_b: u32) -> u64 {
    let a = ((hi_a as u64) << 32) | lo_a as u64;
    let b = ((hi_b as u64) << 32) | lo_b as u64;
    a.wrapping_mul(b)
}

#[cfg(test)]
mod tests {
    use super::fn_004058ec;

    #[test]
    fn mul64_vectors() {
        unsafe {
            assert_eq!(fn_004058ec(2, 0, 3, 0), 6);
            assert_eq!(
                fn_004058ec(0xffff_ffff, 0, 0xffff_ffff, 0),
                0xffff_fffe_0000_0001
            );
            // (2^32+2)(3*2^32+4) mod 2^64 = 0xA_00000008.
            assert_eq!(fn_004058ec(2, 1, 4, 3), 0x0000_000a_0000_0008);
            // Full-width wrap: (2^64-1)^2 mod 2^64 = 1.
            assert_eq!(
                fn_004058ec(
                    0xffff_ffff,
                    0xffff_ffff,
                    0xffff_ffff,
                    0xffff_ffff
                ),
                1
            );
        }
    }
}

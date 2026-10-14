//! Original procedure `0x0040a3c8` (45 bytes, `0x0040a3c8–0x0040a3f4`).
//! Evidence: `evidence/0040a3c8_fn_0040a3c8.md`.

/// Surrogate-pair width probe: 4 when `w0` is a high surrogate
/// (`0xd800..=0xdbff`) and `w1` a low surrogate
/// (`0xdc00..=0xdfff`), else 2. Guards in observed assembly order.
/// `param_1` arrives in EAX per Ghidra `__register` observation.
pub unsafe fn fn_0040a3c8(param_1: *const u16) -> u32 {
    let w0: u16 = core::ptr::read_unaligned(param_1);
    if w0 < 0xd800 {
        return 2;
    }
    if w0 > 0xdbff {
        return 2;
    }
    let w1: u16 = core::ptr::read_unaligned(param_1.wrapping_add(1));
    if w1 < 0xdc00 {
        return 2;
    }
    if w1 > 0xdfff {
        return 2;
    }
    4
}

#[cfg(test)]
mod tests {
    use super::fn_0040a3c8;

    #[test]
    fn pair_or_single_lanes() {
        // No globals, no calls: locals only, no TEST_LOCK.
        let pair = [0xd800u16, 0xdc00];
        let pair_hi = [0xdbffu16, 0xdfff];
        let lone = [0xd800u16, 0x41];
        let low_only = [0x41u16, 0xdc00];
        let hi_nonlow = [0xd834u16, 0xe000];
        let plain = [0x41u16, 0x42];
        let low_edge = [0xd7ffu16, 0xdc00];
        let over = [0xdc00u16, 0xdc00];
        unsafe {
            assert_eq!(fn_0040a3c8(pair.as_ptr()), 4);
            assert_eq!(fn_0040a3c8(pair_hi.as_ptr()), 4);
            assert_eq!(fn_0040a3c8(lone.as_ptr()), 2);
            assert_eq!(fn_0040a3c8(low_only.as_ptr()), 2);
            assert_eq!(fn_0040a3c8(hi_nonlow.as_ptr()), 2);
            assert_eq!(fn_0040a3c8(plain.as_ptr()), 2);
            assert_eq!(fn_0040a3c8(low_edge.as_ptr()), 2);
            assert_eq!(fn_0040a3c8(over.as_ptr()), 2);
        }
    }
}

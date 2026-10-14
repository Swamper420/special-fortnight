//! Original procedure `0x004031e0` (111 bytes, `0x004031e0–0x0040324e`).
//! Evidence: `evidence/004031e0_fn_004031e0.md`.

/// Fixed-length compare of `n` bytes: `(ptr, zf)` where `zf` true iff equal.
/// Register lanes observed: `a` in EAX, `b` in EDX, `n` in ECX.
///
/// Mismatch `ptr` is the enclosing unit: exact dword for slot 1, pair
/// start for slot 2, post-dword pointer for tail. Full equal gives NULL
/// when `n & 3 != 0`, else the end pointer (`start + (n & !3)`).
///
/// ponytail: tuple stands in for `(EAX, ZF)` pair, no flags channel in Rust.
pub unsafe fn fn_004031e0(
    mut a: *const u8,
    mut b: *const u8,
    n: u32,
) -> (*const u8, bool) {
    let mut dwords = n >> 2;
    if dwords != 0 {
        loop {
            let x = core::ptr::read_unaligned(a as *const u32);
            let y = core::ptr::read_unaligned(b as *const u32);
            if x != y {
                return (a, false);
            }
            dwords -= 1;
            if dwords == 0 {
                a = a.wrapping_byte_add(4);
                b = b.wrapping_byte_add(4);
                break;
            }
            let x2 =
                core::ptr::read_unaligned(a.wrapping_byte_add(4) as *const u32);
            let y2 =
                core::ptr::read_unaligned(b.wrapping_byte_add(4) as *const u32);
            if x2 != y2 {
                return (a, false);
            }
            a = a.wrapping_byte_add(8);
            b = b.wrapping_byte_add(8);
            dwords -= 1;
            if dwords == 0 {
                break;
            }
        }
    }
    let mut rem = n & 3;
    if rem == 0 {
        return (a, true);
    }
    if core::ptr::read_unaligned(a) != core::ptr::read_unaligned(b) {
        return (a, false);
    }
    rem -= 1;
    if rem == 0 {
        return (core::ptr::null(), true);
    }
    if core::ptr::read_unaligned(a.wrapping_byte_add(1))
        != core::ptr::read_unaligned(b.wrapping_byte_add(1))
    {
        return (a, false);
    }
    rem -= 1;
    if rem == 0 {
        return (core::ptr::null(), true);
    }
    if core::ptr::read_unaligned(a.wrapping_byte_add(2))
        != core::ptr::read_unaligned(b.wrapping_byte_add(2))
    {
        return (a, false);
    }
    (core::ptr::null(), true)
}

#[cfg(test)]
mod tests {
    use super::fn_004031e0;

    #[test]
    fn compare_contract() {
        let a = *b"abcdefgh";
        let same = *b"abcdefgh";
        unsafe {
            assert_eq!(
                fn_004031e0(a.as_ptr(), same.as_ptr(), 5),
                (core::ptr::null(), true)
            );
            assert_eq!(
                fn_004031e0(a.as_ptr(), same.as_ptr(), 8),
                (a.as_ptr().wrapping_byte_add(8), true)
            );
            let slot1 = *b"Xbcdefgh";
            assert_eq!(
                fn_004031e0(a.as_ptr(), slot1.as_ptr(), 8),
                (a.as_ptr(), false)
            );
            let slot2 = *b"abcdWfgh";
            assert_eq!(
                fn_004031e0(a.as_ptr(), slot2.as_ptr(), 8),
                (a.as_ptr(), false)
            );
            let tail = *b"abcdeYgh";
            assert_eq!(
                fn_004031e0(a.as_ptr(), tail.as_ptr(), 6),
                (a.as_ptr().wrapping_byte_add(4), false)
            );
            assert_eq!(
                fn_004031e0(a.as_ptr(), slot1.as_ptr(), 0),
                (a.as_ptr(), true)
            );
        }
    }
}

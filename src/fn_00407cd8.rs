//! Original procedure `0x00407cd8` (28 bytes, `0x00407cd8–0x00407cf3`).
//! Evidence: `evidence/00407cd8_fn_00407cd8.md`.

/// Signed dispatcher over `fn_00407cf4`: iff the low byte of `param_3`
/// is 0 and `param_1` is negative (signed `JNS` shape), convert the
/// negated value then prepend `'-'` (`0x2d` word at `start-2`,
/// count `+1` via `INC ECX`); every other lane tails into
/// `fn_00407cf4` unchanged (which hardcodes radix 10, so a nonzero
/// `param_3` is accepted but ignored). `(param_1, param_2, param_3)`
/// arrive in `(EAX, EDX, ECX)` per Ghidra `__register` observation;
/// `ESI` is an in/out cursor. Returns the `(start, count)` register
/// pair as a tuple (same precedent as `fn_00403b70`). Direct call to
/// done `fn_00407cf4` (no hook).
pub unsafe fn fn_00407cd8(
    param_1: u32,
    param_2: u32,
    param_3: u32,
    cursor: *mut u16,
) -> (*mut u16, u32) {
    if (param_3 as u8) == 0 && (param_1 as i32) < 0 {
        let (start, n) =
            crate::fn_00407cf4::fn_00407cf4(param_1.wrapping_neg(), param_2, cursor);
        let dash = start.wrapping_byte_offset(-2);
        core::ptr::write_unaligned(dash, 0x2du16);
        return (dash, n.wrapping_add(1));
    }
    crate::fn_00407cf4::fn_00407cf4(param_1, param_2, cursor)
}

#[cfg(test)]
mod tests {
    use super::fn_00407cd8;

    fn run(v: u32, width: u32, radix: u32, buf: &mut [u16; 16]) -> (Vec<u16>, u32, usize) {
        let end = buf.as_mut_ptr().wrapping_add(buf.len());
        let (start, n) = unsafe { fn_00407cd8(v, width, radix, end) };
        let off = (start as usize).wrapping_sub(buf.as_ptr() as usize) / 2;
        (unsafe { core::slice::from_raw_parts(start, n as usize) }.to_vec(), n, off)
    }

    #[test]
    fn sign_and_radix_lanes() {
        let mut buf = [0u16; 16];
        // Radix nonzero: passthrough, radix ignored (body hardcodes 10).
        let (s, n, off) = run(7, 0, 1, &mut buf);
        assert_eq!((s.as_slice(), n, off), (&[0x37u16] as &[_], 1, 15));
        // Radix zero, positive: plain conversion.
        let (s, n, off) = run(42, 0, 0, &mut buf);
        assert_eq!((s.as_slice(), n, off), (&[0x34u16, 0x32] as &[_], 2, 14));
        // Radix zero, negative: negated digits plus '-'.
        let (s, n, off) = run(0xffff_fffbu32, 0, 0, &mut buf);
        assert_eq!((s.as_slice(), n, off), (&[0x2du16, 0x35] as &[_], 2, 14));
        // Negative with width: dash sits outside the zero pad.
        let (s, n, off) = run(0xffff_fffbu32, 3, 0, &mut buf);
        assert_eq!(
            (s.as_slice(), n, off),
            (&[0x2du16, 0x30, 0x30, 0x35] as &[_], 4, 12)
        );
    }
}

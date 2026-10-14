//! Original procedure `0x00407e1c` (52 bytes, `0x407e1c–0x407e4f`).
//! Evidence: `evidence/00407e1c_fn_00407e1c.md`.

/// Signed dispatcher over `fn_00407e50`: iff the low byte of
/// `param_3` is 0 and `*param_1` has the high bit set (high
/// dword `TEST 0x80000000`), convert the negated value at base
/// 10 then prepend `'-'` (`0x2d` byte at `start-1`, count `+1`
/// via `INC ECX`); a zero low byte with a non-negative value
/// tails into `fn_00407e50` with base forced to 10 (`MOV
/// ECX,0xa` before the sign test); a nonzero low byte tails
/// into `fn_00407e50` with the original radix untouched.
/// `(param_1, param_2, param_3)` arrive in `(EAX, EDX, CX)` per
/// Ghidra `__register` observation; `ESI` is an in/out cursor.
/// Returns the `(start, count)` register pair as a tuple (same
/// precedent as `fn_00407cf4`). Direct call to sibling
/// `fn_00407e50` (no hook).
pub unsafe fn fn_00407e1c(
    param_1: *const u64,
    param_2: u32,
    param_3: i16,
    cursor: *mut u8,
) -> (*mut u8, u32) {
    if (param_3 as u8) == 0 {
        let v: u64 = core::ptr::read_unaligned(param_1);
        if ((v.wrapping_shr(32) as u32) as i32) < 0 {
            // NEG low, ADC 0, NEG high = one 64-bit negate.
            let neg = v.wrapping_neg();
            let (start, n) =
                crate::fn_00407e50::fn_00407e50(&neg, param_2, 10, cursor);
            let dash = start.wrapping_byte_offset(-1);
            core::ptr::write_unaligned(dash, 0x2du8);
            return (dash, n.wrapping_add(1));
        }
        return crate::fn_00407e50::fn_00407e50(param_1, param_2, 10, cursor);
    }
    crate::fn_00407e50::fn_00407e50(param_1, param_2, param_3, cursor)
}

#[cfg(test)]
mod tests {
    use super::fn_00407e1c;

    fn run(v: u64, width: u32, radix: i16, buf: &mut [u8; 32]) -> (Vec<u8>, u32, usize) {
        let end = buf.as_mut_ptr().wrapping_add(buf.len());
        let (start, n) = unsafe { fn_00407e1c(&v, width, radix, end) };
        let off = (start as usize).wrapping_sub(buf.as_ptr() as usize);
        (unsafe { core::slice::from_raw_parts(start, n as usize) }.to_vec(), n, off)
    }

    #[test]
    fn sign_and_radix_lanes() {
        let mut buf = [0u8; 32];
        // Radix nonzero: passthrough with that radix.
        let (s, n, off) = run(42, 0, 16, &mut buf);
        assert_eq!((s.as_slice(), n, off), (b"2A" as &[_], 2, 30));
        // Radix zero, non-negative: base forced to 10.
        let (s, n, off) = run(42, 0, 0, &mut buf);
        assert_eq!((s.as_slice(), n, off), (b"42" as &[_], 2, 30));
        // Radix zero, negative (high bit set): negated digits plus '-'.
        let (s, n, off) = run((-5i64) as u64, 0, 0, &mut buf);
        assert_eq!((s.as_slice(), n, off), (b"-5" as &[_], 2, 30));
        // Negative with width: dash sits outside the zero pad.
        let (s, n, off) = run((-5i64) as u64, 3, 0, &mut buf);
        assert_eq!((s.as_slice(), n, off), (b"-005" as &[_], 4, 28));
    }
}

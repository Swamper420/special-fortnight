//! Original procedure `0x00407d70` (171 bytes, `0x407d70–0x407e1a`).
//! Evidence: `evidence/00407d70_fn_00407d70.md`.

/// FPU `u64`-to-digits writer: emits `*param_1` in base
/// `param_3` as words (`rem+0x30`, `+7` past `'9'`) backward
/// from `cursor` (exclusive end), then left-pads with `'0'`
/// words up to `param_2` width iff `width > count` and
/// `width >= 0` (signed `JS` skip, then unsigned `JBE` skip).
/// `(param_1, param_2, param_3)` arrive in `(EAX, EDX, CX)` per
/// Ghidra `__register` observation; the float `div` is modeled
/// as integer `div`/`rem` (exact at feasible bases; see
/// evidence). Returns the `(start, count)` register pair as a
/// tuple (same precedent as `fn_00407cf4`): `count` = digit
/// count, or `width` when padded; `start` = `end - count`
/// words back.
pub unsafe fn fn_00407d70(
    param_1: *const u64,
    param_2: u32,
    param_3: i16,
    cursor: *mut u16,
) -> (*mut u16, u32) {
    let end = cursor;
    let mut cur = cursor;
    let mut v: u64 = core::ptr::read_unaligned(param_1);
    let b: u64 = (param_3 as i64) as u64;
    loop {
        let q = v.wrapping_div(b);
        let r = v.wrapping_rem(b) as u16;
        let mut d = r.wrapping_add(0x30);
        if d >= 0x3a {
            d = d.wrapping_add(7);
        }
        cur = cur.wrapping_byte_offset(-2);
        core::ptr::write_unaligned(cur, d);
        v = q;
        if v == 0 {
            break;
        }
    }
    let count = ((end as usize).wrapping_sub(cur as usize).wrapping_shr(1)) as u32;
    if (param_2 as i32) < 0 {
        return (cur, count);
    }
    if param_2 <= count {
        return (cur, count);
    }
    let pad = param_2.wrapping_sub(count);
    // Double `SUB ESI,EDX`: reserve pad words below the digits.
    let start = cur.wrapping_byte_offset(-((pad as isize).wrapping_mul(2)));
    // DEC/JNZ fill: [start+2k] for k=pad-1..1, then [start].
    let mut left = pad;
    loop {
        left = left.wrapping_sub(1);
        if left == 0 {
            break;
        }
        core::ptr::write_unaligned(
            start.wrapping_byte_offset((left as isize).wrapping_mul(2)),
            0x30u16,
        );
    }
    core::ptr::write_unaligned(start, 0x30u16);
    (start, count.wrapping_add(pad))
}

#[cfg(test)]
mod tests {
    use super::fn_00407d70;

    fn run(v: u64, width: u32, base: i16, buf: &mut [u16; 32]) -> (Vec<u16>, u32, usize) {
        let end = buf.as_mut_ptr().wrapping_add(buf.len());
        let (start, n) = unsafe { fn_00407d70(&v, width, base, end) };
        let off = (start as usize).wrapping_sub(buf.as_ptr() as usize) / 2;
        (unsafe { core::slice::from_raw_parts(start, n as usize) }.to_vec(), n, off)
    }

    #[test]
    fn digits_count_pad_sign_and_base_lanes() {
        let mut buf = [0u16; 32];
        // Zero still emits one digit (do-while).
        let (s, n, off) = run(0, 0, 10, &mut buf);
        assert_eq!((s.as_slice(), n, off), (&[0x30u16] as &[_], 1, 31));
        // Multi-digit, no width.
        let (s, n, off) = run(123, 0, 10, &mut buf);
        assert_eq!((s.as_slice(), n, off), (&[0x31u16, 0x32, 0x33] as &[_], 3, 29));
        // Exact width: JBE taken, no pad.
        let (s, n, off) = run(123, 3, 10, &mut buf);
        assert_eq!((s.as_slice(), n, off), (&[0x31u16, 0x32, 0x33] as &[_], 3, 29));
        // Wider width: '0' pad, start = end - width.
        let (s, n, off) = run(123, 5, 10, &mut buf);
        assert_eq!(
            (s.as_slice(), n, off),
            (&[0x30u16, 0x30, 0x31, 0x32, 0x33] as &[_], 5, 27)
        );
        // Negative width: JS taken, no pad even though width > count unsigned.
        let (s, n, off) = run(123, 0xffff_ffff, 10, &mut buf);
        assert_eq!((s.as_slice(), n, off), (&[0x31u16, 0x32, 0x33] as &[_], 3, 29));
        // Hex base: ADD 7 lane.
        let (s, n, off) = run(255, 0, 16, &mut buf);
        assert_eq!((s.as_slice(), n, off), (&[0x46u16, 0x46] as &[_], 2, 30));
        // u64::MAX: 20 digits, div exactness.
        let (s, n, off) = run(0xffff_ffff_ffff_ffff, 0, 10, &mut buf);
        assert_eq!(
            (s.as_slice(), n, off),
            (
                &[
                    0x31u16, 0x38, 0x34, 0x34, 0x36, 0x37, 0x34, 0x34, 0x30, 0x37,
                    0x33, 0x37, 0x30, 0x39, 0x35, 0x35, 0x31, 0x36, 0x31, 0x35
                ] as &[_],
                20,
                12
            )
        );
    }
}

//! Original procedure `0x00407e50` (151 bytes, `0x00407e50–0x00407ee6`).
//! Evidence: `evidence/00407e50_fn_00407e50.md`.

/// FPU `u64`-to-digits writer: emits `*param_1` in base
/// `param_3` as bytes (`rem+0x30`, `+7` past `'9'`) backward
/// from `cursor` (exclusive end), then left-pads with `'0'`
/// bytes up to `param_2` width iff `width > count` (single
/// unsigned `JBE` skip — no signed gate, unlike
/// `fn_00407d70`). `(param_1, param_2, param_3)` arrive in
/// `(EAX, EDX, CX)` per Ghidra `__register` observation; the
/// float `div` is modeled as integer `div`/`rem` (exact at
/// feasible bases; see evidence). Returns the `(start, count)`
/// register pair as a tuple (same precedent as
/// `fn_00407cf4`): `count` = digit count, or `width` when
/// padded; `start` = `end - count` bytes back.
pub unsafe fn fn_00407e50(
    param_1: *const u64,
    param_2: u32,
    param_3: i16,
    cursor: *mut u8,
) -> (*mut u8, u32) {
    let end = cursor;
    let mut cur = cursor;
    let mut v: u64 = core::ptr::read_unaligned(param_1);
    let b: u64 = (param_3 as i64) as u64;
    loop {
        let q = v.wrapping_div(b);
        // Low byte of the rounded word, exactly like `MOV AL,[ESP]`.
        let r = v.wrapping_rem(b) as u16 as u8;
        let mut d = r.wrapping_add(0x30);
        if d >= 0x3a {
            d = d.wrapping_add(7);
        }
        cur = cur.wrapping_byte_offset(-1);
        core::ptr::write_unaligned(cur, d);
        v = q;
        if v == 0 {
            break;
        }
    }
    let count = ((end as usize).wrapping_sub(cur as usize)) as u32;
    if param_2 <= count {
        return (cur, count);
    }
    let pad = param_2.wrapping_sub(count);
    // Single `SUB ESI,EDX`: reserve pad bytes below the digits.
    let start = cur.wrapping_byte_offset(-(pad as isize));
    // DEC/JNZ fill: [start+k] for k=pad-1..1, then [start].
    let mut left = pad;
    loop {
        left = left.wrapping_sub(1);
        if left == 0 {
            break;
        }
        core::ptr::write_unaligned(start.wrapping_byte_add(left as usize), 0x30u8);
    }
    core::ptr::write_unaligned(start, 0x30u8);
    (start, count.wrapping_add(pad))
}

#[cfg(test)]
mod tests {
    use super::fn_00407e50;

    fn run(v: u64, width: u32, base: i16, buf: &mut [u8; 32]) -> (Vec<u8>, u32, usize) {
        let end = buf.as_mut_ptr().wrapping_add(buf.len());
        let (start, n) = unsafe { fn_00407e50(&v, width, base, end) };
        let off = (start as usize).wrapping_sub(buf.as_ptr() as usize);
        (unsafe { core::slice::from_raw_parts(start, n as usize) }.to_vec(), n, off)
    }

    #[test]
    fn digits_count_pad_and_base_lanes() {
        let mut buf = [0u8; 32];
        // Zero still emits one digit (do-while).
        let (s, n, off) = run(0, 0, 10, &mut buf);
        assert_eq!((s.as_slice(), n, off), (b"0" as &[_], 1, 31));
        // Multi-digit, no width.
        let (s, n, off) = run(123, 0, 10, &mut buf);
        assert_eq!((s.as_slice(), n, off), (b"123" as &[_], 3, 29));
        // Exact width: JBE taken (ZF), no pad.
        let (s, n, off) = run(123, 3, 10, &mut buf);
        assert_eq!((s.as_slice(), n, off), (b"123" as &[_], 3, 29));
        // Wider width: '0' pad, start = end - width.
        let (s, n, off) = run(123, 5, 10, &mut buf);
        assert_eq!((s.as_slice(), n, off), (b"00123" as &[_], 5, 27));
        // Hex base: ADD 7 lane.
        let (s, n, off) = run(255, 0, 16, &mut buf);
        assert_eq!((s.as_slice(), n, off), (b"FF" as &[_], 2, 30));
        // u64::MAX: 20 digits, div exactness.
        let (s, n, off) = run(0xffff_ffff_ffff_ffff, 0, 10, &mut buf);
        assert_eq!((s.as_slice(), n, off), (b"18446744073709551615" as &[_], 20, 12));
    }
}

//! Original procedure `0x00407cf4` (68 bytes, `0x00407cf4–0x00407d37`).
//! Evidence: `evidence/00407cf4_fn_00407cf4.md`.

/// Unsigned base-10 writer: emits `param_1` as words (`rem+0x30`)
/// backward from `cursor` (exclusive end), then left-pads with `'0'`
/// (`0x30`) words up to `param_2` width iff `width > count` (unsigned
/// `JBE` shape). `(param_1, param_2)` arrive in `(EAX, EDX)` per Ghidra
/// `__register` observation; radix is hardcoded (`MOV ECX,0xa` — no
/// param feeds it). Returns the `(start, count)` register pair as a
/// tuple (same precedent as `fn_00403b70`): `count` = digit count, or
/// `width` when padded; `start` = `end - count` words back.
pub unsafe fn fn_00407cf4(param_1: u32, param_2: u32, cursor: *mut u16) -> (*mut u16, u32) {
    let end = cursor;
    let mut cur = cursor;
    let mut v = param_1;
    loop {
        let q = v.wrapping_div(10);
        let r = v.wrapping_rem(10) as u16;
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
    if param_2 <= count {
        return (cur, count);
    }
    let pad = param_2.wrapping_sub(count);
    let mut start = cur.wrapping_byte_offset(-((pad as isize).wrapping_mul(2)));
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
    use super::fn_00407cf4;

    fn run(v: u32, width: u32, buf: &mut [u16; 16]) -> (Vec<u16>, u32, usize) {
        let end = buf.as_mut_ptr().wrapping_add(buf.len());
        let (start, n) = unsafe { fn_00407cf4(v, width, end) };
        let off = (start as usize).wrapping_sub(buf.as_ptr() as usize) / 2;
        (unsafe { core::slice::from_raw_parts(start, n as usize) }.to_vec(), n, off)
    }

    #[test]
    fn digits_count_and_pad_lanes() {
        let mut buf = [0u16; 16];
        // Zero still emits one digit (do-while).
        let (s, n, off) = run(0, 0, &mut buf);
        assert_eq!((s.as_slice(), n, off), (&[0x30u16] as &[_], 1, 15));
        // Multi-digit, no width.
        let (s, n, off) = run(123, 0, &mut buf);
        assert_eq!((s.as_slice(), n, off), (&[0x31u16, 0x32, 0x33] as &[_], 3, 13));
        // Exact width: JBE taken (ZF), no pad.
        let (s, n, off) = run(123, 3, &mut buf);
        assert_eq!((s.as_slice(), n, off), (&[0x31u16, 0x32, 0x33] as &[_], 3, 13));
        // Wider width: '0' pad, start = end - width.
        let (s, n, off) = run(123, 5, &mut buf);
        assert_eq!(
            (s.as_slice(), n, off),
            (&[0x30u16, 0x30, 0x31, 0x32, 0x33] as &[_], 5, 11)
        );
        // u32::MAX: 10 digits, DIV exactness.
        let (s, n, off) = run(0xffff_ffff, 0, &mut buf);
        assert_eq!(
            (s.as_slice(), n, off),
            (
                &[0x34u16, 0x32, 0x39, 0x34, 0x39, 0x36, 0x37, 0x32, 0x39, 0x35] as &[_],
                10,
                6
            )
        );
    }
}

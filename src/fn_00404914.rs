//! Original procedure `0x00404914` (38 bytes, `0x404914–0x404939`).
//! Evidence: `evidence/00404914_fn_00404914.md`.

/// NUL-terminated byte length: null→0, else 4-lane scan
/// (`[p]/[p+1]/[p+2]/[p+3]`, `+4` step), return `end-start`.
/// `param_1` arrives in EAX (null-tested), return in EAX.
/// Byte twin of `fn_00404e14`'s wide-char scan (no `>>1`).
pub unsafe fn fn_00404914(param_1: *const u8) -> u32 {
    if param_1.is_null() {
        return 0;
    }
    let mut p = param_1;
    loop {
        if core::ptr::read_unaligned(p) == 0 {
            break;
        }
        if core::ptr::read_unaligned(p.wrapping_add(1)) == 0 {
            p = p.wrapping_add(1);
            break;
        }
        if core::ptr::read_unaligned(p.wrapping_add(2)) == 0 {
            p = p.wrapping_add(2);
            break;
        }
        if core::ptr::read_unaligned(p.wrapping_add(3)) == 0 {
            p = p.wrapping_add(3);
            break;
        }
        p = p.wrapping_add(4);
    }
    (p as u32).wrapping_sub(param_1 as u32)
}

#[cfg(test)]
mod tests {
    use super::fn_00404914;

    #[test]
    fn strlen_lanes() {
        unsafe { assert_eq!(fn_00404914(core::ptr::null()), 0) };
        let cases: &[&[u8]] = &[
            b"\0",
            b"a\0",
            b"ab\0",
            b"abc\0",
            b"abcd\0",
            b"abcde\0",
            b"abcdefgh\0",
        ];
        for (i, s) in cases.iter().enumerate() {
            let expect = s.len() as u32 - 1;
            assert_eq!(unsafe { fn_00404914(s.as_ptr()) }, expect, "case {i}");
        }
    }
}

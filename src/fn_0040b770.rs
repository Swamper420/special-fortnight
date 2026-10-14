//! Original procedure `0x0040b770` (76 bytes, `0x40b770–0x40b7bb`).
//! Evidence: `evidence/0040b770_fn_0040b770.md`.

/// Scan a wide string with `"` quote handling: `*count=0`, then per
/// char stop on NUL or (when outside quotes) on `c<=0x20`; `0x22`
/// toggles the quote flag without counting, other chars are stored
/// to `dst[count]` unless `dst` is null and always counted.
/// `param_1` (src) arrives in EAX, `param_2` (dst) in EDX,
/// `param_3` (count cell) in ECX per Ghidra `__register`
/// observation. Returns the stop cursor (EAX at every in-body
/// `RET`; all downstream callers consume it as `ushort *`).
/// Count wraps (`INC [ECX]`); boundary compare is unsigned
/// (`SETA`, continue iff `0x20 < c`).
pub unsafe fn fn_0040b770(
    param_1: *mut u16,
    param_2: *mut u16,
    param_3: *mut u32,
) -> *mut u16 {
    core::ptr::write_unaligned(param_3, 0);
    let mut in_quotes = false;
    let mut cur = param_1;
    loop {
        let c: u16 = core::ptr::read_unaligned(cur);
        if c == 0 {
            break;
        }
        if c <= 0x20 && !in_quotes {
            break;
        }
        if c == 0x22 {
            in_quotes = !in_quotes;
        } else {
            if !param_2.is_null() {
                let n: u32 = core::ptr::read_unaligned(param_3);
                core::ptr::write_unaligned(param_2.wrapping_add(n as usize), c);
            }
            let n: u32 = core::ptr::read_unaligned(param_3);
            core::ptr::write_unaligned(param_3, n.wrapping_add(1));
        }
        cur = cur.wrapping_add(1);
    }
    cur
}

#[cfg(test)]
mod tests {
    use super::fn_0040b770;

    #[test]
    fn scan_count_copy_lanes() {
        // Pure callee, no hooks/globals: locals only, no TEST_LOCK.
        let mut dst = [0u16; 8];
        // Empty: count 0, cursor unmoved.
        let mut s0 = [0u16];
        let mut n: u32 = 0xdead;
        let r = unsafe { fn_0040b770(s0.as_mut_ptr(), dst.as_mut_ptr(), &mut n as *mut u32) };
        assert_eq!(r, s0.as_mut_ptr());
        assert_eq!(n, 0);
        // Plain token stops at the space, copies the prefix.
        let mut s1 = [0x61u16, 0x62, 0x20, 0x63, 0x64, 0];
        n = 0xdead;
        let r = unsafe { fn_0040b770(s1.as_mut_ptr(), dst.as_mut_ptr(), &mut n as *mut u32) };
        assert_eq!(n, 2);
        assert_eq!(&dst[..2], &[0x61, 0x62]);
        assert_eq!(r, unsafe { s1.as_mut_ptr().wrapping_add(2) });
        // Quoted span keeps the inner space; quotes toggle, never counted.
        let mut s2 = [0x22u16, 0x61, 0x20, 0x62, 0x22, 0x20, 0x63, 0];
        n = 0xdead;
        let r = unsafe { fn_0040b770(s2.as_mut_ptr(), dst.as_mut_ptr(), &mut n as *mut u32) };
        assert_eq!(n, 3);
        assert_eq!(&dst[..3], &[0x61, 0x20, 0x62]);
        assert_eq!(r, unsafe { s2.as_mut_ptr().wrapping_add(5) });
        // Null dst: count-only lane, same cursor.
        n = 0xdead;
        let r = unsafe {
            fn_0040b770(
                s1.as_mut_ptr(),
                core::ptr::null_mut(),
                &mut n as *mut u32,
            )
        };
        assert_eq!(n, 2);
        assert_eq!(r, unsafe { s1.as_mut_ptr().wrapping_add(2) });
    }
}

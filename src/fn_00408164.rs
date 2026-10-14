//! Original procedure `0x00408164` (108 bytes, `0x408164–0x4081cf`).
//! Evidence: `evidence/00408164_fn_00408164.md`.

/// Bounded case-insensitive u16 compare: fold `a`–`z` via `^ 0x20`,
/// return first `a-b` on difference or NUL, else `0` after `param_3` lanes.
/// Params arrive in EAX/EDX/ECX per Ghidra `__register` observation.
pub unsafe fn fn_00408164(param_1: *const u16, param_2: *const u16, param_3: u32) -> i32 {
    let mut p1 = param_1;
    let mut p2 = param_2;
    let mut i: u32 = 0;
    if param_3 != 0 {
        loop {
            let mut a: u16 = core::ptr::read_unaligned(p1);
            let mut b: u16 = core::ptr::read_unaligned(p2);
            if a.wrapping_sub(0x61) < 0x1a {
                a ^= 0x20;
            }
            if b.wrapping_sub(0x61) < 0x1a {
                b ^= 0x20;
            }
            if a != b || a == 0 {
                return (a as i32).wrapping_sub(b as i32);
            }
            p1 = p1.wrapping_add(1);
            p2 = p2.wrapping_add(1);
            i = i.wrapping_add(1);
            if i >= param_3 {
                break;
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::fn_00408164;

    unsafe fn cmp(a: &[u16], b: &[u16], n: u32) -> i32 {
        fn_00408164(a.as_ptr(), b.as_ptr(), n)
    }

    #[test]
    fn fold_diff_nul_bound_lanes() {
        // Case-insensitive equality, mixed case.
        let a = [0x61u16, 0x42, 0x63, 0];
        let b = [0x41u16, 0x62, 0x43, 0];
        assert_eq!(unsafe { cmp(&a, &b, 4) }, 0);
        // First difference: `0x43 - 0x44`.
        let c = [0x41u16, 0x42, 0x43, 0];
        let d = [0x41u16, 0x42, 0x44, 0];
        assert_eq!(unsafe { cmp(&c, &d, 4) }, -1);
        assert_eq!(unsafe { cmp(&d, &c, 4) }, 1);
        // NUL stop: `0 - 0x42` at the terminator.
        let e = [0x41u16, 0];
        let f = [0x41u16, 0x42, 0];
        assert_eq!(unsafe { cmp(&e, &f, 4) }, -(0x42i32));
        // Bound cutoff: difference past `param_3` is ignored.
        assert_eq!(unsafe { cmp(&c, &d, 2) }, 0);
        // Zero bound: no reads, zero result.
        assert_eq!(unsafe { cmp(&c, &d, 0) }, 0);
    }
}

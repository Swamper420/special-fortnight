//! Original procedure `0x0040d2bc` (126 bytes, `0x0040d2bc–0x0040d339`).
//! Evidence: `evidence/0040d2bc_fn_0040d2bc.md`.

/// Header/tag parse; 1 on reject (`len<5` or `tag>=0xe1`), else 0.
/// `param_1` EAX / `param_2` EDX / `param_3` ECX per `__register` observation.
pub unsafe fn fn_0040d2bc(param_1: *mut u32, param_2: *const u8, param_3: i32) -> u32 {
    if param_3 < 5 {
        return 1;
    }
    let mut tag: u8 = core::ptr::read(param_2);
    // ponytail: `CMP CL,0xe1; JC` is unsigned `<`; `>=` rejects.
    if tag >= 0xe1 {
        return 1;
    }
    let mut q: u32 = 0;
    // ponytail: `ADD CL,0xd3` wraps; `JNC` loops while `tag>=0x2d`.
    while tag >= 0x2d {
        q = q.wrapping_add(1);
        tag = tag.wrapping_sub(0x2d);
    }
    core::ptr::write_unaligned(param_1.wrapping_byte_add(8), q);
    q = 0;
    // ponytail: `ADD CL,0xf7` wraps; `JNC` loops while `tag>=9`.
    while tag >= 9 {
        q = q.wrapping_add(1);
        tag = tag.wrapping_sub(9);
    }
    core::ptr::write_unaligned(param_1.wrapping_byte_add(4), q);
    core::ptr::write_unaligned(param_1, tag as u32);
    core::ptr::write_unaligned(param_1.wrapping_byte_add(0xc), 0u32);
    let mut p = param_2.wrapping_add(1);
    let mut i: u32 = 0;
    loop {
        let b: u32 = core::ptr::read(p) as u32;
        // ponytail: `SHL ESI,CL` masks to low 5 bits; explicit here.
        let sh: u32 = i.wrapping_shl(3) & 31;
        let acc: u32 = core::ptr::read_unaligned(param_1.wrapping_byte_add(0xc) as *const u32);
        core::ptr::write_unaligned(
            param_1.wrapping_byte_add(0xc) as *mut u32,
            acc.wrapping_add(b.wrapping_shl(sh)),
        );
        p = p.wrapping_add(1);
        i = i.wrapping_add(1);
        if i >= 4 {
            break;
        }
    }
    if core::ptr::read_unaligned(param_1.wrapping_byte_add(0xc) as *const u32) == 0 {
        core::ptr::write_unaligned(param_1.wrapping_byte_add(0xc) as *mut u32, 1);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::fn_0040d2bc;

    fn header(out: &[u32; 4]) -> [u32; 4] {
        *out
    }

    #[test]
    fn reject_and_accept_lanes() {
        let mut h = [0xdeadbeefu32; 4];
        let tag = [0x10u8, 0x01, 0x02, 0x03, 0x04];
        // Reject: len < 5.
        assert_eq!(unsafe { fn_0040d2bc(h.as_mut_ptr(), tag.as_ptr(), 4) }, 1);
        // Reject: tag >= 0xe1.
        let big = [0xe5u8, 0, 0, 0, 0];
        assert_eq!(unsafe { fn_0040d2bc(h.as_mut_ptr(), big.as_ptr(), 5) }, 1);
        // Accept: tag 0x10 → q2d=0, q9=1 (0x10-9=7), rem=7;
        // dword = 0x04030201, nonzero so no fixup.
        let mut h = [0u32; 4];
        assert_eq!(unsafe { fn_0040d2bc(h.as_mut_ptr(), tag.as_ptr(), 5) }, 0);
        assert_eq!(header(&h), [7, 1, 0, 0x04030201]);
        // Accept with zero dword → fixup to 1.
        let zero = [0x00u8, 0x00, 0x00, 0x00, 0x00];
        let mut h = [0u32; 4];
        assert_eq!(unsafe { fn_0040d2bc(h.as_mut_ptr(), zero.as_ptr(), 5) }, 0);
        assert_eq!(header(&h), [0, 0, 0, 1]);
    }
}

//! Original procedure `0x004014bc` (27 bytes, `0x004014bc–0x004014d6`).
//! Evidence: `evidence/004014bc_fn_004014bc.md`.

/// x87 `FILD`/`FISTP` roundtrip on an `i64`.
///
/// ponytail: identity copy, upgrade to `f80` emulation if a non-default
/// x87 rounding mode is ever proven at these call sites.
#[inline]
fn roundtrip(v: i64) -> i64 {
    v
}

/// `SUB ECX,4; ADD EAX/ECX; ADD EDX/ECX; NEG; do-while 8-byte
/// FILD/FISTP loop; tail u32 copy`. No pre-check: body runs ≥ once.
/// Params arrive in EAX/EDX/ECX per Ghidra `__register` observation.
pub unsafe fn fn_004014bc(param_1: *const u8, param_2: *mut u8, param_3: u32) {
    let mut ecx = param_3.wrapping_sub(4) as i32;
    let src = (param_1 as usize).wrapping_add(ecx as isize as usize);
    let dst = (param_2 as usize).wrapping_add(ecx as isize as usize);
    ecx = ecx.wrapping_neg();
    loop {
        let base = ecx as isize as usize;
        let v = core::ptr::read_unaligned(src.wrapping_add(base) as *const i64);
        core::ptr::write_unaligned(dst.wrapping_add(base) as *mut i64, roundtrip(v));
        ecx = ecx.wrapping_add(8);
        if ecx >= 0 {
            break;
        }
    }
    let base = ecx as isize as usize;
    let w =
        core::ptr::read_unaligned(src.wrapping_add(base) as *const u32);
    core::ptr::write_unaligned(dst.wrapping_add(base) as *mut u32, w);
}

#[cfg(test)]
mod tests {
    use super::fn_004014bc;

    fn run(count: usize, fill: impl Fn(usize) -> u8) {
        let mut src = vec![0u8; count];
        for (i, b) in src.iter_mut().enumerate() {
            *b = fill(i);
        }
        let mut dst = vec![0u8; count];
        unsafe { fn_004014bc(src.as_ptr(), dst.as_mut_ptr(), count as u32) };
        assert_eq!(dst, src);
    }

    #[test]
    fn loop_and_tail_lanes_copy() {
        // One iteration + tail.
        run(12, |i| (i.wrapping_mul(11).wrapping_add(5)) as u8);
        // Two iterations + tail.
        run(20, |i| (i.wrapping_mul(3).wrapping_add(150)) as u8);
    }
}

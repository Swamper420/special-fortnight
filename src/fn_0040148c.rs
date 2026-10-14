//! Original procedure `0x0040148c` (45 bytes, `0x40148c–0x4014b7`).
//! Evidence: `evidence/0040148c_fn_0040148c.md`.

/// x87 `FILD`/`FISTP` roundtrip on an `i64`.
///
/// ponytail: identity copy, upgrade to `f80` emulation if a non-default
/// x87 rounding mode is ever proven at these call sites.
#[inline]
fn roundtrip(v: i64) -> i64 {
    v
}

/// `SUB ECX,0xc; ADD EAX/ECX; ADD EDX/ECX; NEG; JNS-skip; 16-byte
/// FILD/FISTP loop; tail qword-round + u32 copy`. Params arrive in
/// EAX/EDX/ECX per Ghidra `__register` observation.
pub unsafe fn fn_0040148c(param_1: *const u8, param_2: *mut u8, param_3: u32) {
    let mut ecx = param_3.wrapping_sub(12) as i32;
    let src = (param_1 as usize).wrapping_add(ecx as isize as usize);
    let dst = (param_2 as usize).wrapping_add(ecx as isize as usize);
    ecx = ecx.wrapping_neg();
    if ecx < 0 {
        loop {
            let base = ecx as isize as usize;
            let a0 = core::ptr::read_unaligned(src.wrapping_add(base) as *const i64);
            let a8 = core::ptr::read_unaligned(
                src.wrapping_add(base).wrapping_add(8) as *const i64,
            );
            core::ptr::write_unaligned(
                dst.wrapping_add(base).wrapping_add(8) as *mut i64,
                roundtrip(a8),
            );
            core::ptr::write_unaligned(dst.wrapping_add(base) as *mut i64, roundtrip(a0));
            ecx = ecx.wrapping_add(0x10);
            if ecx >= 0 {
                break;
            }
        }
    }
    let base = ecx as isize as usize;
    let v = core::ptr::read_unaligned(src.wrapping_add(base) as *const i64);
    core::ptr::write_unaligned(dst.wrapping_add(base) as *mut i64, roundtrip(v));
    let w =
        core::ptr::read_unaligned(src.wrapping_add(base).wrapping_add(8) as *const u32);
    core::ptr::write_unaligned(dst.wrapping_add(base).wrapping_add(8) as *mut u32, w);
}

#[cfg(test)]
mod tests {
    use super::fn_0040148c;

    fn run(count: usize, fill: impl Fn(usize) -> u8) -> Vec<u8> {
        let mut src = vec![0u8; count];
        for (i, b) in src.iter_mut().enumerate() {
            *b = fill(i);
        }
        let mut dst = vec![0u8; count];
        unsafe { fn_0040148c(src.as_ptr(), dst.as_mut_ptr(), count as u32) };
        assert_eq!(dst, src);
        dst
    }

    #[test]
    fn tail_and_loop_lanes_copy() {
        // Tail only (12 = 8-round + 4-copy), no loop iterations.
        run(12, |i| (i.wrapping_mul(7).wrapping_add(3)) as u8);
        // One 16-byte iteration + tail.
        run(28, |i| (i.wrapping_mul(13).wrapping_add(29)) as u8);
        // Two iterations + tail; includes negative i64 patterns.
        let dst = run(44, |i| (i.wrapping_mul(5).wrapping_add(200)) as u8);
        assert_eq!(dst.len(), 44);
    }
}

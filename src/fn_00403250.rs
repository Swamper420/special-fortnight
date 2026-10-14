//! Original procedure `0x00403250` (150 bytes, `0x00403250–0x00403292` + `0x00403296–0x004032ab` + `0x004032ae–0x004032ea`).
//! Evidence: `evidence/00403250_fn_00403250.md`.

unsafe fn w16(dst: *mut u8, off: usize, v: u16) {
    core::ptr::write_unaligned(dst.wrapping_add(off) as *mut u16, v);
}

unsafe fn w64(dst: *mut u8, off: usize, v: u64) {
    core::ptr::write_unaligned(dst.wrapping_add(off) as *mut u64, v);
}

/// Byte fill (`dst` EAX, `len` EDX, fill `CL` per `__register`).
/// 8-byte lanes use x87 `FLD`/`FST` in the original; Rust replicates the
/// fill byte over `u16`/`u64` unaligned lanes, same bytes, same order.
pub unsafe fn fn_00403250(param_1: *mut u8, param_2: u32, param_3: u8) {
    if (param_2 as i32) < 0x20 {
        if (param_2 as i32) <= 0 {
            return;
        }
        core::ptr::write_unaligned(param_1.wrapping_add(param_2 as usize - 1), param_3);
        let fill16 = (param_3 as u16).wrapping_mul(0x101);
        let mut k = param_2 & !1;
        while k >= 2 {
            w16(param_1, (k - 2) as usize, fill16);
            k = k.wrapping_sub(2);
        }
        return;
    }
    let fill16 = (param_3 as u16).wrapping_mul(0x101);
    w16(param_1, 0, fill16);
    w16(param_1, 2, fill16);
    w16(param_1, 4, fill16);
    w16(param_1, 6, fill16);
    let len16 = param_2.wrapping_sub(0x10);
    let d = core::ptr::read_unaligned(param_1 as *const u64);
    w64(param_1, len16 as usize, d);
    w64(param_1, (len16.wrapping_add(8)) as usize, d);
    // ponytail: alignment/address math is full-width `usize` on host;
    // on target these are 32-bit `u32` wraps. Low 3 bits (alignment) are
    // identical; high bits are preserved instead of truncated so host
    // pointers stay valid. Revisit with image-relative data layout.
    let ecx: i32 = ((param_1 as usize & 7) as i32).wrapping_sub(8);
    let eax2 = (param_1 as usize).wrapping_add(ecx.wrapping_neg() as usize);
    let edx2 = len16.wrapping_add(ecx as u32);
    let base = eax2.wrapping_add(edx2 as usize);
    let mut off = (edx2 as i32).wrapping_neg();
    loop {
        w64(base as *mut u8, off as usize, d);
        // ponytail: `off+8` stays in signed `i32` so negatives sign-extend
        // to `usize` (target 32-bit wrap = host sign-extend here); the
        // `(off as u32)+8` form would zero-extend to +4G on a 64-bit host.
        w64(base as *mut u8, off.wrapping_add(8) as usize, d);
        off = off.wrapping_add(0x10);
        if off >= 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fn_00403250;

    fn run_case(len: usize, dst_off: usize, fill: u8) {
        let mut arena = [0xAAu8; 128];
        let base = arena.as_mut_ptr();
        unsafe { fn_00403250(base.wrapping_add(dst_off), len as u32, fill) };
        // Full fill over [dst_off, dst_off+len), canaries intact.
        assert!(arena[..dst_off].iter().all(|&b| b == 0xAA));
        assert!(arena[dst_off + len..].iter().all(|&b| b == 0xAA));
        if len > 0 {
            assert!(arena[dst_off..dst_off + len].iter().all(|&b| b == fill));
        }
    }

    #[test]
    fn fill_lanes() {
        // No-op lane.
        run_case(0, 16, 0x5A);
        // Small computed-jump lanes incl. odd/even edges.
        for len in [1usize, 2, 3, 4, 5, 7, 8, 0x1e, 0x1f] {
            for align in [0usize, 1, 3, 5] {
                run_case(len, 16 + align, 0x5A);
            }
        }
        // Big aligned-loop lanes across dst alignments 0..7.
        for len in [0x20usize, 0x21, 0x28, 0x40] {
            for align in 0..8usize {
                run_case(len, 32 + align, 0xC3);
            }
        }
    }
}

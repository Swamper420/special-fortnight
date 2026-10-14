//! Original procedure `0x00402fbc` (215 bytes, `0x402fbc–0x402ff1` + `0x403018–0x4030b8`).
//! Evidence: `evidence/00402fbc_fn_00402fbc.md`.

unsafe fn r64(p: *const u8) -> u64 {
    core::ptr::read_unaligned(p as *const u64)
}

unsafe fn w64(p: *mut u8, v: u64) {
    core::ptr::write_unaligned(p as *mut u64, v);
}

unsafe fn forward_copy(src: *mut u8, dst: *mut u8, len: u32) {
    let first = r64(src);
    let src_end = src.wrapping_add(len.wrapping_sub(8) as usize);
    let dst_end = dst.wrapping_add(len.wrapping_sub(8) as usize);
    let last = r64(src_end);
    let mut off: i32 = ((dst as u32 & 0xfffffff8)
        .wrapping_sub(dst_end as u32)
        .wrapping_add(8)) as i32;
    loop {
        w64(dst_end.wrapping_add(off as usize), r64(src_end.wrapping_add(off as usize)));
        off = off.wrapping_add(8);
        if off >= 0 {
            break;
        }
    }
    w64(dst_end, last);
    w64(dst, first);
}

unsafe fn backward_copy(src: *mut u8, dst: *mut u8, len: u32) {
    let n = len.wrapping_sub(8);
    let tail = r64(src.wrapping_add(n as usize));
    let head = r64(src);
    let mut off: i32 = ((n.wrapping_add(dst as u32) & 0xfffffff8).wrapping_sub(dst as u32))
        as i32;
    loop {
        w64(dst.wrapping_add(off as usize), r64(src.wrapping_add(off as usize)));
        off = off.wrapping_sub(8);
        if off <= 0 {
            break;
        }
    }
    w64(dst, head);
    w64(dst.wrapping_add(n as usize), tail);
}

/// Overlap-aware copy (`src` EAX, `dst` EDX, `len` ECX per `__register`).
/// 8-byte lanes use x87 `FILD`/`FISTP` in the original (exact for integer
/// payloads); Rust uses `u64` unaligned copies, same bytes, same order.
pub unsafe fn fn_00402fbc(param_1: *mut u8, param_2: *mut u8, param_3: u32) {
    if param_1 == param_2 {
        return;
    }
    if param_3 > 0x20 {
        if (param_3 as i32) <= 0x20 {
            return;
        }
        if (param_2 as u32) < (param_1 as u32) {
            forward_copy(param_1, param_2, param_3);
        } else {
            let tmp = (param_2 as u32).wrapping_sub(param_3);
            if (param_1 as u32) <= tmp {
                forward_copy(param_1, param_2, param_3);
            } else {
                backward_copy(param_1, param_2, param_3);
            }
        }
        return;
    }
    let n = param_3.wrapping_sub(8);
    if (n as i32) > 0 {
        let last = r64(param_1.wrapping_add(n as usize));
        let first = r64(param_1);
        if (n as i32) > 8 {
            w64(param_2.wrapping_add(8), r64(param_1.wrapping_add(8)));
            if (n as i32) > 0x10 {
                w64(param_2.wrapping_add(0x10), r64(param_1.wrapping_add(0x10)));
            }
        }
        w64(param_2, first);
        w64(param_2.wrapping_add(n as usize), last);
        return;
    }
    match param_3 {
        0 => {}
        1 => {
            let b = core::ptr::read_unaligned(param_1);
            core::ptr::write_unaligned(param_2, b);
        }
        2 => {
            let v = core::ptr::read_unaligned(param_1 as *const u16);
            core::ptr::write_unaligned(param_2 as *mut u16, v);
        }
        3 => {
            let lo = core::ptr::read_unaligned(param_1 as *const u16);
            let hi = core::ptr::read_unaligned(param_1.wrapping_add(2));
            core::ptr::write_unaligned(param_2 as *mut u16, lo);
            core::ptr::write_unaligned(param_2.wrapping_add(2), hi);
        }
        4 => {
            let v = core::ptr::read_unaligned(param_1 as *const u32);
            core::ptr::write_unaligned(param_2 as *mut u32, v);
        }
        5 => {
            let lo = core::ptr::read_unaligned(param_1 as *const u32);
            let hi = core::ptr::read_unaligned(param_1.wrapping_add(4));
            core::ptr::write_unaligned(param_2 as *mut u32, lo);
            core::ptr::write_unaligned(param_2.wrapping_add(4), hi);
        }
        6 => {
            let lo = core::ptr::read_unaligned(param_1 as *const u32);
            let hi = core::ptr::read_unaligned(param_1.wrapping_add(4) as *const u16);
            core::ptr::write_unaligned(param_2 as *mut u32, lo);
            core::ptr::write_unaligned(param_2.wrapping_add(4) as *mut u16, hi);
        }
        7 => {
            let lo = core::ptr::read_unaligned(param_1 as *const u32);
            let hi = core::ptr::read_unaligned(param_1.wrapping_add(3) as *const u32);
            core::ptr::write_unaligned(param_2 as *mut u32, lo);
            core::ptr::write_unaligned(param_2.wrapping_add(3) as *mut u32, hi);
        }
        8 => {
            w64(param_2, r64(param_1));
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::fn_00402fbc;

    fn run_case(len: usize, src_off: usize, dst_off: usize) {
        let mut arena = [0u8; 256];
        for (i, b) in arena.iter_mut().enumerate() {
            *b = (i.wrapping_mul(0x25).wrapping_add(0x11)) as u8;
        }
        let mut expect = arena;
        expect.copy_within(src_off..src_off + len, dst_off);
        let base = arena.as_mut_ptr();
        unsafe {
            fn_00402fbc(
                base.wrapping_add(src_off),
                base.wrapping_add(dst_off),
                len as u32,
            )
        };
        assert_eq!(arena, expect, "len={len} src={src_off} dst={dst_off}");
    }

    #[test]
    fn copy_lanes() {
        // Small jump-table lanes, non-overlapping.
        for len in [0usize, 1, 2, 3, 4, 5, 6, 7, 8] {
            run_case(len, 16, 64);
        }
        // Small mid lane with [8]/[16] staging.
        for len in [9usize, 16, 0x10, 0x18, 0x20] {
            run_case(len, 16, 64);
        }
        // Big forward/backward non-overlapping.
        run_case(0x21, 0, 0x80);
        run_case(0x40, 0x80, 0);
        // Overlaps both directions, small and big.
        run_case(8, 32, 36);
        run_case(8, 36, 32);
        run_case(0x10, 32, 40);
        run_case(0x10, 40, 32);
        run_case(0x40, 16, 32);
        run_case(0x40, 32, 16);
        // src==dst no-op (canary intact by construction).
        run_case(0x40, 48, 48);
        // Huge (signed-negative) len: no copy.
        let mut arena = [0xAAu8; 64];
        let base = arena.as_mut_ptr();
        unsafe { fn_00402fbc(base, base.wrapping_add(32), 0x80000001) };
        assert_eq!(arena, [0xAAu8; 64]);
    }
}

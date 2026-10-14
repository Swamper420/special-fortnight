//! Original procedure `0x00408c0e` (16 bytes, `0x00408c0e–0x00408c1d`).
//! Evidence: `evidence/00408c0e_fn_00408c0e.md`.

/// Counted word copy: null `src` returns `dst` untouched;
/// else `n=[src-4]` words move `src->dst` (`REP MOVSW`,
/// `ECX=0` copies nothing), returning the advanced `dst`.
/// `src` is caller frame `[EBP-8]`; `PUSH/POP ESI` is
/// callee-save only (no host effect).
pub unsafe fn fn_00408c0e(src: *mut u16, dst: *mut u16) -> *mut u16 {
    if src.is_null() {
        return dst;
    }
    let mut n: u32 = core::ptr::read_unaligned(((src as usize).wrapping_sub(4)) as *const u32);
    let mut s = src;
    let mut d = dst;
    while n != 0 {
        n = n.wrapping_sub(1);
        core::ptr::write_unaligned(d, core::ptr::read_unaligned(s as *const u16));
        s = s.wrapping_byte_add(2);
        d = d.wrapping_byte_add(2);
    }
    d
}

#[cfg(test)]
mod tests {
    use super::fn_00408c0e;

    #[test]
    fn null_zero_and_copy_lanes() {
        // No hooks/globals: locals only, no TEST_LOCK.
        let mut dst = [0u16; 4];
        // Null lane: dst untouched, cursor unchanged.
        let ret = unsafe { fn_00408c0e(core::ptr::null_mut(), dst.as_mut_ptr()) };
        assert_eq!(ret, dst.as_mut_ptr());
        assert_eq!(dst, [0u16; 4]);
        // Header layout: count u32 lives 4 bytes below src words.
        let mut arena = [3u16, 0, 0x41, 0x42, 0x43];
        let src = arena.as_mut_ptr().wrapping_add(2);
        let ret = unsafe { fn_00408c0e(src, dst.as_mut_ptr()) };
        assert_eq!(ret, dst.as_mut_ptr().wrapping_byte_add(6));
        assert_eq!(dst, [0x41u16, 0x42, 0x43, 0]);
        // Zero-count lane: no copy, cursor unchanged.
        let mut arena0 = [0u16, 0, 0x41, 0x42];
        let src0 = arena0.as_mut_ptr().wrapping_add(2);
        let mut dst0 = [0x77u16; 2];
        let ret = unsafe { fn_00408c0e(src0, dst0.as_mut_ptr()) };
        assert_eq!(ret, dst0.as_mut_ptr());
        assert_eq!(dst0, [0x77u16; 2]);
    }
}

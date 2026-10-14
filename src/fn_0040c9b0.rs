//! Original procedure `0x0040c9b0` (84 bytes, `0x0040c9b0–0x0040ca03`).
//! Evidence: `evidence/0040c9b0_fn_0040c9b0.md`.

/// `3a8c`-link, `3894` on `[obj+4]`, optional `[obj+0x10]`-gated
/// vcall pair (`[vtbl+0]` / `[vtbl+0xc]` on the `[obj+8]` object with
/// an 8-byte local, `b2d4`-folded), then `3884` with
/// `DL = BL & 0xfc` and `3a34` unless `BL <= 0` (signed). `param_1`
/// EAX / `param_2` DL per `__register`. Returns void.
pub unsafe fn fn_0040c9b0(param_1: *mut u8, param_2: u8) {
    let esi = crate::fn_00403a8c::fn_00403a8c(param_1, param_2);
    let inner: *mut *const u8 =
        core::ptr::read_unaligned(esi.wrapping_byte_add(4) as *const *mut *const u8);
    crate::fn_00403894::fn_00403894(inner);
    if core::ptr::read_unaligned(esi.wrapping_byte_add(0x10) as *const u8) != 0 {
        let mut local = [0u8; 8];
        let target: *mut u8 =
            core::ptr::read_unaligned(esi.wrapping_byte_add(8) as *const *mut u8);
        let vtbl: *const u8 = core::ptr::read_unaligned(target as *const *const u8);
        // ponytail: vcall lanes observed as `(EAX=obj, EDX=local)`
        // only; widths stay pointer-sized, same as `fn_00403894`.
        let t0 = core::ptr::read_unaligned(vtbl as *const *const core::ffi::c_void);
        let f0: unsafe extern "C" fn(*mut u8, *mut u8) = core::mem::transmute(t0);
        f0(target, local.as_mut_ptr());
        let addend: u32 = core::ptr::read_unaligned(esi.wrapping_byte_add(0xc) as *const u32);
        crate::fn_0040b2d4::fn_0040b2d4(local.as_mut_ptr() as *mut u32, addend);
        let t12 = core::ptr::read_unaligned(
            vtbl.wrapping_byte_add(0xc) as *const *const core::ffi::c_void
        );
        let f12: unsafe extern "C" fn(*mut u8, *mut u8) = core::mem::transmute(t12);
        f12(target, local.as_mut_ptr());
    }
    // ponytail: `mov %ebx,%edx; and $0xfc,%dl` — low byte masked,
    // high bytes are the incoming EDX (zero in our u8 lane model).
    crate::fn_00403884::fn_00403884(esi, param_2 & 0xfc);
    if (param_2 as i8) > 0 {
        crate::fn_00403a34::fn_00403a34(esi as *mut *const u8);
    }
}

#[cfg(test)]
mod tests {
    use super::fn_0040c9b0;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static LINK_HITS: AtomicUsize = AtomicUsize::new(0);
    static INNER_HITS: AtomicUsize = AtomicUsize::new(0);
    static V0_HITS: AtomicUsize = AtomicUsize::new(0);
    static V12_HITS: AtomicUsize = AtomicUsize::new(0);
    static UNLINK_HITS: AtomicUsize = AtomicUsize::new(0);

    /// `[vtbl-0x18]` slot for the real `fn_00403a8c` link lane.
    unsafe extern "C" fn link(_o: *mut u8) {
        LINK_HITS.fetch_add(1, Ordering::SeqCst);
    }
    /// `[vtbl-4]` slot for the real `fn_00403894` inner lane
    /// (inner object shares the outer table here).
    unsafe extern "C" fn inner(_o: *mut *const u8, _f: u8) {
        INNER_HITS.fetch_add(1, Ordering::SeqCst);
    }
    /// `[vtbl+0]` / `[vtbl+0xc]` slots on the `[obj+8]` target.
    unsafe extern "C" fn v0(_o: *mut u8, _l: *mut u8) {
        V0_HITS.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn v12(_o: *mut u8, _l: *mut u8) {
        V12_HITS.fetch_add(1, Ordering::SeqCst);
    }
    /// `[vtbl-8]` slot for the real `fn_00403a34` unlink lane.
    unsafe extern "C" fn unlink(_o: *mut *const u8) {
        UNLINK_HITS.fetch_add(1, Ordering::SeqCst);
    }

    fn outer_vtbl(buf: &mut [u8; 64]) -> *const u8 {
        let l = link as *const core::ffi::c_void;
        let i = inner as *const core::ffi::c_void;
        let u = unlink as *const core::ffi::c_void;
        let vt = unsafe { buf.as_ptr().add(0x20) };
        unsafe {
            // Self-pointer at +0: the inner object shares this table,
            // so `fn_00403894` reads `*vt == vt` and resolves `[vt-4]`.
            // (32-bit-exact; see the `cfg` gate on the test.)
            core::ptr::copy_nonoverlapping(
                &vt as *const _ as *const u8,
                buf.as_mut_ptr().add(0x20),
                core::mem::size_of::<*const u8>(),
            );
            core::ptr::copy_nonoverlapping(
                &l as *const _ as *const u8,
                buf.as_mut_ptr().add(0x20 - 0x18),
                core::mem::size_of::<*const core::ffi::c_void>(),
            );
            core::ptr::copy_nonoverlapping(
                &i as *const _ as *const u8,
                buf.as_mut_ptr().add(0x20 - 4),
                core::mem::size_of::<*const core::ffi::c_void>(),
            );
            core::ptr::copy_nonoverlapping(
                &u as *const _ as *const u8,
                buf.as_mut_ptr().add(0x20 - 8),
                core::mem::size_of::<*const core::ffi::c_void>(),
            );
        }
        vt
    }

    #[test]
    #[cfg(target_pointer_width = "32")]
    fn gated_pair_and_unlink_lanes() {
        let mut vbuf = [0u8; 64];
        let vt = outer_vtbl(&mut vbuf);
        // Target table for the `[obj+8]` object: vcall slots at
        // `+0` / `+0xc`.
        let mut tbuf = [0u8; 32];
        let t0 = v0 as *const core::ffi::c_void;
        let t12 = v12 as *const core::ffi::c_void;
        unsafe {
            core::ptr::copy_nonoverlapping(
                &t0 as *const _ as *const u8,
                tbuf.as_mut_ptr(),
                core::mem::size_of::<*const core::ffi::c_void>(),
            );
            core::ptr::copy_nonoverlapping(
                &t12 as *const _ as *const u8,
                tbuf.as_mut_ptr().add(0xc),
                core::mem::size_of::<*const core::ffi::c_void>(),
            );
        }
        // Object: vtbl, inner (shares table, so its `[vtbl-4]`
        // resolves), target, addend, flag.
        // ponytail: adjacent pointer fields (+0/+4) overlap on a
        // 64-bit host (8-byte reads); exact only on the 32-bit
        // target, hence the `cfg` gate — same ceiling as
        // `fn_0040382c`.
        let mut obuf = [0u8; 0x18];
        unsafe {
            core::ptr::copy_nonoverlapping(
                &vt as *const _ as *const u8,
                obuf.as_mut_ptr(),
                core::mem::size_of::<*const u8>(),
            );
            core::ptr::copy_nonoverlapping(
                &vt as *const _ as *const u8,
                obuf.as_mut_ptr().add(4),
                core::mem::size_of::<*const u8>(),
            );
            let tp = tbuf.as_ptr();
            core::ptr::copy_nonoverlapping(
                &tp as *const _ as *const u8,
                obuf.as_mut_ptr().add(8),
                core::mem::size_of::<*const u8>(),
            );
        }
        let o = obuf.as_mut_ptr();
        // Taken lane (`[obj+0x10] != 0`, `BL=1`): link, inner,
        // both vcalls, unlink.
        for c in [&LINK_HITS, &INNER_HITS, &V0_HITS, &V12_HITS, &UNLINK_HITS] {
            c.store(0, Ordering::SeqCst);
        }
        unsafe {
            *o.wrapping_byte_add(0x10) = 1;
            fn_0040c9b0(o, 1);
        }
        assert_eq!(LINK_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(INNER_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(V0_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(V12_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(UNLINK_HITS.load(Ordering::SeqCst), 1);
        // Skip lane (`[obj+0x10] == 0`, `BL=0`): nothing dispatches.
        for c in [&LINK_HITS, &INNER_HITS, &V0_HITS, &V12_HITS, &UNLINK_HITS] {
            c.store(0, Ordering::SeqCst);
        }
        unsafe {
            *o.wrapping_byte_add(0x10) = 0;
            fn_0040c9b0(o, 0);
        }
        assert_eq!(LINK_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(INNER_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(V0_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(V12_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(UNLINK_HITS.load(Ordering::SeqCst), 0);
    }
}
